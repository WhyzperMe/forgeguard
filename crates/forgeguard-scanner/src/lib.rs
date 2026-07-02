#![forbid(unsafe_code)]

//! Shared scanner abstraction and bounded lockfile discovery for ForgeGuard ecosystem plugins.
//!
//! Scanner implementations are intentionally static: they inspect manifests and lockfiles as data
//! and must not execute package manager commands, build scripts, lifecycle scripts, or project code.
//! The registry in this crate provides deterministic, bounded, symlink-safe discovery for projects
//! that contain multiple ecosystems, for example a Tauri repository with `package-lock.json` at the
//! root and `src-tauri/Cargo.lock` below it.

use forgeguard_core::{DependencyGraph, Ecosystem};
use std::{
    collections::BTreeSet,
    fmt, fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

const DEFAULT_MAX_DISCOVERY_DEPTH: usize = 6;
const DEFAULT_MAX_CANDIDATES: usize = 128;
const DEFAULT_MAX_VISITED_DIRECTORIES: usize = 4096;

const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "node_modules",
    "target",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".cache",
    "vendor",
];

/// Input passed to a dependency scanner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannerInput {
    /// Project directory or lockfile path supplied by the caller.
    pub target: PathBuf,
}

impl ScannerInput {
    /// Create scanner input from a target path.
    #[must_use]
    pub fn new(target: impl Into<PathBuf>) -> Self {
        Self {
            target: target.into(),
        }
    }
}

/// Static dependency scan output for one ecosystem lockfile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannerOutput {
    /// Ecosystem analyzed by the scanner.
    pub ecosystem: Ecosystem,
    /// Original scan target used for this scanner invocation.
    pub target: PathBuf,
    /// Manifest file used for dependency classification, if present.
    pub manifest_path: Option<PathBuf>,
    /// Lockfile used for deterministic dependency resolution, if present.
    pub lockfile_path: Option<PathBuf>,
    /// Normalized dependency graph.
    pub graph: DependencyGraph,
    /// Scanner limitations and safety notes for reports.
    pub limitations: Vec<String>,
}

impl ScannerOutput {
    /// Return the number of discovered packages.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.graph.package_count()
    }

    /// Return the best stable file identity for this output.
    ///
    /// Lockfile paths are preferred because they describe deterministic dependency resolution more
    /// precisely than a project directory target.
    #[must_use]
    pub fn identity_path(&self) -> &Path {
        self.lockfile_path.as_deref().unwrap_or(&self.target)
    }
}

/// Bounded recursive discovery configuration.
///
/// The defaults are intentionally conservative enough for untrusted repositories while still
/// supporting common layouts such as monorepos and Tauri applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryConfig {
    /// Maximum directory depth below the user-provided target.
    pub max_depth: usize,
    /// Maximum scanner candidates to evaluate.
    pub max_candidates: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DISCOVERY_DEPTH,
            max_candidates: DEFAULT_MAX_CANDIDATES,
        }
    }
}

impl DiscoveryConfig {
    /// Validate that the discovery bounds are usable.
    pub fn validate(self) -> Result<(), ScannerError> {
        if self.max_candidates == 0 {
            return Err(ScannerError::InvalidDiscoveryConfig(
                "max_candidates must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Errors from scanner registry and adapter boundaries.
#[derive(Debug, Error)]
pub enum ScannerError {
    /// The registry has no scanners registered.
    #[error("no dependency scanners are registered")]
    EmptyRegistry,
    /// The user-supplied path does not exist.
    #[error("scan target does not exist: {0}")]
    TargetMissing(PathBuf),
    /// The user-supplied path exists but metadata cannot be inspected.
    #[error("scan target is not accessible: {target}: {message}")]
    TargetInaccessible {
        /// Target path.
        target: PathBuf,
        /// Stable error message.
        message: String,
    },
    /// Discovery refused to traverse a symlinked directory or lockfile target.
    #[error("scan target is a symlink and will not be followed: {0}")]
    UnsafeSymlink(PathBuf),
    /// No registered scanner supports the target.
    #[error("no supported dependency lockfile was found for target: {0}")]
    UnsupportedTarget(PathBuf),
    /// Discovery found too many matching scanner candidates.
    #[error(
        "dependency lockfile discovery limit exceeded: found more than {limit} candidate(s) below {target}"
    )]
    DiscoveryLimitExceeded {
        /// Original target.
        target: PathBuf,
        /// Configured candidate limit.
        limit: usize,
    },
    /// Discovery traversed too many directories without completing.
    #[error(
        "dependency lockfile discovery directory limit exceeded: inspected more than {limit} directory candidate(s) below {target}"
    )]
    DiscoveryDirectoryLimitExceeded {
        /// Original target.
        target: PathBuf,
        /// Configured internal directory limit.
        limit: usize,
    },
    /// Invalid discovery configuration.
    #[error("invalid dependency discovery configuration: {0}")]
    InvalidDiscoveryConfig(String),
    /// An ecosystem scanner failed.
    #[error("{ecosystem} scanner failed for {target}: {message}")]
    ScannerFailed {
        /// Scanner ecosystem.
        ecosystem: Ecosystem,
        /// Original target path.
        target: PathBuf,
        /// Stable error message.
        message: String,
    },
}

impl ScannerError {
    /// Construct a scanner failure while preserving a useful message without forcing concrete
    /// scanner errors into this shared crate.
    #[must_use]
    pub fn scanner_failed(
        ecosystem: Ecosystem,
        target: impl Into<PathBuf>,
        source: impl fmt::Display,
    ) -> Self {
        Self::ScannerFailed {
            ecosystem,
            target: target.into(),
            message: source.to_string(),
        }
    }
}

/// Static dependency scanner interface.
///
/// Implementations must be deterministic and must not execute external commands or project code.
/// `can_scan` should be a cheap structural check, usually based on the presence of a supported
/// lockfile. `scan` may perform static parsing of manifests and lockfiles only.
pub trait DependencyScanner: Send + Sync {
    /// Ecosystem handled by this scanner.
    fn ecosystem(&self) -> Ecosystem;

    /// Return true when this scanner can handle the target path.
    fn can_scan(&self, target: &Path) -> bool;

    /// Scan a target using static parsing only.
    fn scan(&self, input: &ScannerInput) -> Result<ScannerOutput, ScannerError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScannerCandidate {
    scanner_index: usize,
    ecosystem: Ecosystem,
    target: PathBuf,
    depth: usize,
}

#[derive(Debug)]
struct DiscoveryState {
    root: PathBuf,
    candidates: Vec<ScannerCandidate>,
    visited_directories: usize,
    visited_paths: BTreeSet<String>,
}

impl DiscoveryState {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            candidates: Vec::new(),
            visited_directories: 0,
            visited_paths: BTreeSet::new(),
        }
    }

    fn push_candidate(
        &mut self,
        candidate: ScannerCandidate,
        max_candidates: usize,
    ) -> Result<(), ScannerError> {
        if self.candidates.len() >= max_candidates {
            return Err(ScannerError::DiscoveryLimitExceeded {
                target: self.root.clone(),
                limit: max_candidates,
            });
        }
        self.candidates.push(candidate);
        Ok(())
    }

    fn record_directory(&mut self, path: &Path) -> Result<bool, ScannerError> {
        self.visited_directories += 1;
        if self.visited_directories > DEFAULT_MAX_VISITED_DIRECTORIES {
            return Err(ScannerError::DiscoveryDirectoryLimitExceeded {
                target: self.root.clone(),
                limit: DEFAULT_MAX_VISITED_DIRECTORIES,
            });
        }
        Ok(self.visited_paths.insert(stable_path_key(path)))
    }
}

/// Registry for ecosystem scanner plugins.
#[derive(Default)]
pub struct ScannerRegistry {
    scanners: Vec<Box<dyn DependencyScanner>>,
    discovery: DiscoveryConfig,
}

impl ScannerRegistry {
    /// Create an empty scanner registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure bounded recursive discovery.
    #[must_use]
    pub fn with_discovery_config(mut self, discovery: DiscoveryConfig) -> Self {
        self.discovery = discovery;
        self
    }

    /// Register a scanner and return the registry for builder-style setup.
    #[must_use]
    pub fn with_scanner<T>(mut self, scanner: T) -> Self
    where
        T: DependencyScanner + 'static,
    {
        self.register(scanner);
        self
    }

    /// Register a scanner.
    pub fn register<T>(&mut self, scanner: T)
    where
        T: DependencyScanner + 'static,
    {
        self.scanners.push(Box::new(scanner));
    }

    /// Return true if the registry has no scanners.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scanners.is_empty()
    }

    /// Return the number of registered scanners.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scanners.len()
    }

    /// Scan with the first scanner that directly supports the target.
    ///
    /// This intentionally does not recurse. Use [`Self::scan_all`] for autonomous repository
    /// discovery across nested lockfiles such as Tauri's `src-tauri/Cargo.lock`.
    pub fn scan_one(&self, input: &ScannerInput) -> Result<ScannerOutput, ScannerError> {
        self.ensure_ready()?;
        validate_target(&input.target)?;

        let scanner = self
            .scanners
            .iter()
            .find(|scanner| scanner.can_scan(&input.target))
            .ok_or_else(|| ScannerError::UnsupportedTarget(input.target.clone()))?;
        scanner.scan(input)
    }

    /// Discover and scan every supported lockfile under the target, within safe bounds.
    ///
    /// The method is deterministic, deduplicates equivalent lockfile outputs, avoids common heavy
    /// generated directories, and never follows symlinked directories. This is the preferred path
    /// for real repositories that may contain multiple ecosystems.
    pub fn scan_all(&self, input: &ScannerInput) -> Result<Vec<ScannerOutput>, ScannerError> {
        self.ensure_ready()?;
        self.discovery.validate()?;
        validate_target(&input.target)?;

        let mut state = DiscoveryState::new(&input.target);
        self.collect_candidates(&input.target, 0, &mut state)?;

        if state.candidates.is_empty() {
            return Err(ScannerError::UnsupportedTarget(input.target.clone()));
        }

        state.candidates.sort_by(|left, right| {
            left.depth
                .cmp(&right.depth)
                .then_with(|| stable_path_key(&left.target).cmp(&stable_path_key(&right.target)))
                .then_with(|| left.ecosystem.cmp(&right.ecosystem))
                .then_with(|| left.scanner_index.cmp(&right.scanner_index))
        });

        let mut outputs = Vec::new();
        let mut seen_outputs = BTreeSet::<(Ecosystem, String)>::new();

        for candidate in state.candidates {
            let scanner = &self.scanners[candidate.scanner_index];
            let candidate_input = ScannerInput::new(candidate.target);
            let output = scanner.scan(&candidate_input)?;
            if seen_outputs.insert(output_key(&output)) {
                outputs.push(output);
            }
        }

        if outputs.is_empty() {
            return Err(ScannerError::UnsupportedTarget(input.target.clone()));
        }

        outputs.sort_by(|left, right| {
            left.ecosystem.cmp(&right.ecosystem).then_with(|| {
                stable_path_key(left.identity_path()).cmp(&stable_path_key(right.identity_path()))
            })
        });
        Ok(outputs)
    }

    fn ensure_ready(&self) -> Result<(), ScannerError> {
        if self.scanners.is_empty() {
            Err(ScannerError::EmptyRegistry)
        } else {
            Ok(())
        }
    }

    fn collect_candidates(
        &self,
        target: &Path,
        depth: usize,
        state: &mut DiscoveryState,
    ) -> Result<(), ScannerError> {
        self.collect_direct_candidates(target, depth, state)?;

        if depth >= self.discovery.max_depth || !is_traversable_directory(target) {
            return Ok(());
        }

        if !state.record_directory(target)? {
            return Ok(());
        }

        let mut child_directories = child_directories(target)?;
        child_directories.sort_by_key(|left| stable_path_key(left));

        for directory in child_directories {
            self.collect_candidates(&directory, depth + 1, state)?;
        }

        Ok(())
    }

    fn collect_direct_candidates(
        &self,
        target: &Path,
        depth: usize,
        state: &mut DiscoveryState,
    ) -> Result<(), ScannerError> {
        if is_symlink(target) {
            return Ok(());
        }

        for (scanner_index, scanner) in self.scanners.iter().enumerate() {
            if scanner.can_scan(target) {
                state.push_candidate(
                    ScannerCandidate {
                        scanner_index,
                        ecosystem: scanner.ecosystem(),
                        target: target.to_path_buf(),
                        depth,
                    },
                    self.discovery.max_candidates,
                )?;
            }
        }
        Ok(())
    }
}

fn validate_target(target: &Path) -> Result<(), ScannerError> {
    match fs::symlink_metadata(target) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(ScannerError::UnsafeSymlink(target.to_path_buf()));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(ScannerError::TargetMissing(target.to_path_buf()))
        }
        Err(error) => Err(ScannerError::TargetInaccessible {
            target: target.to_path_buf(),
            message: error.to_string(),
        }),
    }
}

fn output_key(output: &ScannerOutput) -> (Ecosystem, String) {
    (
        output.ecosystem.clone(),
        stable_path_key(output.identity_path()),
    )
}

fn stable_path_key(path: &Path) -> String {
    let mut key = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");

    if cfg!(windows) {
        key.make_ascii_lowercase();
    }
    key
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn is_traversable_directory(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.is_dir() && !metadata.file_type().is_symlink()
}

fn child_directories(target: &Path) -> Result<Vec<PathBuf>, ScannerError> {
    let entries = fs::read_dir(target).map_err(|error| ScannerError::TargetInaccessible {
        target: target.to_path_buf(),
        message: error.to_string(),
    })?;

    let mut directories = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| ScannerError::TargetInaccessible {
            target: target.to_path_buf(),
            message: error.to_string(),
        })?;
        let path = entry.path();
        if is_traversable_directory(&path) && !should_skip_directory(&path) {
            directories.push(path);
        }
    }
    Ok(directories)
}

fn should_skip_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            SKIPPED_DIRECTORIES
                .iter()
                .any(|skipped| name.eq_ignore_ascii_case(skipped))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeguard_core::DependencyGraph;
    use std::fs;

    struct FilenameScanner {
        ecosystem: Ecosystem,
        filename: &'static str,
    }

    impl DependencyScanner for FilenameScanner {
        fn ecosystem(&self) -> Ecosystem {
            self.ecosystem.clone()
        }

        fn can_scan(&self, target: &Path) -> bool {
            if target.is_file() {
                target.file_name().is_some_and(|name| name == self.filename)
            } else {
                target.join(self.filename).is_file()
            }
        }

        fn scan(&self, input: &ScannerInput) -> Result<ScannerOutput, ScannerError> {
            let lockfile = if input.target.is_file() {
                input.target.clone()
            } else {
                input.target.join(self.filename)
            };
            Ok(ScannerOutput {
                ecosystem: self.ecosystem.clone(),
                target: input.target.clone(),
                manifest_path: None,
                lockfile_path: Some(lockfile),
                graph: DependencyGraph::default(),
                limitations: vec![format!("{} fixture scanner", self.ecosystem)],
            })
        }
    }

    #[test]
    fn registry_detects_supported_target_directly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lockfile = dir.path().join("Cargo.lock");
        fs::write(&lockfile, "").expect("write lockfile");

        let registry = ScannerRegistry::new().with_scanner(FilenameScanner {
            ecosystem: Ecosystem::Cargo,
            filename: "Cargo.lock",
        });
        let output = registry
            .scan_one(&ScannerInput::new(dir.path()))
            .expect("scan succeeds");

        assert_eq!(output.ecosystem, Ecosystem::Cargo);
        assert_eq!(output.lockfile_path, Some(lockfile));
    }

    #[test]
    fn empty_registry_is_reported_explicitly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = ScannerRegistry::new()
            .scan_all(&ScannerInput::new(dir.path()))
            .expect_err("empty registry");

        assert!(matches!(error, ScannerError::EmptyRegistry));
    }

    #[test]
    fn registry_returns_unsupported_for_empty_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = ScannerRegistry::new().with_scanner(FilenameScanner {
            ecosystem: Ecosystem::Cargo,
            filename: "Cargo.lock",
        });
        let error = registry
            .scan_all(&ScannerInput::new(dir.path()))
            .expect_err("unsupported target");

        assert!(matches!(error, ScannerError::UnsupportedTarget(_)));
    }

    #[test]
    fn missing_target_is_reported_explicitly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");
        let registry = ScannerRegistry::new().with_scanner(FilenameScanner {
            ecosystem: Ecosystem::Cargo,
            filename: "Cargo.lock",
        });
        let error = registry
            .scan_all(&ScannerInput::new(missing))
            .expect_err("missing target");

        assert!(matches!(error, ScannerError::TargetMissing(_)));
    }

    #[test]
    fn invalid_candidate_limit_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let registry = ScannerRegistry::new()
            .with_discovery_config(DiscoveryConfig {
                max_depth: 2,
                max_candidates: 0,
            })
            .with_scanner(FilenameScanner {
                ecosystem: Ecosystem::Cargo,
                filename: "Cargo.lock",
            });
        let error = registry
            .scan_all(&ScannerInput::new(dir.path()))
            .expect_err("invalid config");

        assert!(matches!(error, ScannerError::InvalidDiscoveryConfig(_)));
    }

    #[test]
    fn scan_all_discovers_nested_tauri_cargo_and_root_npm() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("package-lock.json"), "{}").expect("write npm lock");
        fs::create_dir(dir.path().join("src-tauri")).expect("create src-tauri");
        fs::write(dir.path().join("src-tauri").join("Cargo.lock"), "").expect("write cargo lock");

        let registry = ScannerRegistry::new()
            .with_scanner(FilenameScanner {
                ecosystem: Ecosystem::Cargo,
                filename: "Cargo.lock",
            })
            .with_scanner(FilenameScanner {
                ecosystem: Ecosystem::Npm,
                filename: "package-lock.json",
            });

        let outputs = registry
            .scan_all(&ScannerInput::new(dir.path()))
            .expect("multi scan succeeds");

        assert_eq!(outputs.len(), 2);
        assert!(outputs
            .iter()
            .any(|output| output.ecosystem == Ecosystem::Cargo));
        assert!(outputs
            .iter()
            .any(|output| output.ecosystem == Ecosystem::Npm));
    }

    #[test]
    fn scan_all_skips_generated_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("node_modules")).expect("create node_modules");
        fs::write(
            dir.path().join("node_modules").join("package-lock.json"),
            "{}",
        )
        .expect("write skipped lock");

        let registry = ScannerRegistry::new().with_scanner(FilenameScanner {
            ecosystem: Ecosystem::Npm,
            filename: "package-lock.json",
        });
        let error = registry
            .scan_all(&ScannerInput::new(dir.path()))
            .expect_err("node_modules must be skipped");

        assert!(matches!(error, ScannerError::UnsupportedTarget(_)));
    }

    #[test]
    fn scan_all_respects_max_depth() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir(dir.path().join("one")).expect("one");
        fs::create_dir(dir.path().join("one").join("two")).expect("two");
        fs::write(dir.path().join("one").join("two").join("Cargo.lock"), "").expect("lockfile");

        let registry = ScannerRegistry::new()
            .with_discovery_config(DiscoveryConfig {
                max_depth: 1,
                max_candidates: 16,
            })
            .with_scanner(FilenameScanner {
                ecosystem: Ecosystem::Cargo,
                filename: "Cargo.lock",
            });
        let error = registry
            .scan_all(&ScannerInput::new(dir.path()))
            .expect_err("nested lockfile beyond depth limit");

        assert!(matches!(error, ScannerError::UnsupportedTarget(_)));
    }

    #[test]
    fn scan_all_enforces_candidate_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("Cargo.lock"), "").expect("cargo lock");
        fs::write(dir.path().join("package-lock.json"), "{}").expect("npm lock");

        let registry = ScannerRegistry::new()
            .with_discovery_config(DiscoveryConfig {
                max_depth: 1,
                max_candidates: 1,
            })
            .with_scanner(FilenameScanner {
                ecosystem: Ecosystem::Cargo,
                filename: "Cargo.lock",
            })
            .with_scanner(FilenameScanner {
                ecosystem: Ecosystem::Npm,
                filename: "package-lock.json",
            });
        let error = registry
            .scan_all(&ScannerInput::new(dir.path()))
            .expect_err("candidate limit");

        assert!(matches!(error, ScannerError::DiscoveryLimitExceeded { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn direct_symlink_target_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("Cargo.lock");
        let link = dir.path().join("lock-link");
        fs::write(&real, "").expect("real lock");
        symlink(&real, &link).expect("symlink");

        let registry = ScannerRegistry::new().with_scanner(FilenameScanner {
            ecosystem: Ecosystem::Cargo,
            filename: "Cargo.lock",
        });
        let error = registry
            .scan_all(&ScannerInput::new(link))
            .expect_err("symlink rejected");

        assert!(matches!(error, ScannerError::UnsafeSymlink(_)));
    }
}
