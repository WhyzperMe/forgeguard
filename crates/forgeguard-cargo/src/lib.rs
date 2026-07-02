#![forbid(unsafe_code)]

//! Static Cargo project discovery and `Cargo.lock` parsing.
//!
//! ForgeGuard's default Cargo scanner never invokes Cargo and never executes
//! project code. It parses lockfiles and manifests as data.

use cargo_lock::Lockfile;
use forgeguard_core::{
    DependencyEdge, DependencyGraph, DependencyKind, Ecosystem, Package, PackageId,
};
use forgeguard_scanner::{DependencyScanner, ScannerError, ScannerInput, ScannerOutput};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;
use toml::{Table, Value};
use tracing::debug;

const CARGO_LOCK_FILE: &str = "Cargo.lock";
const CARGO_TOML_FILE: &str = "Cargo.toml";
const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// Errors produced by Cargo project discovery and parsing.
#[derive(Debug, Error)]
pub enum CargoScannerError {
    /// Target path does not exist.
    #[error("scan target does not exist: {0}")]
    TargetMissing(PathBuf),
    /// Target does not contain a lockfile.
    #[error("no Cargo.lock found for target: {0}")]
    LockfileMissing(PathBuf),
    /// A direct lockfile path was malformed.
    #[error("expected a Cargo.lock file, got: {0}")]
    NotCargoLock(PathBuf),
    /// Unsupported target type.
    #[error("unsupported Cargo scan target: {0}")]
    UnsupportedTarget(PathBuf),
    /// File exceeded static parser size limit.
    #[error("{path} is too large: {size} bytes exceeds {limit} bytes")]
    FileTooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    /// Filesystem read failed.
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Cargo.lock parsing failed.
    #[error("failed to parse Cargo.lock at {path}: {source}")]
    LockfileParse {
        path: PathBuf,
        #[source]
        source: cargo_lock::Error,
    },
    /// Cargo.toml parsing failed.
    #[error("failed to parse Cargo.toml at {path}: {source}")]
    ManifestParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Result type for Cargo scanner operations.
pub type Result<T> = std::result::Result<T, CargoScannerError>;

/// Result of a static Cargo dependency scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CargoScan {
    /// Original target path.
    pub target: PathBuf,
    /// Resolved lockfile path.
    pub lockfile_path: PathBuf,
    /// Cargo.toml used for direct dependency inference, if present.
    pub manifest_path: Option<PathBuf>,
    /// Normalized dependency graph.
    pub graph: DependencyGraph,
}

/// Scanner adapter for the multi-ecosystem registry.
#[derive(Clone, Copy, Debug, Default)]
pub struct CargoScanner;

impl CargoScanner {
    /// Construct a Cargo scanner.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DependencyScanner for CargoScanner {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Cargo
    }

    fn can_scan(&self, target: &Path) -> bool {
        discover_lockfile(target).is_ok()
    }

    fn scan(&self, input: &ScannerInput) -> std::result::Result<ScannerOutput, ScannerError> {
        let scan = scan_path(&input.target).map_err(|source| {
            ScannerError::scanner_failed(Ecosystem::Cargo, input.target.clone(), source)
        })?;

        Ok(ScannerOutput {
            ecosystem: Ecosystem::Cargo,
            target: scan.target,
            manifest_path: scan.manifest_path,
            lockfile_path: Some(scan.lockfile_path),
            graph: scan.graph,
            limitations: vec![
                "Cargo scanning is lockfile-based and does not execute Cargo, build.rs, or project code.".to_owned(),
                "Direct/dev/build dependency classification is inferred from static Cargo.toml when available.".to_owned(),
            ],
        })
    }
}

/// Scan a Cargo project directory or a direct `Cargo.lock` path.
pub fn scan_path(target: impl AsRef<Path>) -> Result<CargoScan> {
    let target = target.as_ref();
    let lockfile_path = discover_lockfile(target)?;
    let manifest_path = discover_manifest(target, &lockfile_path);
    let manifest_kinds = if let Some(path) = manifest_path.as_ref() {
        parse_manifest_dependency_kinds(path)?
    } else {
        BTreeMap::new()
    };
    let graph = parse_lockfile_path_with_kinds(&lockfile_path, &manifest_kinds)?;

    Ok(CargoScan {
        target: target.to_path_buf(),
        lockfile_path,
        manifest_path,
        graph,
    })
}

/// Parse a direct `Cargo.lock` path into a dependency graph.
pub fn parse_lockfile_path(path: impl AsRef<Path>) -> Result<DependencyGraph> {
    parse_lockfile_path_with_kinds(path.as_ref(), &BTreeMap::new())
}

fn parse_lockfile_path_with_kinds(
    path: &Path,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> Result<DependencyGraph> {
    enforce_file_size_limit(path, MAX_LOCKFILE_BYTES)?;
    let contents = fs::read_to_string(path).map_err(|source| CargoScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_lockfile_str_with_kinds(&contents, manifest_kinds).map_err(|error| match error {
        CargoScannerError::LockfileParse { source, .. } => CargoScannerError::LockfileParse {
            path: path.to_path_buf(),
            source,
        },
        other => other,
    })
}

/// Parse a `Cargo.lock` string into a dependency graph.
pub fn parse_lockfile_str(contents: &str) -> Result<DependencyGraph> {
    parse_lockfile_str_with_kinds(contents, &BTreeMap::new())
}

fn parse_lockfile_str_with_kinds(
    contents: &str,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> Result<DependencyGraph> {
    let lockfile =
        contents
            .parse::<Lockfile>()
            .map_err(|source| CargoScannerError::LockfileParse {
                path: PathBuf::from("<memory>"),
                source,
            })?;
    Ok(normalize_lockfile(&lockfile, manifest_kinds))
}

/// Return true when a package source is the public crates.io registry.
#[must_use]
pub fn is_crates_io_package(package: &Package) -> bool {
    if package.id.ecosystem != Ecosystem::Cargo {
        return false;
    }

    package.source.as_deref().is_some_and(|source| {
        source == "registry+https://github.com/rust-lang/crates.io-index"
            || source == "sparse+https://index.crates.io/"
            || source.starts_with("sparse+https://index.crates.io/")
    })
}

/// Generate a Cargo package URL.
#[must_use]
pub fn cargo_purl(name: &str, version: &Version) -> String {
    format!("pkg:cargo/{}@{version}", urlencoding::encode(name))
}

fn discover_lockfile(target: &Path) -> Result<PathBuf> {
    if !target.exists() {
        return Err(CargoScannerError::TargetMissing(target.to_path_buf()));
    }

    if target.is_file() {
        return if target
            .file_name()
            .is_some_and(|name| name == CARGO_LOCK_FILE)
        {
            Ok(target.to_path_buf())
        } else {
            Err(CargoScannerError::NotCargoLock(target.to_path_buf()))
        };
    }

    if !target.is_dir() {
        return Err(CargoScannerError::UnsupportedTarget(target.to_path_buf()));
    }

    let lockfile = target.join(CARGO_LOCK_FILE);
    if lockfile.exists() {
        Ok(lockfile)
    } else {
        Err(CargoScannerError::LockfileMissing(target.to_path_buf()))
    }
}

fn discover_manifest(target: &Path, lockfile_path: &Path) -> Option<PathBuf> {
    let candidate = if target.is_dir() {
        target.join(CARGO_TOML_FILE)
    } else {
        lockfile_path.parent()?.join(CARGO_TOML_FILE)
    };
    candidate.exists().then_some(candidate)
}

fn normalize_lockfile(
    lockfile: &Lockfile,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> DependencyGraph {
    let mut packages = Vec::with_capacity(lockfile.packages.len());

    for package in &lockfile.packages {
        let name = package.name.to_string();
        let version = package.version.clone();
        let dependency_kind = manifest_kinds
            .get(&name)
            .copied()
            .unwrap_or(DependencyKind::Transitive);
        let id = PackageId::new(Ecosystem::Cargo, name.clone(), version.clone());
        packages.push(Package {
            id,
            source: package.source.as_ref().map(ToString::to_string),
            checksum: package.checksum.as_ref().map(ToString::to_string),
            purl: cargo_purl(&name, &version),
            dependency_kind,
        });
    }

    let mut edges = Vec::new();
    for package in &lockfile.packages {
        let from = PackageId::new(
            Ecosystem::Cargo,
            package.name.to_string(),
            package.version.clone(),
        );
        for dependency in &package.dependencies {
            edges.push(DependencyEdge {
                from: from.clone(),
                to: PackageId::new(
                    Ecosystem::Cargo,
                    dependency.name.to_string(),
                    dependency.version.clone(),
                ),
            });
        }
    }

    DependencyGraph::new(packages, edges)
}

fn parse_manifest_dependency_kinds(path: &Path) -> Result<BTreeMap<String, DependencyKind>> {
    enforce_file_size_limit(path, MAX_MANIFEST_BYTES)?;
    let contents = fs::read_to_string(path).map_err(|source| CargoScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let table = contents
        .parse::<Table>()
        .map_err(|source| CargoScannerError::ManifestParse {
            path: path.to_path_buf(),
            source,
        })?;

    let mut kinds = BTreeMap::new();
    collect_named_dependency_table(&table, "dependencies", DependencyKind::Direct, &mut kinds);
    collect_named_dependency_table(
        &table,
        "dev-dependencies",
        DependencyKind::Development,
        &mut kinds,
    );
    collect_named_dependency_table(
        &table,
        "build-dependencies",
        DependencyKind::Build,
        &mut kinds,
    );

    if let Some(targets) = table.get("target").and_then(Value::as_table) {
        for target_table in targets.values().filter_map(Value::as_table) {
            collect_named_dependency_table(
                target_table,
                "dependencies",
                DependencyKind::Direct,
                &mut kinds,
            );
            collect_named_dependency_table(
                target_table,
                "dev-dependencies",
                DependencyKind::Development,
                &mut kinds,
            );
            collect_named_dependency_table(
                target_table,
                "build-dependencies",
                DependencyKind::Build,
                &mut kinds,
            );
        }
    }

    debug!(path = %path.display(), dependencies = kinds.len(), "parsed static manifest dependencies");
    Ok(kinds)
}

fn collect_named_dependency_table(
    parent: &Table,
    table_name: &str,
    kind: DependencyKind,
    kinds: &mut BTreeMap<String, DependencyKind>,
) {
    let Some(dependencies) = parent.get(table_name).and_then(Value::as_table) else {
        return;
    };

    for (declared_name, value) in dependencies {
        let package_name = value
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(Value::as_str)
            .unwrap_or(declared_name);
        insert_dependency_kind(kinds, package_name.to_owned(), kind);
    }
}

fn insert_dependency_kind(
    kinds: &mut BTreeMap<String, DependencyKind>,
    name: String,
    kind: DependencyKind,
) {
    let new_rank = dependency_kind_rank(kind);
    let should_replace = match kinds.get(&name) {
        Some(existing) => new_rank < dependency_kind_rank(*existing),
        None => true,
    };
    if should_replace {
        kinds.insert(name, kind);
    }
}

fn dependency_kind_rank(kind: DependencyKind) -> u8 {
    match kind {
        DependencyKind::Direct => 0,
        DependencyKind::Build => 1,
        DependencyKind::Development => 2,
        DependencyKind::Transitive | DependencyKind::Unknown => 3,
    }
}

fn enforce_file_size_limit(path: &Path, limit: u64) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|source| CargoScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > limit {
        Err(CargoScannerError::FileTooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            limit,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SIMPLE_LOCK: &str = include_str!("../../../tests/fixtures/cargo/simple-Cargo.lock");

    #[test]
    fn parses_lockfile_packages_and_edges() {
        let graph = parse_lockfile_str(SIMPLE_LOCK).expect("fixture parses");

        assert_eq!(graph.packages.len(), 2);
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn scanner_adapter_scans_directory_without_invoking_cargo() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join(CARGO_LOCK_FILE), SIMPLE_LOCK).expect("write lock");
        fs::write(
            temp.path().join(CARGO_TOML_FILE),
            r#"[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde_json = "1"
"#,
        )
        .expect("write manifest");

        let output = CargoScanner::new()
            .scan(&ScannerInput::new(temp.path()))
            .expect("scan succeeds");

        assert_eq!(output.ecosystem, Ecosystem::Cargo);
        assert_eq!(output.graph.packages.len(), 2);
    }
}
