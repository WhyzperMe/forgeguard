#![forbid(unsafe_code)]

//! Static npm `package-lock.json` scanner for ForgeGuard.
//!
//! The scanner treats npm lockfiles as untrusted data. It never invokes `npm`, never runs
//! lifecycle scripts, never evaluates JavaScript, and never follows dependency paths outside the
//! lockfile model. The parser supports `package-lock.json` `lockfileVersion` 2 and 3 and preserves
//! multiple resolved versions of the same npm package.

use forgeguard_core::{
    DependencyEdge, DependencyGraph, DependencyKind, Ecosystem, Package, PackageId,
};
use forgeguard_scanner::{DependencyScanner, ScannerError, ScannerInput, ScannerOutput};
use semver::Version;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

const PACKAGE_LOCK_FILE: &str = "package-lock.json";
const PNPM_LOCK_FILE: &str = "pnpm-lock.yaml";
const YARN_LOCK_FILE: &str = "yarn.lock";
const BUN_LOCK_FILE: &str = "bun.lock";
const BUN_LOCKB_FILE: &str = "bun.lockb";
const PACKAGE_JSON_FILE: &str = "package.json";
const MAX_PACKAGE_LOCK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TEXT_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES: u64 = 8 * 1024 * 1024;
const NODE_MODULES: &str = "node_modules";

/// npm scanner errors.
#[derive(Debug, Error)]
pub enum NpmScannerError {
    /// Target path does not exist.
    #[error("scan target does not exist: {0}")]
    TargetMissing(PathBuf),
    /// Target is not a package-lock.json file.
    #[error("expected a supported JavaScript lockfile, got: {0}")]
    NotSupportedLockfile(PathBuf),
    /// No package-lock.json was found in the target directory.
    #[error("no supported JavaScript lockfile found for target: {0}")]
    LockfileMissing(PathBuf),
    /// Unsupported target type.
    #[error("unsupported npm scan target: {0}")]
    UnsupportedTarget(PathBuf),
    /// File exceeded the static parser size limit.
    #[error("package-lock.json at {path} is too large: {size} bytes exceeds {limit} bytes")]
    FileTooLarge {
        /// Lockfile path.
        path: PathBuf,
        /// Observed file size in bytes.
        size: u64,
        /// Configured limit in bytes.
        limit: u64,
    },
    /// Filesystem read failed.
    #[error("failed to read {path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// I/O source error.
        #[source]
        source: std::io::Error,
    },
    /// JSON parsing failed.
    #[error("failed to parse package-lock.json at {path}: {source}")]
    Json {
        /// Lockfile path.
        path: PathBuf,
        /// JSON source error.
        #[source]
        source: serde_json::Error,
    },
    /// YAML parsing failed.
    #[error("failed to parse pnpm-lock.yaml at {path}: {source}")]
    Yaml {
        /// Lockfile path.
        path: PathBuf,
        /// YAML source error.
        #[source]
        source: serde_yaml_ng::Error,
    },
    /// Lockfile was recognized but is not statically supported yet.
    #[error("{path} is recognized but not yet supported: {reason}")]
    UnsupportedLockfile {
        /// Lockfile path.
        path: PathBuf,
        /// Explanation.
        reason: String,
    },
    /// Unsupported lockfile version.
    #[error(
        "unsupported package-lock.json lockfileVersion {version}; supported versions are 2 and 3"
    )]
    UnsupportedLockfileVersion {
        /// Observed lockfileVersion.
        version: u64,
    },
}

/// Result type for npm scanner operations.
pub type Result<T> = std::result::Result<T, NpmScannerError>;

/// Result of a static npm dependency scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NpmScan {
    /// Original target path.
    pub target: PathBuf,
    /// Resolved package-lock.json path.
    pub lockfile_path: PathBuf,
    /// package.json path if present next to the lockfile.
    pub manifest_path: Option<PathBuf>,
    /// Normalized dependency graph.
    pub graph: DependencyGraph,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JavaScriptLockfileKind {
    PackageLock,
    Pnpm,
    Yarn,
    BunText,
    BunBinary,
}

/// Scanner adapter for the multi-ecosystem registry.
#[derive(Clone, Copy, Debug, Default)]
pub struct NpmScanner;

impl NpmScanner {
    /// Construct an npm scanner.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DependencyScanner for NpmScanner {
    fn ecosystem(&self) -> Ecosystem {
        Ecosystem::Npm
    }

    fn can_scan(&self, target: &Path) -> bool {
        discover_lockfile(target).is_ok()
    }

    fn scan(&self, input: &ScannerInput) -> std::result::Result<ScannerOutput, ScannerError> {
        let scan = scan_path(&input.target).map_err(|source| {
            ScannerError::scanner_failed(Ecosystem::Npm, input.target.clone(), source)
        })?;

        Ok(ScannerOutput {
            ecosystem: Ecosystem::Npm,
            target: scan.target,
            manifest_path: scan.manifest_path,
            lockfile_path: Some(scan.lockfile_path),
            graph: scan.graph,
            limitations: vec![
                "npm scanning is package-lock-based and does not execute npm, lifecycle scripts, or JavaScript.".to_owned(),
                "Direct/dev dependency classification is inferred from the root package-lock entry when available.".to_owned(),
                "npm package resolution preserves multiple installed versions when represented in package-lock.json.".to_owned(),
            ],
        })
    }
}

/// Scan an npm project directory or a direct package-lock.json path.
pub fn scan_path(target: impl AsRef<Path>) -> Result<NpmScan> {
    let target = target.as_ref();
    let lockfile_path = discover_lockfile(target)?;
    let manifest_path = lockfile_path
        .parent()
        .map(|parent| parent.join(PACKAGE_JSON_FILE))
        .filter(|path| path.is_file());
    let manifest_kinds = manifest_path
        .as_deref()
        .map(parse_package_json_dependency_kinds)
        .transpose()?
        .unwrap_or_default();
    let graph = parse_javascript_lockfile_path(&lockfile_path, &manifest_kinds)?;

    Ok(NpmScan {
        target: target.to_path_buf(),
        lockfile_path,
        manifest_path,
        graph,
    })
}

fn parse_javascript_lockfile_path(
    path: &Path,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> Result<DependencyGraph> {
    match lockfile_kind(path) {
        Some(JavaScriptLockfileKind::PackageLock) => parse_package_lock_path(path),
        Some(JavaScriptLockfileKind::Pnpm) => parse_pnpm_lock_path(path, manifest_kinds),
        Some(JavaScriptLockfileKind::Yarn) => parse_yarn_lock_path(path, manifest_kinds),
        Some(JavaScriptLockfileKind::BunText | JavaScriptLockfileKind::BunBinary) => {
            Err(NpmScannerError::UnsupportedLockfile {
                path: path.to_path_buf(),
                reason: "Bun lockfile parsing is not implemented; use package-lock.json, pnpm-lock.yaml, or yarn.lock for static JavaScript dependency analysis".to_owned(),
            })
        }
        None => Err(NpmScannerError::NotSupportedLockfile(path.to_path_buf())),
    }
}

/// Return true when a package appears to come from the public npm registry.
///
/// ForgeGuard uses this as a privacy guard before sending npm package names to OSV. Packages with
/// missing, local, git, workspace, file, or private-registry sources are deliberately excluded from
/// online vulnerability queries.
#[must_use]
pub fn is_npm_registry_package(package: &Package) -> bool {
    package.id.ecosystem == Ecosystem::Npm
        && package
            .source
            .as_deref()
            .is_some_and(is_public_npm_registry_source)
}

/// Parse a package-lock.json file into a dependency graph.
pub fn parse_package_lock_path(path: impl AsRef<Path>) -> Result<DependencyGraph> {
    let path = path.as_ref();
    let metadata = fs::metadata(path).map_err(|source| NpmScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.len() > MAX_PACKAGE_LOCK_BYTES {
        return Err(NpmScannerError::FileTooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            limit: MAX_PACKAGE_LOCK_BYTES,
        });
    }

    let contents = fs::read(path).map_err(|source| NpmScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_package_lock_bytes(&contents).map_err(|error| match error {
        NpmScannerError::Json { source, .. } => NpmScannerError::Json {
            path: path.to_path_buf(),
            source,
        },
        other => other,
    })
}

/// Parse package-lock.json bytes into a dependency graph.
pub fn parse_package_lock_bytes(contents: &[u8]) -> Result<DependencyGraph> {
    let lockfile: PackageLock =
        serde_json::from_slice(contents).map_err(|source| NpmScannerError::Json {
            path: PathBuf::from("<memory>"),
            source,
        })?;

    if !matches!(lockfile.lockfile_version, 2 | 3) {
        return Err(NpmScannerError::UnsupportedLockfileVersion {
            version: lockfile.lockfile_version,
        });
    }

    Ok(normalize_lockfile(&lockfile))
}

/// Parse package-lock.json text into a dependency graph.
pub fn parse_package_lock_str(contents: &str) -> Result<DependencyGraph> {
    parse_package_lock_bytes(contents.as_bytes())
}

fn parse_pnpm_lock_path(
    path: &Path,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> Result<DependencyGraph> {
    enforce_file_size_limit(path, MAX_TEXT_LOCKFILE_BYTES)?;
    let contents = fs::read_to_string(path).map_err(|source| NpmScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_pnpm_lock_str_with_kinds(&contents, manifest_kinds).map_err(|error| match error {
        NpmScannerError::Yaml { source, .. } => NpmScannerError::Yaml {
            path: path.to_path_buf(),
            source,
        },
        other => other,
    })
}

fn parse_pnpm_lock_str_with_kinds(
    contents: &str,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> Result<DependencyGraph> {
    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(contents).map_err(|source| NpmScannerError::Yaml {
            path: PathBuf::from("<memory>"),
            source,
        })?;
    Ok(normalize_pnpm_lock(&document, manifest_kinds))
}

fn parse_yarn_lock_path(
    path: &Path,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> Result<DependencyGraph> {
    enforce_file_size_limit(path, MAX_TEXT_LOCKFILE_BYTES)?;
    let contents = fs::read_to_string(path).map_err(|source| NpmScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(parse_yarn_lock_str_with_kinds(&contents, manifest_kinds))
}

fn parse_yarn_lock_str_with_kinds(
    contents: &str,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> DependencyGraph {
    let entries = parse_yarn_v1_entries(contents);
    let mut packages = BTreeMap::<PackageId, Package>::new();
    let mut name_to_ids = BTreeMap::<String, BTreeSet<PackageId>>::new();

    for entry in &entries {
        let Some(version) = parse_version(&entry.version) else {
            continue;
        };
        let Ok(id) = PackageId::try_new(Ecosystem::Npm, entry.name.clone(), version) else {
            continue;
        };
        let kind = manifest_kinds
            .get(&entry.name)
            .copied()
            .unwrap_or(DependencyKind::Transitive);
        upsert_package(
            &mut packages,
            Package::new(
                id.clone(),
                entry.resolved.clone(),
                entry.integrity.clone(),
                kind,
            ),
        );
        name_to_ids
            .entry(entry.name.clone())
            .or_default()
            .insert(id);
    }

    let mut edges = Vec::new();
    for entry in &entries {
        let Some(from_id) = packages
            .keys()
            .find(|id| id.name == entry.name && id.version.to_string() == entry.version)
            .cloned()
        else {
            continue;
        };
        for dependency_name in &entry.dependencies {
            let Some(ids) = name_to_ids.get(dependency_name) else {
                continue;
            };
            if ids.len() == 1 {
                if let Some(to) = ids.iter().next() {
                    edges.push(DependencyEdge {
                        from: from_id.clone(),
                        to: to.clone(),
                    });
                }
            }
        }
    }

    DependencyGraph::new(packages.into_values().collect(), edges)
}

fn discover_lockfile(target: &Path) -> Result<PathBuf> {
    if !target.exists() {
        return Err(NpmScannerError::TargetMissing(target.to_path_buf()));
    }

    if target.is_file() {
        return if lockfile_kind(target).is_some() {
            Ok(target.to_path_buf())
        } else {
            Err(NpmScannerError::NotSupportedLockfile(target.to_path_buf()))
        };
    }

    if !target.is_dir() {
        return Err(NpmScannerError::UnsupportedTarget(target.to_path_buf()));
    }

    for name in [
        PACKAGE_LOCK_FILE,
        PNPM_LOCK_FILE,
        YARN_LOCK_FILE,
        BUN_LOCK_FILE,
        BUN_LOCKB_FILE,
    ] {
        let lockfile = target.join(name);
        if lockfile.is_file() {
            return Ok(lockfile);
        }
    }

    Err(NpmScannerError::LockfileMissing(target.to_path_buf()))
}

fn lockfile_kind(path: &Path) -> Option<JavaScriptLockfileKind> {
    match path.file_name().and_then(|name| name.to_str())? {
        PACKAGE_LOCK_FILE => Some(JavaScriptLockfileKind::PackageLock),
        PNPM_LOCK_FILE => Some(JavaScriptLockfileKind::Pnpm),
        YARN_LOCK_FILE => Some(JavaScriptLockfileKind::Yarn),
        BUN_LOCK_FILE => Some(JavaScriptLockfileKind::BunText),
        BUN_LOCKB_FILE => Some(JavaScriptLockfileKind::BunBinary),
        _ => None,
    }
}

fn normalize_pnpm_lock(
    document: &serde_yaml_ng::Value,
    manifest_kinds: &BTreeMap<String, DependencyKind>,
) -> DependencyGraph {
    let root_kinds = pnpm_importer_dependency_kinds(document);
    let Some(packages) = yaml_get(document, "packages").and_then(yaml_mapping) else {
        return DependencyGraph::default();
    };

    let mut normalized_packages = BTreeMap::<PackageId, Package>::new();
    let mut package_dependencies = BTreeMap::<PackageId, BTreeSet<String>>::new();
    let mut name_to_ids = BTreeMap::<String, BTreeSet<PackageId>>::new();

    for (key, value) in packages {
        let Some(key) = key.as_str() else {
            continue;
        };
        let Some((name, version)) = parse_pnpm_package_key(key) else {
            continue;
        };
        let Ok(id) = PackageId::try_new(Ecosystem::Npm, name.clone(), version) else {
            continue;
        };
        let kind = manifest_kinds
            .get(&name)
            .or_else(|| root_kinds.get(&name))
            .copied()
            .unwrap_or(DependencyKind::Transitive);
        let integrity = yaml_get(value, "resolution")
            .and_then(|resolution| yaml_get(resolution, "integrity"))
            .and_then(serde_yaml_ng::Value::as_str)
            .and_then(|value| normalize_optional_string(Some(value)));
        let dependencies = yaml_dependency_names(value);

        upsert_package(
            &mut normalized_packages,
            Package::new(id.clone(), None, integrity, kind),
        );
        package_dependencies.insert(id.clone(), dependencies);
        name_to_ids.entry(name).or_default().insert(id);
    }

    let mut edges = Vec::new();
    for (from, dependency_names) in package_dependencies {
        for dependency_name in dependency_names {
            let Some(ids) = name_to_ids.get(&dependency_name) else {
                continue;
            };
            if ids.len() == 1 {
                if let Some(to) = ids.iter().next() {
                    edges.push(DependencyEdge {
                        from: from.clone(),
                        to: to.clone(),
                    });
                }
            }
        }
    }

    DependencyGraph::new(normalized_packages.into_values().collect(), edges)
}

fn parse_pnpm_package_key(key: &str) -> Option<(String, Version)> {
    let without_peer_suffix = key.trim().split('(').next()?.trim();
    let normalized = without_peer_suffix
        .trim_start_matches('/')
        .strip_prefix("npm:")
        .unwrap_or(without_peer_suffix.trim_start_matches('/'));
    let separator = normalized.rfind('@')?;
    if separator == 0 {
        return None;
    }
    let name = normalize_package_name(&normalized[..separator])?;
    let version_text = normalized[separator + 1..]
        .strip_prefix("npm:")
        .unwrap_or(&normalized[separator + 1..]);
    let version = parse_version(version_text)?;
    Some((name, version))
}

fn pnpm_importer_dependency_kinds(
    document: &serde_yaml_ng::Value,
) -> BTreeMap<String, DependencyKind> {
    let mut kinds = BTreeMap::new();
    let Some(importers) = yaml_get(document, "importers").and_then(yaml_mapping) else {
        return kinds;
    };

    for importer in importers.values() {
        collect_yaml_dependency_kind(importer, "dependencies", DependencyKind::Direct, &mut kinds);
        collect_yaml_dependency_kind(
            importer,
            "optionalDependencies",
            DependencyKind::Direct,
            &mut kinds,
        );
        collect_yaml_dependency_kind(
            importer,
            "devDependencies",
            DependencyKind::Development,
            &mut kinds,
        );
    }

    kinds
}

fn collect_yaml_dependency_kind(
    parent: &serde_yaml_ng::Value,
    field: &str,
    kind: DependencyKind,
    kinds: &mut BTreeMap<String, DependencyKind>,
) {
    let Some(dependencies) = yaml_get(parent, field).and_then(yaml_mapping) else {
        return;
    };

    for key in dependencies.keys() {
        if let Some(name) = key.as_str().and_then(normalize_package_name) {
            insert_dependency_kind(kinds, name, kind);
        }
    }
}

fn yaml_dependency_names(value: &serde_yaml_ng::Value) -> BTreeSet<String> {
    ["dependencies", "optionalDependencies", "peerDependencies"]
        .into_iter()
        .filter_map(|field| yaml_get(value, field).and_then(yaml_mapping))
        .flat_map(|mapping| mapping.keys())
        .filter_map(|key| key.as_str().and_then(normalize_package_name))
        .collect()
}

fn yaml_get<'a>(value: &'a serde_yaml_ng::Value, key: &str) -> Option<&'a serde_yaml_ng::Value> {
    yaml_mapping(value)?.get(serde_yaml_ng::Value::String(key.to_owned()))
}

fn yaml_mapping(value: &serde_yaml_ng::Value) -> Option<&serde_yaml_ng::Mapping> {
    match value {
        serde_yaml_ng::Value::Mapping(mapping) => Some(mapping),
        _ => None,
    }
}

#[derive(Clone, Debug, Default)]
struct YarnEntry {
    name: String,
    version: String,
    resolved: Option<String>,
    integrity: Option<String>,
    dependencies: BTreeSet<String>,
}

fn parse_yarn_v1_entries(contents: &str) -> Vec<YarnEntry> {
    let mut entries = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current = YarnEntry::default();
    let mut in_dependencies = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if !line.chars().next().is_some_and(char::is_whitespace) && trimmed.ends_with(':') {
            flush_yarn_entry(&mut entries, &mut current_name, &mut current);
            let header = trimmed.trim_end_matches(':');
            current_name = yarn_name_from_header(header);
            in_dependencies = false;
            continue;
        }

        if current_name.is_none() {
            continue;
        }

        if trimmed == "dependencies:" {
            in_dependencies = true;
            continue;
        }

        if in_dependencies && line.starts_with("    ") {
            if let Some(name) = yarn_dependency_name(trimmed) {
                current.dependencies.insert(name);
            }
            continue;
        }

        in_dependencies = false;
        if let Some(version) = yarn_field_value(trimmed, "version") {
            current.version = version;
        } else if let Some(resolved) = yarn_field_value(trimmed, "resolved") {
            current.resolved = normalize_optional_string(Some(&resolved));
        } else if let Some(integrity) = yarn_field_value(trimmed, "integrity") {
            current.integrity = normalize_optional_string(Some(&integrity));
        }
    }

    flush_yarn_entry(&mut entries, &mut current_name, &mut current);
    entries
}

fn flush_yarn_entry(
    entries: &mut Vec<YarnEntry>,
    current_name: &mut Option<String>,
    current: &mut YarnEntry,
) {
    let Some(name) = current_name.take() else {
        return;
    };
    if current.version.trim().is_empty() {
        *current = YarnEntry::default();
        return;
    }
    current.name = name;
    entries.push(std::mem::take(current));
}

fn yarn_name_from_header(header: &str) -> Option<String> {
    header
        .split(',')
        .next()
        .map(str::trim)
        .map(trim_yarn_quotes)
        .and_then(yarn_name_from_descriptor)
}

fn yarn_name_from_descriptor(descriptor: &str) -> Option<String> {
    let separator = descriptor.rfind('@')?;
    if separator == 0 {
        return None;
    }
    normalize_package_name(&descriptor[..separator])
}

fn yarn_dependency_name(line: &str) -> Option<String> {
    let name = line.split_whitespace().next().map(trim_yarn_quotes)?;
    normalize_package_name(name)
}

fn yarn_field_value(line: &str, field: &str) -> Option<String> {
    let rest = line.strip_prefix(field)?.trim();
    if rest.is_empty() {
        None
    } else {
        Some(trim_yarn_quotes(rest).to_owned())
    }
}

fn trim_yarn_quotes(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageLock {
    lockfile_version: u64,
    #[serde(default)]
    packages: BTreeMap<String, LockPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, LegacyDependency>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LockPackage {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    peer_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    link: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyDependency {
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, LegacyDependency>,
    #[serde(default)]
    dev: bool,
}

fn normalize_lockfile(lockfile: &PackageLock) -> DependencyGraph {
    if lockfile.packages.is_empty() {
        return normalize_legacy_dependencies(&lockfile.dependencies);
    }

    let all_paths = package_paths(&lockfile.packages);
    let root = lockfile.packages.get("");
    let root_runtime_names = root.map(root_runtime_dependency_names).unwrap_or_default();
    let root_development_names = root
        .map(root_development_dependency_names)
        .unwrap_or_default();
    let root_runtime_paths = resolve_root_dependency_paths(&root_runtime_names, &all_paths);
    let root_development_paths = resolve_root_dependency_paths(&root_development_names, &all_paths);

    let mut packages = BTreeMap::<PackageId, Package>::new();
    let mut path_to_id = BTreeMap::<String, PackageId>::new();

    for (path, package) in &lockfile.packages {
        if path.is_empty() || package.link {
            continue;
        }

        let Some(id) = package_id_from_lock_entry(path, package) else {
            continue;
        };
        let kind = classify_dependency(
            path,
            &id.name,
            package.dev,
            &root_runtime_paths,
            &root_development_paths,
            &root_runtime_names,
            &root_development_names,
        );
        let normalized = Package::new(
            id.clone(),
            normalize_optional_string(package.resolved.as_deref()),
            normalize_optional_string(package.integrity.as_deref()),
            kind,
        );
        upsert_package(&mut packages, normalized);
        path_to_id.insert(path.clone(), id);
    }

    let mut edges = Vec::new();
    for (path, package) in &lockfile.packages {
        let Some(from_id) = path_to_id.get(path) else {
            continue;
        };

        for dependency_name in package_dependency_names(package) {
            let Some(to_path) = resolve_dependency_path(path, &dependency_name, &all_paths) else {
                continue;
            };
            let Some(to_id) = path_to_id.get(&to_path) else {
                continue;
            };
            if from_id != to_id {
                edges.push(DependencyEdge {
                    from: from_id.clone(),
                    to: to_id.clone(),
                });
            }
        }
    }

    DependencyGraph::new(packages.into_values().collect(), edges)
}

fn normalize_legacy_dependencies(
    dependencies: &BTreeMap<String, LegacyDependency>,
) -> DependencyGraph {
    let mut packages = BTreeMap::<PackageId, Package>::new();
    let mut edges = Vec::new();

    for (name, dependency) in dependencies {
        visit_legacy_dependency(
            name,
            dependency,
            None,
            if dependency.dev {
                DependencyKind::Development
            } else {
                DependencyKind::Direct
            },
            &mut packages,
            &mut edges,
        );
    }

    DependencyGraph::new(packages.into_values().collect(), edges)
}

fn visit_legacy_dependency(
    name: &str,
    dependency: &LegacyDependency,
    parent: Option<&PackageId>,
    kind: DependencyKind,
    packages: &mut BTreeMap<PackageId, Package>,
    edges: &mut Vec<DependencyEdge>,
) -> Option<PackageId> {
    let id = PackageId::try_new(
        Ecosystem::Npm,
        name.trim().to_owned(),
        dependency.version.as_deref().and_then(parse_version)?,
    )
    .ok()?;

    upsert_package(
        packages,
        Package::new(
            id.clone(),
            normalize_optional_string(dependency.resolved.as_deref()),
            normalize_optional_string(dependency.integrity.as_deref()),
            kind,
        ),
    );

    if let Some(parent) = parent {
        edges.push(DependencyEdge {
            from: parent.clone(),
            to: id.clone(),
        });
    }

    for (child_name, child) in &dependency.dependencies {
        let child_kind = if child.dev {
            DependencyKind::Development
        } else {
            DependencyKind::Transitive
        };
        visit_legacy_dependency(child_name, child, Some(&id), child_kind, packages, edges);
    }

    Some(id)
}

fn package_paths(packages: &BTreeMap<String, LockPackage>) -> BTreeSet<String> {
    packages
        .keys()
        .filter(|path| !path.is_empty())
        .cloned()
        .collect()
}

fn package_id_from_lock_entry(path: &str, package: &LockPackage) -> Option<PackageId> {
    let name = package
        .name
        .as_deref()
        .and_then(normalize_package_name)
        .or_else(|| {
            package_name_from_lock_path(path).and_then(|name| normalize_package_name(&name))
        })?;
    let version = package.version.as_deref().and_then(parse_version)?;
    PackageId::try_new(Ecosystem::Npm, name, version).ok()
}

fn root_runtime_dependency_names(root: &LockPackage) -> BTreeSet<String> {
    root.dependencies
        .keys()
        .chain(root.optional_dependencies.keys())
        .filter_map(|name| normalize_dependency_key(name))
        .collect()
}

fn root_development_dependency_names(root: &LockPackage) -> BTreeSet<String> {
    root.dev_dependencies
        .keys()
        .filter_map(|name| normalize_dependency_key(name))
        .collect()
}

fn resolve_root_dependency_paths(
    dependency_names: &BTreeSet<String>,
    all_paths: &BTreeSet<String>,
) -> BTreeSet<String> {
    dependency_names
        .iter()
        .filter_map(|name| {
            let path = dependency_path_from_base("", name);
            all_paths.contains(&path).then_some(path)
        })
        .collect()
}

fn classify_dependency(
    path: &str,
    package_name: &str,
    dev_flag: bool,
    root_runtime_paths: &BTreeSet<String>,
    root_development_paths: &BTreeSet<String>,
    root_runtime_names: &BTreeSet<String>,
    root_development_names: &BTreeSet<String>,
) -> DependencyKind {
    if root_runtime_paths.contains(path) {
        DependencyKind::Direct
    } else if root_development_paths.contains(path) || dev_flag {
        DependencyKind::Development
    } else if root_runtime_names.contains(package_name) && root_runtime_paths.is_empty() {
        DependencyKind::Direct
    } else if root_development_names.contains(package_name) && root_development_paths.is_empty() {
        DependencyKind::Development
    } else {
        DependencyKind::Transitive
    }
}

fn package_dependency_names(package: &LockPackage) -> BTreeSet<String> {
    package
        .dependencies
        .keys()
        .chain(package.optional_dependencies.keys())
        .chain(package.peer_dependencies.keys())
        .filter_map(|name| normalize_dependency_key(name))
        .collect()
}

fn resolve_dependency_path(
    from_path: &str,
    dependency_name: &str,
    all_paths: &BTreeSet<String>,
) -> Option<String> {
    let dependency_name = normalize_dependency_key(dependency_name)?;
    let mut current = Some(normalize_lock_path(from_path));

    while let Some(base) = current {
        let candidate = dependency_path_from_base(&base, &dependency_name);
        if all_paths.contains(&candidate) {
            return Some(candidate);
        }
        current = parent_package_path(&base);
    }

    None
}

fn dependency_path_from_base(base: &str, dependency_name: &str) -> String {
    if base.is_empty() {
        format!("{NODE_MODULES}/{dependency_name}")
    } else {
        format!("{base}/{NODE_MODULES}/{dependency_name}")
    }
}

fn parent_package_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }

    let segments = path.split('/').collect::<Vec<_>>();
    let node_modules_index = segments
        .iter()
        .rposition(|segment| *segment == NODE_MODULES)?;

    if node_modules_index == 0 {
        Some(String::new())
    } else {
        Some(segments[..node_modules_index].join("/"))
    }
}

fn package_name_from_lock_path(path: &str) -> Option<String> {
    let normalized = normalize_lock_path(path);
    let segments = normalized.split('/').collect::<Vec<_>>();
    let index = segments
        .iter()
        .rposition(|segment| *segment == NODE_MODULES)?;
    let first = *segments.get(index + 1)?;

    if first.is_empty() {
        return None;
    }

    if first.starts_with('@') {
        let second = *segments.get(index + 2)?;
        if second.is_empty() {
            None
        } else {
            Some(format!("{first}/{second}"))
        }
    } else {
        Some(first.to_owned())
    }
}

fn normalize_lock_path(path: &str) -> String {
    path.replace('\\', "/")
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_dependency_key(name: &str) -> Option<String> {
    normalize_package_name(name)
}

fn parse_package_json_dependency_kinds(path: &Path) -> Result<BTreeMap<String, DependencyKind>> {
    enforce_file_size_limit(path, MAX_PACKAGE_JSON_BYTES)?;
    let bytes = fs::read(path).map_err(|source| NpmScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let document: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|source| NpmScannerError::Json {
            path: path.to_path_buf(),
            source,
        })?;

    let mut kinds = BTreeMap::new();
    collect_json_dependency_kind(
        &document,
        "dependencies",
        DependencyKind::Direct,
        &mut kinds,
    );
    collect_json_dependency_kind(
        &document,
        "optionalDependencies",
        DependencyKind::Direct,
        &mut kinds,
    );
    collect_json_dependency_kind(
        &document,
        "devDependencies",
        DependencyKind::Development,
        &mut kinds,
    );
    Ok(kinds)
}

fn collect_json_dependency_kind(
    parent: &serde_json::Value,
    field: &str,
    kind: DependencyKind,
    kinds: &mut BTreeMap<String, DependencyKind>,
) {
    let Some(dependencies) = parent.get(field).and_then(serde_json::Value::as_object) else {
        return;
    };

    for name in dependencies
        .keys()
        .filter_map(|name| normalize_package_name(name))
    {
        insert_dependency_kind(kinds, name, kind);
    }
}

fn normalize_package_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.contains("..")
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
    {
        return None;
    }

    if trimmed.starts_with('@') {
        let mut parts = trimmed.split('/');
        let scope = parts.next()?;
        let package = parts.next()?;
        if parts.next().is_some()
            || scope.len() <= 1
            || package.is_empty()
            || scope.contains('\\')
            || package.contains('\\')
        {
            return None;
        }
    } else if trimmed.contains('/') || trimmed.contains('\\') {
        return None;
    }

    Some(trimmed.to_owned())
}

fn normalize_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .map(ToOwned::to_owned)
}

fn parse_version(value: &str) -> Option<Version> {
    Version::parse(value.trim()).ok()
}

fn enforce_file_size_limit(path: &Path, limit: u64) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|source| NpmScannerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > limit {
        Err(NpmScannerError::FileTooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
            limit,
        })
    } else {
        Ok(())
    }
}

fn upsert_package(packages: &mut BTreeMap<PackageId, Package>, package: Package) {
    match packages.get_mut(&package.id) {
        Some(existing) => {
            existing.dependency_kind =
                merge_dependency_kind(existing.dependency_kind, package.dependency_kind);
            if existing.source.is_none() {
                existing.source = package.source;
            }
            if existing.checksum.is_none() {
                existing.checksum = package.checksum;
            }
        }
        None => {
            packages.insert(package.id.clone(), package);
        }
    }
}

fn insert_dependency_kind(
    kinds: &mut BTreeMap<String, DependencyKind>,
    name: String,
    kind: DependencyKind,
) {
    let should_replace = kinds
        .get(&name)
        .is_none_or(|existing| dependency_kind_rank(kind) > dependency_kind_rank(*existing));
    if should_replace {
        kinds.insert(name, kind);
    }
}

fn merge_dependency_kind(left: DependencyKind, right: DependencyKind) -> DependencyKind {
    if dependency_kind_rank(right) > dependency_kind_rank(left) {
        right
    } else {
        left
    }
}

fn dependency_kind_rank(kind: DependencyKind) -> u8 {
    match kind {
        DependencyKind::Unknown => 0,
        DependencyKind::Transitive => 1,
        DependencyKind::Build => 2,
        DependencyKind::Development => 3,
        DependencyKind::Direct => 4,
    }
}

fn is_public_npm_registry_source(source: &str) -> bool {
    let source = source.trim().to_ascii_lowercase();
    source.starts_with("https://registry.npmjs.org/")
        || source.starts_with("http://registry.npmjs.org/")
        || source.starts_with("registry.npmjs.org/")
        || source.contains("//registry.npmjs.org/")
        || source.starts_with("https://registry.yarnpkg.com/")
        || source.starts_with("http://registry.yarnpkg.com/")
        || source.contains("//registry.yarnpkg.com/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const LOCK_V3: &str = r#"{
      "lockfileVersion": 3,
      "packages": {
        "": {
          "name": "fixture",
          "version": "1.0.0",
          "dependencies": { "express": "4.18.2" },
          "devDependencies": { "@types/node": "20.0.0" }
        },
        "node_modules/express": {
          "version": "4.18.2",
          "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
          "integrity": "sha512-demo",
          "dependencies": { "qs": "6.11.0" }
        },
        "node_modules/qs": {
          "version": "6.11.0",
          "resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz"
        },
        "node_modules/@types/node": {
          "version": "20.0.0",
          "resolved": "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz",
          "dev": true
        }
      }
    }"#;

    const MULTI_VERSION_LOCK: &str = r#"{
      "lockfileVersion": 3,
      "packages": {
        "": {
          "name": "fixture",
          "version": "1.0.0",
          "dependencies": { "foo": "1.0.0", "bar": "1.0.0" }
        },
        "node_modules/foo": {
          "version": "1.0.0",
          "resolved": "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"
        },
        "node_modules/bar": {
          "version": "1.0.0",
          "resolved": "https://registry.npmjs.org/bar/-/bar-1.0.0.tgz",
          "dependencies": { "foo": "2.0.0" }
        },
        "node_modules/bar/node_modules/foo": {
          "version": "2.0.0",
          "resolved": "https://registry.npmjs.org/foo/-/foo-2.0.0.tgz"
        }
      }
    }"#;

    const ALIAS_LOCK: &str = r#"{
      "lockfileVersion": 3,
      "packages": {
        "": {
          "name": "fixture",
          "version": "1.0.0",
          "dependencies": { "leftpad-alias": "npm:left-pad@1.3.0" }
        },
        "node_modules/leftpad-alias": {
          "name": "left-pad",
          "version": "1.3.0",
          "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
        }
      }
    }"#;

    const PNPM_LOCK: &str = r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: 18.2.0
        version: 18.2.0
    devDependencies:
      vite:
        specifier: 5.0.0
        version: 5.0.0
packages:
  /react@18.2.0:
    resolution:
      integrity: sha512-react
    dependencies:
      loose-envify: 1.4.0
  /loose-envify@1.4.0:
    resolution:
      integrity: sha512-env
  /vite@5.0.0:
    resolution:
      integrity: sha512-vite
"#;

    const YARN_LOCK: &str = r#"
react@^18.2.0:
  version "18.2.0"
  resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"
  integrity sha512-react
  dependencies:
    loose-envify "^1.1.0"

loose-envify@^1.1.0:
  version "1.4.0"
  resolved "https://registry.yarnpkg.com/loose-envify/-/loose-envify-1.4.0.tgz"
  integrity sha512-env
"#;

    #[test]
    fn parses_package_lock_v3() {
        let graph = parse_package_lock_str(LOCK_V3).expect("lock parses");
        assert_eq!(graph.packages.len(), 3);
        assert!(graph
            .packages
            .iter()
            .any(|package| package.id.name == "express"
                && package.dependency_kind == DependencyKind::Direct));
        assert!(graph
            .packages
            .iter()
            .any(|package| package.id.name == "@types/node"
                && package.dependency_kind == DependencyKind::Development));
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn preserves_multiple_versions_of_same_package() {
        let graph = parse_package_lock_str(MULTI_VERSION_LOCK).expect("lock parses");
        let foo_versions = graph
            .packages
            .iter()
            .filter(|package| package.id.name == "foo")
            .map(|package| package.id.version.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            foo_versions,
            BTreeSet::from(["1.0.0".to_owned(), "2.0.0".to_owned()])
        );
        assert!(graph.packages.iter().any(|package| {
            package.id.name == "foo"
                && package.id.version == Version::parse("1.0.0").expect("version")
                && package.dependency_kind == DependencyKind::Direct
        }));
        assert!(graph.packages.iter().any(|package| {
            package.id.name == "foo"
                && package.id.version == Version::parse("2.0.0").expect("version")
                && package.dependency_kind == DependencyKind::Transitive
        }));
    }

    #[test]
    fn resolves_edges_to_nearest_nested_dependency_version() {
        let graph = parse_package_lock_str(MULTI_VERSION_LOCK).expect("lock parses");
        let bar = PackageId::new(
            Ecosystem::Npm,
            "bar",
            Version::parse("1.0.0").expect("version"),
        );
        let nested_foo = PackageId::new(
            Ecosystem::Npm,
            "foo",
            Version::parse("2.0.0").expect("version"),
        );

        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.from == bar && edge.to == nested_foo));
    }

    #[test]
    fn handles_scoped_package_names() {
        assert_eq!(
            package_name_from_lock_path("node_modules/@scope/name"),
            Some("@scope/name".to_owned())
        );
        assert_eq!(
            package_name_from_lock_path("node_modules/a/node_modules/@scope/name"),
            Some("@scope/name".to_owned())
        );
    }

    #[test]
    fn aliases_use_real_package_name_when_lock_entry_provides_it() {
        let graph = parse_package_lock_str(ALIAS_LOCK).expect("lock parses");
        assert!(graph
            .packages
            .iter()
            .any(|package| package.id.name == "left-pad"));
        assert!(!graph
            .packages
            .iter()
            .any(|package| package.id.name == "leftpad-alias"));
    }

    #[test]
    fn detects_npm_registry_packages() {
        let graph = parse_package_lock_str(LOCK_V3).expect("lock parses");
        let express = graph
            .packages
            .iter()
            .find(|package| package.id.name == "express")
            .expect("express");
        assert!(is_npm_registry_package(express));
    }

    #[test]
    fn does_not_treat_missing_or_private_source_as_public_registry_package() {
        let package = Package::new(
            PackageId::new(
                Ecosystem::Npm,
                "private-package",
                Version::parse("1.0.0").expect("version"),
            ),
            None,
            None,
            DependencyKind::Direct,
        );
        assert!(!is_npm_registry_package(&package));

        let private_registry_package = Package::new(
            PackageId::new(
                Ecosystem::Npm,
                "private-package",
                Version::parse("1.0.0").expect("version"),
            ),
            Some(
                "https://registry.internal.example/private-package/-/private-package-1.0.0.tgz"
                    .to_owned(),
            ),
            None,
            DependencyKind::Direct,
        );
        assert!(!is_npm_registry_package(&private_registry_package));
    }

    #[test]
    fn scanner_detects_direct_package_lock_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lockfile = dir.path().join(PACKAGE_LOCK_FILE);
        fs::write(&lockfile, LOCK_V3).expect("write lock");
        let scanner = NpmScanner::new();
        assert!(scanner.can_scan(&lockfile));
        let output = scanner.scan(&ScannerInput::new(&lockfile)).expect("scan");
        assert_eq!(output.ecosystem, Ecosystem::Npm);
        assert_eq!(output.package_count(), 3);
    }

    #[test]
    fn rejects_unsupported_lockfile_version() {
        let error = parse_package_lock_str(r#"{ "lockfileVersion": 1, "dependencies": {} }"#)
            .expect_err("v1 is unsupported");
        assert!(matches!(
            error,
            NpmScannerError::UnsupportedLockfileVersion { version: 1 }
        ));
    }

    #[test]
    fn parses_pnpm_lock_packages_and_classifies_root_dependencies() {
        let mut manifest_kinds = BTreeMap::new();
        insert_dependency_kind(
            &mut manifest_kinds,
            "react".to_owned(),
            DependencyKind::Direct,
        );
        insert_dependency_kind(
            &mut manifest_kinds,
            "vite".to_owned(),
            DependencyKind::Development,
        );

        let graph =
            parse_pnpm_lock_str_with_kinds(PNPM_LOCK, &manifest_kinds).expect("pnpm parses");

        assert_eq!(graph.packages.len(), 3);
        assert!(graph.packages.iter().any(|package| {
            package.id.name == "react" && package.dependency_kind == DependencyKind::Direct
        }));
        assert!(graph.packages.iter().any(|package| {
            package.id.name == "vite" && package.dependency_kind == DependencyKind::Development
        }));
        assert!(graph
            .edges
            .iter()
            .any(|edge| { edge.from.name == "react" && edge.to.name == "loose-envify" }));
    }

    #[test]
    fn parses_yarn_lock_packages_and_edges() {
        let mut manifest_kinds = BTreeMap::new();
        insert_dependency_kind(
            &mut manifest_kinds,
            "react".to_owned(),
            DependencyKind::Direct,
        );

        let graph = parse_yarn_lock_str_with_kinds(YARN_LOCK, &manifest_kinds);

        assert_eq!(graph.packages.len(), 2);
        assert!(graph.packages.iter().any(|package| {
            package.id.name == "react" && package.dependency_kind == DependencyKind::Direct
        }));
        assert!(graph
            .edges
            .iter()
            .any(|edge| { edge.from.name == "react" && edge.to.name == "loose-envify" }));
        let react = graph
            .packages
            .iter()
            .find(|package| package.id.name == "react")
            .expect("react");
        assert!(is_npm_registry_package(react));
    }

    #[test]
    fn bun_lockfiles_are_detected_but_reported_as_unsupported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lockfile = dir.path().join(BUN_LOCKB_FILE);
        fs::write(&lockfile, b"binary").expect("write bun lock");

        let scanner = NpmScanner::new();
        assert!(scanner.can_scan(&lockfile));
        let error = scanner
            .scan(&ScannerInput::new(&lockfile))
            .expect_err("bun is explicit unsupported");

        assert!(matches!(error, ScannerError::ScannerFailed { .. }));
    }

    #[test]
    fn parent_package_path_walks_scoped_and_nested_packages() {
        assert_eq!(
            parent_package_path("node_modules/a/node_modules/@scope/name"),
            Some("node_modules/a".to_owned())
        );
        assert_eq!(
            parent_package_path("node_modules/@scope/name"),
            Some(String::new())
        );
        assert_eq!(parent_package_path(""), None);
    }
}
