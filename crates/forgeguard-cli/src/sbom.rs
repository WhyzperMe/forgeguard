#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use forgeguard_cargo::CargoScan;
use forgeguard_core::{DependencyGraph, DependencyKind, Package, PackageId};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const CYCLONEDX_SPEC_VERSION: &str = "1.6";
const ROOT_BOM_REF: &str = "forgeguard:metadata:component:scan-target";
const MAX_NAME_LEN: usize = 512;
const MAX_PURL_LEN: usize = 2048;
const MAX_PROPERTY_VALUE_LEN: usize = 4096;
const MAX_BOM_REF_LEN: usize = 2048;

/// CycloneDX output encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CycloneDxFormat {
    /// JSON encoding.
    Json,
}

/// Render a CycloneDX JSON SBOM for packages discovered by ForgeGuard.
///
/// The renderer is intentionally data-only: it serializes the already-normalized dependency graph
/// and never executes package managers, scripts, build hooks, or project code. It supports mixed
/// ecosystem graphs, so a Tauri repository containing `package-lock.json` and `src-tauri/Cargo.lock`
/// can be represented in one SBOM when the caller provides a combined graph.
pub fn render_cyclonedx(scan: &CargoScan, format: CycloneDxFormat) -> Result<String> {
    render_cyclonedx_from_graph(&scan.target, &scan.graph, format)
}

/// Render a CycloneDX SBOM directly from a normalized graph.
///
/// This API avoids coupling future multi-ecosystem callers to Cargo-specific scan structs while
/// preserving the existing CLI call path through [`render_cyclonedx`].
pub fn render_cyclonedx_from_graph(
    target: &Path,
    graph: &DependencyGraph,
    format: CycloneDxFormat,
) -> Result<String> {
    match format {
        CycloneDxFormat::Json => render_cyclonedx_json(target, graph),
    }
}

fn render_cyclonedx_json(target: &Path, graph: &DependencyGraph) -> Result<String> {
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("failed to format SBOM timestamp")?;

    let bom_refs = build_bom_ref_map(&graph.packages);
    let components = graph
        .packages
        .iter()
        .filter_map(|package| component_for_package(package, &bom_refs))
        .collect::<Vec<_>>();
    let dependencies = dependency_entries(graph, &bom_refs);

    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "forgeguard",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": ROOT_BOM_REF,
                "name": target_component_name(target)
            },
            "properties": metadata_properties(graph)
        },
        "components": components,
        "dependencies": dependencies
    });

    serde_json::to_string_pretty(&bom).context("failed to serialize CycloneDX JSON")
}

fn component_for_package(
    package: &Package,
    bom_refs: &BTreeMap<PackageId, String>,
) -> Option<Value> {
    let bom_ref = bom_refs.get(&package.id)?;
    let mut component = json!({
        "type": "library",
        "bom-ref": bom_ref,
        "name": bounded_clean(&package.id.name, MAX_NAME_LEN),
        "version": package.id.version.to_string(),
        "scope": cyclone_scope(package.dependency_kind),
        "purl": bounded_clean(&package.purl, MAX_PURL_LEN),
        "properties": component_properties(package)
    });

    let hashes = cyclone_hashes(package.checksum.as_deref());
    if !hashes.is_empty() {
        component["hashes"] = Value::Array(hashes);
    }

    if let Some(source) = external_reference(package.source.as_deref()) {
        component["externalReferences"] = Value::Array(vec![source]);
    }

    Some(component)
}

fn metadata_properties(graph: &DependencyGraph) -> Vec<Value> {
    let ecosystems = graph
        .packages
        .iter()
        .map(|package| package.id.ecosystem.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");

    vec![
        property("forgeguard:ecosystems", ecosystems),
        property("forgeguard:package_count", graph.packages.len().to_string()),
        property("forgeguard:dependency_edge_count", graph.edges.len().to_string()),
        property("forgeguard:generation_mode", "static-lockfile"),
        property(
            "forgeguard:limitations",
            "CycloneDX 1.6 JSON generated from ForgeGuard's normalized static lockfile graph; licenses, services, attestations, and VEX statements are intentionally not modeled in this output.",
        ),
        property(
            "forgeguard:safety",
            "SBOM generation does not execute package managers, lifecycle scripts, build scripts, JavaScript, or project code.",
        ),
    ]
}

fn component_properties(package: &Package) -> Vec<Value> {
    let mut properties = vec![
        property("forgeguard:ecosystem", package.id.ecosystem.to_string()),
        property(
            "forgeguard:dependency_kind",
            package.dependency_kind.to_string(),
        ),
        property("forgeguard:package_id", package.id.to_string()),
    ];

    if let Some(source) = non_empty_clean(package.source.as_deref(), MAX_PROPERTY_VALUE_LEN) {
        properties.push(property("forgeguard:source", source));
    }

    if let Some(checksum) = package.checksum.as_deref() {
        if !is_supported_hex_hash(checksum.trim()) {
            if let Some(integrity) = non_empty_clean(Some(checksum), MAX_PROPERTY_VALUE_LEN) {
                properties.push(property("forgeguard:integrity", integrity));
            }
        }
    }

    properties
}

fn property(name: &str, value: impl Into<String>) -> Value {
    json!({
        "name": name,
        "value": bounded_clean(&value.into(), MAX_PROPERTY_VALUE_LEN)
    })
}

fn build_bom_ref_map(packages: &[Package]) -> BTreeMap<PackageId, String> {
    let mut refs = BTreeMap::new();
    let mut used = BTreeSet::new();

    for package in packages {
        let base = preferred_bom_ref(package);
        let unique = unique_bom_ref(&base, &mut used);
        refs.insert(package.id.clone(), unique);
    }

    refs
}

fn preferred_bom_ref(package: &Package) -> String {
    let purl = bounded_clean(&package.purl, MAX_BOM_REF_LEN);
    if !purl.is_empty() {
        purl
    } else {
        bounded_clean(
            &format!("forgeguard:package:{}", package.id),
            MAX_BOM_REF_LEN,
        )
    }
}

fn unique_bom_ref(base: &str, used: &mut BTreeSet<String>) -> String {
    let sanitized = sanitize_bom_ref(base);
    if used.insert(sanitized.clone()) {
        return sanitized;
    }

    for index in 2.. {
        let suffix = format!("#{index}");
        let max_base_len = MAX_BOM_REF_LEN.saturating_sub(suffix.len());
        let candidate = format!("{}{}", truncate_chars(&sanitized, max_base_len), suffix);
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }

    unreachable!("unbounded integer iteration must eventually produce a unique bom-ref")
}

fn dependency_entries(
    graph: &DependencyGraph,
    bom_refs: &BTreeMap<PackageId, String>,
) -> Vec<Value> {
    let mut relationships = BTreeMap::<String, BTreeSet<String>>::new();

    relationships.insert(
        ROOT_BOM_REF.to_owned(),
        root_dependencies(&graph.packages, bom_refs),
    );

    for package in &graph.packages {
        if let Some(reference) = bom_refs.get(&package.id) {
            relationships.entry(reference.clone()).or_default();
        }
    }

    for edge in &graph.edges {
        let Some(from_ref) = bom_refs.get(&edge.from) else {
            continue;
        };
        let Some(to_ref) = bom_refs.get(&edge.to) else {
            continue;
        };
        if from_ref != to_ref {
            relationships
                .entry(from_ref.clone())
                .or_default()
                .insert(to_ref.clone());
        }
    }

    relationships
        .into_iter()
        .map(|(reference, depends_on)| {
            json!({
                "ref": reference,
                "dependsOn": depends_on.into_iter().collect::<Vec<_>>()
            })
        })
        .collect()
}

fn root_dependencies(
    packages: &[Package],
    bom_refs: &BTreeMap<PackageId, String>,
) -> BTreeSet<String> {
    packages
        .iter()
        .filter(|package| {
            matches!(
                package.dependency_kind,
                DependencyKind::Direct | DependencyKind::Development | DependencyKind::Build
            )
        })
        .filter_map(|package| bom_refs.get(&package.id).cloned())
        .collect()
}

fn cyclone_scope(kind: DependencyKind) -> &'static str {
    match kind {
        DependencyKind::Development => "excluded",
        DependencyKind::Build => "optional",
        DependencyKind::Direct | DependencyKind::Transitive | DependencyKind::Unknown => "required",
    }
}

fn cyclone_hashes(checksum: Option<&str>) -> Vec<Value> {
    let Some(checksum) = checksum.map(str::trim).filter(|value| !value.is_empty()) else {
        return Vec::new();
    };

    let Some(algorithm) = hex_hash_algorithm(checksum) else {
        return Vec::new();
    };

    vec![json!({
        "alg": algorithm,
        "content": checksum.to_ascii_lowercase()
    })]
}

fn hex_hash_algorithm(value: &str) -> Option<&'static str> {
    if !is_hex(value) {
        return None;
    }

    match value.len() {
        64 => Some("SHA-256"),
        96 => Some("SHA-384"),
        128 => Some("SHA-512"),
        _ => None,
    }
}

fn is_supported_hex_hash(value: &str) -> bool {
    hex_hash_algorithm(value).is_some()
}

fn is_hex(value: &str) -> bool {
    value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn external_reference(source: Option<&str>) -> Option<Value> {
    let source = non_empty_clean(source, MAX_PROPERTY_VALUE_LEN)?;
    if !(source.starts_with("https://") || source.starts_with("http://")) {
        return None;
    }

    Some(json!({
        "type": "distribution",
        "url": source
    }))
}

fn target_component_name(target: &Path) -> String {
    target
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| bounded_clean(name, MAX_NAME_LEN))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "scan-target".to_owned())
}

fn non_empty_clean(value: Option<&str>, max_len: usize) -> Option<String> {
    let cleaned = bounded_clean(value?, max_len);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn bounded_clean(value: &str, max_len: usize) -> String {
    truncate_chars(&clean_string(value), max_len)
}

fn clean_string(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_bom_ref(value: &str) -> String {
    let cleaned = bounded_clean(value, MAX_BOM_REF_LEN);
    if cleaned.is_empty() {
        "forgeguard:package:unknown".to_owned()
    } else {
        cleaned
    }
}

fn truncate_chars(value: &str, max_len: usize) -> String {
    value.chars().take(max_len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeguard_core::{DependencyEdge, Ecosystem, PackageId};
    use std::path::PathBuf;

    fn package(
        ecosystem: Ecosystem,
        name: &str,
        version: &str,
        source: Option<&str>,
        checksum: Option<&str>,
        kind: DependencyKind,
    ) -> Package {
        Package::new(
            PackageId::new(
                ecosystem,
                name,
                version.parse().expect("valid semver version"),
            ),
            source.map(ToOwned::to_owned),
            checksum.map(ToOwned::to_owned),
            kind,
        )
    }

    fn scan(graph: DependencyGraph) -> CargoScan {
        CargoScan {
            target: PathBuf::from("fixture-app"),
            lockfile_path: PathBuf::from("fixture-app/Cargo.lock"),
            manifest_path: None,
            graph,
        }
    }

    fn render_json(graph: DependencyGraph) -> Value {
        let rendered = render_cyclonedx(&scan(graph), CycloneDxFormat::Json).expect("render sbom");
        serde_json::from_str(&rendered).expect("valid json")
    }

    #[test]
    fn renders_multi_ecosystem_components() {
        let graph = DependencyGraph::new(
            vec![
                package(
                    Ecosystem::Cargo,
                    "tauri",
                    "1.0.0",
                    Some("registry+https://github.com/rust-lang/crates.io-index"),
                    Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
                    DependencyKind::Direct,
                ),
                package(
                    Ecosystem::Npm,
                    "vite",
                    "8.0.14",
                    Some("https://registry.npmjs.org/vite/-/vite-8.0.14.tgz"),
                    Some("sha512-demo"),
                    DependencyKind::Development,
                ),
            ],
            Vec::new(),
        );

        let bom = render_json(graph);
        let components = bom["components"].as_array().expect("components array");

        assert_eq!(components.len(), 2);
        assert!(components
            .iter()
            .any(|component| component["name"] == "tauri"));
        assert!(components
            .iter()
            .any(|component| component["name"] == "vite"));
        assert_eq!(bom["metadata"]["component"]["name"], "fixture-app");
    }

    #[test]
    fn emits_hex_hashes_but_keeps_sri_as_property() {
        let graph = DependencyGraph::new(
            vec![
                package(
                    Ecosystem::Cargo,
                    "hex-hash",
                    "1.0.0",
                    None,
                    Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    DependencyKind::Direct,
                ),
                package(
                    Ecosystem::Npm,
                    "sri-integrity",
                    "1.0.0",
                    None,
                    Some("sha512-not-hex"),
                    DependencyKind::Direct,
                ),
            ],
            Vec::new(),
        );

        let bom = render_json(graph);
        let components = bom["components"].as_array().expect("components array");
        let hex = components
            .iter()
            .find(|component| component["name"] == "hex-hash")
            .expect("hex component");
        let sri = components
            .iter()
            .find(|component| component["name"] == "sri-integrity")
            .expect("sri component");

        assert_eq!(hex["hashes"][0]["alg"], "SHA-256");
        assert!(sri.get("hashes").is_none());
        assert!(sri["properties"]
            .as_array()
            .expect("properties")
            .iter()
            .any(|property| property["name"] == "forgeguard:integrity"));
    }

    #[test]
    fn renders_root_and_package_dependency_relationships() {
        let parent = package(
            Ecosystem::Cargo,
            "parent",
            "1.0.0",
            None,
            None,
            DependencyKind::Direct,
        );
        let child = package(
            Ecosystem::Cargo,
            "child",
            "1.0.0",
            None,
            None,
            DependencyKind::Transitive,
        );
        let graph = DependencyGraph::new(
            vec![parent.clone(), child.clone()],
            vec![DependencyEdge {
                from: parent.id.clone(),
                to: child.id.clone(),
            }],
        );

        let bom = render_json(graph);
        let dependencies = bom["dependencies"].as_array().expect("dependencies array");
        let root = dependencies
            .iter()
            .find(|entry| entry["ref"] == ROOT_BOM_REF)
            .expect("root dependency entry");
        let parent_ref = parent.purl;
        let child_ref = child.purl;
        assert!(root["dependsOn"]
            .as_array()
            .expect("root dependsOn")
            .iter()
            .any(|reference| reference == &parent_ref));

        let parent_entry = dependencies
            .iter()
            .find(|entry| entry["ref"] == parent_ref)
            .expect("parent dependency entry");
        assert!(parent_entry["dependsOn"]
            .as_array()
            .expect("parent dependsOn")
            .iter()
            .any(|reference| reference == &child_ref));
    }

    #[test]
    fn sanitizes_control_characters() {
        let graph = DependencyGraph::new(
            vec![package(
                Ecosystem::Npm,
                "bad\u{0000}name\npackage",
                "1.0.0",
                Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"),
                None,
                DependencyKind::Direct,
            )],
            Vec::new(),
        );

        let bom = render_json(graph);
        let name = bom["components"][0]["name"]
            .as_str()
            .expect("component name");
        assert_eq!(name, "bad name package");
    }
}
