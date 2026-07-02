#![forbid(unsafe_code)]

//! Shared domain model and risk scoring for ForgeGuard.
//!
//! This crate intentionally contains no HTTP, CLI, or heavy filesystem logic.
//! It is the stable boundary a future GUI, service, or alternate scanner can
//! consume without depending on the command-line application.

mod risk;

pub use risk::{calculate_risk, RiskFactors};

use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};
use thiserror::Error;

/// Current stable ForgeGuard report schema version.
pub const REPORT_SCHEMA_VERSION: &str = "forgeguard.report/v1";

/// Errors produced by core model helpers.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CoreError {
    /// A risk level string was not recognized.
    #[error("unknown risk level '{0}'")]
    UnknownRiskLevel(String),
    /// A package name was empty or contained only whitespace.
    #[error("package name must not be empty")]
    EmptyPackageName,
    /// An advisory identifier was empty or contained only whitespace.
    #[error("advisory identifier must not be empty")]
    EmptyAdvisoryIdentifier,
    /// A CVSS score was outside the valid range or not finite.
    #[error("invalid CVSS score {0}; expected a finite value between 0.0 and 10.0")]
    InvalidCvssScore(String),
}

/// A supported package ecosystem.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    /// Rust packages resolved by Cargo.
    Cargo,
    /// npm packages. Planned for a future release.
    Npm,
    /// Python packages from PyPI. Planned for a future release.
    Pypi,
    /// Go modules. Planned for a future release.
    Go,
    /// Maven artifacts. Planned for a future release.
    Maven,
}

impl Ecosystem {
    /// Return the ecosystem name expected by OSV.dev.
    #[must_use]
    pub fn osv_name(&self) -> &'static str {
        match self {
            Self::Cargo => "crates.io",
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
            Self::Go => "Go",
            Self::Maven => "Maven",
        }
    }

    /// Parse an OSV ecosystem name into a ForgeGuard ecosystem.
    #[must_use]
    pub fn from_osv_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "crates.io" | "cargo" => Some(Self::Cargo),
            "npm" => Some(Self::Npm),
            "pypi" | "python" => Some(Self::Pypi),
            "go" | "golang" => Some(Self::Go),
            "maven" => Some(Self::Maven),
            _ => None,
        }
    }

    /// Return the package-url type for this ecosystem.
    #[must_use]
    pub fn purl_type(&self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Go => "golang",
            Self::Maven => "maven",
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cargo => "Cargo",
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
            Self::Go => "Go",
            Self::Maven => "Maven",
        })
    }
}

/// Stable package identity.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct PackageId {
    /// Package ecosystem.
    pub ecosystem: Ecosystem,
    /// Package name in the ecosystem namespace.
    pub name: String,
    /// Resolved package version.
    pub version: Version,
}

impl PackageId {
    /// Create a new package identity without validation.
    ///
    /// Prefer [`Self::try_new`] at trust boundaries. This constructor is kept
    /// infallible for ergonomic use in parsers that have already validated
    /// package metadata.
    #[must_use]
    pub fn new(ecosystem: Ecosystem, name: impl Into<String>, version: Version) -> Self {
        Self {
            ecosystem,
            name: name.into(),
            version,
        }
    }

    /// Create a new validated package identity.
    pub fn try_new(
        ecosystem: Ecosystem,
        name: impl Into<String>,
        version: Version,
    ) -> Result<Self, CoreError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(CoreError::EmptyPackageName);
        }
        Ok(Self {
            ecosystem,
            name: name.trim().to_owned(),
            version,
        })
    }

    /// Return a normalized package-url string.
    #[must_use]
    pub fn purl(&self) -> String {
        format!(
            "pkg:{}/{}@{}",
            self.ecosystem.purl_type(),
            encode_purl_component(&self.name),
            self.version
        )
    }

    /// Validate basic invariants.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.name.trim().is_empty() {
            return Err(CoreError::EmptyPackageName);
        }
        Ok(())
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}@{}", self.ecosystem, self.name, self.version)
    }
}

/// How a dependency relates to the scanned target.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Declared in normal Cargo dependencies.
    Direct,
    /// Pulled in through another dependency.
    Transitive,
    /// Declared as a development dependency.
    Development,
    /// Declared as a build dependency.
    Build,
    /// Relationship could not be determined from static files.
    #[default]
    Unknown,
}

impl fmt::Display for DependencyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Direct => "direct",
            Self::Transitive => "transitive",
            Self::Development => "development",
            Self::Build => "build",
            Self::Unknown => "unknown",
        })
    }
}

/// A normalized package discovered in a lockfile or SBOM.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Package {
    /// Stable package identity.
    pub id: PackageId,
    /// Package source string, if present in the source lockfile.
    pub source: Option<String>,
    /// Package checksum, if present in the source lockfile.
    pub checksum: Option<String>,
    /// Package URL representation.
    pub purl: String,
    /// Dependency relationship inferred from static manifests.
    pub dependency_kind: DependencyKind,
}

impl Package {
    /// Create a normalized package and derive its package-url from the package identity.
    #[must_use]
    pub fn new(
        id: PackageId,
        source: Option<String>,
        checksum: Option<String>,
        dependency_kind: DependencyKind,
    ) -> Self {
        let purl = id.purl();
        Self {
            id,
            source,
            checksum,
            purl,
            dependency_kind,
        }
    }

    /// Return a human-readable `name version` label.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} {}", self.id.name, self.id.version)
    }

    /// Validate basic package invariants.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.id.validate()?;
        Ok(())
    }
}

/// A directed dependency edge in a dependency graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// Parent package identity.
    pub from: PackageId,
    /// Child package identity.
    pub to: PackageId,
}

/// Normalized dependency graph for a scan target.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependencyGraph {
    /// Packages in deterministic order.
    pub packages: Vec<Package>,
    /// Dependency edges in deterministic order.
    pub edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    /// Create a deterministic dependency graph.
    #[must_use]
    pub fn new(mut packages: Vec<Package>, mut edges: Vec<DependencyEdge>) -> Self {
        packages.sort_by(|left, right| left.id.cmp(&right.id));
        edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
        });
        edges.dedup();
        Self { packages, edges }
    }

    /// Number of packages in the graph.
    #[must_use]
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Return true if no packages were discovered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

/// Severity-like risk levels used consistently across reports and policies.
#[derive(
    Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Informational signal.
    #[default]
    Info,
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk.
    Critical,
}

impl RiskLevel {
    /// Return true when `self` is at least as severe as `minimum`.
    #[must_use]
    pub fn is_at_least(self, minimum: Self) -> bool {
        self >= minimum
    }

    /// Convert a numeric ForgeGuard risk score to a level.
    #[must_use]
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Self::Info,
            20..=39 => Self::Low,
            40..=69 => Self::Medium,
            70..=89 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Convert a CVSS base score into a severity level.
    ///
    /// Returns `None` for non-finite scores or values outside the CVSS range.
    #[must_use]
    pub fn from_cvss(score: f32) -> Option<Self> {
        if !score.is_finite() || !(0.0..=10.0).contains(&score) {
            return None;
        }
        Some(if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else if score > 0.0 {
            Self::Low
        } else {
            Self::Info
        })
    }

    /// Uppercase label for terminal output.
    #[must_use]
    pub fn as_uppercase(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for RiskLevel {
    type Err = CoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" | "informational" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" | "moderate" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(CoreError::UnknownRiskLevel(value.to_owned())),
        }
    }
}

/// Deterministic risk score with explanation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    /// Numeric risk score from 0 to 100.
    pub score: u8,
    /// Risk level derived from the numeric score.
    pub level: RiskLevel,
    /// Deterministic reasons that contributed to the score.
    pub reasons: Vec<String>,
}

impl RiskScore {
    /// Create a risk score and derive its level deterministically.
    #[must_use]
    pub fn new(score: u8, reasons: Vec<String>) -> Self {
        Self {
            score,
            level: RiskLevel::from_score(score),
            reasons,
        }
    }

    /// Return the stronger of two risk scores.
    #[must_use]
    pub fn max_by_score(left: Self, right: Self) -> Self {
        if right.score > left.score || (right.score == left.score && right.level > left.level) {
            right
        } else {
            left
        }
    }
}

/// Advisory source namespace.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilitySource {
    /// OSV.dev.
    Osv,
    /// RustSec advisory database.
    RustSec,
    /// GitHub Advisory Database.
    GitHub,
    /// Another source.
    Other(String),
}

impl fmt::Display for VulnerabilitySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Osv => f.write_str("OSV"),
            Self::RustSec => f.write_str("RustSec"),
            Self::GitHub => f.write_str("GitHub"),
            Self::Other(source) => f.write_str(source),
        }
    }
}

/// External advisory reference.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Reference {
    /// Reference type, such as `ADVISORY`, `WEB`, or `FIX`.
    pub kind: String,
    /// Reference URL.
    pub url: String,
}

/// Advisory metadata from an intelligence source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Advisory {
    /// Primary advisory identifier.
    pub id: String,
    /// Alternate advisory identifiers.
    pub aliases: Vec<String>,
    /// Short summary.
    pub summary: String,
    /// Longer details when available.
    pub details: Option<String>,
    /// Source-reported severity when available.
    pub severity: Option<RiskLevel>,
    /// Source-reported CVSS score when available.
    pub cvss_score: Option<f32>,
    /// Published timestamp as supplied by the source.
    pub published: Option<String>,
    /// Last modified timestamp as supplied by the source.
    pub modified: Option<String>,
    /// External references.
    pub references: Vec<Reference>,
    /// Advisory source.
    pub source: VulnerabilitySource,
}

impl Advisory {
    /// Validate advisory invariants.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.id.trim().is_empty() {
            return Err(CoreError::EmptyAdvisoryIdentifier);
        }
        if let Some(score) = self.cvss_score {
            if RiskLevel::from_cvss(score).is_none() {
                return Err(CoreError::InvalidCvssScore(score.to_string()));
            }
        }
        Ok(())
    }

    /// Return the primary identifier plus aliases, deduplicated and deterministic.
    #[must_use]
    pub fn identifiers(&self) -> Vec<String> {
        let values = std::iter::once(self.id.clone()).chain(self.aliases.clone());
        unique_strings_by_normalized(values)
    }

    /// Normalize identifier fields in-place.
    pub fn normalize_identifiers(&mut self) {
        let canonical = preferred_advisory_identifier(self.identifiers());
        let aliases = self
            .identifiers()
            .into_iter()
            .filter(|identifier| {
                normalize_identifier(identifier) != normalize_identifier(&canonical)
            })
            .collect::<Vec<_>>();
        self.id = canonical;
        self.aliases = unique_strings_by_normalized(aliases);
    }
}

/// Vulnerability affecting a concrete package.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Advisory metadata.
    pub advisory: Advisory,
    /// Affected package.
    pub affected: PackageId,
    /// Versions known to fix the vulnerability.
    pub fixed_versions: Vec<Version>,
}

impl Vulnerability {
    /// Sort and deduplicate fixed versions.
    pub fn normalize_fixed_versions(&mut self) {
        self.fixed_versions.sort();
        self.fixed_versions.dedup();
    }
}

/// Developer-facing remediation guidance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixRecommendation {
    /// Whether a fixed version is known.
    pub available: bool,
    /// Known fixed versions.
    pub versions: Vec<Version>,
    /// Human-readable recommendation.
    pub note: String,
}

impl FixRecommendation {
    /// Construct a recommendation from fixed version data.
    #[must_use]
    pub fn from_fixed_versions(package_name: &str, mut versions: Vec<Version>) -> Self {
        versions.sort();
        versions.dedup();

        if versions.is_empty() {
            Self {
                available: false,
                versions,
                note: format!("Fix version not provided by advisory source for {package_name}."),
            }
        } else {
            let version_list = versions
                .iter()
                .map(Version::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            Self {
                available: true,
                versions,
                note: format!("Upgrade {package_name} to one of: {version_list}."),
            }
        }
    }
}

/// A vulnerability finding for a scanned package.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Vulnerability details.
    pub vulnerability: Vulnerability,
    /// Package instance where the vulnerability was found.
    pub package: Package,
    /// Risk score.
    pub risk: RiskScore,
    /// Fix guidance.
    pub fix: FixRecommendation,
    /// Placeholder for CISA KEV or source-specific exploitation signals.
    pub known_exploited: bool,
}

impl Finding {
    /// Primary advisory identifier for the finding.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.vulnerability.advisory.id
    }

    /// All identifiers that should match policy allowlists.
    #[must_use]
    pub fn identifiers(&self) -> Vec<&str> {
        let mut ids = Vec::with_capacity(1 + self.vulnerability.advisory.aliases.len());
        ids.push(self.vulnerability.advisory.id.as_str());
        ids.extend(
            self.vulnerability
                .advisory
                .aliases
                .iter()
                .map(String::as_str),
        );
        ids
    }

    /// All identifiers as owned strings, deduplicated by case-insensitive comparison.
    #[must_use]
    pub fn owned_identifiers(&self) -> Vec<String> {
        self.vulnerability.advisory.identifiers()
    }

    /// Normalized identifier set used for deduplication and policy matching.
    #[must_use]
    pub fn normalized_identifier_set(&self) -> BTreeSet<String> {
        self.owned_identifiers()
            .iter()
            .map(|identifier| normalize_identifier(identifier.as_str()))
            .collect()
    }

    /// Return true when both findings affect the same package and represent the same advisory.
    #[must_use]
    pub fn overlaps_with(&self, other: &Self) -> bool {
        self.package.id == other.package.id
            && !self
                .normalized_identifier_set()
                .is_disjoint(&other.normalized_identifier_set())
    }

    /// Merge another finding into this finding when both represent the same vulnerability.
    ///
    /// Returns `true` when the merge happened and `false` when the findings do not overlap.
    pub fn merge_with(&mut self, other: Self) -> bool {
        if !self.overlaps_with(&other) {
            return false;
        }

        merge_advisory(
            &mut self.vulnerability.advisory,
            other.vulnerability.advisory,
        );
        self.vulnerability
            .fixed_versions
            .extend(other.vulnerability.fixed_versions);
        self.vulnerability.normalize_fixed_versions();
        self.fix = FixRecommendation::from_fixed_versions(
            &self.package.id.name,
            self.vulnerability.fixed_versions.clone(),
        );
        self.known_exploited |= other.known_exploited;
        self.risk = merge_risk_scores(self.risk.clone(), other.risk);
        true
    }
}

/// Deduplicate findings that represent the same advisory through primary IDs or aliases.
///
/// The function is deterministic and intentionally conservative: findings are merged only when
/// they affect the same package identity and share at least one normalized advisory identifier.
#[must_use]
pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: Vec<Finding> = Vec::new();

    for mut finding in findings {
        finding.vulnerability.advisory.normalize_identifiers();
        finding.vulnerability.normalize_fixed_versions();
        finding.fix = FixRecommendation::from_fixed_versions(
            &finding.package.id.name,
            finding.vulnerability.fixed_versions.clone(),
        );

        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.overlaps_with(&finding))
        {
            existing.merge_with(finding);
        } else {
            merged.push(finding);
        }
    }

    // A later finding can bridge two groups through aliases. Collapse until stable.
    let mut changed = true;
    while changed {
        changed = false;
        let mut index = 0;
        'outer: while index < merged.len() {
            let mut candidate = index + 1;
            while candidate < merged.len() {
                if merged[index].overlaps_with(&merged[candidate]) {
                    let other = merged.remove(candidate);
                    merged[index].merge_with(other);
                    changed = true;
                    break 'outer;
                }
                candidate += 1;
            }
            index += 1;
        }
    }

    merged.sort_by(|left, right| {
        right
            .risk
            .level
            .cmp(&left.risk.level)
            .then_with(|| right.risk.score.cmp(&left.risk.score))
            .then_with(|| left.package.id.cmp(&right.package.id))
            .then_with(|| left.id().cmp(right.id()))
    });
    merged
}

/// Count of findings by risk level.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RiskCounts {
    /// Informational finding count.
    pub info: usize,
    /// Low finding count.
    pub low: usize,
    /// Medium finding count.
    pub medium: usize,
    /// High finding count.
    pub high: usize,
    /// Critical finding count.
    pub critical: usize,
}

impl RiskCounts {
    /// Count risk levels from findings.
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut counts = Self::default();
        for finding in findings {
            match finding.risk.level {
                RiskLevel::Info => counts.info += 1,
                RiskLevel::Low => counts.low += 1,
                RiskLevel::Medium => counts.medium += 1,
                RiskLevel::High => counts.high += 1,
                RiskLevel::Critical => counts.critical += 1,
            }
        }
        counts
    }

    /// Return the total count across all risk levels.
    #[must_use]
    pub fn total(&self) -> usize {
        self.info + self.low + self.medium + self.high + self.critical
    }

    /// Return counts in display order.
    #[must_use]
    pub fn ordered(&self) -> [(RiskLevel, usize); 5] {
        [
            (RiskLevel::Critical, self.critical),
            (RiskLevel::High, self.high),
            (RiskLevel::Medium, self.medium),
            (RiskLevel::Low, self.low),
            (RiskLevel::Info, self.info),
        ]
    }
}

/// Policy result status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    /// Scan complies with policy.
    #[default]
    Pass,
    /// Scan should be reviewed but does not fail CI.
    Warn,
    /// Scan violates policy and should fail CI.
    Fail,
}

impl PolicyStatus {
    /// Return true when this status should fail CI.
    #[must_use]
    pub fn is_failure(self) -> bool {
        self == Self::Fail
    }
}

impl fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pass => "passed",
            Self::Warn => "warning",
            Self::Fail => "failed",
        })
    }
}

/// Policy decision with clear reasons.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Result status.
    pub status: PolicyStatus,
    /// Human-readable decision reasons.
    pub reasons: Vec<String>,
    /// Finding identifiers suppressed by active allowlist entries.
    pub suppressed: Vec<String>,
}

impl PolicyDecision {
    /// Return true when the decision should fail CI.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        self.status.is_failure()
    }
}

/// Summary fields intended for CI and report consumers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Number of dependencies scanned.
    pub dependencies_scanned: usize,
    /// Number of unsuppressed and suppressed findings returned by sources.
    pub findings_total: usize,
    /// Risk counts for all findings.
    pub risk_counts: RiskCounts,
    /// Policy decision.
    pub policy: PolicyDecision,
}

impl ScanSummary {
    /// Build a summary from graph, findings, and policy decision.
    #[must_use]
    pub fn new(
        graph: &DependencyGraph,
        findings: &[Finding],
        policy_decision: PolicyDecision,
    ) -> Self {
        Self {
            dependencies_scanned: graph.package_count(),
            findings_total: findings.len(),
            risk_counts: RiskCounts::from_findings(findings),
            policy: policy_decision,
        }
    }
}

/// Scan metadata useful for auditability and privacy review.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Whether network advisory queries were enabled.
    pub network_enabled: bool,
    /// Advisory sources consulted.
    pub advisory_sources: Vec<VulnerabilitySource>,
    /// Explicit limitations that apply to this scan.
    pub limitations: Vec<String>,
    /// Local advisory cache status, when a cache was used or updated.
    #[serde(default)]
    pub advisory_cache: Option<AdvisoryCacheInfo>,
    /// Whether discovery or advisory lookup completed with explicit omissions.
    #[serde(default)]
    pub partial: bool,
}

/// Local advisory cache metadata recorded in machine-readable reports.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryCacheInfo {
    /// Cache path, if the caller chose to disclose it.
    pub path: Option<String>,
    /// Whether cache data was loaded for this scan.
    pub loaded: bool,
    /// Whether cache data was refreshed during this scan.
    pub updated: bool,
    /// Cache generation timestamp as RFC 3339.
    pub generated_at: Option<String>,
    /// Cache age in whole days at report generation time.
    pub age_days: Option<i64>,
    /// Number of package records stored in the cache.
    pub package_records: usize,
    /// Whether the cache exceeded the configured freshness threshold.
    pub stale: bool,
    /// Configured freshness threshold in days.
    pub max_age_days: u64,
}

/// Complete scanner report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Stable JSON schema version for ForgeGuard report output.
    pub schema_version: String,
    /// Scanned target as provided by the caller.
    pub target: String,
    /// Primary ecosystem scanned.
    pub ecosystem: Ecosystem,
    /// RFC 3339 timestamp generated by the CLI or caller.
    pub generated_at: String,
    /// Dependency graph.
    pub dependency_graph: DependencyGraph,
    /// Vulnerability findings.
    pub findings: Vec<Finding>,
    /// Summary.
    pub summary: ScanSummary,
    /// Additional metadata.
    pub metadata: ScanMetadata,
}

impl ScanReport {
    /// Create a report and derive its summary from findings and policy decision.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        target: impl Into<String>,
        ecosystem: Ecosystem,
        generated_at: impl Into<String>,
        dependency_graph: DependencyGraph,
        findings: Vec<Finding>,
        policy: PolicyDecision,
        metadata: ScanMetadata,
    ) -> Self {
        let summary = ScanSummary::new(&dependency_graph, &findings, policy);
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            target: target.into(),
            ecosystem,
            generated_at: generated_at.into(),
            dependency_graph,
            findings,
            summary,
            metadata,
        }
    }
}

/// Stable JSON schema description for report consumers.
///
/// This type is a lightweight schema descriptor, not a full JSON Schema document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JsonSchemaDocument {
    /// Schema version identifier.
    pub schema_version: String,
    /// Top-level field names and brief descriptions.
    pub fields: BTreeMap<String, String>,
}

impl JsonSchemaDocument {
    /// Return the documented v0.1 report schema descriptor.
    #[must_use]
    pub fn report_v1() -> Self {
        let fields = BTreeMap::from([
            (
                "schema_version".to_owned(),
                "ForgeGuard report schema version string.".to_owned(),
            ),
            ("target".to_owned(), "Scanned target path.".to_owned()),
            (
                "ecosystem".to_owned(),
                "Primary ecosystem scanned, currently cargo.".to_owned(),
            ),
            (
                "generated_at".to_owned(),
                "RFC 3339 UTC timestamp for report generation.".to_owned(),
            ),
            (
                "dependency_graph".to_owned(),
                "Normalized packages and dependency edges.".to_owned(),
            ),
            (
                "findings".to_owned(),
                "Array of vulnerability findings.".to_owned(),
            ),
            (
                "summary".to_owned(),
                "Dependency count, finding count, risk counts, and policy decision.".to_owned(),
            ),
            (
                "metadata".to_owned(),
                "Network mode, advisory sources, advisory cache status, partial scan state, and scan limitations.".to_owned(),
            ),
        ]);
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            fields,
        }
    }
}

fn merge_risk_scores(left: RiskScore, right: RiskScore) -> RiskScore {
    let left_score = left.score;
    let left_level = left.level;
    let right_score = right.score;
    let right_level = right.level;

    let mut reasons = left.reasons;
    reasons.extend(right.reasons);
    reasons = unique_strings_by_normalized(reasons);

    let mut stronger = RiskScore::max_by_score(
        RiskScore {
            score: left_score,
            level: left_level,
            reasons: Vec::new(),
        },
        RiskScore {
            score: right_score,
            level: right_level,
            reasons: Vec::new(),
        },
    );
    stronger.reasons = reasons;
    stronger
}

fn merge_advisory(target: &mut Advisory, incoming: Advisory) {
    let all_identifiers = target
        .identifiers()
        .into_iter()
        .chain(incoming.identifiers())
        .collect::<Vec<_>>();
    let canonical = preferred_advisory_identifier(all_identifiers.clone());
    target.id = canonical.clone();
    target.aliases =
        unique_strings_by_normalized(all_identifiers.into_iter().filter(|identifier| {
            normalize_identifier(identifier) != normalize_identifier(&canonical)
        }));

    target.summary = select_better_summary(&target.summary, &incoming.summary);
    target.details = select_better_optional_text(target.details.take(), incoming.details);
    target.severity = max_option(target.severity, incoming.severity);
    target.cvss_score = max_cvss(target.cvss_score, incoming.cvss_score);
    target.published = select_earlier_timestamp(target.published.take(), incoming.published);
    target.modified = select_later_timestamp(target.modified.take(), incoming.modified);
    target.references =
        merge_references(std::mem::take(&mut target.references), incoming.references);
}

fn select_better_summary(current: &str, incoming: &str) -> String {
    let current_trimmed = current.trim();
    let incoming_trimmed = incoming.trim();
    let current_is_placeholder = current_trimmed.eq_ignore_ascii_case("no summary provided");

    if current_trimmed.is_empty() || current_is_placeholder {
        incoming_trimmed.to_owned()
    } else {
        current_trimmed.to_owned()
    }
}

fn select_better_optional_text(
    current: Option<String>,
    incoming: Option<String>,
) -> Option<String> {
    match (current, incoming) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => {
            if right.len() > left.len() {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

fn max_option<T: Ord + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn max_cvss(left: Option<f32>, right: Option<f32>) -> Option<f32> {
    [left, right]
        .into_iter()
        .flatten()
        .filter(|score| RiskLevel::from_cvss(*score).is_some())
        .max_by(|left, right| left.total_cmp(right))
}

fn select_earlier_timestamp(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn select_later_timestamp(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn merge_references(left: Vec<Reference>, right: Vec<Reference>) -> Vec<Reference> {
    let mut references = BTreeMap::<(String, String), Reference>::new();
    for reference in left.into_iter().chain(right) {
        if reference.url.trim().is_empty() {
            continue;
        }
        references
            .entry((reference.kind.clone(), reference.url.clone()))
            .or_insert(reference);
    }
    references.into_values().collect()
}

fn preferred_advisory_identifier<I>(identifiers: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let identifiers = unique_strings_by_normalized(identifiers);
    identifiers
        .into_iter()
        .min_by_key(|identifier| {
            let normalized = normalize_identifier(identifier);
            let priority = if normalized.starts_with("RUSTSEC-") {
                0
            } else if normalized.starts_with("CVE-") {
                1
            } else if normalized.starts_with("GHSA-") {
                2
            } else {
                3
            };
            (priority, normalized)
        })
        .unwrap_or_else(|| "UNKNOWN".to_owned())
}

fn unique_strings_by_normalized<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut unique = BTreeMap::<String, String>::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        unique
            .entry(normalize_identifier(trimmed))
            .or_insert_with(|| trimmed.to_owned());
    }
    unique.into_values().collect()
}

fn normalize_identifier(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn encode_purl_component(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(char::from(byte))
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package() -> Package {
        Package::new(
            PackageId::new(
                Ecosystem::Cargo,
                "time",
                Version::parse("0.1.44").expect("valid version"),
            ),
            Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            Some("0".repeat(64)),
            DependencyKind::Direct,
        )
    }

    fn finding(id: &str, aliases: Vec<&str>, risk: RiskLevel, score: u8) -> Finding {
        let package = package();
        let fixed_versions = vec![Version::parse("0.1.45").expect("valid version")];
        Finding {
            vulnerability: Vulnerability {
                advisory: Advisory {
                    id: id.to_owned(),
                    aliases: aliases.into_iter().map(str::to_owned).collect(),
                    summary: "summary".to_owned(),
                    details: None,
                    severity: Some(risk),
                    cvss_score: None,
                    published: None,
                    modified: None,
                    references: Vec::new(),
                    source: VulnerabilitySource::Osv,
                },
                affected: package.id.clone(),
                fixed_versions: fixed_versions.clone(),
            },
            package: package.clone(),
            risk: RiskScore {
                score,
                level: risk,
                reasons: vec!["test".to_owned()],
            },
            fix: FixRecommendation::from_fixed_versions(&package.id.name, fixed_versions),
            known_exploited: false,
        }
    }

    #[test]
    fn risk_level_maps_cvss_boundaries() {
        assert_eq!(RiskLevel::from_cvss(9.0), Some(RiskLevel::Critical));
        assert_eq!(RiskLevel::from_cvss(7.0), Some(RiskLevel::High));
        assert_eq!(RiskLevel::from_cvss(4.0), Some(RiskLevel::Medium));
        assert_eq!(RiskLevel::from_cvss(0.1), Some(RiskLevel::Low));
        assert_eq!(RiskLevel::from_cvss(0.0), Some(RiskLevel::Info));
        assert_eq!(RiskLevel::from_cvss(10.1), None);
        assert_eq!(RiskLevel::from_cvss(f32::NAN), None);
    }

    #[test]
    fn package_id_generates_purl() {
        let id = PackageId::new(
            Ecosystem::Cargo,
            "tokio-util",
            Version::parse("0.7.10").expect("valid version"),
        );
        assert_eq!(id.purl(), "pkg:cargo/tokio-util@0.7.10");
    }

    #[test]
    fn fix_recommendation_deduplicates_versions() {
        let recommendation = FixRecommendation::from_fixed_versions(
            "time",
            vec![
                Version::parse("0.1.45").expect("valid version"),
                Version::parse("0.1.45").expect("valid version"),
            ],
        );
        assert!(recommendation.available);
        assert_eq!(recommendation.versions.len(), 1);
    }

    #[test]
    fn deduplicates_findings_by_alias_overlap() {
        let first = finding(
            "GHSA-wcg3-cvx6-7396",
            vec!["RUSTSEC-2020-0071"],
            RiskLevel::Low,
            25,
        );
        let second = finding(
            "RUSTSEC-2020-0071",
            vec!["GHSA-wcg3-cvx6-7396"],
            RiskLevel::High,
            75,
        );

        let findings = deduplicate_findings(vec![first, second]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id(), "RUSTSEC-2020-0071");
        assert_eq!(findings[0].risk.level, RiskLevel::High);
        assert!(findings[0]
            .owned_identifiers()
            .contains(&"GHSA-wcg3-cvx6-7396".to_owned()));
    }

    #[test]
    fn policy_status_failure_helper_matches_fail_only() {
        assert!(PolicyStatus::Fail.is_failure());
        assert!(!PolicyStatus::Warn.is_failure());
        assert!(!PolicyStatus::Pass.is_failure());
    }
}
