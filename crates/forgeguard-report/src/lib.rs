#![forbid(unsafe_code)]

//! Report generation for ForgeGuard scan reports.
//!
//! This crate renders the normalized [`forgeguard_core::ScanReport`] model into
//! human-readable and machine-readable formats. It intentionally performs no
//! filesystem, network, policy, or advisory-query work. Rendering is deterministic
//! and sanitizes untrusted strings before they are embedded into terminal,
//! Markdown, and SARIF output.

use comfy_table::{presets::UTF8_FULL, Cell, Table};
use forgeguard_core::{Ecosystem, Finding, PolicyStatus, RiskLevel, ScanReport};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_TABLE_CELL_CHARS: usize = 96;
const MAX_SARIF_MESSAGE_CHARS: usize = 4096;
const MAX_SARIF_TEXT_CHARS: usize = 8192;
const MAX_MARKDOWN_TEXT_CHARS: usize = 16_384;

/// Report rendering errors.
#[derive(Debug, Error)]
pub enum ReportError {
    /// JSON serialization failed.
    #[error("failed to serialize report: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Result type for report rendering.
pub type Result<T> = std::result::Result<T, ReportError>;

/// Supported report formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    /// Human-friendly terminal output.
    Table,
    /// Stable JSON output using the core [`ScanReport`] schema.
    Json,
    /// Markdown report intended for pull requests and release artifacts.
    Markdown,
    /// SARIF 2.1.0 output for code-scanning systems.
    Sarif,
}

/// Render a report in the requested format.
pub fn render_report(report: &ScanReport, format: ReportFormat) -> Result<String> {
    match format {
        ReportFormat::Table => Ok(render_table(report)),
        ReportFormat::Json => render_json(report),
        ReportFormat::Markdown => Ok(render_markdown(report)),
        ReportFormat::Sarif => render_sarif(report),
    }
}

/// Render human-friendly terminal output.
#[must_use]
pub fn render_table(report: &ScanReport) -> String {
    let context = ReportContext::new(report);
    let mut output = String::new();

    output.push_str("ForgeGuard Scan Report\n\n");
    output.push_str(&format!("Target: {}\n", sanitize_line(&report.target)));
    output.push_str(&format!(
        "{}: {}\n",
        context.ecosystem_heading(),
        context.ecosystem_label()
    ));
    output.push_str(&format!(
        "Dependencies scanned: {}\n",
        report.summary.dependencies_scanned
    ));
    output.push_str(&format!("Findings: {}\n", report.summary.findings_total));
    output.push_str(&format!("Policy: {}\n", report.summary.policy.status));
    if !report.metadata.network_enabled {
        output.push_str("Mode: offline/no-network\n");
    }
    if report.metadata.partial {
        output.push_str("Completeness: partial\n");
    }
    if let Some(cache) = &report.metadata.advisory_cache {
        output.push_str(&format!(
            "Advisory cache: loaded={}, updated={}, stale={}, records={}\n",
            cache.loaded, cache.updated, cache.stale, cache.package_records
        ));
    }

    output.push_str("\nRisk summary:\n");
    for (level, count) in report.summary.risk_counts.ordered() {
        let label = format!("{}:", title_level(level));
        output.push_str(&format!("  {label:<9} {count}\n"));
    }

    output.push_str("\nFindings:\n");
    if report.findings.is_empty() {
        output.push_str("  No vulnerability findings.\n");
    } else {
        output.push_str(&finding_table(report, context.show_ecosystem_column()));
        output.push('\n');
    }

    append_bullets(
        &mut output,
        "Policy reasons",
        &report.summary.policy.reasons,
    );
    append_bullets(
        &mut output,
        "Suppressed findings",
        &report.summary.policy.suppressed,
    );
    append_bullets(&mut output, "Limitations", &report.metadata.limitations);

    output
}

/// Render stable JSON output.
pub fn render_json(report: &ScanReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(ReportError::Serialize)
}

/// Render Markdown output.
#[must_use]
pub fn render_markdown(report: &ScanReport) -> String {
    let context = ReportContext::new(report);
    let mut output = String::new();

    output.push_str("# ForgeGuard Scan Report\n\n");
    output.push_str("## Executive Summary\n\n");
    output.push_str(&format!(
        "- Target: {}\n",
        markdown_code_span(&report.target)
    ));
    output.push_str(&format!(
        "- {}: {}\n",
        context.ecosystem_heading(),
        markdown_text(&context.ecosystem_label())
    ));
    output.push_str(&format!(
        "- Dependencies scanned: {}\n",
        report.summary.dependencies_scanned
    ));
    output.push_str(&format!("- Findings: {}\n", report.summary.findings_total));
    output.push_str(&format!(
        "- Policy decision: {}\n",
        markdown_text(&report.summary.policy.status.to_string())
    ));
    if !report.metadata.network_enabled {
        output.push_str("- Network: disabled; advisory queries were not performed.\n");
    }
    output.push_str(&format!("- Partial scan: {}\n", report.metadata.partial));
    if let Some(cache) = &report.metadata.advisory_cache {
        output.push_str(&format!(
            "- Advisory cache: loaded={}, updated={}, stale={}, records={}\n",
            cache.loaded, cache.updated, cache.stale, cache.package_records
        ));
        if let Some(age_days) = cache.age_days {
            output.push_str(&format!(", age_days={age_days}"));
        }
        output.push('\n');
    }

    output.push_str("\n## Dependency Counts\n\n");
    output.push_str("| Metric | Count |\n| --- | ---: |\n");
    output.push_str(&format!(
        "| Packages | {} |\n",
        report.dependency_graph.packages.len()
    ));
    output.push_str(&format!(
        "| Dependency edges | {} |\n",
        report.dependency_graph.edges.len()
    ));

    output.push_str("\n## Finding Table\n\n");
    if report.findings.is_empty() {
        output.push_str("No vulnerability findings were returned for this scan.\n");
    } else {
        append_markdown_findings_table(report, context.show_ecosystem_column(), &mut output);
    }

    output.push_str("\n## Risk Explanation\n\n");
    if report.findings.is_empty() {
        output.push_str("No risk scoring was required because no findings were present.\n");
    } else {
        for finding in &report.findings {
            let reasons = finding.risk.reasons.join(" ");
            output.push_str(&format!(
                "- {} on {} scored **{}** ({}) for ecosystem **{}**: {}\n",
                markdown_code_span(finding.id()),
                markdown_code_span(&finding.package.label()),
                finding.risk.score,
                markdown_text(&finding.risk.level.to_string()),
                markdown_text(&finding.package.id.ecosystem.to_string()),
                markdown_text(&reasons)
            ));
        }
    }

    output.push_str("\n## Fix Recommendations\n\n");
    if report.findings.is_empty() {
        output.push_str("No fix recommendations are available because no findings were present.\n");
    } else {
        for finding in &report.findings {
            output.push_str(&format!(
                "- {}: {}\n",
                markdown_code_span(finding.id()),
                markdown_text(&finding.fix.note)
            ));
        }
    }

    output.push_str("\n## Policy Decision\n\n");
    output.push_str(&format!(
        "Status: **{}**\n\n",
        markdown_text(&report.summary.policy.status.to_string())
    ));
    if report.summary.policy.reasons.is_empty() {
        output.push_str("- No policy reasons were provided.\n");
    } else {
        for reason in &report.summary.policy.reasons {
            output.push_str(&format!("- {}\n", markdown_text(reason)));
        }
    }

    if !report.summary.policy.suppressed.is_empty() {
        output.push_str("\nSuppressed findings:\n");
        for item in &report.summary.policy.suppressed {
            output.push_str(&format!("- {}\n", markdown_code_span(item)));
        }
    }

    if !report.metadata.limitations.is_empty() {
        output.push_str("\n## Limitations\n\n");
        for limitation in &report.metadata.limitations {
            output.push_str(&format!("- {}\n", markdown_text(limitation)));
        }
    }

    output
}

/// Render SARIF 2.1.0 output.
pub fn render_sarif(report: &ScanReport) -> Result<String> {
    let context = ReportContext::new(report);
    let rules = sarif_rules(report);
    let results = report
        .findings
        .iter()
        .map(|finding| sarif_result(report, finding))
        .collect::<Vec<_>>();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ForgeGuard",
                        "informationUri": "https://github.com/whyzper/forgeguard",
                        "semanticVersion": env!("CARGO_PKG_VERSION"),
                        "rules": rules
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report.summary.policy.status != PolicyStatus::Fail,
                        "properties": {
                            "networkEnabled": report.metadata.network_enabled,
                            "schemaVersion": report.schema_version,
                            "ecosystems": context.ecosystem_names(),
                            "partial": report.metadata.partial,
                            "advisoryCache": report.metadata.advisory_cache,
                            "limitations": &report.metadata.limitations
                        }
                    }
                ],
                "properties": {
                    "target": sanitize_line(&report.target),
                    "dependenciesScanned": report.summary.dependencies_scanned,
                    "findingsTotal": report.summary.findings_total,
                    "policyStatus": report.summary.policy.status.to_string()
                }
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).map_err(ReportError::Serialize)
}

#[derive(Debug)]
struct ReportContext {
    ecosystems: BTreeSet<Ecosystem>,
}

impl ReportContext {
    fn new(report: &ScanReport) -> Self {
        let mut ecosystems = report
            .dependency_graph
            .packages
            .iter()
            .map(|package| package.id.ecosystem.clone())
            .collect::<BTreeSet<_>>();

        if ecosystems.is_empty() {
            ecosystems.insert(report.ecosystem.clone());
        }

        Self { ecosystems }
    }

    fn ecosystem_heading(&self) -> &'static str {
        if self.show_ecosystem_column() {
            "Ecosystems"
        } else {
            "Ecosystem"
        }
    }

    fn show_ecosystem_column(&self) -> bool {
        self.ecosystems.len() > 1
    }

    fn ecosystem_label(&self) -> String {
        self.ecosystem_names().join(", ")
    }

    fn ecosystem_names(&self) -> Vec<String> {
        self.ecosystems
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    }
}

fn finding_table(report: &ScanReport, include_ecosystem: bool) -> String {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);

    if include_ecosystem {
        table.set_header(vec![
            "Risk",
            "Ecosystem",
            "Advisory",
            "Package",
            "Version",
            "Fix",
        ]);
    } else {
        table.set_header(vec!["Risk", "Advisory", "Package", "Version", "Fix"]);
    }

    for finding in &report.findings {
        let mut row = Vec::with_capacity(if include_ecosystem { 6 } else { 5 });
        row.push(Cell::new(finding.risk.level.as_uppercase()));
        if include_ecosystem {
            row.push(Cell::new(finding.package.id.ecosystem.to_string()));
        }
        row.extend([
            Cell::new(truncate(&advisory_label(finding), MAX_TABLE_CELL_CHARS)),
            Cell::new(truncate(
                &sanitize_line(&finding.package.id.name),
                MAX_TABLE_CELL_CHARS,
            )),
            Cell::new(finding.package.id.version.to_string()),
            Cell::new(truncate(&fix_label(finding), MAX_TABLE_CELL_CHARS)),
        ]);
        table.add_row(row);
    }

    table.to_string()
}

fn append_markdown_findings_table(
    report: &ScanReport,
    include_ecosystem: bool,
    output: &mut String,
) {
    if include_ecosystem {
        output.push_str("| Risk | Ecosystem | Advisory | Aliases | Package | Version | Fix |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    } else {
        output.push_str("| Risk | Advisory | Aliases | Package | Version | Fix |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- |\n");
    }

    for finding in &report.findings {
        if include_ecosystem {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                markdown_cell(finding.risk.level.as_uppercase()),
                markdown_cell(&finding.package.id.ecosystem.to_string()),
                markdown_cell(finding.id()),
                markdown_cell(&aliases_label(finding)),
                markdown_cell(&finding.package.id.name),
                markdown_cell(&finding.package.id.version.to_string()),
                markdown_cell(&fix_label(finding))
            ));
        } else {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                markdown_cell(finding.risk.level.as_uppercase()),
                markdown_cell(finding.id()),
                markdown_cell(&aliases_label(finding)),
                markdown_cell(&finding.package.id.name),
                markdown_cell(&finding.package.id.version.to_string()),
                markdown_cell(&fix_label(finding))
            ));
        }
    }
}

fn sarif_result(report: &ScanReport, finding: &Finding) -> Value {
    let message = format!(
        "{} {} ({}) is affected by {}. {}",
        finding.package.id.name,
        finding.package.id.version,
        finding.package.id.ecosystem,
        advisory_label(finding),
        finding.fix.note
    );

    json!({
        "ruleId": finding.id(),
        "level": sarif_level(finding.risk.level),
        "message": {
            "text": truncate_chars(&sanitize_line(&message), MAX_SARIF_MESSAGE_CHARS)
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri(&report.target)
                    },
                    "region": {
                        "startLine": 1
                    }
                },
                "logicalLocations": [
                    {
                        "name": sanitize_line(&finding.package.id.name),
                        "fullyQualifiedName": sanitize_line(&finding.package.purl),
                        "kind": "package"
                    }
                ]
            }
        ],
        "partialFingerprints": {
            "forgeguardFinding": stable_fingerprint(finding)
        },
        "properties": {
            "ecosystem": finding.package.id.ecosystem.to_string(),
            "package": sanitize_line(&finding.package.id.name),
            "version": finding.package.id.version.to_string(),
            "purl": sanitize_line(&finding.package.purl),
            "dependencyKind": finding.package.dependency_kind.to_string(),
            "advisory": sanitize_line(finding.id()),
            "aliases": finding.vulnerability.advisory.aliases.iter().map(|value| sanitize_line(value)).collect::<Vec<_>>(),
            "cvssScore": finding.vulnerability.advisory.cvss_score,
            "knownExploited": finding.known_exploited,
            "fixAvailable": finding.fix.available,
            "riskScore": finding.risk.score,
            "riskLevel": finding.risk.level.to_string(),
            "policyStatus": report.summary.policy.status.to_string()
        }
    })
}

fn sarif_rules(report: &ScanReport) -> Vec<Value> {
    let mut rules = BTreeMap::<String, RuleAggregate>::new();

    for finding in &report.findings {
        rules
            .entry(finding.id().to_owned())
            .and_modify(|aggregate| aggregate.absorb(finding))
            .or_insert_with(|| RuleAggregate::from_finding(finding));
    }

    rules
        .into_values()
        .map(RuleAggregate::into_sarif_rule)
        .collect()
}

#[derive(Debug)]
struct RuleAggregate {
    id: String,
    summary: String,
    description: String,
    fix_note: String,
    source: String,
    aliases: BTreeSet<String>,
    ecosystems: BTreeSet<String>,
    package_names: BTreeSet<String>,
    highest_risk: RiskLevel,
    highest_score: u8,
    cvss_score: Option<f32>,
    fix_available: bool,
    known_exploited: bool,
    help_uri: Option<String>,
}

impl RuleAggregate {
    fn from_finding(finding: &Finding) -> Self {
        let advisory = &finding.vulnerability.advisory;
        let description = advisory
            .details
            .as_deref()
            .unwrap_or(&advisory.summary)
            .to_owned();

        Self {
            id: finding.id().to_owned(),
            summary: advisory.summary.clone(),
            description,
            fix_note: finding.fix.note.clone(),
            source: advisory.source.to_string(),
            aliases: advisory
                .aliases
                .iter()
                .map(|value| sanitize_line(value))
                .collect(),
            ecosystems: BTreeSet::from([finding.package.id.ecosystem.to_string()]),
            package_names: BTreeSet::from([sanitize_line(&finding.package.id.name)]),
            highest_risk: finding.risk.level,
            highest_score: finding.risk.score,
            cvss_score: advisory.cvss_score,
            fix_available: finding.fix.available,
            known_exploited: finding.known_exploited,
            help_uri: advisory
                .references
                .iter()
                .find_map(|reference| valid_http_uri(&reference.url)),
        }
    }

    fn absorb(&mut self, finding: &Finding) {
        let advisory = &finding.vulnerability.advisory;
        self.aliases
            .extend(advisory.aliases.iter().map(|value| sanitize_line(value)));
        self.ecosystems
            .insert(finding.package.id.ecosystem.to_string());
        self.package_names
            .insert(sanitize_line(&finding.package.id.name));
        self.fix_available |= finding.fix.available;
        self.known_exploited |= finding.known_exploited;

        if finding.risk.level > self.highest_risk
            || (finding.risk.level == self.highest_risk && finding.risk.score > self.highest_score)
        {
            self.highest_risk = finding.risk.level;
            self.highest_score = finding.risk.score;
            self.fix_note = finding.fix.note.clone();
        }

        if self.cvss_score.is_none() {
            self.cvss_score = advisory.cvss_score;
        }

        if self.help_uri.is_none() {
            self.help_uri = advisory
                .references
                .iter()
                .find_map(|reference| valid_http_uri(&reference.url));
        }
    }

    fn into_sarif_rule(self) -> Value {
        let mut rule = json!({
            "id": sanitize_line(&self.id),
            "name": truncate_chars(&sanitize_line(&self.summary), 120),
            "shortDescription": {
                "text": truncate_chars(&sanitize_line(&self.summary), 256)
            },
            "fullDescription": {
                "text": truncate_chars(&sanitize_line(&self.description), MAX_SARIF_TEXT_CHARS)
            },
            "defaultConfiguration": {
                "level": sarif_level(self.highest_risk)
            },
            "help": {
                "text": truncate_chars(&sanitize_line(&self.fix_note), MAX_SARIF_TEXT_CHARS),
                "markdown": markdown_text(&self.fix_note)
            },
            "properties": {
                "source": sanitize_line(&self.source),
                "aliases": self.aliases.into_iter().collect::<Vec<_>>(),
                "ecosystems": self.ecosystems.into_iter().collect::<Vec<_>>(),
                "affectedPackages": self.package_names.into_iter().collect::<Vec<_>>(),
                "riskLevel": self.highest_risk.to_string(),
                "riskScore": self.highest_score,
                "cvssScore": self.cvss_score,
                "fixAvailable": self.fix_available,
                "knownExploited": self.known_exploited
            }
        });

        if let Some(help_uri) = self.help_uri {
            rule["helpUri"] = json!(help_uri);
        }

        rule
    }
}

fn append_bullets(output: &mut String, heading: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    output.push('\n');
    output.push_str(heading);
    output.push_str(":\n");
    for value in values {
        output.push_str(&format!("  - {}\n", sanitize_line(value)));
    }
}

fn advisory_label(finding: &Finding) -> String {
    let identifiers = finding.vulnerability.advisory.identifiers();
    if identifiers.is_empty() {
        sanitize_line(finding.id())
    } else {
        identifiers
            .iter()
            .map(|identifier| sanitize_line(identifier))
            .collect::<Vec<_>>()
            .join(" / ")
    }
}

fn aliases_label(finding: &Finding) -> String {
    if finding.vulnerability.advisory.aliases.is_empty() {
        "-".to_owned()
    } else {
        finding
            .vulnerability
            .advisory
            .aliases
            .iter()
            .map(|alias| sanitize_line(alias))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn fix_label(finding: &Finding) -> String {
    if finding.fix.available {
        sanitize_line(&finding.fix.note)
    } else {
        "fix not provided by advisory source".to_owned()
    }
}

fn title_level(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Info => "Info",
        RiskLevel::Low => "Low",
        RiskLevel::Medium => "Medium",
        RiskLevel::High => "High",
        RiskLevel::Critical => "Critical",
    }
}

fn sarif_level(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical | RiskLevel::High => "error",
        RiskLevel::Medium | RiskLevel::Low => "warning",
        RiskLevel::Info => "note",
    }
}

fn artifact_uri(target: &str) -> String {
    let sanitized = sanitize_line(target).replace('\\', "/");
    if sanitized.is_empty() {
        "scan-target".to_owned()
    } else {
        sanitized
    }
}

fn valid_http_uri(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return None;
    }

    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("https://") || lowered.starts_with("http://") {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

fn stable_fingerprint(finding: &Finding) -> String {
    let ids = finding
        .vulnerability
        .advisory
        .identifiers()
        .iter()
        .map(|identifier| identifier.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("|");

    format!(
        "{}:{}:{}:{}:{}",
        finding.package.id.ecosystem,
        finding.package.id.name,
        finding.package.id.version,
        finding.package.dependency_kind,
        ids
    )
}

fn sanitize_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && character != '\t' {
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

fn truncate(value: &str, max_chars: usize) -> String {
    truncate_chars(&sanitize_line(value), max_chars)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_owned();
    }

    let take = max_chars.saturating_sub(1);
    let mut truncated = value.chars().take(take).collect::<String>();
    truncated.push('…');
    truncated
}

fn markdown_cell(value: &str) -> String {
    markdown_text(value).replace('|', "\\|")
}

fn markdown_text(value: &str) -> String {
    let sanitized = sanitize_line(value);
    truncate_chars(&sanitized, MAX_MARKDOWN_TEXT_CHARS)
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn markdown_code_span(value: &str) -> String {
    let sanitized = sanitize_line(value);
    if sanitized.contains('`') {
        format!("`` {} ``", sanitized.replace("``", "` `"))
    } else {
        format!("`{sanitized}`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeguard_core::{
        Advisory, DependencyEdge, DependencyGraph, DependencyKind, Ecosystem, FixRecommendation,
        Package, PackageId, PolicyDecision, RiskCounts, RiskScore, ScanMetadata, ScanSummary,
        Vulnerability, VulnerabilitySource,
    };
    use semver::Version;

    fn package(ecosystem: Ecosystem, name: &str, version: &str, kind: DependencyKind) -> Package {
        Package::new(
            PackageId::new(
                ecosystem,
                name,
                Version::parse(version).expect("valid version"),
            ),
            Some(match name {
                "vite" => "https://registry.npmjs.org/vite/-/vite-8.0.14.tgz".to_owned(),
                _ => "registry+https://github.com/rust-lang/crates.io-index".to_owned(),
            }),
            None,
            kind,
        )
    }

    fn finding(package: Package, advisory_id: &str, risk_level: RiskLevel) -> Finding {
        Finding {
            vulnerability: Vulnerability {
                advisory: Advisory {
                    id: advisory_id.to_owned(),
                    aliases: vec!["GHSA-wcg3-cvx6-7396".to_owned()],
                    summary: "Potential segfault in time | markdown".to_owned(),
                    details: Some("Fixture details with <html> and control\u{0007}".to_owned()),
                    severity: Some(risk_level),
                    cvss_score: Some(7.5),
                    published: None,
                    modified: None,
                    references: Vec::new(),
                    source: VulnerabilitySource::Osv,
                },
                affected: package.id.clone(),
                fixed_versions: vec![Version::parse("0.2.23").expect("valid version")],
            },
            package,
            risk: RiskScore {
                score: 82,
                level: risk_level,
                reasons: vec!["Advisory severity is high.".to_owned()],
            },
            fix: FixRecommendation::from_fixed_versions(
                "time",
                vec![Version::parse("0.2.23").expect("valid version")],
            ),
            known_exploited: false,
        }
    }

    fn sample_report() -> ScanReport {
        let cargo_package = package(Ecosystem::Cargo, "time", "0.1.44", DependencyKind::Direct);
        let findings = vec![finding(
            cargo_package.clone(),
            "RUSTSEC-2020-0071",
            RiskLevel::High,
        )];
        let graph = DependencyGraph::new(vec![cargo_package], Vec::new());
        let policy = PolicyDecision {
            status: PolicyStatus::Fail,
            reasons: vec!["threshold met".to_owned()],
            suppressed: Vec::new(),
        };
        ScanReport {
            schema_version: "forgeguard.report/v1".to_owned(),
            target: "Cargo.lock".to_owned(),
            ecosystem: Ecosystem::Cargo,
            generated_at: "2026-01-01T00:00:00Z".to_owned(),
            dependency_graph: graph.clone(),
            summary: ScanSummary {
                dependencies_scanned: graph.package_count(),
                findings_total: findings.len(),
                risk_counts: RiskCounts::from_findings(&findings),
                policy,
            },
            findings,
            metadata: ScanMetadata {
                network_enabled: true,
                advisory_sources: vec![VulnerabilitySource::Osv],
                limitations: Vec::new(),
                advisory_cache: None,
                partial: false,
            },
        }
    }

    fn multi_ecosystem_report() -> ScanReport {
        let mut report = sample_report();
        let npm_package = package(
            Ecosystem::Npm,
            "vite",
            "8.0.14",
            DependencyKind::Development,
        );
        report.findings.push(finding(
            npm_package.clone(),
            "GHSA-fx2h-pf6j-xcff",
            RiskLevel::Medium,
        ));
        report.dependency_graph = DependencyGraph::new(
            vec![report.dependency_graph.packages[0].clone(), npm_package],
            vec![DependencyEdge {
                from: report.dependency_graph.packages[0].id.clone(),
                to: PackageId::new(
                    Ecosystem::Npm,
                    "vite",
                    Version::parse("8.0.14").expect("valid version"),
                ),
            }],
        );
        report.summary.dependencies_scanned = report.dependency_graph.package_count();
        report.summary.findings_total = report.findings.len();
        report.summary.risk_counts = RiskCounts::from_findings(&report.findings);
        report
    }

    #[test]
    fn table_risk_summary_keeps_spacing_for_critical() {
        let table = render_table(&sample_report());

        assert!(table.contains("Critical: 0") || table.contains("Critical: 1"));
        assert!(!table.contains("Critical:0"));
    }

    #[test]
    fn table_shows_ecosystem_column_only_for_multi_ecosystem_reports() {
        let single = render_table(&sample_report());
        assert!(single.contains("Ecosystem: Cargo"));
        assert!(!single.contains("Ecosystems: Cargo, npm"));

        let multi = render_table(&multi_ecosystem_report());
        assert!(multi.contains("Ecosystems: Cargo, npm"));
        assert!(multi.contains("Ecosystem"));
        assert!(multi.contains("vite"));
    }

    #[test]
    fn markdown_contains_aliases_sections_and_ecosystem_column() {
        let markdown = render_markdown(&multi_ecosystem_report());

        assert!(markdown.contains("## Executive Summary"));
        assert!(markdown.contains("## Finding Table"));
        assert!(markdown.contains("GHSA-wcg3-cvx6-7396"));
        assert!(markdown.contains("| Risk | Ecosystem | Advisory"));
        assert!(markdown.contains("## Policy Decision"));
    }

    #[test]
    fn markdown_helpers_escape_cells_and_html_angle_brackets() {
        assert_eq!(markdown_cell("alpha|beta"), "alpha\\|beta");
        assert_eq!(markdown_text("<html>"), "&lt;html&gt;");
    }

    #[test]
    fn sarif_has_required_top_level_fields_and_ecosystem_properties() {
        let rendered = render_sarif(&multi_ecosystem_report()).expect("sarif renders");
        let sarif: Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"][0]["tool"]["driver"]["rules"].is_array());
        assert!(sarif["runs"][0]["results"].is_array());
        assert_eq!(
            sarif["runs"][0]["invocations"][0]["properties"]["ecosystems"][0],
            "Cargo"
        );
        assert_eq!(
            sarif["runs"][0]["results"][1]["properties"]["ecosystem"],
            "npm"
        );
    }

    #[test]
    fn sarif_uses_forward_slash_artifact_uris() {
        let mut report = sample_report();
        report.target = r"examples\vulnerable-rust-app\Cargo.lock".to_owned();

        let rendered = render_sarif(&report).expect("sarif renders");
        let sarif: Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "examples/vulnerable-rust-app/Cargo.lock"
        );
    }

    #[test]
    fn table_uses_fix_note_when_available() {
        let table = render_table(&sample_report());

        assert!(table.contains("Upgrade time"));
        assert!(table.contains("RUSTSEC-2020-0071"));
    }

    #[test]
    fn stable_json_output_is_valid_pretty_json() {
        let json = render_json(&sample_report()).expect("json renders");
        let parsed: Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(parsed["schema_version"], "forgeguard.report/v1");
        assert!(json.contains('\n'));
    }
}
