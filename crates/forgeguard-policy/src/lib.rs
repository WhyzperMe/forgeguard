//! Policy loading, validation, and evaluation for ForgeGuard.
//!
//! The policy engine is intentionally deterministic and side-effect free after
//! loading. It evaluates already-normalized findings and returns a structured
//! [`PolicyDecision`] that callers can use for CI/CD exit codes and reports.

#![forbid(unsafe_code)]

use forgeguard_core::{Finding, PolicyDecision, PolicyStatus, RiskLevel};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use thiserror::Error;
use time::{Date, OffsetDateTime};

/// Maximum accepted policy file size.
///
/// ForgeGuard may be asked to scan untrusted repositories. Bounding policy file
/// size prevents accidental or intentional memory abuse when a repository-local
/// `forgeguard.yml` is loaded by the CLI.
pub const MAX_POLICY_FILE_BYTES: u64 = 1024 * 1024;

/// Errors produced by policy loading and validation.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Filesystem metadata lookup failed.
    #[error("failed to inspect policy file {path}: {source}")]
    Metadata {
        /// Policy path.
        path: String,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Policy file is too large.
    #[error("policy file {path} is too large: {size} bytes exceeds limit of {max_size} bytes")]
    PolicyTooLarge {
        /// Policy path.
        path: String,
        /// Observed file size.
        size: u64,
        /// Maximum accepted file size.
        max_size: u64,
    },
    /// Filesystem read failed.
    #[error("failed to read policy file {path}: {source}")]
    Io {
        /// Policy path.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// YAML parsing failed.
    #[error("failed to parse policy file {path}: {source}")]
    Yaml {
        /// Policy path.
        path: String,
        /// Underlying YAML error.
        #[source]
        source: serde_yaml_ng::Error,
    },
    /// An allowlist entry had an empty identifier.
    #[error("allowlist entry at index {index} has an empty id")]
    EmptyAllowlistId {
        /// Entry index.
        index: usize,
    },
    /// An allowlist entry had an empty reason.
    #[error("allowlist entry for '{id}' has an empty reason")]
    EmptyAllowlistReason {
        /// Allowlist identifier.
        id: String,
    },
    /// An allowlist date was invalid.
    #[error("invalid allowlist expiry date for '{id}': '{expires}' must use YYYY-MM-DD")]
    InvalidAllowlistDate {
        /// Allowlist identifier.
        id: String,
        /// Invalid date string.
        expires: String,
    },
    /// An allowlist identifier was configured more than once.
    #[error("duplicate allowlist id '{id}'")]
    DuplicateAllowlistId {
        /// Normalized allowlist identifier.
        id: String,
    },
    /// A denied license entry was empty.
    #[error("licenses.deny entry at index {index} is empty")]
    EmptyDeniedLicense {
        /// Entry index.
        index: usize,
    },
}

/// Result type for policy operations.
pub type Result<T> = std::result::Result<T, PolicyError>;

/// Top-level ForgeGuard policy file.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Failure thresholds.
    pub fail_on: FailOnConfig,
    /// Temporary finding suppressions.
    pub allowlist: Vec<AllowlistEntry>,
    /// Placeholder license policy structure.
    pub licenses: LicensePolicy,
}

impl PolicyConfig {
    /// Load and validate a policy file from disk.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let path_label = path.display().to_string();

        let metadata = fs::metadata(path).map_err(|source| PolicyError::Metadata {
            path: path_label.clone(),
            source,
        })?;
        if metadata.len() > MAX_POLICY_FILE_BYTES {
            return Err(PolicyError::PolicyTooLarge {
                path: path_label,
                size: metadata.len(),
                max_size: MAX_POLICY_FILE_BYTES,
            });
        }

        let contents = fs::read_to_string(path).map_err(|source| PolicyError::Io {
            path: path.display().to_string(),
            source,
        })?;

        if contents.len() as u64 > MAX_POLICY_FILE_BYTES {
            return Err(PolicyError::PolicyTooLarge {
                path: path.display().to_string(),
                size: contents.len() as u64,
                max_size: MAX_POLICY_FILE_BYTES,
            });
        }

        Self::from_yaml_str(&contents, Some(path))
    }

    /// Parse and validate a policy from YAML text.
    pub fn from_yaml_str(contents: &str, source_path: Option<&Path>) -> Result<Self> {
        let policy: Self =
            serde_yaml_ng::from_str(contents).map_err(|source| PolicyError::Yaml {
                path: source_path
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<inline policy>".to_owned()),
                source,
            })?;
        policy.validate()?;
        Ok(policy)
    }

    /// Validate policy fields and invariants.
    pub fn validate(&self) -> Result<()> {
        let mut seen_allowlist_ids = BTreeSet::new();

        for (index, entry) in self.allowlist.iter().enumerate() {
            let normalized_id = normalize_identifier(&entry.id);
            if normalized_id.is_empty() {
                return Err(PolicyError::EmptyAllowlistId { index });
            }
            if !seen_allowlist_ids.insert(normalized_id.clone()) {
                return Err(PolicyError::DuplicateAllowlistId { id: normalized_id });
            }
            if entry.reason.trim().is_empty() {
                return Err(PolicyError::EmptyAllowlistReason {
                    id: entry.id.clone(),
                });
            }
            if let Some(expires) = entry.expires.as_deref() {
                parse_date(expires.trim()).map_err(|_| PolicyError::InvalidAllowlistDate {
                    id: entry.id.clone(),
                    expires: expires.to_owned(),
                })?;
            }
        }

        for (index, license) in self.licenses.deny.iter().enumerate() {
            if license.trim().is_empty() {
                return Err(PolicyError::EmptyDeniedLicense { index });
            }
        }

        Ok(())
    }

    /// Evaluate findings using the current UTC date.
    #[must_use]
    pub fn evaluate(&self, findings: &[Finding]) -> PolicyDecision {
        self.evaluate_at(findings, OffsetDateTime::now_utc().date())
    }

    /// Evaluate findings using an explicit date.
    ///
    /// `expires` dates are treated as valid through the specified day. An entry
    /// with `expires: 2026-01-01` is considered expired on `2026-01-02`.
    #[must_use]
    pub fn evaluate_at(&self, findings: &[Finding], today: Date) -> PolicyDecision {
        let allowlist_index = self.allowlist_index();
        let mut fail_reasons = Vec::new();
        let mut warn_reasons = Vec::new();
        let mut suppressed = Vec::new();
        let mut unsuppressed_findings = 0usize;

        for finding in findings {
            match allowlist_match(finding, &allowlist_index, today) {
                AllowlistMatch::Active(entry) => {
                    suppressed.push(finding.id().to_owned());
                    warn_reasons.push(format!(
                        "{} suppressed by active allowlist entry '{}': {}{}.",
                        finding.id(),
                        entry.id,
                        entry.reason.trim(),
                        entry
                            .expires
                            .as_deref()
                            .map(|expires| format!(" Expires {expires}"))
                            .unwrap_or_default()
                    ));
                    continue;
                }
                AllowlistMatch::Expired(entry) => {
                    warn_reasons.push(format!(
                        "Allowlist entry '{}' expired on {} and no longer suppresses {}.",
                        entry.id,
                        entry.expires.as_deref().unwrap_or("an unknown date"),
                        finding.id()
                    ));
                }
                AllowlistMatch::None => {}
            }

            unsuppressed_findings += 1;
            self.evaluate_finding_thresholds(finding, &mut fail_reasons);
        }

        if !fail_reasons.is_empty() {
            let mut reasons = fail_reasons;
            reasons.extend(warn_reasons);
            PolicyDecision {
                status: PolicyStatus::Fail,
                reasons,
                suppressed,
            }
        } else if unsuppressed_findings > 0 {
            let mut reasons = warn_reasons;
            reasons.push(format!(
                "{unsuppressed_findings} unsuppressed finding(s) did not meet configured fail thresholds."
            ));
            PolicyDecision {
                status: PolicyStatus::Warn,
                reasons,
                suppressed,
            }
        } else if !warn_reasons.is_empty() {
            PolicyDecision {
                status: PolicyStatus::Pass,
                reasons: warn_reasons,
                suppressed,
            }
        } else {
            PolicyDecision {
                status: PolicyStatus::Pass,
                reasons: vec!["No findings violated policy.".to_owned()],
                suppressed,
            }
        }
    }

    /// Override the severity threshold.
    pub fn set_fail_on_severity(&mut self, severity: RiskLevel) {
        self.fail_on.severity = severity;
    }

    fn evaluate_finding_thresholds(&self, finding: &Finding, fail_reasons: &mut Vec<String>) {
        if finding.risk.level.is_at_least(self.fail_on.severity) {
            fail_reasons.push(format!(
                "{} affects {} {} with {} risk, meeting fail_on.severity {}.",
                finding.id(),
                finding.package.id.name,
                finding.package.id.version,
                finding.risk.level,
                self.fail_on.severity
            ));
        }

        if self.fail_on.known_exploited && finding.known_exploited {
            fail_reasons.push(format!(
                "{} is marked as known exploited by the advisory source.",
                finding.id()
            ));
        }

        if self.fail_on.fix_available && finding.fix.available {
            fail_reasons.push(format!(
                "{} has a known fix available for {}.",
                finding.id(),
                finding.package.id.name
            ));
        }
    }

    fn allowlist_index(&self) -> BTreeMap<String, &AllowlistEntry> {
        self.allowlist
            .iter()
            .map(|entry| (normalize_identifier(&entry.id), entry))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllowlistMatch<'a> {
    Active(&'a AllowlistEntry),
    Expired(&'a AllowlistEntry),
    None,
}

fn allowlist_match<'a>(
    finding: &Finding,
    allowlist: &'a BTreeMap<String, &'a AllowlistEntry>,
    today: Date,
) -> AllowlistMatch<'a> {
    let mut expired_match = None;

    for identifier in finding.identifiers() {
        let normalized = normalize_identifier(identifier);
        let Some(entry) = allowlist.get(&normalized).copied() else {
            continue;
        };

        if entry.is_expired(today) {
            expired_match = Some(entry);
            continue;
        }

        return AllowlistMatch::Active(entry);
    }

    expired_match.map_or(AllowlistMatch::None, AllowlistMatch::Expired)
}

/// Failure threshold configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FailOnConfig {
    /// Minimum risk level that fails policy.
    pub severity: RiskLevel,
    /// Fail on known-exploited signals.
    pub known_exploited: bool,
    /// Fail when a fix is available.
    pub fix_available: bool,
}

impl Default for FailOnConfig {
    fn default() -> Self {
        Self {
            severity: RiskLevel::Critical,
            known_exploited: true,
            fix_available: false,
        }
    }
}

/// Temporary finding allowlist entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistEntry {
    /// Advisory ID or alias to suppress.
    pub id: String,
    /// Required human justification.
    pub reason: String,
    /// Expiry date in YYYY-MM-DD format.
    pub expires: Option<String>,
}

impl AllowlistEntry {
    fn expires_date(&self) -> Option<Date> {
        self.expires
            .as_deref()
            .and_then(|value| parse_date(value.trim()).ok())
    }

    fn is_expired(&self, today: Date) -> bool {
        self.expires_date().is_some_and(|expires| expires < today)
    }
}

/// License policy placeholder.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LicensePolicy {
    /// Denied SPDX license IDs.
    pub deny: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DateParseError;

fn parse_date(value: &str) -> std::result::Result<Date, DateParseError> {
    let value = value.trim();

    if value.len() != 10 {
        return Err(DateParseError);
    }

    let bytes = value.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(DateParseError);
    }

    if !bytes[..4].iter().all(u8::is_ascii_digit)
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return Err(DateParseError);
    }

    let year = value[..4].parse::<i32>().map_err(|_| DateParseError)?;
    let month_number = value[5..7].parse::<u8>().map_err(|_| DateParseError)?;
    let day = value[8..10].parse::<u8>().map_err(|_| DateParseError)?;

    let month = match month_number {
        1 => time::Month::January,
        2 => time::Month::February,
        3 => time::Month::March,
        4 => time::Month::April,
        5 => time::Month::May,
        6 => time::Month::June,
        7 => time::Month::July,
        8 => time::Month::August,
        9 => time::Month::September,
        10 => time::Month::October,
        11 => time::Month::November,
        12 => time::Month::December,
        _ => return Err(DateParseError),
    };

    Date::from_calendar_date(year, month, day).map_err(|_| DateParseError)
}

fn normalize_identifier(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeguard_core::{
        Advisory, DependencyKind, Ecosystem, FixRecommendation, Package, PackageId, RiskScore,
        Vulnerability, VulnerabilitySource,
    };
    use semver::Version;
    use time::Month;

    fn test_date() -> Date {
        Date::from_calendar_date(2026, Month::January, 1).expect("valid date")
    }

    fn finding(id: &str, risk: RiskLevel, fix_available: bool) -> Finding {
        let version = Version::parse("1.0.0").expect("valid version");
        let package = Package {
            id: PackageId::new(Ecosystem::Cargo, "demo", version.clone()),
            source: Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            checksum: None,
            purl: "pkg:cargo/demo@1.0.0".to_owned(),
            dependency_kind: DependencyKind::Direct,
        };
        Finding {
            vulnerability: Vulnerability {
                advisory: Advisory {
                    id: id.to_owned(),
                    aliases: vec!["GHSA-demo-demo".to_owned()],
                    summary: "demo".to_owned(),
                    details: None,
                    severity: Some(risk),
                    cvss_score: None,
                    published: None,
                    modified: None,
                    references: Vec::new(),
                    source: VulnerabilitySource::Osv,
                },
                affected: package.id.clone(),
                fixed_versions: Vec::new(),
            },
            package,
            risk: RiskScore {
                score: 75,
                level: risk,
                reasons: vec!["test".to_owned()],
            },
            fix: FixRecommendation {
                available: fix_available,
                versions: Vec::new(),
                note: "test".to_owned(),
            },
            known_exploited: false,
        }
    }

    #[test]
    fn high_finding_fails_high_threshold() {
        let policy = PolicyConfig {
            fail_on: FailOnConfig {
                severity: RiskLevel::High,
                known_exploited: true,
                fix_available: false,
            },
            ..PolicyConfig::default()
        };

        let decision = policy.evaluate_at(
            &[finding("RUSTSEC-0000-0001", RiskLevel::High, false)],
            test_date(),
        );

        assert_eq!(decision.status, PolicyStatus::Fail);
    }

    #[test]
    fn active_allowlist_suppresses_finding_by_alias_case_insensitively() {
        let policy = PolicyConfig {
            fail_on: FailOnConfig {
                severity: RiskLevel::High,
                known_exploited: true,
                fix_available: false,
            },
            allowlist: vec![AllowlistEntry {
                id: "ghsa-demo-demo".to_owned(),
                reason: "accepted for test".to_owned(),
                expires: Some("2026-12-31".to_owned()),
            }],
            ..PolicyConfig::default()
        };

        let decision = policy.evaluate_at(
            &[finding("RUSTSEC-0000-0001", RiskLevel::High, false)],
            test_date(),
        );

        assert_eq!(decision.status, PolicyStatus::Pass);
        assert_eq!(decision.suppressed, vec!["RUSTSEC-0000-0001"]);
    }

    #[test]
    fn expired_allowlist_does_not_suppress() {
        let policy = PolicyConfig {
            fail_on: FailOnConfig {
                severity: RiskLevel::High,
                known_exploited: true,
                fix_available: false,
            },
            allowlist: vec![AllowlistEntry {
                id: "RUSTSEC-0000-0001".to_owned(),
                reason: "expired".to_owned(),
                expires: Some("2025-12-31".to_owned()),
            }],
            ..PolicyConfig::default()
        };

        let decision = policy.evaluate_at(
            &[finding("RUSTSEC-0000-0001", RiskLevel::High, false)],
            test_date(),
        );

        assert_eq!(decision.status, PolicyStatus::Fail);
        assert!(decision.suppressed.is_empty());
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("expired")));
    }

    #[test]
    fn invalid_allowlist_date_is_rejected() {
        let policy = PolicyConfig {
            allowlist: vec![AllowlistEntry {
                id: "RUSTSEC-0000-0001".to_owned(),
                reason: "bad date".to_owned(),
                expires: Some("01-01-2026".to_owned()),
            }],
            ..PolicyConfig::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(PolicyError::InvalidAllowlistDate { .. })
        ));
    }

    #[test]
    fn duplicate_allowlist_ids_are_rejected_case_insensitively() {
        let policy = PolicyConfig {
            allowlist: vec![
                AllowlistEntry {
                    id: "ghsa-demo-demo".to_owned(),
                    reason: "one".to_owned(),
                    expires: None,
                },
                AllowlistEntry {
                    id: "GHSA-DEMO-DEMO".to_owned(),
                    reason: "two".to_owned(),
                    expires: None,
                },
            ],
            ..PolicyConfig::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(PolicyError::DuplicateAllowlistId { .. })
        ));
    }

    #[test]
    fn yaml_unknown_fields_are_rejected() {
        let yaml = r#"
fail_on:
  severity: high
unexpected: true
"#;

        assert!(matches!(
            PolicyConfig::from_yaml_str(yaml, None),
            Err(PolicyError::Yaml { .. })
        ));
    }

    #[test]
    fn fix_available_threshold_can_fail_policy() {
        let policy = PolicyConfig {
            fail_on: FailOnConfig {
                severity: RiskLevel::Critical,
                known_exploited: true,
                fix_available: true,
            },
            ..PolicyConfig::default()
        };

        let decision = policy.evaluate_at(
            &[finding("RUSTSEC-0000-0001", RiskLevel::Low, true)],
            test_date(),
        );

        assert_eq!(decision.status, PolicyStatus::Fail);
    }

    #[test]
    fn parse_date_accepts_strict_iso_date() {
        let parsed = parse_date("2026-01-31").expect("valid date");
        assert_eq!(
            parsed,
            Date::from_calendar_date(2026, Month::January, 31).expect("valid fixture date")
        );
    }

    #[test]
    fn parse_date_rejects_invalid_or_non_strict_dates() {
        for value in [
            "2026-1-31",
            "2026-13-01",
            "2026-02-30",
            "26-01-01",
            "2026/01/01",
        ] {
            assert!(parse_date(value).is_err(), "{value} should be rejected");
        }
    }
}
