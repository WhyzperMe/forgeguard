use crate::{DependencyKind, Ecosystem, RiskLevel, RiskScore};

/// Input factors for deterministic vulnerability risk scoring.
///
/// `RiskFactors` intentionally contains only normalized, source-independent
/// signals. Advisory-source clients should map their native metadata into this
/// type before calling [`calculate_risk`].
///
/// The current public API keeps `cvss_score` as `u8` for workspace
/// compatibility. A future breaking release should prefer `Option<f32>` or a
/// dedicated CVSS type to preserve decimal precision such as 7.5.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RiskFactors {
    /// Source advisory severity when available.
    pub advisory_severity: Option<RiskLevel>,
    /// CVSS base score when available.
    ///
    /// Values above 10 are clamped defensively and recorded in the risk
    /// reasons. Callers should pass CVSS base scores in the inclusive range
    /// `0..=10`.
    pub cvss_score: Option<u8>,
    /// Dependency relationship.
    pub dependency_kind: DependencyKind,
    /// Whether a fixed version is known.
    pub fix_available: bool,
    /// Whether the vulnerability is known to be exploited.
    pub known_exploited: bool,
    /// Package ecosystem.
    pub ecosystem: Ecosystem,
}

impl RiskFactors {
    /// Construct risk factors with explicit values.
    #[must_use]
    pub const fn new(
        advisory_severity: Option<RiskLevel>,
        cvss_score: Option<u8>,
        dependency_kind: DependencyKind,
        fix_available: bool,
        known_exploited: bool,
        ecosystem: Ecosystem,
    ) -> Self {
        Self {
            advisory_severity,
            cvss_score,
            dependency_kind,
            fix_available,
            known_exploited,
            ecosystem,
        }
    }
}

/// Calculate a deterministic 0-100 risk-priority score.
///
/// The model is deliberately simple, auditable, and stable:
///
/// 1. Establish technical severity from CVSS if available.
/// 2. Fall back to source advisory severity.
/// 3. Apply bounded context modifiers for dependency relationship, fix
///    availability, and exploitation signals.
/// 4. Clamp the final score to `0..=100`.
///
/// Important distinction: this is a **risk-priority score**, not a pure CVSS
/// replacement. It helps CI and developers prioritize remediation while keeping
/// every score explainable through [`RiskScore::reasons`].
#[must_use]
pub fn calculate_risk(factors: RiskFactors) -> RiskScore {
    RiskCalculator.calculate(&factors)
}

#[derive(Clone, Copy, Debug, Default)]
struct RiskCalculator;

impl RiskCalculator {
    fn calculate(self, factors: &RiskFactors) -> RiskScore {
        let mut reasons = Vec::new();
        let mut score = self.base_score(factors, &mut reasons);

        score += self.dependency_modifier(factors.dependency_kind, &mut reasons);
        score += self.fix_modifier(factors.fix_available, &mut reasons);
        score = self.apply_exploitation_signal(score, factors.known_exploited, &mut reasons);

        self.add_ecosystem_reason(&factors.ecosystem, &mut reasons);

        let score = clamp_score(score);
        RiskScore {
            score,
            level: RiskLevel::from_score(score),
            reasons,
        }
    }

    fn base_score(self, factors: &RiskFactors, reasons: &mut Vec<String>) -> i16 {
        if let Some(raw_cvss) = factors.cvss_score {
            let cvss = raw_cvss.min(CVSS_MAX);
            if raw_cvss > CVSS_MAX {
                reasons.push(format!(
                    "CVSS base score {raw_cvss} exceeded 10 and was clamped to {cvss}."
                ));
            } else {
                reasons.push(format!("CVSS base score {cvss}."));
            }
            return base_score_from_cvss(cvss);
        }

        if let Some(severity) = factors.advisory_severity {
            reasons.push(format!("Advisory severity is {severity}."));
            return base_score_from_advisory_severity(severity);
        }

        reasons.push(
            "No source severity or CVSS score was available; using conservative informational baseline."
                .to_owned(),
        );
        BASE_UNKNOWN_SEVERITY
    }

    fn dependency_modifier(
        self,
        dependency_kind: DependencyKind,
        reasons: &mut Vec<String>,
    ) -> i16 {
        match dependency_kind {
            DependencyKind::Direct => {
                reasons.push("Direct dependency increases remediation priority.".to_owned());
                DIRECT_DEPENDENCY_BONUS
            }
            DependencyKind::Transitive => {
                reasons.push("Transitive dependency has no direct-use signal yet.".to_owned());
                TRANSITIVE_DEPENDENCY_BONUS
            }
            DependencyKind::Development => {
                reasons.push("Development dependency lowers likely runtime exposure.".to_owned());
                DEVELOPMENT_DEPENDENCY_PENALTY
            }
            DependencyKind::Build => {
                reasons.push("Build dependency can influence produced artifacts.".to_owned());
                BUILD_DEPENDENCY_BONUS
            }
            DependencyKind::Unknown => {
                reasons.push("Dependency relationship is unknown from static files.".to_owned());
                UNKNOWN_DEPENDENCY_BONUS
            }
        }
    }

    fn fix_modifier(self, fix_available: bool, reasons: &mut Vec<String>) -> i16 {
        if fix_available {
            reasons.push(
                "A fixed version is available; remediation can be prioritized immediately."
                    .to_owned(),
            );
            FIX_AVAILABLE_BONUS
        } else {
            reasons.push(
                "No fixed version was provided by the advisory source; remediation may require mitigation or monitoring."
                    .to_owned(),
            );
            NO_FIX_BONUS
        }
    }

    fn apply_exploitation_signal(
        self,
        score: i16,
        known_exploited: bool,
        reasons: &mut Vec<String>,
    ) -> i16 {
        if known_exploited {
            reasons.push(
                "Known exploitation signal is present; risk priority is elevated.".to_owned(),
            );
            (score + KNOWN_EXPLOITED_BONUS).max(KNOWN_EXPLOITED_MINIMUM_SCORE)
        } else {
            score
        }
    }

    fn add_ecosystem_reason(self, ecosystem: &Ecosystem, reasons: &mut Vec<String>) {
        match ecosystem {
            Ecosystem::Cargo => reasons.push(
                "Cargo ecosystem advisory matching is explicitly supported in this release."
                    .to_owned(),
            ),
            other => reasons.push(format!(
                "{other} ecosystem support is experimental or planned; confidence may be lower."
            )),
        }
    }
}

const CVSS_MAX: u8 = 10;

const BASE_UNKNOWN_SEVERITY: i16 = 10;

const BASE_INFO: i16 = 5;
const BASE_LOW: i16 = 25;
const BASE_MEDIUM: i16 = 50;
const BASE_HIGH: i16 = 75;
const BASE_CRITICAL: i16 = 95;

const DIRECT_DEPENDENCY_BONUS: i16 = 8;
const TRANSITIVE_DEPENDENCY_BONUS: i16 = 0;
const DEVELOPMENT_DEPENDENCY_PENALTY: i16 = -12;
const BUILD_DEPENDENCY_BONUS: i16 = 6;
const UNKNOWN_DEPENDENCY_BONUS: i16 = 0;

const FIX_AVAILABLE_BONUS: i16 = 3;
const NO_FIX_BONUS: i16 = 0;

const KNOWN_EXPLOITED_BONUS: i16 = 20;
const KNOWN_EXPLOITED_MINIMUM_SCORE: i16 = 80;

fn base_score_from_cvss(cvss: u8) -> i16 {
    match cvss {
        9..=10 => BASE_CRITICAL,
        7..=8 => BASE_HIGH,
        4..=6 => BASE_MEDIUM,
        1..=3 => BASE_LOW,
        _ => BASE_INFO,
    }
}

fn base_score_from_advisory_severity(severity: RiskLevel) -> i16 {
    match severity {
        RiskLevel::Critical => 90,
        RiskLevel::High => BASE_HIGH,
        RiskLevel::Medium => BASE_MEDIUM,
        RiskLevel::Low => BASE_LOW,
        RiskLevel::Info => BASE_INFO,
    }
}

fn clamp_score(score: i16) -> u8 {
    score.clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factors_with_cvss(cvss_score: u8) -> RiskFactors {
        RiskFactors::new(
            None,
            Some(cvss_score),
            DependencyKind::Transitive,
            false,
            false,
            Ecosystem::Cargo,
        )
    }

    fn factors_with_severity(severity: RiskLevel) -> RiskFactors {
        RiskFactors::new(
            Some(severity),
            None,
            DependencyKind::Transitive,
            false,
            false,
            Ecosystem::Cargo,
        )
    }

    #[test]
    fn scoring_is_deterministic_for_high_direct_fixable_findings() {
        let factors = RiskFactors::new(
            Some(RiskLevel::High),
            None,
            DependencyKind::Direct,
            true,
            false,
            Ecosystem::Cargo,
        );

        let first = calculate_risk(factors.clone());
        let second = calculate_risk(factors);

        assert_eq!(first, second);
        assert_eq!(first.score, 86);
        assert_eq!(first.level, RiskLevel::High);
        assert!(first
            .reasons
            .iter()
            .any(|reason| reason.contains("Direct dependency")));
        assert!(first
            .reasons
            .iter()
            .any(|reason| reason.contains("fixed version")));
    }

    #[test]
    fn development_dependency_reduces_score() {
        let score = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Medium),
            None,
            DependencyKind::Development,
            false,
            false,
            Ecosystem::Cargo,
        ));

        assert_eq!(score.score, 38);
        assert_eq!(score.level, RiskLevel::Low);
    }

    #[test]
    fn build_dependency_increases_score_less_than_direct_dependency() {
        let build = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Medium),
            None,
            DependencyKind::Build,
            false,
            false,
            Ecosystem::Cargo,
        ));
        let direct = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Medium),
            None,
            DependencyKind::Direct,
            false,
            false,
            Ecosystem::Cargo,
        ));

        assert!(build.score > 50);
        assert!(direct.score > build.score);
    }

    #[test]
    fn cvss_boundaries_map_to_expected_levels() {
        let cases = [
            (0, RiskLevel::Info),
            (1, RiskLevel::Low),
            (3, RiskLevel::Low),
            (4, RiskLevel::Medium),
            (6, RiskLevel::Medium),
            (7, RiskLevel::High),
            (8, RiskLevel::High),
            (9, RiskLevel::Critical),
            (10, RiskLevel::Critical),
        ];

        for (cvss, expected) in cases {
            let score = calculate_risk(factors_with_cvss(cvss));
            assert_eq!(
                score.level, expected,
                "unexpected level for CVSS score {cvss}"
            );
        }
    }

    #[test]
    fn advisory_severity_boundaries_map_to_expected_levels() {
        let cases = [
            (RiskLevel::Info, RiskLevel::Info),
            (RiskLevel::Low, RiskLevel::Low),
            (RiskLevel::Medium, RiskLevel::Medium),
            (RiskLevel::High, RiskLevel::High),
            (RiskLevel::Critical, RiskLevel::Critical),
        ];

        for (severity, expected) in cases {
            let score = calculate_risk(factors_with_severity(severity));
            assert_eq!(
                score.level, expected,
                "unexpected level for severity {severity}"
            );
        }
    }

    #[test]
    fn cvss_takes_precedence_over_source_severity() {
        let score = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Low),
            Some(9),
            DependencyKind::Transitive,
            false,
            false,
            Ecosystem::Cargo,
        ));

        assert_eq!(score.level, RiskLevel::Critical);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("CVSS base score 9")));
    }

    #[test]
    fn excessive_cvss_is_clamped_and_explained() {
        let score = calculate_risk(factors_with_cvss(42));

        assert_eq!(score.score, 95);
        assert_eq!(score.level, RiskLevel::Critical);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("clamped")));
    }

    #[test]
    fn known_exploitation_sets_high_priority_floor() {
        let score = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Low),
            None,
            DependencyKind::Development,
            false,
            true,
            Ecosystem::Cargo,
        ));

        assert_eq!(score.score, 80);
        assert_eq!(score.level, RiskLevel::High);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("Known exploitation")));
    }

    #[test]
    fn critical_known_exploited_direct_dependency_clamps_to_100() {
        let score = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Critical),
            None,
            DependencyKind::Direct,
            true,
            true,
            Ecosystem::Cargo,
        ));

        assert_eq!(score.score, 100);
        assert_eq!(score.level, RiskLevel::Critical);
    }

    #[test]
    fn missing_severity_gets_explicit_reason() {
        let score = calculate_risk(RiskFactors::new(
            None,
            None,
            DependencyKind::Unknown,
            false,
            false,
            Ecosystem::Cargo,
        ));

        assert_eq!(score.score, 10);
        assert_eq!(score.level, RiskLevel::Info);
        assert!(score
            .reasons
            .iter()
            .any(|reason| reason.contains("No source severity")));
    }

    #[test]
    fn unsupported_ecosystem_adds_reason_without_score_modifier() {
        let cargo = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Medium),
            None,
            DependencyKind::Transitive,
            false,
            false,
            Ecosystem::Cargo,
        ));
        let npm = calculate_risk(RiskFactors::new(
            Some(RiskLevel::Medium),
            None,
            DependencyKind::Transitive,
            false,
            false,
            Ecosystem::Npm,
        ));

        assert_eq!(cargo.score, npm.score);
        assert!(npm
            .reasons
            .iter()
            .any(|reason| reason.contains("experimental or planned")));
    }
}
