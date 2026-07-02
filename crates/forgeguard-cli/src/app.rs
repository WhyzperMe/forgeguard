#![forbid(unsafe_code)]

use crate::sbom::{render_cyclonedx, CycloneDxFormat};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use forgeguard_cargo::{is_crates_io_package, CargoScanner};
use forgeguard_core::{
    deduplicate_findings, AdvisoryCacheInfo, DependencyGraph, Ecosystem, Finding, Package,
    PolicyStatus, RiskLevel, ScanMetadata, ScanReport, VulnerabilitySource,
};
use forgeguard_npm::{is_npm_registry_package, NpmScanner};
use forgeguard_osv::{
    current_cache_timestamp, AdvisoryCacheDocument, AdvisoryCacheError, OsvClient,
};
use forgeguard_policy::PolicyConfig;
use forgeguard_report::{render_report, ReportFormat};
use forgeguard_scanner::{ScannerInput, ScannerOutput, ScannerRegistry};
use std::{
    collections::BTreeSet,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MAX_POLICY_PARENT_SEARCH_DEPTH: usize = 6;
const DEFAULT_CACHE_MAX_AGE_DAYS: u64 = 30;
const CACHE_FILE_NAME: &str = "osv-cache.json";
const FORGEGUARD_CACHE_DIR_ENV: &str = "FORGEGUARD_CACHE_DIR";

/// ForgeGuard CLI.
#[derive(Debug, Parser)]
#[command(name = "forgeguard")]
#[command(
    version,
    about = "CLI-first software supply-chain vulnerability and risk scanner"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan all supported project lockfiles below the target.
    Scan(ScanArgs),
    /// Explain a vulnerability by querying OSV.dev.
    Explain(ExplainArgs),
    /// Generate a minimal SBOM from all supported lockfile dependencies below the target.
    Sbom(SbomArgs),
    /// Manage the local advisory cache used by offline scans.
    Cache(CacheArgs),
    /// Evaluate policies against an existing ForgeGuard JSON report.
    Policy(PolicyArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// Project directory or supported lockfile path to scan.
    path: PathBuf,
    /// Report format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,
    /// Write report to a file instead of stdout.
    #[arg(long)]
    #[arg(long, alias = "output")]
    out: Option<PathBuf>,
    /// Policy file path.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Override policy severity threshold.
    #[arg(long, value_parser = parse_risk_level)]
    fail_on: Option<RiskLevel>,
    /// Disable network advisory queries.
    #[arg(long)]
    offline: bool,
    /// Force network advisory queries. This conflicts with --offline/--no-network.
    #[arg(long)]
    online: bool,
    /// Disable network advisory queries.
    #[arg(long)]
    no_network: bool,
    /// Emit stable machine-readable output. Defaults scan output to JSON.
    #[arg(long)]
    machine: bool,
    /// Fail when offline advisory cache data is missing or stale.
    #[arg(long)]
    strict: bool,
    /// Local OSV advisory cache path.
    #[arg(long)]
    cache: Option<PathBuf>,
    /// Maximum acceptable offline cache age in days.
    #[arg(long, default_value_t = DEFAULT_CACHE_MAX_AGE_DAYS)]
    cache_max_age_days: u64,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Vulnerability ID, such as RUSTSEC-2020-0071 or GHSA-xxxx-yyyy.
    vulnerability_id: String,
}

#[derive(Debug, Args)]
struct SbomArgs {
    /// Project directory or supported lockfile path.
    path: PathBuf,
    /// SBOM output format.
    #[arg(long, value_enum, default_value_t = SbomFormat::Cyclonedx)]
    format: SbomFormat,
    /// Write SBOM to a file instead of stdout.
    #[arg(long)]
    #[arg(long, alias = "output")]
    out: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CacheArgs {
    #[command(subcommand)]
    command: CacheCommand,
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Query OSV for a target and write the local cache.
    Update(CacheUpdateArgs),
    /// Show local advisory cache status.
    Status(CacheStatusArgs),
    /// Print the resolved advisory cache path.
    Path(CachePathArgs),
}

#[derive(Debug, Args)]
struct CacheUpdateArgs {
    /// Project directory or supported lockfile path used to populate the cache.
    path: PathBuf,
    /// Local OSV advisory cache path.
    #[arg(long)]
    cache: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct CacheStatusArgs {
    /// Local OSV advisory cache path.
    #[arg(long)]
    cache: Option<PathBuf>,
    /// Status output format.
    #[arg(long, value_enum, default_value_t = CacheStatusFormat::Table)]
    format: CacheStatusFormat,
    /// Maximum acceptable cache age in days.
    #[arg(long, default_value_t = DEFAULT_CACHE_MAX_AGE_DAYS)]
    cache_max_age_days: u64,
}

#[derive(Debug, Args)]
struct CachePathArgs {
    /// Local OSV advisory cache path.
    #[arg(long)]
    cache: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct PolicyArgs {
    #[command(subcommand)]
    command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Evaluate a ForgeGuard JSON report against a policy.
    Check(PolicyCheckArgs),
}

#[derive(Debug, Args)]
struct PolicyCheckArgs {
    /// ForgeGuard JSON report path.
    report: PathBuf,
    /// Policy file path.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Override policy severity threshold.
    #[arg(long, value_parser = parse_risk_level)]
    fail_on: Option<RiskLevel>,
    /// Emit JSON policy decision.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Markdown,
    Sarif,
}

impl From<OutputFormat> for ReportFormat {
    fn from(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Table => Self::Table,
            OutputFormat::Json => Self::Json,
            OutputFormat::Markdown => Self::Markdown,
            OutputFormat::Sarif => Self::Sarif,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum SbomFormat {
    #[value(alias = "cyclonedx-json")]
    Cyclonedx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CacheStatusFormat {
    Table,
    Json,
}

/// Documented process status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunStatus {
    /// Scan succeeded and policy passed or warned.
    Success,
    /// Scan succeeded but policy failed.
    PolicyFailure,
    /// Usage or configuration error.
    UsageConfigError,
    /// Scan or runtime error.
    ScanRuntimeError,
    /// Network or advisory source error.
    NetworkAdvisoryError,
    /// Internal error.
    InternalError,
}

impl RunStatus {
    /// Convert to the documented process exit code.
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        match self {
            Self::Success => ExitCode::from(0),
            Self::PolicyFailure => ExitCode::from(1),
            Self::UsageConfigError => ExitCode::from(2),
            Self::ScanRuntimeError => ExitCode::from(3),
            Self::NetworkAdvisoryError => ExitCode::from(4),
            Self::InternalError => ExitCode::from(5),
        }
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ClassifiedCliError {
    status: RunStatus,
    message: String,
}

impl ClassifiedCliError {
    fn new(status: RunStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// Map an error chain to a documented process status.
#[must_use]
pub fn status_for_error(error: &anyhow::Error) -> RunStatus {
    error
        .chain()
        .find_map(|cause| {
            cause
                .downcast_ref::<ClassifiedCliError>()
                .map(|classified| classified.status)
        })
        .unwrap_or(RunStatus::InternalError)
}

#[derive(Clone, Debug)]
struct CombinedScan {
    target: PathBuf,
    primary_ecosystem: Ecosystem,
    outputs: Vec<ScannerOutput>,
    graph: DependencyGraph,
    limitations: Vec<String>,
}

impl CombinedScan {
    fn new(target: PathBuf, outputs: Vec<ScannerOutput>) -> Result<Self> {
        let Some(first) = outputs.first() else {
            bail!("no scanner outputs were produced for {}", target.display());
        };

        let graph = merge_dependency_graphs(&outputs);
        let mut limitations = Vec::new();
        push_unique(
            &mut limitations,
            format!(
                "Detected {} supported dependency lockfile(s): {}.",
                outputs.len(),
                lockfile_summary(&outputs)
            ),
        );
        for output in &outputs {
            for limitation in &output.limitations {
                push_unique(&mut limitations, limitation.clone());
            }
        }

        Ok(Self {
            target,
            primary_ecosystem: first.ecosystem.clone(),
            outputs,
            graph,
            limitations,
        })
    }

    fn ecosystem_count(&self) -> usize {
        self.outputs
            .iter()
            .map(|output| output.ecosystem.clone())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

#[derive(Clone, Debug)]
struct AdvisoryResolution {
    findings: Vec<Finding>,
    advisory_sources: Vec<VulnerabilitySource>,
    cache_info: Option<AdvisoryCacheInfo>,
    limitations: Vec<String>,
    partial: bool,
}

impl AdvisoryResolution {
    fn empty() -> Self {
        Self {
            findings: Vec::new(),
            advisory_sources: Vec::new(),
            cache_info: None,
            limitations: Vec::new(),
            partial: false,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
struct CacheStatusReport {
    path: String,
    exists: bool,
    readable: bool,
    schema_version: Option<String>,
    generated_at: Option<String>,
    age_days: Option<i64>,
    stale: bool,
    max_age_days: u64,
    package_records: usize,
    findings: usize,
    error: Option<String>,
}

impl CacheStatusReport {
    fn render_table(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Path: {}", self.path));
        lines.push(format!("Exists: {}", self.exists));
        lines.push(format!("Readable: {}", self.readable));
        lines.push(format!(
            "Schema: {}",
            self.schema_version.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "Generated at: {}",
            self.generated_at.as_deref().unwrap_or("unknown")
        ));
        lines.push(format!(
            "Age days: {}",
            self.age_days
                .map(|age| age.to_string())
                .unwrap_or_else(|| "unknown".to_owned())
        ));
        lines.push(format!("Stale: {}", self.stale));
        lines.push(format!("Max age days: {}", self.max_age_days));
        lines.push(format!("Package records: {}", self.package_records));
        lines.push(format!("Findings: {}", self.findings));
        if let Some(error) = &self.error {
            lines.push(format!("Error: {error}"));
        }
        lines.join("\n")
    }
}

/// Run the CLI.
pub async fn run(cli: Cli) -> Result<RunStatus> {
    match cli.command {
        Command::Scan(args) => scan(args).await,
        Command::Explain(args) => explain(&args).await,
        Command::Sbom(args) => sbom(&args),
        Command::Cache(args) => cache(args).await,
        Command::Policy(args) => policy(args),
    }
}

async fn scan(args: ScanArgs) -> Result<RunStatus> {
    validate_scan_args(&args)?;
    let combined = inspect_all_supported_lockfiles(&args.path)?;

    let network_enabled = args.online || !(args.offline || args.no_network);
    let query_packages = queryable_packages(&combined.graph);
    let mut limitations = combined.limitations.clone();
    append_query_limitations(
        &mut limitations,
        &combined,
        query_packages.len(),
        network_enabled,
    );

    let advisory_resolution = resolve_advisories(&args, &query_packages, network_enabled).await?;
    limitations.extend(advisory_resolution.limitations);

    let mut policy = load_policy(&args)?;
    if let Some(severity) = args.fail_on {
        policy.set_fail_on_severity(severity);
    }
    let policy_decision = policy.evaluate(&advisory_resolution.findings);

    let metadata = ScanMetadata {
        network_enabled,
        advisory_sources: advisory_resolution.advisory_sources,
        limitations,
        advisory_cache: advisory_resolution.cache_info,
        partial: advisory_resolution.partial,
    };

    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| classified(RunStatus::InternalError, error.to_string()))?;
    let report = ScanReport::new(
        args.path.display().to_string(),
        combined.primary_ecosystem,
        generated_at,
        combined.graph,
        advisory_resolution.findings,
        policy_decision,
        metadata,
    );

    let rendered = render_report(&report, effective_output_format(&args).into())
        .map_err(|error| classified(RunStatus::InternalError, error.to_string()))?;
    write_or_print(args.out.as_ref(), &rendered).with_context(|| {
        args.out
            .as_ref()
            .map(|path| format!("failed to write report to {}", path.display()))
            .unwrap_or_else(|| "failed to write report to stdout".to_owned())
    })?;

    if report.summary.policy.status == PolicyStatus::Fail {
        Ok(RunStatus::PolicyFailure)
    } else {
        Ok(RunStatus::Success)
    }
}

async fn resolve_advisories(
    args: &ScanArgs,
    query_packages: &[Package],
    network_enabled: bool,
) -> Result<AdvisoryResolution> {
    if query_packages.is_empty() {
        return Ok(AdvisoryResolution::empty());
    }

    let cache_path = advisory_cache_path(args.cache.as_ref())?;

    if network_enabled {
        resolve_online_advisories(query_packages, &cache_path, args.cache.as_ref()).await
    } else {
        resolve_offline_advisories(args, query_packages, &cache_path)
    }
}

async fn resolve_online_advisories(
    query_packages: &[Package],
    cache_path: &Path,
    explicit_cache_path: Option<&PathBuf>,
) -> Result<AdvisoryResolution> {
    let client = OsvClient::new()
        .map_err(|error| classified(RunStatus::NetworkAdvisoryError, error.to_string()))?;
    let raw_findings = client
        .query_batch_enriched(query_packages)
        .await
        .map_err(|error| classified(RunStatus::NetworkAdvisoryError, error.to_string()))?;
    let findings = deduplicate_findings(raw_findings);
    let generated_at = current_cache_timestamp()
        .map_err(|error| classified(RunStatus::InternalError, error.to_string()))?;
    let cache = AdvisoryCacheDocument::from_packages_and_findings(
        query_packages,
        findings.clone(),
        generated_at.clone(),
    );

    let mut limitations = Vec::new();
    let mut cache_info = AdvisoryCacheInfo {
        path: disclose_cache_path(explicit_cache_path),
        loaded: false,
        updated: true,
        generated_at: Some(generated_at),
        age_days: Some(0),
        package_records: cache.package_record_count(),
        stale: false,
        max_age_days: DEFAULT_CACHE_MAX_AGE_DAYS,
    };

    if let Err(error) = cache.save_path(cache_path) {
        cache_info.updated = false;
        limitations.push(format!(
            "OSV advisory cache could not be updated; online findings were still used for this scan: {error}."
        ));
    }

    Ok(AdvisoryResolution {
        findings,
        advisory_sources: vec![VulnerabilitySource::Osv],
        cache_info: Some(cache_info),
        limitations,
        partial: false,
    })
}

fn resolve_offline_advisories(
    args: &ScanArgs,
    query_packages: &[Package],
    cache_path: &Path,
) -> Result<AdvisoryResolution> {
    let mut limitations = vec![
        "offline/no-network mode: OSV was not contacted; advisory data came only from the local cache."
            .to_owned(),
    ];
    let now = OffsetDateTime::now_utc();

    match AdvisoryCacheDocument::load_path(cache_path) {
        Ok(cache) => {
            let lookup = cache.lookup_packages(query_packages);
            let age_days = cache.age_days_at(now);
            let stale = cache.is_stale_at(now, args.cache_max_age_days);
            if stale {
                limitations.push(format!(
                    "offline advisory cache is older than the configured freshness limit of {} day(s).",
                    args.cache_max_age_days
                ));
            }
            if !lookup.missing.is_empty() {
                limitations.push(format!(
                    "offline advisory cache is missing {} queried package record(s).",
                    lookup.missing.len()
                ));
            }

            if args.strict && (stale || !lookup.missing.is_empty()) {
                return Err(classified(
                    RunStatus::NetworkAdvisoryError,
                    "strict offline mode requires a fresh advisory cache with entries for every queried package",
                ));
            }

            Ok(AdvisoryResolution {
                findings: deduplicate_findings(lookup.findings),
                advisory_sources: vec![VulnerabilitySource::Osv],
                cache_info: Some(AdvisoryCacheInfo {
                    path: disclose_cache_path(args.cache.as_ref()),
                    loaded: true,
                    updated: false,
                    generated_at: Some(cache.generated_at.clone()),
                    age_days,
                    package_records: cache.package_record_count(),
                    stale,
                    max_age_days: args.cache_max_age_days,
                }),
                limitations,
                partial: stale || !lookup.missing.is_empty(),
            })
        }
        Err(error) => {
            limitations.push(format!(
                "offline advisory cache could not be loaded: {error}."
            ));
            if args.strict {
                return Err(classified(
                    RunStatus::NetworkAdvisoryError,
                    "strict offline mode requires a readable local advisory cache",
                ));
            }

            Ok(AdvisoryResolution {
                findings: Vec::new(),
                advisory_sources: Vec::new(),
                cache_info: Some(AdvisoryCacheInfo {
                    path: disclose_cache_path(args.cache.as_ref()),
                    loaded: false,
                    updated: false,
                    generated_at: None,
                    age_days: None,
                    package_records: 0,
                    stale: true,
                    max_age_days: args.cache_max_age_days,
                }),
                limitations,
                partial: true,
            })
        }
    }
}

async fn explain(args: &ExplainArgs) -> Result<RunStatus> {
    if args.vulnerability_id.trim().is_empty() {
        return Err(classified(
            RunStatus::UsageConfigError,
            "vulnerability ID must not be empty",
        ));
    }

    let client = OsvClient::new()
        .map_err(|error| classified(RunStatus::NetworkAdvisoryError, error.to_string()))?;
    let advisory = client
        .get_advisory(&args.vulnerability_id)
        .await
        .map_err(|error| {
            classified(
                RunStatus::NetworkAdvisoryError,
                format!("failed to query OSV for {}: {error}", args.vulnerability_id),
            )
        })?;

    println!("ForgeGuard Vulnerability Explanation\n");
    println!("ID: {}", advisory.id);
    if !advisory.aliases.is_empty() {
        println!("Aliases: {}", advisory.aliases.join(", "));
    }
    println!("Source: {}", advisory.source);
    println!(
        "Severity: {}",
        advisory
            .severity
            .map(|severity| severity.to_string())
            .unwrap_or_else(|| "unknown".to_owned())
    );
    println!("Summary: {}", advisory.summary);
    if let Some(details) = advisory.details {
        println!("\nDetails:\n{details}");
    }
    if !advisory.references.is_empty() {
        println!("\nReferences:");
        for reference in advisory.references {
            println!("  - [{}] {}", reference.kind, reference.url);
        }
    }

    Ok(RunStatus::Success)
}

fn sbom(args: &SbomArgs) -> Result<RunStatus> {
    let combined = inspect_all_supported_lockfiles(&args.path)?;

    let rendered = match args.format {
        SbomFormat::Cyclonedx => {
            render_cyclonedx_from_combined_scan(&combined, CycloneDxFormat::Json)
                .context("failed to render CycloneDX SBOM")?
        }
    };
    write_or_print(args.out.as_ref(), &rendered).with_context(|| {
        args.out
            .as_ref()
            .map(|path| format!("failed to write SBOM to {}", path.display()))
            .unwrap_or_else(|| "failed to write SBOM to stdout".to_owned())
    })?;
    Ok(RunStatus::Success)
}

async fn cache(args: CacheArgs) -> Result<RunStatus> {
    match args.command {
        CacheCommand::Update(args) => cache_update(&args).await,
        CacheCommand::Status(args) => cache_status(&args),
        CacheCommand::Path(args) => cache_path(&args),
    }
}

async fn cache_update(args: &CacheUpdateArgs) -> Result<RunStatus> {
    let combined = inspect_all_supported_lockfiles(&args.path)?;
    let query_packages = queryable_packages(&combined.graph);
    let cache_path = advisory_cache_path(args.cache.as_ref())?;
    let findings = if query_packages.is_empty() {
        Vec::new()
    } else {
        let client = OsvClient::new()
            .map_err(|error| classified(RunStatus::NetworkAdvisoryError, error.to_string()))?;
        let raw_findings = client
            .query_batch_enriched(&query_packages)
            .await
            .map_err(|error| classified(RunStatus::NetworkAdvisoryError, error.to_string()))?;
        deduplicate_findings(raw_findings)
    };
    let generated_at = current_cache_timestamp()
        .map_err(|error| classified(RunStatus::InternalError, error.to_string()))?;
    let cache =
        AdvisoryCacheDocument::from_packages_and_findings(&query_packages, findings, generated_at);
    cache
        .save_path(&cache_path)
        .map_err(|error| classified(RunStatus::NetworkAdvisoryError, error.to_string()))?;

    println!(
        "Updated OSV advisory cache: {} package record(s), {} finding(s).",
        cache.package_record_count(),
        cache.finding_count()
    );
    Ok(RunStatus::Success)
}

fn cache_status(args: &CacheStatusArgs) -> Result<RunStatus> {
    let cache_path = advisory_cache_path(args.cache.as_ref())?;
    let now = OffsetDateTime::now_utc();
    let status = match AdvisoryCacheDocument::load_path(&cache_path) {
        Ok(cache) => CacheStatusReport {
            path: cache_path.display().to_string(),
            exists: true,
            readable: true,
            schema_version: Some(cache.schema_version.clone()),
            generated_at: Some(cache.generated_at.clone()),
            age_days: cache.age_days_at(now),
            stale: cache.is_stale_at(now, args.cache_max_age_days),
            max_age_days: args.cache_max_age_days,
            package_records: cache.package_record_count(),
            findings: cache.finding_count(),
            error: None,
        },
        Err(error) if advisory_cache_not_found(&error) => CacheStatusReport {
            path: cache_path.display().to_string(),
            exists: false,
            readable: false,
            schema_version: None,
            generated_at: None,
            age_days: None,
            stale: true,
            max_age_days: args.cache_max_age_days,
            package_records: 0,
            findings: 0,
            error: Some(error.to_string()),
        },
        Err(error) => {
            return Err(classified(
                RunStatus::NetworkAdvisoryError,
                format!("failed to read advisory cache status: {error}"),
            ));
        }
    };

    match args.format {
        CacheStatusFormat::Table => println!("{}", status.render_table()),
        CacheStatusFormat::Json => {
            let rendered = serde_json::to_string_pretty(&status)
                .map_err(|error| classified(RunStatus::InternalError, error.to_string()))?;
            println!("{rendered}");
        }
    }

    Ok(RunStatus::Success)
}

fn cache_path(args: &CachePathArgs) -> Result<RunStatus> {
    println!("{}", advisory_cache_path(args.cache.as_ref())?.display());
    Ok(RunStatus::Success)
}

fn policy(args: PolicyArgs) -> Result<RunStatus> {
    match args.command {
        PolicyCommand::Check(args) => policy_check(&args),
    }
}

fn policy_check(args: &PolicyCheckArgs) -> Result<RunStatus> {
    let contents = fs::read_to_string(&args.report).map_err(|error| {
        classified(
            RunStatus::ScanRuntimeError,
            format!("failed to read report {}: {error}", args.report.display()),
        )
    })?;
    let report: ScanReport = serde_json::from_str(&contents).map_err(|error| {
        classified(
            RunStatus::UsageConfigError,
            format!(
                "failed to parse ForgeGuard JSON report {}: {error}",
                args.report.display()
            ),
        )
    })?;
    let mut policy = load_policy_for_target(args.policy.as_ref(), Path::new(&report.target))?;
    if let Some(severity) = args.fail_on {
        policy.set_fail_on_severity(severity);
    }
    let decision = policy.evaluate(&report.findings);

    if args.json {
        let rendered = serde_json::to_string_pretty(&decision)
            .map_err(|error| classified(RunStatus::InternalError, error.to_string()))?;
        println!("{rendered}");
    } else {
        println!("Policy: {}", decision.status);
        for reason in &decision.reasons {
            println!("- {reason}");
        }
    }

    if decision.status == PolicyStatus::Fail {
        Ok(RunStatus::PolicyFailure)
    } else {
        Ok(RunStatus::Success)
    }
}

fn inspect_all_supported_lockfiles(path: &Path) -> Result<CombinedScan> {
    let registry = scanner_registry();
    let outputs = registry
        .scan_all(&ScannerInput::new(path.to_path_buf()))
        .map_err(|error| {
            classified(
                RunStatus::ScanRuntimeError,
                format!(
                    "failed to inspect dependency target {}: {error}",
                    path.display()
                ),
            )
        })?;
    CombinedScan::new(path.to_path_buf(), outputs)
}

fn render_cyclonedx_from_combined_scan(
    scan: &CombinedScan,
    format: CycloneDxFormat,
) -> Result<String> {
    // Compatibility bridge for the current SBOM implementation. The renderer already emits
    // ecosystem-aware package properties, so a combined graph is safe here.
    let synthetic_scan = forgeguard_cargo::CargoScan {
        target: scan.target.clone(),
        lockfile_path: scan
            .outputs
            .first()
            .and_then(|output| output.lockfile_path.clone())
            .unwrap_or_else(|| scan.target.clone()),
        manifest_path: None,
        graph: scan.graph.clone(),
    };
    render_cyclonedx(&synthetic_scan, format)
}

fn scanner_registry() -> ScannerRegistry {
    ScannerRegistry::new()
        .with_scanner(CargoScanner::new())
        .with_scanner(NpmScanner::new())
}

fn merge_dependency_graphs(outputs: &[ScannerOutput]) -> DependencyGraph {
    let packages = outputs
        .iter()
        .flat_map(|output| output.graph.packages.iter().cloned())
        .collect::<Vec<_>>();
    let edges = outputs
        .iter()
        .flat_map(|output| output.graph.edges.iter().cloned())
        .collect::<Vec<_>>();
    DependencyGraph::new(packages, edges)
}

fn queryable_packages(graph: &DependencyGraph) -> Vec<Package> {
    graph
        .packages
        .iter()
        .filter(|package| match package.id.ecosystem {
            Ecosystem::Cargo => is_crates_io_package(package),
            Ecosystem::Npm => is_npm_registry_package(package),
            Ecosystem::Pypi | Ecosystem::Go | Ecosystem::Maven => false,
        })
        .cloned()
        .collect()
}

fn append_query_limitations(
    limitations: &mut Vec<String>,
    scan: &CombinedScan,
    query_package_count: usize,
    network_enabled: bool,
) {
    if !network_enabled {
        return;
    }

    let excluded = scan
        .graph
        .packages
        .len()
        .saturating_sub(query_package_count);
    if excluded > 0 {
        push_unique(
            limitations,
            format!(
                "{excluded} local/path or non-public-registry package(s) were excluded from OSV queries."
            ),
        );
    }

    if scan.ecosystem_count() > 1 {
        push_unique(
            limitations,
            "Policy evaluation was performed over the combined multi-ecosystem finding set."
                .to_owned(),
        );
    }
}

fn load_policy(args: &ScanArgs) -> Result<PolicyConfig> {
    load_policy_for_target(args.policy.as_ref(), &args.path)
}

fn load_policy_for_target(policy_path: Option<&PathBuf>, target: &Path) -> Result<PolicyConfig> {
    let policy_path = policy_path.cloned().or_else(|| default_policy_path(target));

    if let Some(path) = policy_path {
        PolicyConfig::from_path(&path).map_err(|error| {
            classified(
                RunStatus::UsageConfigError,
                format!("failed to load policy file {}: {error}", path.display()),
            )
        })
    } else {
        Ok(PolicyConfig::default())
    }
}

fn default_policy_path(target: &Path) -> Option<PathBuf> {
    let start = if target.is_dir() {
        target.to_path_buf()
    } else {
        target.parent()?.to_path_buf()
    };
    find_policy_upwards(&start, MAX_POLICY_PARENT_SEARCH_DEPTH)
}

fn find_policy_upwards(start: &Path, max_depth: usize) -> Option<PathBuf> {
    let mut current = Some(start);
    for _ in 0..=max_depth {
        let directory = current?;
        let candidate = directory.join("forgeguard.yml");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = directory.parent();
    }
    None
}

fn write_or_print(path: Option<&PathBuf>, contents: &str) -> Result<()> {
    if let Some(path) = path {
        validate_output_path(path)?;
        fs::write(path, contents).map_err(|error| {
            classified(
                RunStatus::ScanRuntimeError,
                format!("failed to write {}: {error}", path.display()),
            )
        })
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(contents.as_bytes()).map_err(|error| {
            classified(
                RunStatus::ScanRuntimeError,
                format!("failed to write stdout: {error}"),
            )
        })?;
        stdout.write_all(b"\n").map_err(|error| {
            classified(
                RunStatus::ScanRuntimeError,
                format!("failed to write stdout: {error}"),
            )
        })
    }
}

fn validate_output_path(path: &Path) -> Result<()> {
    if path.exists() && path.is_dir() {
        return Err(classified(
            RunStatus::UsageConfigError,
            format!("output path {} is a directory", path.display()),
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(classified(
                RunStatus::UsageConfigError,
                format!("output directory {} does not exist", parent.display()),
            ));
        }
    }
    Ok(())
}

fn lockfile_summary(outputs: &[ScannerOutput]) -> String {
    outputs
        .iter()
        .map(|output| {
            let lockfile = output
                .lockfile_path
                .as_ref()
                .unwrap_or(&output.target)
                .display()
                .to_string();
            format!("{} at {lockfile}", output.ecosystem)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn validate_scan_args(args: &ScanArgs) -> Result<()> {
    if args.online && (args.offline || args.no_network) {
        return Err(classified(
            RunStatus::UsageConfigError,
            "--online cannot be combined with --offline or --no-network",
        ));
    }
    if args.cache_max_age_days == 0 {
        return Err(classified(
            RunStatus::UsageConfigError,
            "--cache-max-age-days must be greater than zero",
        ));
    }
    Ok(())
}

fn effective_output_format(args: &ScanArgs) -> OutputFormat {
    if args.machine && args.format == OutputFormat::Table {
        OutputFormat::Json
    } else {
        args.format
    }
}

fn advisory_cache_path(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path.clone());
    }

    if let Some(cache_dir) = env::var_os(FORGEGUARD_CACHE_DIR_ENV) {
        return Ok(PathBuf::from(cache_dir).join(CACHE_FILE_NAME));
    }

    if cfg!(windows) {
        if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_app_data)
                .join("ForgeGuard")
                .join(CACHE_FILE_NAME));
        }
    } else if let Some(xdg_cache_home) = env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg_cache_home)
            .join("forgeguard")
            .join(CACHE_FILE_NAME));
    } else if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join(".cache")
            .join("forgeguard")
            .join(CACHE_FILE_NAME));
    }

    Err(classified(
        RunStatus::UsageConfigError,
        format!(
            "could not determine advisory cache path; set {FORGEGUARD_CACHE_DIR_ENV} or pass --cache"
        ),
    ))
}

fn disclose_cache_path(explicit: Option<&PathBuf>) -> Option<String> {
    explicit.map(|path| path.display().to_string())
}

fn advisory_cache_not_found(error: &AdvisoryCacheError) -> bool {
    matches!(
        error,
        AdvisoryCacheError::Metadata { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound
    )
}

fn classified(status: RunStatus, message: impl Into<String>) -> anyhow::Error {
    ClassifiedCliError::new(status, message).into()
}

fn parse_risk_level(value: &str) -> std::result::Result<RiskLevel, String> {
    RiskLevel::from_str(value).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeguard_core::{DependencyKind, PackageId};
    use semver::Version;

    fn package(ecosystem: Ecosystem, name: &str) -> Package {
        Package::new(
            PackageId::new(
                ecosystem,
                name,
                Version::parse("1.0.0").expect("valid version"),
            ),
            Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
            None,
            DependencyKind::Direct,
        )
    }

    #[test]
    fn registry_contains_scanners() {
        let registry = scanner_registry();
        assert!(!registry.is_empty());
    }

    #[test]
    fn merge_dependency_graphs_preserves_multiple_ecosystems() {
        let cargo = ScannerOutput {
            ecosystem: Ecosystem::Cargo,
            target: PathBuf::from("src-tauri"),
            manifest_path: None,
            lockfile_path: Some(PathBuf::from("src-tauri/Cargo.lock")),
            graph: DependencyGraph::new(vec![package(Ecosystem::Cargo, "tauri")], Vec::new()),
            limitations: Vec::new(),
        };
        let npm = ScannerOutput {
            ecosystem: Ecosystem::Npm,
            target: PathBuf::from("."),
            manifest_path: None,
            lockfile_path: Some(PathBuf::from("package-lock.json")),
            graph: DependencyGraph::new(vec![package(Ecosystem::Npm, "vite")], Vec::new()),
            limitations: Vec::new(),
        };

        let combined = CombinedScan::new(PathBuf::from("."), vec![cargo, npm]).expect("combined");

        assert_eq!(combined.graph.package_count(), 2);
        assert_eq!(combined.ecosystem_count(), 2);
    }

    #[test]
    fn classified_errors_map_to_documented_status() {
        let error = classified(RunStatus::NetworkAdvisoryError, "network down");

        assert_eq!(status_for_error(&error), RunStatus::NetworkAdvisoryError);
        assert_eq!(status_for_error(&error).exit_code(), ExitCode::from(4));
    }

    #[test]
    fn explicit_cache_path_is_used_as_is() {
        let path = PathBuf::from("target/test-cache/osv-cache.json");

        assert_eq!(advisory_cache_path(Some(&path)).expect("path"), path);
    }
}
