#![forbid(unsafe_code)]

//! OSV.dev client and response mapping.
//!
//! The client only sends package ecosystem, package name, and package version
//! to OSV.dev. Offline and no-network modes are enforced by callers by not
//! constructing or calling this client.

use forgeguard_core::{
    calculate_risk, Advisory, Finding, FixRecommendation, Package, Reference, RiskFactors,
    RiskLevel, Vulnerability, VulnerabilitySource,
};
use reqwest::{StatusCode, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::time::sleep;
use tracing::{debug, warn};

const DEFAULT_OSV_BASE_URL: &str = "https://api.osv.dev";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_MAX_RETRIES: usize = 2;
const MAX_BATCH_SIZE: usize = 500;
const MAX_RESPONSE_BODY_SNIPPET: usize = 512;
const MAX_CACHE_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Current stable OSV advisory cache schema version.
pub const ADVISORY_CACHE_SCHEMA_VERSION: &str = "forgeguard.osv-cache/v1";

/// Errors returned by the OSV client.
#[derive(Debug, Error)]
pub enum OsvError {
    /// Base URL was invalid.
    #[error("invalid OSV base URL '{url}': {source}")]
    InvalidBaseUrl {
        /// Configured URL.
        url: String,
        /// URL parser error.
        #[source]
        source: url::ParseError,
    },
    /// HTTP client construction failed.
    #[error("failed to build OSV HTTP client: {0}")]
    ClientBuild(#[source] reqwest::Error),
    /// Network request failed.
    #[error("OSV request failed: {0}")]
    Request(#[source] reqwest::Error),
    /// OSV returned an unsuccessful status.
    #[error("OSV returned HTTP {status}: {body}")]
    Http {
        /// HTTP status code.
        status: StatusCode,
        /// Response body snippet.
        body: String,
    },
    /// Response JSON could not be decoded.
    #[error("failed to decode OSV response from {path}: {source}; response body: {body}")]
    Decode {
        /// API path.
        path: String,
        /// Decoder error.
        #[source]
        source: serde_json::Error,
        /// Response body snippet.
        body: String,
    },
    /// Querybatch response length did not match request length.
    #[error("OSV batch response length mismatch: expected {expected} result(s), got {actual}")]
    BatchResponseLengthMismatch {
        /// Number of submitted queries.
        expected: usize,
        /// Number of returned result entries.
        actual: usize,
    },
}

/// Result type for OSV operations.
pub type Result<T> = std::result::Result<T, OsvError>;

/// Conservative OSV client configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsvClientConfig {
    /// OSV API base URL.
    pub base_url: String,
    /// HTTP timeout per request.
    pub timeout: Duration,
    /// User agent sent with requests.
    pub user_agent: String,
    /// Maximum retry attempts after the initial request.
    pub max_retries: usize,
    /// Delay before the first retry.
    pub retry_delay: Duration,
}

impl Default for OsvClientConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_OSV_BASE_URL.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            user_agent: format!("forgeguard/{}", env!("CARGO_PKG_VERSION")),
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay: DEFAULT_RETRY_DELAY,
        }
    }
}

/// Errors produced by local advisory cache loading and writing.
#[derive(Debug, Error)]
pub enum AdvisoryCacheError {
    /// Filesystem metadata lookup failed.
    #[error("failed to inspect advisory cache {path}: {source}")]
    Metadata {
        /// Cache path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Cache file was too large.
    #[error("advisory cache {path} is too large: {size} bytes exceeds {limit} bytes")]
    TooLarge {
        /// Cache path.
        path: PathBuf,
        /// Observed size.
        size: u64,
        /// Maximum accepted size.
        limit: u64,
    },
    /// Cache file read or write failed.
    #[error("advisory cache I/O failed for {path}: {source}")]
    Io {
        /// Cache path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// Cache JSON parsing or serialization failed.
    #[error("failed to decode advisory cache {path}: {source}")]
    Json {
        /// Cache path.
        path: PathBuf,
        /// JSON error.
        #[source]
        source: serde_json::Error,
    },
    /// Cache schema version was not supported.
    #[error("unsupported advisory cache schema version '{version}' in {path}")]
    UnsupportedSchemaVersion {
        /// Cache path.
        path: PathBuf,
        /// Observed schema version.
        version: String,
    },
    /// Cache timestamp formatting failed.
    #[error("failed to format advisory cache timestamp: {0}")]
    TimestampFormat(#[from] time::error::Format),
}

/// Stable package key used by the local advisory cache.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CachedPackageKey {
    /// Package ecosystem.
    pub ecosystem: forgeguard_core::Ecosystem,
    /// Package name.
    pub name: String,
    /// Resolved package version.
    pub version: Version,
}

impl CachedPackageKey {
    /// Build a cache key from a normalized package.
    #[must_use]
    pub fn from_package(package: &Package) -> Self {
        Self {
            ecosystem: package.id.ecosystem.clone(),
            name: package.id.name.clone(),
            version: package.id.version.clone(),
        }
    }
}

/// Findings cached for one package version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedPackageFindings {
    /// Package identity.
    pub package: CachedPackageKey,
    /// Findings returned by the advisory source for this package.
    pub findings: Vec<Finding>,
}

/// Local OSV advisory cache document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisoryCacheDocument {
    /// Stable cache schema version.
    pub schema_version: String,
    /// Cache generation timestamp as RFC 3339.
    pub generated_at: String,
    /// Advisory source label.
    pub source: String,
    /// Package findings in deterministic order.
    pub packages: Vec<CachedPackageFindings>,
}

/// Result of resolving packages from a local advisory cache.
#[derive(Clone, Debug)]
pub struct AdvisoryCacheLookup {
    /// Findings available from the cache.
    pub findings: Vec<Finding>,
    /// Packages not present in the cache.
    pub missing: Vec<CachedPackageKey>,
}

impl AdvisoryCacheDocument {
    /// Create an empty OSV cache with the provided timestamp.
    #[must_use]
    pub fn new(generated_at: impl Into<String>) -> Self {
        Self {
            schema_version: ADVISORY_CACHE_SCHEMA_VERSION.to_owned(),
            generated_at: generated_at.into(),
            source: "OSV.dev".to_owned(),
            packages: Vec::new(),
        }
    }

    /// Build a deterministic package cache from query packages and findings.
    #[must_use]
    pub fn from_packages_and_findings(
        packages: &[Package],
        findings: Vec<Finding>,
        generated_at: impl Into<String>,
    ) -> Self {
        let mut by_package = BTreeMap::<CachedPackageKey, Vec<Finding>>::new();

        for package in packages {
            by_package
                .entry(CachedPackageKey::from_package(package))
                .or_default();
        }

        for finding in findings {
            by_package
                .entry(CachedPackageKey {
                    ecosystem: finding.package.id.ecosystem.clone(),
                    name: finding.package.id.name.clone(),
                    version: finding.package.id.version.clone(),
                })
                .or_default()
                .push(finding);
        }

        let mut document = Self::new(generated_at);
        document.packages = by_package
            .into_iter()
            .map(|(package, mut findings)| {
                findings.sort_by(|left, right| {
                    left.id()
                        .cmp(right.id())
                        .then_with(|| left.package.id.cmp(&right.package.id))
                });
                CachedPackageFindings { package, findings }
            })
            .collect();
        document
    }

    /// Load and validate a cache file.
    pub fn load_path(path: impl AsRef<Path>) -> std::result::Result<Self, AdvisoryCacheError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|source| AdvisoryCacheError::Metadata {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.len() > MAX_CACHE_FILE_BYTES {
            return Err(AdvisoryCacheError::TooLarge {
                path: path.to_path_buf(),
                size: metadata.len(),
                limit: MAX_CACHE_FILE_BYTES,
            });
        }

        let bytes = fs::read(path).map_err(|source| AdvisoryCacheError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let cache: Self =
            serde_json::from_slice(&bytes).map_err(|source| AdvisoryCacheError::Json {
                path: path.to_path_buf(),
                source,
            })?;
        cache.validate(path)?;
        Ok(cache)
    }

    /// Write the cache file. Parent directories are created when necessary.
    pub fn save_path(&self, path: impl AsRef<Path>) -> std::result::Result<(), AdvisoryCacheError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| AdvisoryCacheError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }

        let bytes = serde_json::to_vec_pretty(self).map_err(|source| AdvisoryCacheError::Json {
            path: path.to_path_buf(),
            source,
        })?;
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, bytes).map_err(|source| AdvisoryCacheError::Io {
            path: temp_path.clone(),
            source,
        })?;
        if path.exists() {
            fs::remove_file(path).map_err(|source| AdvisoryCacheError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        }
        fs::rename(&temp_path, path).map_err(|source| AdvisoryCacheError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Return findings for the requested packages and report missing cache entries.
    #[must_use]
    pub fn lookup_packages(&self, packages: &[Package]) -> AdvisoryCacheLookup {
        let index = self
            .packages
            .iter()
            .map(|entry| (&entry.package, &entry.findings))
            .collect::<BTreeMap<_, _>>();
        let mut findings = Vec::new();
        let mut missing = Vec::new();

        for package in packages {
            let key = CachedPackageKey::from_package(package);
            if let Some(cached_findings) = index.get(&key) {
                findings.extend(cached_findings.iter().cloned());
            } else {
                missing.push(key);
            }
        }

        findings.sort_by(|left, right| {
            left.package
                .id
                .cmp(&right.package.id)
                .then_with(|| left.id().cmp(right.id()))
        });
        missing.sort();
        missing.dedup();
        AdvisoryCacheLookup { findings, missing }
    }

    /// Number of package records in the cache.
    #[must_use]
    pub fn package_record_count(&self) -> usize {
        self.packages.len()
    }

    /// Number of findings stored in the cache.
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.packages
            .iter()
            .map(|package| package.findings.len())
            .sum()
    }

    /// Whole cache age in days at a given time.
    #[must_use]
    pub fn age_days_at(&self, now: OffsetDateTime) -> Option<i64> {
        let generated_at = OffsetDateTime::parse(&self.generated_at, &Rfc3339).ok()?;
        Some((now - generated_at).whole_days().max(0))
    }

    /// Return true when the cache is older than the configured freshness threshold.
    #[must_use]
    pub fn is_stale_at(&self, now: OffsetDateTime, max_age_days: u64) -> bool {
        self.age_days_at(now)
            .is_some_and(|age_days| age_days > max_age_days as i64)
    }

    fn validate(&self, path: &Path) -> std::result::Result<(), AdvisoryCacheError> {
        if self.schema_version != ADVISORY_CACHE_SCHEMA_VERSION {
            return Err(AdvisoryCacheError::UnsupportedSchemaVersion {
                path: path.to_path_buf(),
                version: self.schema_version.clone(),
            });
        }
        Ok(())
    }
}

/// Return the current UTC timestamp formatted for cache metadata.
pub fn current_cache_timestamp() -> std::result::Result<String, AdvisoryCacheError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

/// Async OSV.dev API client.
#[derive(Clone)]
pub struct OsvClient {
    http: reqwest::Client,
    base_url: Url,
    config: OsvClientConfig,
}

impl OsvClient {
    /// Build a client with default settings.
    pub fn new() -> Result<Self> {
        Self::with_config(OsvClientConfig::default())
    }

    /// Build a client with explicit settings.
    pub fn with_config(mut config: OsvClientConfig) -> Result<Self> {
        if !config.base_url.ends_with('/') {
            config.base_url.push('/');
        }

        let base_url = Url::parse(&config.base_url).map_err(|source| OsvError::InvalidBaseUrl {
            url: config.base_url.clone(),
            source,
        })?;

        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent(config.user_agent.clone())
            .use_rustls_tls()
            .build()
            .map_err(OsvError::ClientBuild)?;

        Ok(Self {
            http,
            base_url,
            config,
        })
    }

    /// Query OSV for a single package.
    pub async fn query_package(&self, package: &Package) -> Result<Vec<Finding>> {
        let query = OsvQuery::from_package(package);
        let response: OsvQueryResponse = self.post_json("v1/query", &query).await?;
        Ok(response.into_findings(package))
    }

    /// Query OSV for multiple packages using the batch API.
    ///
    /// This method maps the querybatch response as-is. For scan pipelines,
    /// prefer [`Self::query_batch_enriched`] so sparse querybatch advisories are
    /// completed via `v1/vulns/{id}` before report generation and deduplication.
    pub async fn query_batch(&self, packages: &[Package]) -> Result<Vec<Finding>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        let mut findings = Vec::new();

        for chunk in packages.chunks(MAX_BATCH_SIZE) {
            let queries = chunk.iter().map(OsvQuery::from_package).collect::<Vec<_>>();
            let response: OsvBatchResponse = self
                .post_json("v1/querybatch", &OsvBatchQuery { queries })
                .await?;

            if response.results.len() != chunk.len() {
                return Err(OsvError::BatchResponseLengthMismatch {
                    expected: chunk.len(),
                    actual: response.results.len(),
                });
            }

            for (package, result) in chunk.iter().zip(response.results) {
                findings.extend(result.into_findings(package));
            }
        }

        Ok(findings)
    }

    /// Query OSV and enrich sparse batch results with full advisory details.
    ///
    /// OSV querybatch responses can be less complete than `v1/vulns/{id}`. This
    /// method keeps the efficient batch lookup, then fetches full advisory
    /// records only for findings missing aliases, severity/CVSS, references, or
    /// fixed versions. This is the recommended online scan path.
    pub async fn query_batch_enriched(&self, packages: &[Package]) -> Result<Vec<Finding>> {
        let mut findings = self.query_batch(packages).await?;

        for finding in &mut findings {
            if !finding_needs_enrichment(finding) {
                continue;
            }

            let advisory_id = finding.id().to_owned();
            match self.get_vulnerability(&advisory_id).await {
                Ok(vulnerability) => merge_osv_vulnerability_into_finding(finding, vulnerability),
                Err(error) => {
                    warn!(
                        advisory_id,
                        error = %error,
                        "failed to enrich OSV advisory; using batch metadata"
                    );
                }
            }
        }

        Ok(findings)
    }

    /// Fetch advisory details by vulnerability ID.
    pub async fn get_advisory(&self, id: &str) -> Result<Advisory> {
        Ok(self.get_vulnerability(id).await?.into_advisory())
    }

    /// Fetch the full OSV vulnerability object by ID.
    async fn get_vulnerability(&self, id: &str) -> Result<OsvVulnerability> {
        let path = format!("v1/vulns/{}", urlencoding::encode(id.trim()));
        self.get_json(&path).await
    }

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = self.endpoint(path)?;
        let response = self
            .send_with_retries(|| self.http.get(url.clone()))
            .await?;
        decode_response(path, response).await
    }

    async fn post_json<B, T>(&self, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: for<'de> Deserialize<'de>,
    {
        let url = self.endpoint(path)?;
        let response = self
            .send_with_retries(|| self.http.post(url.clone()).json(body))
            .await?;
        decode_response(path, response).await
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|source| OsvError::InvalidBaseUrl {
                url: self.base_url.to_string(),
                source,
            })
    }

    async fn send_with_retries<F>(&self, mut build_request: F) -> Result<reqwest::Response>
    where
        F: FnMut() -> reqwest::RequestBuilder,
    {
        let mut attempt = 0usize;

        loop {
            let response = build_request().send().await;

            match response {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response)
                    if should_retry_status(response.status())
                        && attempt < self.config.max_retries =>
                {
                    let status = response.status();
                    warn!(%status, attempt, "transient OSV HTTP status; retrying");
                }
                Ok(response) => {
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<response body unavailable>".to_owned());
                    return Err(OsvError::Http {
                        status,
                        body: truncate_body(&body),
                    });
                }
                Err(error) if should_retry_error(&error) && attempt < self.config.max_retries => {
                    warn!(attempt, error = %error, "transient OSV request error; retrying");
                }
                Err(error) => return Err(OsvError::Request(error)),
            }

            attempt += 1;
            sleep(self.config.retry_delay.saturating_mul(attempt as u32)).await;
        }
    }
}

async fn decode_response<T>(path: &str, response: reqwest::Response) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let body = response.text().await.map_err(OsvError::Request)?;
    serde_json::from_str::<T>(&body).map_err(|source| OsvError::Decode {
        path: path.to_owned(),
        source,
        body: truncate_body(&body),
    })
}

fn should_retry_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn should_retry_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

fn truncate_body(body: &str) -> String {
    let mut snippet = body
        .chars()
        .take(MAX_RESPONSE_BODY_SNIPPET)
        .collect::<String>();
    if body.chars().count() > MAX_RESPONSE_BODY_SNIPPET {
        snippet.push_str("...");
    }
    snippet
}

#[derive(Clone, Debug, Serialize)]
struct OsvBatchQuery {
    queries: Vec<OsvQuery>,
}

#[derive(Clone, Debug, Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

impl OsvQuery {
    fn from_package(package: &Package) -> Self {
        Self {
            package: OsvPackage {
                name: package.id.name.clone(),
                ecosystem: package.id.ecosystem.osv_name().to_owned(),
            },
            version: package.id.version.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvQueryResponse>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

impl OsvQueryResponse {
    fn into_findings(self, package: &Package) -> Vec<Finding> {
        self.vulns
            .into_iter()
            .map(|vulnerability| vulnerability.into_finding(package))
            .collect()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvVulnerability {
    #[serde(default)]
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    summary: Option<String>,
    details: Option<String>,
    modified: Option<String>,
    published: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Value,
}

impl OsvVulnerability {
    fn into_finding(self, package: &Package) -> Finding {
        let known_exploited = self.known_exploited();
        let fixed_versions = self.fixed_versions_for(package);
        let advisory = self.into_advisory();
        build_finding_from_parts(package, advisory, fixed_versions, known_exploited)
    }

    fn into_advisory(self) -> Advisory {
        let severity = self.source_severity();
        let cvss_score = self.cvss_score();

        let mut advisory = Advisory {
            id: empty_to_unknown(self.id),
            aliases: unique_non_empty(self.aliases),
            summary: self
                .summary
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "No summary provided".to_owned()),
            details: self.details.filter(|value| !value.trim().is_empty()),
            severity,
            cvss_score,
            published: self.published,
            modified: self.modified,
            references: self
                .references
                .into_iter()
                .filter_map(OsvReference::into_reference)
                .collect(),
            source: VulnerabilitySource::Osv,
        };
        advisory.normalize_identifiers();
        advisory
    }

    fn fixed_versions_for(&self, package: &Package) -> Vec<Version> {
        let mut versions = Vec::new();

        for affected in &self.affected {
            if !affected.matches_package(package) {
                continue;
            }

            for range in &affected.ranges {
                for event in &range.events {
                    if let Some(fixed) = event.fixed.as_deref() {
                        match Version::parse(fixed.trim()) {
                            Ok(version) => versions.push(version),
                            Err(error) => {
                                debug!(
                                    fixed,
                                    error = %error,
                                    "ignored malformed OSV fixed version"
                                );
                            }
                        }
                    }
                }
            }
        }

        versions.sort();
        versions.dedup();
        versions
    }

    fn known_exploited(&self) -> bool {
        find_boolish(
            &self.database_specific,
            &["known_exploited", "kev", "cisa_kev"],
        )
        .unwrap_or(false)
    }

    fn source_severity(&self) -> Option<RiskLevel> {
        self.database_specific_severity()
            .or_else(|| self.severity.iter().find_map(OsvSeverity::risk_level))
            .or_else(|| self.cvss_score().and_then(RiskLevel::from_cvss))
            .or_else(|| self.cvss_vector_present().then_some(RiskLevel::Low))
    }

    fn database_specific_severity(&self) -> Option<RiskLevel> {
        find_stringish(&self.database_specific, &["severity"])
            .and_then(|value| parse_risk_level_or_cvss(&value))
            .or_else(|| {
                find_number(&self.database_specific, &["cvss_score", "cvss"])
                    .and_then(|score| RiskLevel::from_cvss(score as f32))
            })
            .or_else(|| {
                self.database_specific
                    .get("cvss")
                    .and_then(|cvss| find_number(cvss, &["score", "base_score"]))
                    .and_then(|score| RiskLevel::from_cvss(score as f32))
            })
    }

    fn cvss_score(&self) -> Option<f32> {
        find_number(&self.database_specific, &["cvss_score"])
            .map(|score| score as f32)
            .or_else(|| {
                self.database_specific
                    .get("cvss")
                    .and_then(|cvss| find_number(cvss, &["score", "base_score"]))
                    .map(|score| score as f32)
            })
            .or_else(|| self.severity.iter().find_map(OsvSeverity::numeric_score))
            .filter(|score| RiskLevel::from_cvss(*score).is_some())
    }

    fn cvss_vector_present(&self) -> bool {
        self.severity.iter().any(OsvSeverity::is_cvss_vector)
            || find_stringish(&self.database_specific, &["cvss_vector", "cvss"])
                .is_some_and(|value| value.trim_start().starts_with("CVSS:"))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvAffected {
    package: Option<OsvAffectedPackage>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

impl OsvAffected {
    fn matches_package(&self, package: &Package) -> bool {
        let Some(affected_package) = self.package.as_ref() else {
            return true;
        };

        if let Some(name) = affected_package.name.as_deref() {
            if name != package.id.name {
                return false;
            }
        }

        if let Some(ecosystem) = affected_package.ecosystem.as_deref() {
            if forgeguard_core::Ecosystem::from_osv_name(ecosystem)
                .is_some_and(|ecosystem| ecosystem != package.id.ecosystem)
            {
                return false;
            }
        }

        if let Some(purl) = affected_package.purl.as_deref() {
            if !purl.trim().is_empty() && purl != package.purl {
                return false;
            }
        }

        true
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvAffectedPackage {
    name: Option<String>,
    ecosystem: Option<String>,
    purl: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvEvent {
    fixed: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    kind: Option<String>,
    url: Option<String>,
}

impl OsvReference {
    fn into_reference(self) -> Option<Reference> {
        let url = self.url?.trim().to_owned();
        if url.is_empty() {
            return None;
        }

        Some(Reference {
            kind: self.kind.unwrap_or_else(|| "WEB".to_owned()),
            url,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    score: String,
}

impl OsvSeverity {
    fn risk_level(&self) -> Option<RiskLevel> {
        parse_risk_level_or_cvss(&self.score)
    }

    fn numeric_score(&self) -> Option<f32> {
        self.score
            .trim()
            .parse::<f32>()
            .ok()
            .filter(|score| RiskLevel::from_cvss(*score).is_some())
    }

    fn is_cvss_vector(&self) -> bool {
        self.score.trim_start().starts_with("CVSS:")
            || self
                .kind
                .as_deref()
                .is_some_and(|kind| kind.to_ascii_uppercase().starts_with("CVSS"))
    }
}

fn build_finding_from_parts(
    package: &Package,
    advisory: Advisory,
    fixed_versions: Vec<Version>,
    known_exploited: bool,
) -> Finding {
    let vulnerability = Vulnerability {
        advisory: advisory.clone(),
        affected: package.id.clone(),
        fixed_versions: fixed_versions.clone(),
    };
    let fix = FixRecommendation::from_fixed_versions(&package.id.name, fixed_versions);

    let cvss_score = advisory.cvss_score.and_then(cvss_to_risk_input);
    let mut risk = calculate_risk(RiskFactors {
        advisory_severity: advisory.severity,
        cvss_score,
        dependency_kind: package.dependency_kind,
        fix_available: fix.available,
        known_exploited,
        ecosystem: package.id.ecosystem.clone(),
    });

    if advisory.cvss_score.is_none() && advisory.severity.is_none() {
        risk.reasons
            .push("OSV did not provide numeric severity metadata for this advisory.".to_owned());
    }

    Finding {
        vulnerability,
        package: package.clone(),
        risk,
        fix,
        known_exploited,
    }
}

fn finding_needs_enrichment(finding: &Finding) -> bool {
    finding.vulnerability.advisory.aliases.is_empty()
        || finding.vulnerability.advisory.severity.is_none()
        || finding.vulnerability.advisory.cvss_score.is_none()
        || finding.vulnerability.advisory.references.is_empty()
        || finding.vulnerability.fixed_versions.is_empty()
}

fn merge_osv_vulnerability_into_finding(finding: &mut Finding, vulnerability: OsvVulnerability) {
    let known_exploited = finding.known_exploited || vulnerability.known_exploited();
    let fixed_versions = merge_versions(
        finding.vulnerability.fixed_versions.clone(),
        vulnerability.fixed_versions_for(&finding.package),
    );

    let mut incoming_advisory = vulnerability.into_advisory();
    incoming_advisory.normalize_identifiers();

    let mut identifiers = finding.vulnerability.advisory.identifiers();
    identifiers.extend(incoming_advisory.identifiers());

    let canonical = preferred_identifier(identifiers.clone());
    finding.vulnerability.advisory.id = canonical.clone();
    finding.vulnerability.advisory.aliases = identifiers
        .into_iter()
        .filter(|identifier| normalize_identifier(identifier) != normalize_identifier(&canonical))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    if finding.vulnerability.advisory.summary == "No summary provided" {
        finding.vulnerability.advisory.summary = incoming_advisory.summary;
    }
    if finding.vulnerability.advisory.details.is_none() {
        finding.vulnerability.advisory.details = incoming_advisory.details;
    }
    if finding.vulnerability.advisory.severity.is_none() {
        finding.vulnerability.advisory.severity = incoming_advisory.severity;
    }
    if finding.vulnerability.advisory.cvss_score.is_none() {
        finding.vulnerability.advisory.cvss_score = incoming_advisory.cvss_score;
    }
    if finding.vulnerability.advisory.references.is_empty() {
        finding.vulnerability.advisory.references = incoming_advisory.references;
    }
    if finding.vulnerability.advisory.published.is_none() {
        finding.vulnerability.advisory.published = incoming_advisory.published;
    }
    if finding.vulnerability.advisory.modified.is_none() {
        finding.vulnerability.advisory.modified = incoming_advisory.modified;
    }

    let rebuilt = build_finding_from_parts(
        &finding.package,
        finding.vulnerability.advisory.clone(),
        fixed_versions,
        known_exploited,
    );
    *finding = rebuilt;
}

fn merge_versions(left: Vec<Version>, right: Vec<Version>) -> Vec<Version> {
    let mut versions = left.into_iter().chain(right).collect::<Vec<_>>();
    versions.sort();
    versions.dedup();
    versions
}

fn parse_risk_level_or_cvss(value: &str) -> Option<RiskLevel> {
    let value = value.trim();
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some(RiskLevel::Critical),
        "high" => Some(RiskLevel::High),
        "medium" | "moderate" => Some(RiskLevel::Medium),
        "low" => Some(RiskLevel::Low),
        "info" | "informational" | "none" => Some(RiskLevel::Info),
        _ if value.starts_with("CVSS:") => Some(RiskLevel::Low),
        _ => value.parse::<f32>().ok().and_then(RiskLevel::from_cvss),
    }
}

fn cvss_to_risk_input(score: f32) -> Option<u8> {
    RiskLevel::from_cvss(score)?;

    if score > 0.0 && score < 1.0 {
        Some(1)
    } else {
        Some(score.floor() as u8)
    }
}

fn find_stringish(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(candidate) = value.get(*key) {
            match candidate {
                Value::String(string) => return Some(string.clone()),
                Value::Number(number) => return Some(number.to_string()),
                Value::Bool(boolean) => return Some(boolean.to_string()),
                _ => {}
            }
        }
    }
    None
}

fn find_number(value: &Value, keys: &[&str]) -> Option<f64> {
    for key in keys {
        if let Some(number) = value.get(*key).and_then(Value::as_f64) {
            return Some(number);
        }
    }
    None
}

fn find_boolish(value: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(candidate) = value.get(*key) else {
            continue;
        };

        match candidate {
            Value::Bool(boolean) => return Some(*boolean),
            Value::String(string) => match string.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => return Some(true),
                "false" | "no" | "0" => return Some(false),
                _ => {}
            },
            Value::Number(number) => {
                if number.as_i64() == Some(1) {
                    return Some(true);
                }
                if number.as_i64() == Some(0) {
                    return Some(false);
                }
            }
            _ => {}
        }
    }
    None
}

fn preferred_identifier<I>(identifiers: I) -> String
where
    I: IntoIterator<Item = String>,
{
    unique_non_empty(identifiers)
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

fn normalize_identifier(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

fn unique_non_empty<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut seen = BTreeSet::<String>::new();
    let mut output = Vec::new();

    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        if seen.insert(normalize_identifier(value)) {
            output.push(value.to_owned());
        }
    }

    output
}

fn empty_to_unknown(value: String) -> String {
    let value = value.trim();
    if value.is_empty() {
        "UNKNOWN".to_owned()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forgeguard_core::{DependencyKind, Ecosystem, PackageId};
    use httpmock::{Method::GET, Method::POST, MockServer};

    fn fixture_package() -> Package {
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

    #[test]
    fn osv_version_query_does_not_include_purl() {
        let query = OsvQuery::from_package(&fixture_package());
        let json = serde_json::to_value(query).expect("query serializes");

        assert_eq!(json["package"]["name"], "time");
        assert_eq!(json["package"]["ecosystem"], "crates.io");
        assert_eq!(json["version"], "0.1.44");
        assert!(json["package"].get("purl").is_none());
    }

    #[test]
    fn fixed_versions_are_extracted_for_matching_package() {
        let vulnerability: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "RUSTSEC-2020-0071",
            "affected": [
                {
                    "package": { "name": "time", "ecosystem": "crates.io" },
                    "ranges": [
                        { "events": [ { "introduced": "0" }, { "fixed": "0.2.23" } ] }
                    ]
                }
            ]
        }))
        .expect("fixture parses");

        let fixed = vulnerability.fixed_versions_for(&fixture_package());

        assert_eq!(
            fixed,
            vec![Version::parse("0.2.23").expect("valid version")]
        );
    }

    #[test]
    fn severity_numeric_score_maps_to_high() {
        let vulnerability: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "TEST-1",
            "severity": [{ "type": "CVSS_V3", "score": "7.5" }]
        }))
        .expect("fixture parses");

        assert_eq!(vulnerability.source_severity(), Some(RiskLevel::High));
        assert_eq!(vulnerability.cvss_score(), Some(7.5));
    }

    #[test]
    fn cvss_vector_gets_explicit_low_baseline() {
        let vulnerability: OsvVulnerability = serde_json::from_value(serde_json::json!({
            "id": "TEST-1",
            "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }]
        }))
        .expect("fixture parses");

        assert!(vulnerability.cvss_vector_present());
        assert_eq!(vulnerability.source_severity(), Some(RiskLevel::Low));
    }

    #[tokio::test]
    async fn enriched_batch_merges_sparse_alias_metadata() {
        let server = MockServer::start_async().await;

        let batch_body = serde_json::json!({
            "results": [
                {
                    "vulns": [
                        { "id": "GHSA-wcg3-cvx6-7396", "summary": "sparse" },
                        { "id": "RUSTSEC-2020-0071", "summary": "sparse" }
                    ]
                }
            ]
        });

        let ghsa_body = serde_json::json!({
            "id": "GHSA-wcg3-cvx6-7396",
            "aliases": ["RUSTSEC-2020-0071"],
            "summary": "Potential segfault in time",
            "database_specific": { "severity": "medium" },
            "affected": [
                {
                    "package": { "name": "time", "ecosystem": "crates.io" },
                    "ranges": [{ "events": [{ "fixed": "0.2.23" }] }]
                }
            ]
        });

        let rustsec_body = serde_json::json!({
            "id": "RUSTSEC-2020-0071",
            "aliases": ["GHSA-wcg3-cvx6-7396"],
            "summary": "Potential segfault in time",
            "database_specific": { "severity": "medium" },
            "affected": [
                {
                    "package": { "name": "time", "ecosystem": "crates.io" },
                    "ranges": [{ "events": [{ "fixed": "0.2.23" }] }]
                }
            ]
        });

        let batch_mock = server
            .mock_async(|when, then| {
                when.method(POST).path("/v1/querybatch");
                then.status(200).json_body(batch_body);
            })
            .await;
        let ghsa_mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/vulns/GHSA-wcg3-cvx6-7396");
                then.status(200).json_body(ghsa_body);
            })
            .await;
        let rustsec_mock = server
            .mock_async(|when, then| {
                when.method(GET).path("/v1/vulns/RUSTSEC-2020-0071");
                then.status(200).json_body(rustsec_body);
            })
            .await;

        let client = OsvClient::with_config(OsvClientConfig {
            base_url: server.base_url(),
            timeout: Duration::from_secs(2),
            user_agent: "forgeguard-test".to_owned(),
            max_retries: 0,
            retry_delay: Duration::from_millis(1),
        })
        .expect("client");

        let findings = client
            .query_batch_enriched(&[fixture_package()])
            .await
            .expect("query succeeds");

        batch_mock.assert_async().await;
        ghsa_mock.assert_async().await;
        rustsec_mock.assert_async().await;

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|finding| !finding.vulnerability.advisory.aliases.is_empty()));
        assert!(findings.iter().all(|finding| finding.fix.available));
    }

    #[test]
    fn advisory_cache_round_trips_empty_package_results() {
        let package = fixture_package();
        let cache = AdvisoryCacheDocument::from_packages_and_findings(
            std::slice::from_ref(&package),
            Vec::new(),
            "2026-01-01T00:00:00Z",
        );

        assert_eq!(cache.package_record_count(), 1);
        assert_eq!(cache.finding_count(), 0);

        let lookup = cache.lookup_packages(&[package]);
        assert!(lookup.findings.is_empty());
        assert!(lookup.missing.is_empty());
    }

    #[test]
    fn advisory_cache_reports_missing_package_entries() {
        let cache = AdvisoryCacheDocument::new("2026-01-01T00:00:00Z");
        let lookup = cache.lookup_packages(&[fixture_package()]);

        assert!(lookup.findings.is_empty());
        assert_eq!(lookup.missing.len(), 1);
        assert_eq!(lookup.missing[0].name, "time");
    }

    #[test]
    fn advisory_cache_save_and_load_validates_schema() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("osv-cache.json");
        let cache = AdvisoryCacheDocument::from_packages_and_findings(
            &[fixture_package()],
            Vec::new(),
            "2026-01-01T00:00:00Z",
        );

        cache.save_path(&path).expect("cache writes");
        let loaded = AdvisoryCacheDocument::load_path(&path).expect("cache loads");

        assert_eq!(loaded.schema_version, ADVISORY_CACHE_SCHEMA_VERSION);
        assert_eq!(loaded.package_record_count(), 1);
    }
}
