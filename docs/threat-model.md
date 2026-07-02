# ForgeGuard Threat Model

## Purpose

ForgeGuard scans software dependency metadata and produces risk reports. The primary security objective is to let developers inspect untrusted repositories without executing their code.

## Assets

ForgeGuard protects:

- developer workstations and CI runners;
- source repositories being scanned;
- dependency metadata and reports;
- CI/CD policy decisions;
- local secrets and environment variables;
- generated SBOM, SARIF, JSON, and Markdown outputs.

## Trust boundaries

| Boundary | Description | Risk |
| --- | --- | --- |
| Local filesystem -> scanner | ForgeGuard reads lockfiles, manifests, policy files, and optional advisory cache files | Malformed or oversized input |
| Scanner -> advisory API | Online mode sends package identity queries | Metadata disclosure |
| Scanner -> reports | Advisory and repository metadata are rendered into output formats | Injection/control-character issues |
| Scanner -> CI/CD | Exit code controls pipeline behavior | Incorrect policy decision |

## Scanning untrusted repositories

ForgeGuard's default Cargo scanner is static. It does not:

- invoke Cargo;
- run `cargo build`;
- execute `build.rs`;
- run package-manager install scripts;
- execute project binaries or tests;
- evaluate application source code.

This prevents common scanner footguns where dependency analysis accidentally executes code from the repository being inspected.

## Data sent to external services

When online advisory mode is enabled, ForgeGuard sends only normalized public-registry package identifiers to OSV.dev:

- ecosystem name;
- package name;
- resolved package version.

ForgeGuard does not send:

- source code;
- complete lockfiles;
- environment variables;
- secrets;
- credentials;
- local absolute paths unless explicitly included by the user in report output.

Use these flags to prevent network queries:

```bash
forgeguard scan . --offline
forgeguard scan . --no-network
```

Strict offline mode uses only the local cache and fails if required cache entries
are missing or stale:

```bash
forgeguard scan . --offline --strict --cache .forgeguard/osv-cache.json
```

## Input threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Oversized lockfiles, manifests, policies, or cache files | Parser layer enforces file-size limits before reading large files |
| Malformed TOML or lockfile data | Parsing errors are returned as operational errors |
| Control-character injection in advisory or package metadata | Reports should sanitize terminal/Markdown/SARIF-visible strings |
| Alias duplication causing inflated findings | Core model deduplicates findings using advisory IDs and aliases |
| Expired risk exceptions | Policy layer ignores expired allowlist entries |
| Case-sensitive allowlist bypass | Policy matching normalizes identifiers |
| Untrusted dependency scripts | Scanner does not execute package manager commands |
| Permission-denied directories during discovery | Discovery returns an explicit scan error instead of silently treating the scan as complete |
| Stale offline advisory cache | Cache age is reported; strict offline mode fails |

## CI/CD threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Overprivileged workflow token | CI uses least-privilege `permissions` by default |
| Credential persistence in checkout | CI disables persisted checkout credentials where possible |
| Non-deterministic network failures | CI self-scan uses offline mode for deterministic quality gates |
| SARIF upload from forks | SARIF job is constrained to repository-owned branches/PRs |
| Unreviewed policy suppressions | Allowlist entries require reasons and should have expiry dates |

## Policy model

Policy evaluation occurs after advisory normalization and deduplication. This is required so a vulnerability represented by multiple IDs, such as `RUSTSEC-*`, `GHSA-*`, and `CVE-*`, is evaluated as one finding instead of multiple independent failures.

Policy status:

- `pass`: no unsuppressed finding violates policy;
- `warn`: findings exist but do not meet fail thresholds;
- `fail`: at least one unsuppressed finding violates a fail condition.

## Non-goals

ForgeGuard does not attempt to:

- prove exploitability;
- perform full reachability analysis in v0.1;
- sandbox untrusted code;
- detect all malicious packages;
- replace manual security review;
- replace SCA platforms in regulated production environments.

## Residual risk

ForgeGuard v0.1 relies on available advisory metadata. If an advisory source lacks severity, fixed versions, or exploitability information, ForgeGuard must report that limitation rather than invent certainty. Risk scoring is deterministic and explainable, but it is not a substitute for product-specific threat analysis.
