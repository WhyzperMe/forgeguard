# ForgeGuard

ForgeGuard is a Rust-based, CLI-first software supply-chain vulnerability and risk scanner. It is designed for defensive security engineering, CI/CD gates, SBOM generation, and security review workflows.

ForgeGuard currently supports static Rust/Cargo and JavaScript package metadata scanning. It recursively discovers supported lockfiles, normalizes dependencies across ecosystems, queries advisory intelligence in online mode, can reuse a local advisory cache in offline mode, applies a deterministic risk model, evaluates a local policy, and renders reports for humans and automation.

## Status

ForgeGuard is an early but production-shaped v0.1 project. Cargo and npm-compatible JavaScript lockfile support are implemented first. PyPI, Go, Maven, RustSec local database integration, EPSS, CISA KEV, VEX, and richer SBOM support remain planned extension points.

## Security posture

ForgeGuard is intentionally conservative when scanning untrusted repositories.

By default, the Cargo scanner:

- parses static files only;
- does not run `cargo build`;
- does not execute `build.rs`;
- does not run package manager install scripts;
- does not evaluate project source code;
- sends only package ecosystem, package name, and resolved version to OSV.dev when network advisory queries are enabled.

Use `--offline` or `--no-network` to disable external advisory queries completely.

## Features

- Bounded recursive repository discovery
- Static Cargo project discovery
- `Cargo.lock` parsing
- Direct, build, development, and transitive dependency classification where inferable from static manifests
- Static `package-lock.json`, `pnpm-lock.yaml`, and Yarn v1 `yarn.lock` parsing
- Explicit unsupported reporting for Bun lockfiles
- Public crates.io package filtering before OSV queries
- Public npm registry filtering before OSV queries
- OSV.dev batch advisory queries
- Local OSV advisory cache for offline scans
- Advisory alias handling and finding deduplication
- Deterministic risk scoring with explainable reasons
- Policy enforcement via `forgeguard.yml`
- Terminal, JSON, Markdown, and SARIF reports
- Minimal CycloneDX JSON SBOM export
- Offline/no-network mode
- CI-friendly exit codes

## Non-goals

ForgeGuard is not:

- an exploit framework;
- an EDR evasion tool;
- a network scanner;
- a web vulnerability scanner;
- a malware sandbox;
- a tool that executes untrusted dependencies.

## Installation

From the repository root:

```bash
cargo build -p forgeguard --release
```

Run the debug build during development:

```bash
cargo run -p forgeguard -- --help
```

## Quickstart

Scan a Cargo project or a direct `Cargo.lock` path:

```bash
forgeguard scan .
forgeguard scan Cargo.lock
```

Generate JSON output:

```bash
forgeguard scan . --format json --out forgeguard-report.json
forgeguard scan . --format json --output forgeguard-report.json
```

Generate Markdown output:

```bash
forgeguard scan . --format markdown --out forgeguard-report.md
```

Generate SARIF output:

```bash
forgeguard scan . --format sarif --out forgeguard.sarif
```

Run without network advisory queries:

```bash
forgeguard scan . --offline
forgeguard scan . --no-network
forgeguard scan . --offline --strict --cache .forgeguard/osv-cache.json
forgeguard cache update .
forgeguard cache status --format json
forgeguard cache path
forgeguard policy check forgeguard-report.json --policy forgeguard.yml --json
```

Generate a minimal CycloneDX SBOM:

```bash
forgeguard sbom . --format cyclonedx-json --output bom.cdx.json
```

Explain a vulnerability by ID:

```bash
forgeguard explain RUSTSEC-2020-0071
```

## Exit codes

| Exit code | Meaning |
| ---: | --- |
| `0` | Command completed; scan policy passed or warned |
| `1` | Scan completed and policy failed |
| `2` | Usage or configuration error, including invalid policy files |
| `3` | Scan/runtime error, including unreadable targets or malformed lockfiles |
| `4` | Network or advisory-source/cache error |
| `5` | Internal error |

## Policy file

ForgeGuard automatically looks for `forgeguard.yml` next to the scanned project or lockfile. You can also pass one explicitly:

```bash
forgeguard scan . --policy forgeguard.yml
```

Example policy:

```yaml
fail_on:
  severity: high
  known_exploited: true
  fix_available: false

allowlist:
  - id: "RUSTSEC-0000-0000"
    reason: "Temporary exception while upstream patch is validated"
    expires: "2026-01-31"

licenses:
  deny:
    - AGPL-3.0
    - GPL-3.0
```

Allowlist entries must include a reason. Expired entries do not suppress findings.

## CI/CD example

```yaml
name: Supply Chain Security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  forgeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - run: cargo run -p forgeguard -- scan . --policy forgeguard.yml --format markdown --out forgeguard-report.md
```

## Example terminal output

```text
ForgeGuard Scan Report

Target: examples/vulnerable-rust-app
Ecosystem: Cargo
Dependencies scanned: 2
Findings: 1
Policy: warning

Risk summary:
  Critical: 0
  High:     0
  Medium:   0
  Low:      1
  Info:     0
```

## Supported ecosystems

| Ecosystem | Status |
| --- | --- |
| Cargo | Supported in v0.1 |
| npm package-lock | Supported in v0.1 |
| pnpm lockfile | Supported in v0.1, conservative graph reconstruction |
| Yarn v1 lockfile | Supported in v0.1, conservative graph reconstruction |
| Bun lockfile | Detected; parser not implemented yet |
| PyPI | Planned |
| Go modules | Planned |
| Maven | Planned |
| CycloneDX SBOM import | Planned |
| SPDX | Planned |

## Privacy model

Online mode sends advisory queries containing only:

- ecosystem;
- package name;
- package version.

ForgeGuard does not upload source code, environment variables, secrets, full manifests, or full lockfiles to advisory APIs. Offline/no-network mode performs local static analysis only and does not call advisory services.

## Architecture

ForgeGuard is a Cargo workspace with strict crate boundaries:

| Crate | Responsibility |
| --- | --- |
| `forgeguard-core` | Domain model, risk scoring, scan report types |
| `forgeguard-scanner` | Bounded multi-ecosystem lockfile discovery |
| `forgeguard-cargo` | Static Cargo discovery and lockfile parsing |
| `forgeguard-npm` | Static npm/pnpm/Yarn lockfile parsing |
| `forgeguard-osv` | OSV.dev client and advisory mapping |
| `forgeguard-policy` | Policy loading, validation, and evaluation |
| `forgeguard-report` | Table, JSON, Markdown, and SARIF rendering |
| `forgeguard-cli` | CLI orchestration and process exit behavior |

See [`docs/architecture.md`](docs/architecture.md) for details.

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md).

## Development

Quality gate:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo build --workspace --all-features --locked
cargo doc --workspace --no-deps --locked
```

Local run:

```bash
cargo run -p forgeguard -- scan examples/vulnerable-rust-app
```

## Roadmap

- RustSec local advisory database
- GitHub Advisory Database enrichment
- EPSS scoring
- CISA KEV enrichment
- VEX support
- Full CycloneDX import/export
- SPDX support
- Dependency diff scanning for pull requests
- npm, PyPI, Go, and Maven support
- Signed releases and provenance metadata
