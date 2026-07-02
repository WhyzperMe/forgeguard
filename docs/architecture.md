# ForgeGuard Architecture

## Design goals

ForgeGuard is designed as a CLI-first, library-backed supply-chain security scanner.

Primary goals:

- safe analysis of untrusted repositories;
- deterministic CI/CD behavior;
- clear crate boundaries;
- stable machine-readable outputs;
- extensibility for additional ecosystems and advisory sources.

The project intentionally does not start with a GUI. A future Tauri or web UI should consume `forgeguard-core` models and report outputs instead of owning scanner logic.

## Workspace layout

```text
forgeguard/
  crates/
    forgeguard-core/
    forgeguard-scanner/
    forgeguard-cargo/
    forgeguard-npm/
    forgeguard-osv/
    forgeguard-policy/
    forgeguard-report/
    forgeguard-cli/
  docs/
  examples/
  tests/
```

## Crate boundaries

| Crate | Responsibility | Must not do |
| --- | --- | --- |
| `forgeguard-core` | Domain models, risk scoring, finding deduplication, scan reports | HTTP, CLI parsing, heavy filesystem IO |
| `forgeguard-scanner` | Bounded recursive discovery, scanner registry, symlink-safe traversal | Parse ecosystem lockfiles deeply, perform advisory queries |
| `forgeguard-cargo` | Static Cargo project discovery, `Cargo.lock` parsing, manifest dependency inference | Run Cargo, execute `build.rs`, install dependencies |
| `forgeguard-npm` | Static `package-lock.json`, `pnpm-lock.yaml`, and Yarn v1 parsing | Run npm/pnpm/yarn/bun, execute lifecycle scripts, install dependencies |
| `forgeguard-osv` | OSV.dev API client, response parsing, advisory mapping | Make policy decisions, render reports |
| `forgeguard-policy` | Load and evaluate `forgeguard.yml` | Query advisory sources, mutate findings |
| `forgeguard-report` | Render terminal, JSON, Markdown, and SARIF reports | Perform scanning or policy evaluation |
| `forgeguard-cli` | Orchestrate commands, IO, exit codes | Contain core business logic that belongs in libraries |

## Scan flow

```text
CLI arguments
  -> bounded target discovery
  -> static ecosystem lockfile scans
  -> graph aggregation
  -> query package filtering
  -> advisory lookup if network enabled, or cache lookup in offline mode
  -> finding normalization and deduplication
  -> policy evaluation
  -> report construction
  -> report rendering
  -> exit code
```

Policy and reports must consume deduplicated findings. This prevents alias inflation when one vulnerability appears under multiple IDs.

## Discovery

The scanner registry recursively discovers supported lockfiles within bounded
depth, candidate, and directory limits. It skips common generated directories
such as `.git`, `node_modules`, `target`, `dist`, `build`, and cache folders.
Symlinked scan targets are rejected, and symlinked directories are not followed.
Directory access errors are returned as scan errors so partial filesystem access
does not masquerade as a complete scan.

## Ecosystem scanners

Ecosystem scanners are static by default. The Cargo scanner reads:

- `Cargo.lock`;
- root `Cargo.toml` when available;
- workspace member manifests when statically discoverable.

The JavaScript scanner reads:

- `package-lock.json`;
- `pnpm-lock.yaml`;
- Yarn v1 `yarn.lock`;
- root `package.json` when available for direct/dev classification.

It does not run:

- `cargo metadata` by default;
- `cargo build`;
- `build.rs`;
- package manager scripts;
- npm, pnpm, yarn, or bun commands;
- tests or examples.

This is a deliberate security boundary.

## Advisory lookup

`forgeguard-osv` maps internal package identities into OSV queries. Online mode sends package ecosystem, name, and version. Successful online scans can update a local JSON advisory cache. Offline/no-network mode never constructs an OSV HTTP request and uses only the local cache when available.

Additional sources should be added behind separate crates or traits, for example:

- `forgeguard-rustsec`;
- `forgeguard-ghsa`;
- `forgeguard-kev`;
- `forgeguard-epss`.

## Risk model

Risk scoring is deterministic and explainable. The current model considers:

- source severity;
- CVSS where available;
- dependency relationship;
- fix availability;
- known-exploited signals;
- ecosystem support confidence.

Future inputs:

- EPSS;
- CISA KEV;
- VEX status;
- reachability;
- runtime/dev/build target context;
- malicious package heuristics;
- license risk.

## Reporting

Reports are generated after policy evaluation.

| Format | Intended consumer |
| --- | --- |
| Table | Local developer CLI output |
| JSON | Automation and stable machine consumption |
| Markdown | Pull request comments, artifacts, manual review |
| SARIF | GitHub code scanning and compatible tools |
| CycloneDX JSON | SBOM consumers |

## Error and exit-code model

| Exit code | Meaning |
| ---: | --- |
| `0` | Command completed; scan policy passed or warned |
| `1` | Scan completed and policy failed |
| `2` | Usage or configuration error |
| `3` | Scan/runtime error |
| `4` | Network or advisory source/cache error |
| `5` | Internal error |

Malformed policies are configuration errors. Unreadable targets and malformed lockfiles are scan/runtime errors. Failed OSV requests and strict offline cache failures are advisory-source errors.

## Extension points

### New ecosystem

Add a new crate, for example `forgeguard-npm`, that outputs `DependencyGraph` and `Package` values from static package metadata. The rest of the pipeline should remain unchanged.

### New advisory source

Add a client crate that maps source-specific responses into `Finding` or `Advisory` values. Deduplication in `forgeguard-core` should merge aliases across sources.

### New report format

Add a renderer in `forgeguard-report` that consumes `ScanReport`. It must not perform scanning or policy evaluation.

### Future GUI

A GUI should be a thin consumer of:

- `ScanReport` JSON;
- CycloneDX SBOM output;
- `forgeguard-core` domain models.

It should not duplicate scanner logic.
