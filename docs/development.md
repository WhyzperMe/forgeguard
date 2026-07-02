# Development

## Build

```powershell
cargo check --workspace
```

## Test

```powershell
cargo test --workspace
```

Unit tests use static fixtures and mocked HTTP. They must not require live
network access.

## Format

```powershell
cargo fmt --all
```

## Lint

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

## Docs

```powershell
cargo doc --workspace --no-deps
```

## Add A New Ecosystem Parser

1. Create a focused crate such as `forgeguard-pypi`.
2. Parse static lockfiles only by default.
3. Normalize packages into `forgeguard-core::Package`.
4. Build a `forgeguard-core::DependencyGraph`.
5. Document privacy behavior and unsupported package sources.
6. Add fixtures and offline tests.
7. Wire the parser into `forgeguard-cli` without adding business logic to
   argument parsing.

## Add A New Advisory Source

1. Create a source-specific client crate.
2. Set explicit user agent, timeout, and retry policy.
3. Do not send source code, secrets, or full manifests.
4. Map partial or malformed responses defensively.
5. Add fixture-based tests that do not require live network access.

## Add A New Report Format

1. Add the format enum variant in `forgeguard-report`.
2. Render only from `ScanReport`.
3. Add snapshot or structural tests.
4. Document whether the format is stable or experimental.

## Release Checks

Run the full quality gate before release:

```powershell
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --all-features
cargo doc --workspace --no-deps
```

## Offline Cache Development

The local OSV cache is a deterministic JSON document written by
`forgeguard cache update <PATH>` or by successful online scans. Tests must not
depend on a user cache path. Use temporary directories and explicit `--cache`
arguments for CLI tests.

Strict offline behavior should fail when a cache is missing, stale, or lacks a
package entry that would have been queried online. Non-strict offline behavior
may return a partial scan, but it must record the limitation in report metadata.
