# Security Policy

## Supported Version

ForgeGuard is pre-1.0. Security fixes are applied to the current `main` branch.

## Scanner Safety Guarantees

ForgeGuard scanners are static. They do not execute:

- project binaries;
- tests or examples;
- `build.rs`;
- Cargo commands for scanned targets;
- npm, pnpm, yarn, or bun commands;
- package manager lifecycle scripts.

Online OSV queries include only ecosystem, package name, and resolved version.
Offline mode does not contact advisory services.

## Known Limitations

ForgeGuard does not prove exploitability or reachability. Advisory coverage
depends on source data quality. Bun lockfile parsing, license extraction, VEX,
EPSS, and CISA KEV enrichment are not complete in v0.1.
