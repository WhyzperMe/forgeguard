# GitHub Actions

ForgeGuard is designed to run in least-privilege GitHub Actions jobs.

```yaml
name: ForgeGuard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false

      - uses: actions/cache@v4
        with:
          path: .forgeguard-cache
          key: forgeguard-osv-${{ runner.os }}-${{ hashFiles('**/Cargo.lock', '**/package-lock.json', '**/pnpm-lock.yaml', '**/yarn.lock') }}

      - run: cargo run -p forgeguard -- cache update . --cache .forgeguard-cache/osv-cache.json

      - run: cargo run -p forgeguard -- scan . --format sarif --output forgeguard.sarif --cache .forgeguard-cache/osv-cache.json

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: forgeguard.sarif
          category: forgeguard
```

For deterministic no-network gates, pre-warm the cache in a trusted job and run:

```bash
forgeguard scan . --offline --strict --cache .forgeguard-cache/osv-cache.json --format json --output forgeguard.json
```

Recommended hardening:

- keep `permissions: contents: read` unless SARIF upload is needed;
- use `security-events: write` only in SARIF upload jobs;
- disable checkout credential persistence;
- avoid passing secrets to ForgeGuard jobs;
- upload JSON/SARIF/SBOM files as artifacts for auditability.
