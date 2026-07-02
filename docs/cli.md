# CLI Reference

ForgeGuard is terminal-only and designed for scripts, CI systems, and bots.

## Scan

```bash
forgeguard scan <PATH>
forgeguard scan <PATH> --format json
forgeguard scan <PATH> --format sarif --output forgeguard.sarif
forgeguard scan <PATH> --offline
forgeguard scan <PATH> --online
forgeguard scan <PATH> --policy forgeguard.yml
forgeguard scan <PATH> --fail-on high
forgeguard scan <PATH> --machine
forgeguard scan <PATH> --strict --offline --cache .forgeguard/osv-cache.json
```

Formats:

- `table`: human terminal output.
- `json`: stable ForgeGuard report schema.
- `markdown`: pull request or artifact text.
- `sarif`: GitHub code scanning compatible SARIF 2.1.0.

`--machine` defaults table output to JSON. `--out` and `--output` are
equivalent.

## Cache

```bash
forgeguard cache update <PATH>
forgeguard cache status
forgeguard cache status --format json
forgeguard cache path
```

Use `--cache <PATH>` or `FORGEGUARD_CACHE_DIR` to make cache placement
deterministic in CI.

## SBOM

```bash
forgeguard sbom <PATH> --format cyclonedx-json --output bom.cdx.json
```

The SBOM is generated from the normalized static dependency graph. ForgeGuard
does not run package managers or project code.

## Policy

```bash
forgeguard policy check forgeguard-report.json
forgeguard policy check forgeguard-report.json --policy forgeguard.yml --fail-on high --json
```

`policy check` reads an existing ForgeGuard JSON report and returns exit code 1
when the evaluated policy fails.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | Command completed; scan policy passed or warned |
| 1 | Scan completed and policy failed |
| 2 | Usage or configuration error |
| 3 | Scan/runtime error |
| 4 | Network or advisory source/cache error |
| 5 | Internal error |
