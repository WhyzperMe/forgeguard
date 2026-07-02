# Offline Mode

Offline mode never contacts OSV.dev or any other network advisory source.

```bash
forgeguard scan . --offline
forgeguard scan . --offline --strict --cache .forgeguard/osv-cache.json
```

## Cache Model

ForgeGuard stores OSV findings in a local JSON cache keyed by ecosystem, package
name, and resolved version. Successful online scans update the cache. You can
also pre-warm it explicitly:

```bash
forgeguard cache update . --cache .forgeguard/osv-cache.json
forgeguard cache status --cache .forgeguard/osv-cache.json
```

Cache metadata includes schema version, generation time, package record count,
finding count, cache age, and stale status.

## Strict Offline

`--strict` fails with exit code 4 when:

- the cache cannot be read;
- the cache is older than `--cache-max-age-days`;
- any package that would be queried online is missing from the cache.

Without `--strict`, ForgeGuard completes with explicit `partial: true` metadata
and limitations when cache data is missing or stale.

## Reproducibility

For reproducible CI output, pin the cache path and upload the generated JSON
report as an artifact. Offline scans do not execute package managers, build
scripts, lifecycle scripts, tests, or project binaries.
