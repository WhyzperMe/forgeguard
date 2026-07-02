# Supported Ecosystems

## Cargo

Cargo is supported in v0.1.

Implemented:

- Project directory scanning when `Cargo.lock` is present.
- Direct `Cargo.lock` scanning.
- Static `Cargo.lock` parsing.
- Static `Cargo.toml` parsing for dependency kind inference.
- Cargo package URL generation.
- OSV.dev lookup for public crates.io registry packages.
- Minimal CycloneDX JSON SBOM generation from lockfile packages.

Limitations:

- ForgeGuard does not invoke Cargo metadata in v0.1.
- Workspace member classification is best-effort from static manifests.
- Private registries, git dependencies, and local path packages are not sent to
  OSV by default.
- Full CycloneDX graph, license, service, and VEX support is not complete.

## npm-compatible JavaScript

Implemented in v0.1:

- `package-lock.json` lockfileVersion 2 and 3 parsing.
- `pnpm-lock.yaml` package extraction and conservative graph reconstruction.
- Yarn v1 `yarn.lock` package extraction and conservative graph reconstruction.
- Root `package.json` parsing for direct/development classification when
  available.
- npm package URL generation through the shared core model.
- OSV.dev lookup for packages resolved from public npm registry URLs,
  including npmjs and yarnpkg registry hosts.
- Explicit unsupported errors for `bun.lock` and `bun.lockb`.

Limitations:

- pnpm and Yarn lockfiles can encode resolver state that is not always
  reconstructable without running the package manager. ForgeGuard only creates
  dependency edges when the target package name maps unambiguously to one
  resolved version.
- Private registries, workspace, file, git, and missing sources are not sent to
  OSV by default.
- Bun lockfile parsing is not implemented yet.

## Planned Ecosystems

- PyPI requirements.txt and poetry.lock.
- Go go.sum.
- Maven pom.xml.

Each future ecosystem should produce `forgeguard-core::Package` records and a
`DependencyGraph`, then reuse the same policy and report pipeline.
