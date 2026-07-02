# Risk Model

ForgeGuard scores each finding deterministically from 0 to 100 and maps the
score to a risk level:

- `0-19`: info
- `20-39`: low
- `40-69`: medium
- `70-89`: high
- `90-100`: critical

## Current Inputs

- Advisory severity when supplied by the source.
- CVSS base score when supplied as a numeric value.
- Direct, development, build, transitive, or unknown dependency relationship.
- Fix availability.
- Known-exploited placeholder signal.
- Ecosystem confidence for Cargo advisories.

## Current Behavior

CVSS has priority over textual severity. Direct dependencies raise priority,
development dependencies lower runtime exposure, build dependencies receive a
small increase, and fixed versions add urgency because a clear remediation path
exists.

The model is intentionally simple in v0.1. It is designed to be predictable for
CI and unit tested so the same inputs produce the same score.

## Limitations

- Lockfile-only Cargo scans cannot always classify dependency reachability.
- OSV CVSS vectors do not always include a numeric base score.
- Known-exploited status is only consumed when a source provides a compatible
  boolean field.
- License, malicious package, VEX, and runtime reachability signals are not yet
  included.

## Planned Enhancements

- EPSS probability.
- CISA KEV enrichment.
- VEX affected/not-affected status.
- Static and dynamic reachability signals.
- Runtime versus dev dependency confidence.
- License risk scoring.
- Malicious package heuristics.
