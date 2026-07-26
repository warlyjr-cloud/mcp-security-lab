# Governance

MCP Security Lab is an independent open-source project governed in public.

## Roles

- **Contributors** propose issues, documentation, fixtures, rules, and code.
- **Maintainers** triage work, review changes, manage releases, and uphold safety
  invariants.
- **Security maintainers** coordinate private vulnerability reports and embargoed fixes.

Maintainer status is earned through sustained, technically sound contributions and
responsible security judgment. Existing maintainers decide additions and removals by
consensus.

## Decision process

Routine changes use pull-request review. Material changes to rule semantics, consent
boundaries, telemetry, data collection, governance, or compatibility policy require a
public design issue and at least one maintainer approval.

When consensus cannot be reached, the project owner makes the final decision and records
the rationale publicly. Private security details remain private until coordinated
disclosure.

## Release authority

Only maintainers may create protected release tags or approve the `npm` deployment
environment. Releases must pass CI, benchmark, coverage, dependency audit, and release
metadata checks. Published artifacts use OIDC and provenance; long-lived npm publish tokens
are not part of the normal process.

## Neutrality

Rules target the open MCP specification and observable security properties. No model
vendor receives preferential scoring. Sponsorship or participation in an ecosystem program
does not grant control over findings, disclosure, or roadmap.
