# Changelog

All notable changes are documented here. The project follows Semantic Versioning before
1.0 with the usual allowance that minor releases may change experimental interfaces.

## [0.3.0] - Unreleased

### Added

- Streamable HTTP discovery and bounded OAuth metadata audit.
- Versioned 43-rule catalog for launch, server, tool, resource, prompt, authentication,
  sandbox, and behavioral findings.
- Docker execution adapter with verified preflight and restrictive runtime flags.
- Explicit behavioral exercises with synthetic canaries and output digests.
- Public synthetic benchmark with exact precision and recall thresholds.
- Property-based tests, coverage gates, and scheduled mutation testing.
- CodeQL, dependency review, OpenSSF Scorecard, npm OIDC release, SBOM, provenance,
  attestations, and GHCR publishing workflows.
- Architecture, threat model, governance, contribution, release, and compatibility
  documentation.

### Changed

- Report schema advanced to `2.0`.
- Minimum Node.js version advanced to 22.14 because Node 20 is end-of-life.
- Policy profiles now select medium, high, or critical failure thresholds.

### Security

- Environment inheritance is allowlisted.
- Remote destinations are checked for SSRF-sensitive address ranges.
- Response bodies, discovery pagination, metadata counts, and execution time are bounded.
- GitHub Actions are pinned to immutable commit SHAs.
