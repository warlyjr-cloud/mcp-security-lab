# MCP Security Lab

[![CI](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/warlyjr-cloud/mcp-security-lab/badge)](https://scorecard.dev/viewer/?uri=github.com/warlyjr-cloud/mcp-security-lab)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Evidence-first security, conformance, and isolation checks for Model Context Protocol
servers. The scanner is model-agnostic, deterministic, and does not require an LLM or API
key.

MCP Security Lab inspects local stdio servers and remote Streamable HTTP endpoints,
evaluates their launch configuration, negotiated protocol metadata, tools, resources,
prompts, and OAuth discovery, then emits text, JSON, or SARIF 2.1.0. The versioned
`2026.07` catalog currently contains 43 rules.

## Safety contract

| Operation | Starts target | Calls a tool | OS isolation |
| --- | ---: | ---: | --- |
| `scan` | No | No | Not applicable |
| `scan --execute`, `sandbox.adapter=none` | Yes | Never | No; reported as a high finding |
| `scan --execute`, `sandbox.adapter=docker` | Yes | Never | Docker preflight must succeed |
| `exercise --consent-call` | Yes | One named tool, at most twice | Verified Docker is mandatory |
| Remote OAuth audit | Metadata requests only | Never | Private-network destinations blocked by default |

Discovery calls only `initialize`, `tools/list`, `resources/list`, and `prompts/list` when
the server advertises the corresponding capability. Pagination, response sizes, item
counts, process lifetime, redirects, and error text are bounded. Discovered tool names are
never executed implicitly.

Docker is a defense-in-depth boundary, not a claim of perfect containment. See
[the threat model](THREAT_MODEL.md) and [sandbox documentation](docs/sandbox.md).

## Quick start

Requirements: Node.js 22.14 or newer. Node 24 LTS is recommended.

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run build
node dist/src/cli.js scan --config examples/insecure-server.json
node dist/src/cli.js scan --config examples/insecure-server.json --execute
```

The first command performs static launch checks. `--execute` is explicit consent to start
the configured target and discover metadata. It still never invokes a tool.

Install the CLI after it is published:

```powershell
npm.cmd install --global mcp-security-lab
mcpsl --help
```

## Commands

```text
mcpsl scan --config <path> [--execute] [--format text|json|sarif] [--output <path>]
mcpsl benchmark --manifest <path> --consent-synthetic-execution [--format text|json]
mcpsl exercise --config <path> --tool <name> --input <json-path> --consent-call
               [--repeat 1|2] [--format text|json]
mcpsl rules [--format text|json]
mcpsl --version
```

Exit codes:

- `0`: command completed and the selected policy threshold was not reached.
- `1`: invalid input, consent failure, or bounded runtime failure.
- `2`: scan completed with findings at or above the policy threshold.

Policy profiles fail at different severities:

| Profile | Failure threshold |
| --- | --- |
| `strict` | medium |
| `balanced` | high |
| `compatibility` | critical |

## Local stdio configuration

```json
{
  "target": {
    "transport": "stdio",
    "command": "node",
    "args": ["server.js"],
    "cwd": "."
  },
  "policy": {
    "timeoutMs": 5000,
    "maxTools": 100,
    "maxResources": 100,
    "maxPrompts": 100,
    "maxResponseBytes": 1048576,
    "profile": "strict"
  },
  "sandbox": {
    "adapter": "docker",
    "image": "node@sha256:d45d78e7929b46875bbd4e29bea672d5bc48186c6c3588306521c815e78352d6",
    "network": "none",
    "memoryMb": 256,
    "cpus": 1,
    "pidsLimit": 128
  }
}
```

The Docker adapter mounts the configured working directory read-only, drops Linux
capabilities, enables `no-new-privileges`, uses a read-only root filesystem, bounds memory,
CPU and PIDs, and disables networking by default. An image is only treated as immutable
when pinned by `sha256`.

## Remote Streamable HTTP

```json
{
  "target": {
    "transport": "streamable-http",
    "url": "https://mcp.example.com/mcp"
  },
  "policy": {
    "timeoutMs": 5000,
    "maxTools": 100,
    "profile": "strict",
    "allowPrivateNetwork": false
  }
}
```

The audit discovers RFC 9728 protected-resource metadata and RFC 8414 or OpenID Connect
authorization-server metadata. It checks HTTPS, exact resource binding, declared
authorization servers, and PKCE S256. It does not perform login, dynamic client
registration, authorization, or token exchange.

Private, loopback, link-local, and metadata-service address ranges are blocked after DNS
resolution unless `allowPrivateNetwork` is explicitly enabled. Loopback is permitted for
local development.

## Explicit behavioral exercise

Behavioral tests have a separate command and separate consent:

```powershell
node dist/src/cli.js exercise `
  --config examples/docker-stdio.json `
  --tool read_file `
  --input examples/exercise-input.json `
  --consent-call `
  --repeat 2
```

The command requires verified Docker, creates a random synthetic canary, mounts it
read-only, invokes only the exact named tool, and returns hashes instead of raw tool
outputs. It detects canary disclosure, canary modification, oversized results, bounded
call failures, and inconsistent output from tools marked idempotent.

## Reports and automation

```powershell
node dist/src/cli.js scan --config examples/insecure-server.json --execute --format json
node dist/src/cli.js scan --config examples/insecure-server.json --execute --format sarif
node dist/src/cli.js scan --config examples/insecure-server.json --output reports/scan.json
```

Every finding includes rule ID, severity, confidence, category, bounded evidence,
recommendation, references, and a stable logical location. Sensitive launcher arguments,
URL credentials, secret-like query values, and untrusted error text are redacted.

The repository includes a composite GitHub Action:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v6
  - uses: warlyjr-cloud/mcp-security-lab@v0
    with:
      config: mcp-security-lab.json
      execute: "true"
      upload-sarif: "true"
      fail-on-findings: "true"
```

Pin the action to a full release commit SHA in high-trust consumers.

## Reproducible benchmark

The public corpus contains only synthetic fixtures and exact expected rule IDs:

```powershell
npm.cmd run benchmark
```

The current manifest requires precision `1.0` and recall `1.0`. The benchmark command
refuses executable cases without `--consent-synthetic-execution`. Corpus methodology is in
[docs/benchmark.md](docs/benchmark.md).

## Quality and supply chain

```powershell
npm.cmd run check
npm.cmd test
npm.cmd run coverage
npm.cmd run benchmark
npm.cmd audit
npm.cmd run mutation:dry
```

The repository enforces:

- Node 22, 24, and 26 on Linux; Node 24 on Windows and macOS.
- 80% line, 65% branch, and 80% function coverage.
- property-based tests for redaction and deterministic schema inspection.
- scheduled mutation testing with a 70% break threshold.
- CodeQL, dependency review, OpenSSF Scorecard, and SARIF.
- SHA-pinned GitHub Actions.
- npm trusted publishing with OIDC, package provenance, CycloneDX SBOM, checksums, and
  GitHub build attestations.
- an AMD64 GHCR image built from a digest-pinned base with SBOM and provenance.

## Project documentation

- [Architecture](docs/architecture.md)
- [Rule catalog and versioning](docs/rules.md)
- [Threat model](THREAT_MODEL.md)
- [Sandbox guarantees](docs/sandbox.md)
- [Benchmark methodology](docs/benchmark.md)
- [MCP compatibility and conformance](docs/conformance.md)
- [Release process](docs/releasing.md)
- [Platform distribution](docs/platform-distribution.md)
- [Governance](GOVERNANCE.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Scope and non-goals

MCP Security Lab is a security analysis aid, not an official MCP certification, malware
detector, formal verifier, or guarantee that a server is safe. Static metadata rules can
produce false positives and cannot prove runtime behavior. The behavioral engine is
deliberately narrow and does not fuzz arbitrary tools.

The project is independent, open source, and intended to benefit the entire MCP ecosystem.
It is not affiliated with or endorsed by Anthropic, OpenAI, Microsoft, Apple, or the MCP
Steering Group.

## License

Apache License 2.0. See [LICENSE](LICENSE).
