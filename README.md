# MCP Security Lab

[![CI](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/mcp-security-lab.svg)](https://badge.fury.io/js/mcp-security-lab)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Evidence-first security checks for local and remote Model Context Protocol (MCP) servers.

> **MCP Security Lab is a DevSecOps DevTool that automatically audits Model Context Protocol (MCP) servers for prompt injections, context window exhaustion, and unsafe tool schemas without requiring an LLM or API keys. It runs natively in CI/CD pipelines (SARIF 2.1.0) and supports Docker Sandboxing for safe active probing.**

The MVP audits how a local or remote MCP server is launched and what it advertises during the MCP
handshake. It detects risky launcher patterns (including inline code execution and encoded payloads),
missing tool annotations, mixed read/write interfaces, least-privilege violations, overly broad
schemas, context exhaustion risks, and prompt-injection-like text. Prompt-injection scanning covers
the full surface a server injects into the model's context — tool descriptions, annotation titles,
parameter names, enum values, server instructions, and every advertised **prompt** and **resource** —
and is resilient to Unicode evasion (homoglyphs, zero-width and bidirectional characters).

Every finding is mapped to a **CWE** and, where relevant, to the **OWASP Top 10 for LLM Applications**,
and this taxonomy is emitted in the SARIF output. By default the scanner does not call discovered
tools and requires no LLM or API key. Reports can be emitted as text, JSON, or SARIF 2.1.0. The full
rule catalog is documented in [docs/RULES.md](docs/RULES.md); the trust boundaries are described in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Why this exists

Installing a local MCP server executes code with the user's privileges. Protocol compliance
alone does not show whether a server asks for excessive access or advertises unsafe tools.
MCP Security Lab produces a small, reviewable report before deeper testing.

## Quick start

```powershell
npm.cmd install
npm.cmd run build
node dist/src/cli.js scan --config examples/insecure-server.json
node dist/src/cli.js scan --config examples/insecure-server.json --execute
```

The first scan performs launch-configuration checks only. `--execute` acknowledges that the
target command will run and enables MCP discovery.

## Configuration

```json
{
  "target": {
    "command": "node",
    "args": ["dist/fixtures/insecure-server.js"],
    "cwd": "."
  },
  "policy": {
    "timeoutMs": 5000,
    "maxTools": 100
  }
}
```

Paths are resolved relative to the configuration file. Environment values are intentionally
not supported in the MVP; this prevents secrets from entering reports or committed examples.

## Output

```powershell
node dist/src/cli.js scan --config examples/insecure-server.json --execute --format json
node dist/src/cli.js scan --config examples/insecure-server.json --execute --format sarif
node dist/src/cli.js scan --config examples/insecure-server.json --execute --output reports/scan.json
```

Sensitive values supplied through common arguments such as `--token`, `--api-key`,
`--password`, and `--secret` are redacted from every report. Avoid credentials in command
arguments entirely when the target supports a safer authentication mechanism.

Exit codes:

- `0`: scan completed without high or critical findings
- `1`: invalid input or runtime failure
- `2`: scan completed with at least one high or critical finding

## Remote servers

To scan a remote MCP server, give the target a `url` instead of a `command`:

```json
{
  "target": {
    "url": "https://mcp.example.com/mcp",
    "transport": "http"
  },
  "policy": { "timeoutMs": 5000, "maxTools": 100 }
}
```

`transport` defaults to `"http"` (the modern **Streamable HTTP** transport); use `"sse"` only for
legacy servers. Remote targets are checked for plaintext HTTP on non-local hosts (`REMOTE002`),
credentials embedded in the URL (`REMOTE003`, redacted from the report), and — with `--execute` —
whether the server accepts unauthenticated connections (`REMOTE004`).

With `--execute`, a protected remote server is also audited against the MCP authorization spec
(OAuth 2.1 + RFC 9728 / RFC 8414): a missing resource-metadata pointer (`AUTH001`), unreachable or
malformed OAuth metadata (`AUTH002`), an authorization server that does not require PKCE/S256
(`AUTH003`), and OAuth endpoints served over plaintext HTTP (`AUTH004`). See [docs/RULES.md](docs/RULES.md).

```powershell
node dist/src/cli.js scan --config examples/remote-server.json --execute
```

## Active probing (fuzzing)

By default the scanner never invokes a discovered tool. Active probing is opt-in through `--fuzz`,
which sends malformed and injection-shaped arguments to each tool to see whether the server validates
input or crashes/hangs. Because this executes tool code, `--fuzz` **requires both `--execute` and
`--sandbox docker`** so the target is network-isolated; the scanner refuses to fuzz on the host.

```powershell
node dist/src/cli.js scan --config examples/vulnerable-server.json --execute --sandbox docker --fuzz
```

`examples/vulnerable-server.json` targets a bundled honeypot (`fixtures/honeypot.ts`) that intentionally
crashes on malicious input, so this command demonstrates a `FUZZ001` critical finding. A well-behaved
server that returns a proper MCP error for bad input produces no fuzzing finding.

## GitHub Action

The repository includes a composite action that generates SARIF and can upload it to GitHub
code scanning. The calling workflow must grant `security-events: write`.

```yaml
name: MCP security

on:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: warlyjr-cloud/mcp-security-lab@v0.3.0
        with:
          config: mcp-security-lab.json
          execute: "true"
          upload-sarif: "true"
          fail-on-findings: "true"
```

Use `execute: "false"` for launch-configuration checks that must not start the target.
SARIF upload is available for public repositories and for eligible private repositories with
GitHub Code Security enabled.

`execute: "true"` runs the configured server without OS-level filesystem or network isolation.
Use it only for reviewed code or inside a disposable runner that contains no sensitive source
or credentials.

## Current limitations

Without `--sandbox docker`, `--execute` provides no OS-level filesystem or network isolation: the
server runs with the current user's permissions. Use `--sandbox docker` (which runs the target in a
`--network none` container) or a disposable VM for untrusted software. The Docker adapter is
POSIX-oriented; Windows paths are translated for bind-mounts but Docker Desktop must be running.
Remote scanning uses the Streamable HTTP transport by default (SSE is available for legacy servers).
See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Roadmap

1. Windows Sandbox execution adapter (Docker container adapter shipped).
2. Explicit, synthetic tool-call scenarios with canary files and blocked egress.
3. Public conformance corpus maintained with the MCP community.

Shipped: Streamable HTTP transport, remote transport checks, and OAuth authorization-posture checks
(RFC 9728 / RFC 8414).
