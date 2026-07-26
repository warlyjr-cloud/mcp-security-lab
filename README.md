# CyberConsult Advanced Security Suite

[![CI](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/mcp-security-lab.svg)](https://badge.fury.io/js/mcp-security-lab)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**CyberConsult Advanced Security Suite** (formerly MCP Security Lab) is an evidence-first
security toolkit for local and remote Model Context Protocol (MCP) servers. Its core engine,
**MCP Verifier**, audits how an MCP server is launched and what it advertises during the MCP
handshake — without requiring an LLM or API key for its deterministic checks.

> The GitHub repository, npm package, and CLI binary keep their existing identifiers
> (`mcp-security-lab`, `mcpsl`) during this rebrand so existing installs, CI pipelines, and the
> GitHub Action referenced below keep working without changes. "CyberConsult Advanced Security
> Suite" and "MCP Verifier" are the product's new brand names layered on top of that unchanged
> technical foundation.

> **MCP Verifier automatically audits Model Context Protocol (MCP) servers for prompt injections, context window exhaustion, and unsafe tool schemas without requiring an LLM or API keys. It runs natively in CI/CD pipelines (SARIF 2.1.0) and supports Docker Sandboxing for safe active probing.**

The MVP audits how a local or remote MCP server is launched and what it advertises during the MCP
handshake. It detects risky launcher patterns (including inline code execution and encoded payloads),
missing tool annotations, mixed read/write interfaces, least-privilege violations, overly broad
schemas, context exhaustion risks, and prompt-injection-like text. Prompt-injection scanning covers
the full surface a server injects into the model's context — tool descriptions, annotation titles,
parameter names, enum values, server instructions, and every advertised **prompt** and **resource** —
and is resilient to Unicode evasion (homoglyphs, zero-width and bidirectional characters).

Every finding is mapped to a **CWE** and, where relevant, to the **OWASP Top 10 for LLM Applications**,
and this taxonomy is emitted in the SARIF output. By default MCP Verifier does not call discovered
tools and requires no LLM or API key. Reports can be emitted as text, JSON, or SARIF 2.1.0. The full
rule catalog is documented in [docs/RULES.md](docs/RULES.md); the trust boundaries are described in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Market differentiation

Most MCP tooling either (a) trusts server metadata at face value, or (b) requires an LLM/API key
to reason about risk, adding cost, latency, and a non-deterministic verdict to a security gate.
CyberConsult Advanced Security Suite is positioned differently:

- **Deterministic by default.** MCP Verifier's core rule set (launcher patterns, tool annotations,
  schema hygiene, prompt-injection text matching, context-exhaustion heuristics) runs with no LLM
  and no API key, so results are reproducible and safe to gate CI/CD on.
- **Evidence-first reporting.** Every finding carries the matched evidence, a CWE mapping, and,
  where applicable, an OWASP Top 10 for LLM Applications category — not just a severity label.
- **Optional AI escalation, not a dependency.** The Anthropic-powered features (`--auto-fix`
  remediation, the in-TUI Security Consultant chat) are opt-in additions on top of the
  deterministic engine, not a requirement to get a baseline audit.
- **CI-native output.** SARIF 2.1.0 output integrates directly with GitHub code scanning; a
  composite GitHub Action ships in-repo (see below).
- **Safety-conscious active probing.** Optional fuzzing (`--fuzz`) only runs inside a
  network-isolated Docker sandbox, never against a live/trusted server on the host.

## CyberConsult and the Claude for OSS Incubator

This project has architected its AI-assisted features — automated remediation suggestions and an
interactive Security Consultant — directly on top of Anthropic's Claude and the Model Context
Protocol, and treats MCP server auditing as a concrete, real-world case study of an AI system
acting as a security architect. On that basis, CyberConsult Advanced Security Suite considers
itself a strong **candidate** for the Claude for OSS Incubator: an open-source project built from
the ground up to demonstrate what Claude and MCP can do to strengthen security practices across
the open-source community.

To be clear: this project has **not** been accepted into, and is not officially affiliated with,
the Claude for OSS Incubator or Anthropic. The above describes the project's alignment and
aspirations, not a confirmed relationship.

## Why this exists

Installing a local MCP server executes code with the user's privileges. Protocol compliance
alone does not show whether a server asks for excessive access or advertises unsafe tools.
MCP Verifier produces a small, reviewable report before deeper testing.

## Quick start

Run it without installing anything:

```bash
npx mcp-security-lab scan --config mcp-security-lab.json
npx mcp-security-lab scan --config mcp-security-lab.json --execute
```

Or from a clone:

```bash
npm install
npm run build
node dist/src/cli.js scan --config examples/insecure-server.json --execute
```

The first form performs launch-configuration checks only. `--execute` acknowledges that the
target command will run and enables MCP discovery.

## Example output

Scanning the bundled intentionally-insecure fixture (`--execute`):

```text
CyberConsult Advanced Security Suite — MCP Verifier
Target: node dist/fixtures/insecure-server.js
Connected: yes | Transport: stdio | Tools invoked: 0 | OS sandbox: no
Findings: 0 critical, 7 high, 2 medium, 2 low, 0 info

[HIGH] TOOL003 Text contains a prompt-injection-like instruction
  Evidence: The description matched the instruction override pattern.
  Recommendation: Describe functionality only; remove behavioral or hidden instructions.
  Taxonomy: CWE-77, LLM01
  Location: tool:delete_everything
[HIGH] TOOL006 Potentially destructive tool is not marked destructive
  Taxonomy: CWE-250, LLM08
  Location: tool:delete_everything
[HIGH] TOOL011 Dangerous Capability Combination (Least Privilege Violation)
  Taxonomy: CWE-250, LLM08
  Location: server
...
```

Exit code is `2` when any high or critical finding is present, so a scan fails CI on real issues.

### Against a real server

Pointed at the official reference server `@modelcontextprotocol/server-everything` (13 tools, 4
prompts, 7 resources), the scanner surfaces genuine hygiene gaps without any LLM or API key:

```text
Findings: 0 critical, 0 high, 21 medium, 13 low, 0 info

  LAUNCH002 x1   Target may download executable code at startup (launched via npx)
  TOOL010   x7   Context exhaustion risk: read tools missing pagination limits
  TOOL004   x13  Tool annotation title is missing
  TOOL009   x13  Input schema accepts undeclared properties
```

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

## 🚀 Version 1.0.0 Golden Key Features (AI-Driven)

The v1.0.0 release introduces 3 major AI-driven capabilities for DevSecOps:

1. **Auto-Remediation (`--auto-fix`)**: Connects to the Anthropic API (requires `ANTHROPIC_API_KEY`) to generate a `MCP_REMEDIATION.md` file with precise code snippets and instructions on how to patch vulnerabilities detected during the scan.
2. **Zero-Trust Firewall Generator (`--generate-firewall`)**: Generates an `mcp-firewall.json` policy that you can use to block malicious or unauthenticated tools based on the scan results.
3. **Cyber-Consultant TUI (`--format dashboard`)**: Run in dashboard mode and press `c` while highlighting a vulnerability to open a built-in terminal chat session. You can talk to an AI Security Consultant to ask for live help on fixing the specific issue.

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
      - uses: warlyjr-cloud/mcp-security-lab@v1.0.0
        with:
          config: mcp-security-lab.json
          execute: "true"
          upload-sarif: "true"
          fail-on-findings: "true"
          comment-pr: "true"
          github-token: ${{ secrets.GITHUB_TOKEN }}
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
