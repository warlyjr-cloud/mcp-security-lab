# MCP Security Lab

[![CI](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/mcp-security-lab.svg)](https://badge.fury.io/js/mcp-security-lab)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Evidence-first security checks for local Model Context Protocol servers.

The MVP audits how a local MCP server is launched and what it advertises during the MCP
handshake. It detects risky launcher patterns, missing tool annotations, mixed read/write
interfaces, overly broad schemas, and prompt-injection-like tool descriptions. It does not
call discovered tools and does not require an LLM or API key. Reports can be emitted as text,
JSON, or SARIF 2.1.0.

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
    "args": ["dist/test/fixtures/insecure-server.js"],
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
      - uses: your-org/mcp-security-lab@v0
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

This MVP does not provide OS-level filesystem or network isolation. A server started with
`--execute` still runs with the current user's permissions. Use a disposable VM or container
for untrusted software. See [SECURITY.md](SECURITY.md).

## Roadmap

1. Container and Windows Sandbox execution adapters.
2. Explicit, synthetic tool-call scenarios with canary files and blocked egress.
3. Remote Streamable HTTP and OAuth security checks.
4. Public conformance corpus maintained with the MCP community.
