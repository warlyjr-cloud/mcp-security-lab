# MCP Security Lab — MCP Verifier

[![CI](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/warlyjr-cloud/mcp-security-lab/actions/workflows/codeql.yml)
[![npm version](https://badge.fury.io/js/mcp-security-lab.svg)](https://badge.fury.io/js/mcp-security-lab)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/warlyjr-cloud/mcp-security-lab/badge)](https://securityscorecards.dev/viewer/?uri=github.com/warlyjr-cloud/mcp-security-lab)

**MCP Verifier automatically audits Model Context Protocol (MCP) servers for prompt injections, context-window exhaustion, and unsafe tool schemas — deterministically, without requiring an LLM or API keys. It runs natively in CI/CD pipelines (SARIF 2.1.0) and supports Docker sandboxing for safe active probing.**

The deterministic CLI is the core product. On top of it, two **optional** AI features are built directly on **Anthropic's Claude**: `--auto-fix` remediation and an interactive Security Consultant. An **experimental** web UI (React + Node.js, retro-terminal styling) wraps the Claude Consultant for demos — see [Experimental web UI](#experimental-web-ui) below; the CLI does not depend on it.

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
MCP Verifier is positioned differently:

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
- **Lifecycle-aware.** Beyond static text, it detects MCP-specific attack classes — rug pulls
  (`listChanged`), confused-deputy token passthrough, SSRF/traversal in resource templates, and
  server-initiated sampling/elicitation. See [SPEC_COVERAGE.md](SPEC_COVERAGE.md) for the spec-to-rule
  map and [docs/MCP_ATTACK_CLASSES.md](docs/MCP_ATTACK_CLASSES.md) for a full explainer of each class.

| Capability                                            | MCP Verifier | Typical MCP tooling   |
| ----------------------------------------------------- | ------------ | --------------------- |
| Deterministic, no LLM/API key required                | ✅           | often requires an LLM |
| Prompt-injection scanning (Unicode-evasion resilient) | ✅           | partial               |
| CWE + OWASP-LLM taxonomy in output                    | ✅           | rare                  |
| SARIF 2.1.0 / GitHub code scanning                    | ✅           | rare                  |
| Lifecycle attacks (rug pull, sampling, elicitation)   | ✅           | ✗                     |
| Confused-deputy / token-passthrough detection         | ✅           | ✗                     |
| OAuth 2.1 posture (RFC 9728 / 8414) + SSRF guard      | ✅           | ✗                     |
| Safe active probing in a network-isolated sandbox     | ✅           | varies                |
| Optional Claude-powered remediation                   | ✅           | varies                |

The comparison describes the class of trust-metadata-only or LLM-required scanners the project was
built to improve on; it is not a claim about any specific named tool.

## MCP Security Lab and the Claude for OSS Incubator

This project has architected its AI-assisted features — automated remediation suggestions and an
interactive Security Consultant — directly on top of Anthropic's Claude and the Model Context
Protocol, and treats MCP server auditing as a concrete, real-world case study of an AI system
acting as a security architect. On that basis, MCP Security Lab considers
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

Releases are automated (Release Please) and each version is published to npm with **build
provenance** (a signed [Sigstore attestation](https://docs.npmjs.com/generating-provenance-statements)
linking the tarball to the GitHub commit and workflow that built it).

## Example output

Scanning the bundled intentionally-insecure fixture (`--execute`):

```text
MCP Security Lab — MCP Verifier
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

Findings carry a `confidence` rating (`low`/`medium`/`high`). Pass `--min-confidence medium`
(or `high`) to drop lower-confidence findings from the report and the exit code; findings the
scanner does not confidence-rate are always kept, so raising the bar never hides an unrated result.

Pass `--baseline <report.json>` (a prior `--format json` report) to close the remediation loop:
after fixing a server, re-scan against the baseline to see exactly which findings were **resolved**,
which **remain**, and whether any were **introduced**. A newly introduced finding fails the exit
code, so `--baseline` doubles as a regression gate in CI.

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
`--sandbox docker`** so the target is network-isolated; the scanner refuses to fuzz on the host. It
also refuses to fuzz a **remote** target — the sandbox only isolates a locally-launched process, so a
remote URL is never actively probed and is never reported as OS-sandboxed.

```powershell
node dist/src/cli.js scan --config examples/vulnerable-server.json --execute --sandbox docker --fuzz
```

`examples/vulnerable-server.json` targets a bundled honeypot (`fixtures/honeypot.ts`) that intentionally
crashes on malicious input, so this command demonstrates a `FUZZ001` critical finding. A well-behaved
server that returns a proper MCP error for bad input produces no fuzzing finding.

### Discovering servers that need the network at boot

The Docker sandbox runs the target with `--network none`. Some servers open a connection (or read a
required credential and then connect) during `initialize` and would time out under that isolation.
`--sandbox-network bridge` is an explicit opt-in that lets such a server start inside the sandbox;
the relaxation is recorded as an informational `SANDBOX010` finding so the report stays honest. When a
target exits during startup (for example a missing API key), the scanner surfaces a redacted tail of
its stderr so you can see _why_ instead of a bare "Connection closed".

```powershell
node dist/src/cli.js scan --config examples/remote-server.json --execute --sandbox docker --sandbox-network bridge
```

`--fuzz` always forces `--network none`, regardless of `--sandbox-network` — active probing is never
given the network.

## Claude-powered features (optional, AI-driven)

On top of the deterministic engine, three opt-in capabilities use **Anthropic's Claude**
(`claude-opus-4-8`, requires `ANTHROPIC_API_KEY`):

1. **Rule-Verified Auto-Remediation (`--auto-fix`)**: An **agentic, self-verifying** loop. Claude proposes a corrected tool definition, and the **deterministic engine — not the model — decides whether the fix holds**, feeding the remaining rule ids back so Claude iterates until every rule passes. Each fix in `MCP_REMEDIATION.md` is marked ✅ _rule-verified_ only when re-running every MCP Verifier rule on the proposed definition yields zero findings. **This verifies rule compliance only — not that the fix preserves the tool's original behavior** (a proposal that drops parameters or loosens a schema can still pass). Review the diff and run the tool's own tests before applying. This makes Claude the engine of remediation while keeping the verdict deterministic. (Requires `ANTHROPIC_API_KEY`.)
2. **Zero-Trust Firewall Generator (`--generate-firewall`)**: Generates an `mcp-firewall.json` policy that you can use to block malicious or unauthenticated tools based on the scan results. (Deterministic — no API key required.)
3. **Security Consultant TUI (`--format dashboard`)**: Run in dashboard mode and press `c` while highlighting a finding to open a built-in terminal chat session backed by Claude, for live help fixing that specific issue.

## Experimental web UI

The `frontend/` (React + Vite) and `backend/` (Node.js + Express) directories contain an
**experimental, demo-only** web interface with retro-terminal styling. Its purpose is to
showcase the **Claude-powered Security Consultant** in a browser:

- The **MCP Server Scanner** panel runs the **real** MCP Verifier engine: it POSTs a config to the
  `backend/` `POST /api/scan` endpoint, which shells out to the installed `mcp-security-lab` CLI and
  returns the genuine JSON report. For safety the endpoint runs **launch-configuration checks only**
  (it never passes `--execute`, so it never starts the target), the config is strictly rebuilt
  server-side, CORS is restricted to localhost, and the server binds to `127.0.0.1`. Run a full
  `--execute` discovery scan with the CLI on a trusted host.
- The **AI Security Consultant** panel calls the `backend/` service, which talks to **Anthropic's
  Claude** (`claude-opus-4-8`). Set `ANTHROPIC_API_KEY` for the backend.
- The **System Summary** panel shows illustrative aggregate figures (clearly labelled as sample
  data), not a live rollup.

Both `POST /api/consult` and `POST /api/scan` require HTTP Basic Auth so that any other local
process or user on a shared host can't spend your Anthropic quota or trigger scans for free: set
`MCP_CONSULT_USER` / `MCP_CONSULT_PASSWORD` for the backend and the matching `VITE_CONSULT_USER` /
`VITE_CONSULT_PASSWORD` for the frontend. If you don't set a password, the backend generates one at
startup and prints it once to its console. Repeated failed attempts on either endpoint trigger a
shared, temporary lockout to slow down local password guessing.

Run `npm install && npm run dev` in `backend/`, then `npm install && npm run dev` in `frontend/`.
The web UI is not required to use MCP Verifier and is not published to npm; it is a proof-of-concept
of Claude-assisted MCP security tooling and is under active development.

## GitHub Action

The repository includes a composite action that scans your MCP server on every push or PR,
generates SARIF, and can upload it to GitHub code scanning.

**Zero-config** — point it at your published npm package, no config file needed:

```yaml
name: MCP security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: warlyjr-cloud/mcp-security-lab@mcp-security-lab-v1.4.5
        with:
          package: your-mcp-server # launched via `npx -y`
          execute: "true"
```

Building from source instead? Use `command` + `args` (still no config file):

```yaml
- uses: actions/checkout@v6
- uses: warlyjr-cloud/mcp-security-lab@mcp-security-lab-v1.4.5
  with:
    command: node
    args: dist/server.js
    execute: "true"
```

For advanced setups (custom policy, env, transport) pass a `config:` JSON file instead of
`package`/`command`. All three are mutually exclusive; provide exactly one. Add
`comment-pr: "true"` with `github-token: ${{ secrets.GITHUB_TOKEN }}` to post a scorecard on PRs.

Use `execute: "false"` for launch-configuration checks that must not start the target.
SARIF upload is available for public repositories and for eligible private repositories with
GitHub Code Security enabled.

`execute: "true"` runs the configured server without OS-level filesystem or network isolation.
Use it only for reviewed code or inside a disposable runner that contains no sensitive source
or credentials.

## Current limitations

Without `--sandbox docker`, `--execute` provides no OS-level filesystem or network isolation: the
server runs with the current user's permissions. Use `--sandbox docker` — which runs the target in a
digest-pinned, `--network none`, `--read-only`, non-root (uid 1000) container with `--cap-drop ALL`,
`no-new-privileges`, `--ipc none`, a read-only workspace mount, and process/memory caps — or a
disposable VM for untrusted software. This shrinks the blast radius but does not eliminate a
determined container-escape; see [SECURITY.md](SECURITY.md). The Docker adapter is
POSIX-oriented; Windows paths are translated for bind-mounts but Docker Desktop must be running.
Remote scanning uses the Streamable HTTP transport by default (SSE is available for legacy servers).
See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Real-world validation

MCP Verifier is exercised against real, well-known public MCP servers — not only its own fixtures.
`npm run scan:registry` audits the servers in `corpus/registry.json` and writes
[FINDINGS.md](FINDINGS.md). A run against three official reference servers:

| Server                       | Tools | high | med | low | Notable                                                           |
| ---------------------------- | ----- | ---- | --- | --- | ----------------------------------------------------------------- |
| `server-everything`          | 15    | 0    | 24  | 15  | MUT001 (mutable surface), TOOL004/009/010 hygiene                 |
| `server-memory`              | 9     | 1    | 13  | 9   | **TOOL011** — exposes both broad read and destructive write tools |
| `server-sequential-thinking` | 1     | 0    | 3   | 1   | MUT001, schema hygiene                                            |

These are **hygiene** findings, not confirmed vulnerabilities — but they are real, actionable signal
from real servers, and they validate the engine outside synthetic fixtures. Notably the lifecycle
rule `MUT001` fired on all three (each declares `listChanged`), and `server-memory` surfaced a
genuine least-privilege observation. Reproduce with `npm run scan:registry` (use `--sandbox docker`
for untrusted servers).

## Detection benchmark

A small, labeled conformance corpus (`corpus/manifest.json`) pins detection quality. Each entry
lists the rule ids that **must** fire (`expect`) and those that **must not** (`forbid`); the same
labels gate CI (`test/corpus.test.ts`). Run it locally:

```bash
npm run benchmark
```

```text
MCP Verifier detection benchmark
  [OK] vulnerable
  [OK] clean
  Precision: 100.0%
  Recall:    100.0%
  Sample:    2 corpus cases, 4 labeled detections (synthetic; not a statistical claim)
```

The corpus is intentionally small and synthetic; it is a regression gate and a starting point for a
community-maintained conformance suite (see roadmap), not a claim of exhaustive coverage. The
precision/recall numbers hold **on those two cases only** — they are not a statistical accuracy claim.

## Remediation loop (Claude-assisted)

The Claude features and the baseline diff compose into a fix-and-verify loop:

```bash
# 1. Scan and save a baseline
npx mcp-security-lab scan --config mcp.json --execute --format json --output before.json
# 2. Generate a Claude-authored remediation plan for the high/critical findings
npx mcp-security-lab scan --config mcp.json --execute --auto-fix   # writes MCP_REMEDIATION.md
# 3. Apply the fixes to your server, then re-scan against the baseline
npx mcp-security-lab scan --config mcp.json --execute --baseline before.json
#    -> prints which findings were resolved / remain / were introduced
```

Step 3 fails the exit code if a fix introduced a new finding, so the loop is safe to run in CI.

## Roadmap

1. Windows Sandbox execution adapter (Docker container adapter shipped).
2. Explicit, synthetic tool-call scenarios with canary files and blocked egress.
3. Public conformance corpus maintained with the MCP community.

Shipped: Streamable HTTP transport, remote transport checks, and OAuth authorization-posture checks
(RFC 9728 / RFC 8414).
