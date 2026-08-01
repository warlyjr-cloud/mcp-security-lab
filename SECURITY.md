# Security model

MCP Security Lab (MCP Verifier) treats a configured MCP server as untrusted
code.

## What it protects

- Dynamic scanning requires the explicit `--execute` flag.
- The target receives a small allowlist of inherited environment variables.
- Target startup and protocol discovery have a hard timeout.
- By default, the scanner lists tools but never calls them. Active probing (`--fuzz`) is opt-in,
  requires both `--execute` and `--sandbox docker`, and refuses to run against tools on the host.
- Findings are deterministic and contain no environment values or credentials from the target.

## What it does not protect

Without `--sandbox docker`, the process runner is not an OS-level sandbox: a target process runs
with the current user's operating-system permissions and may access the filesystem or network.
`--sandbox docker` runs the target inside a digest-pinned container that is `--network none`,
`--read-only` (writes go to a small `noexec` tmpfs on `/tmp`), `--cap-drop ALL`,
`no-new-privileges`, `--ipc none`, runs as an unprivileged user (uid 1000, not root), and is
process/memory-capped, with the workspace bind-mounted read-only. This removes network access and
shrinks the blast radius, but does not eliminate the risk of a determined container-escape exploit.
Run unknown servers inside a disposable VM when the software is not trusted.

A Windows Sandbox execution adapter is not yet implemented; on Windows, use the Docker adapter or
a disposable VM instead. Future adapters must be opt-in and independently verifiable.

## Claude-powered features and the experimental web UI

The CLI's optional AI features (`--auto-fix`, the Security Consultant TUI) and the `backend/`/
`frontend/` web UI (see [Experimental web UI](README.md#experimental-web-ui)) send data to
**Anthropic's Claude API**. This has its own, narrower threat model:

**What it protects:**

- Untrusted content that reaches a Claude prompt (tool descriptions, schemas, scan evidence taken
  from the server under audit) is wrapped in an explicit `<untrusted_mcp_server_data>` delimiter
  with a system instruction to treat it as data, not instructions (`src/prompt-safety.ts`). This
  narrows, but cannot eliminate, the model's exposure to a prompt-injection payload embedded in the
  server being scanned.
- `--auto-fix`'s agentic remediation loop never trusts the model's "fix" on its say-so: every
  proposal is re-scanned by the same deterministic rule engine that found the original issue
  (`src/remediator/verify.ts`), and a fix whose original findings included a prompt-injection
  detection (`TOOL003`/`TOOL012`) is reported as requiring manual review rather than a plain
  checkmark, since the fixer model was shown the exact injected text while drafting its proposal.
- `DATA001` (leaked-secret detection) never echoes the matched secret value into a finding's
  `evidence` -- only the name of the pattern that matched -- because findings feed these same
  Claude prompts and the Markdown reports written to disk.
- Neither `--auto-fix` nor the web UI's scanner endpoint (`/api/scan`) applies a model's output to
  a live target automatically: `--auto-fix` only ever writes an advisory `MCP_REMEDIATION.md`, and
  `/api/scan` never runs `--execute`, so a scanned/AI-touched config cannot start a process.
- `POST /api/consult` and `POST /api/scan` require HTTP Basic Auth (`MCP_CONSULT_USER` /
  `MCP_CONSULT_PASSWORD`), with a shared, temporary lockout after repeated failed attempts, so
  another local process or user on a shared host cannot spend the operator's Anthropic quota or
  trigger scans for free.

**What it does not protect:**

- Delimiting untrusted content narrows, but does not eliminate, prompt-injection risk: a
  sufficiently crafted payload could still influence the model's advisory output (a Markdown
  remediation plan, a TUI chat reply, an AI-generated fuzz payload). None of these outputs are
  auto-applied, but a human who blindly trusts them without review can still be misled.
- The backend binds to `127.0.0.1` and restricts CORS to localhost, which keeps _remote_ web pages
  out, but not other local processes or users on a shared host -- Basic Auth is the control for
  that threat, not network isolation.
- The Basic Auth lockout slows down guessing of a weak, operator-set `MCP_CONSULT_PASSWORD`; it
  offers no additional protection when the password is left at its randomly generated default,
  which is not practically guessable in the first place. It does not distinguish attackers by
  source, since loopback-only binding makes every caller look like `127.0.0.1`.
- The web UI is transport-plaintext HTTP on loopback; it is not intended to run on a shared network
  interface or behind a reverse proxy without additional hardening (TLS, a real auth provider).

## Supported versions

Security fixes are provided for the latest published `1.x` release. Older versions are not patched;
upgrade to the current release on npm.

## Reporting a vulnerability

**Report privately, not in a public issue.** Use GitHub's private vulnerability reporting:
open the repository's **Security** tab → **Report a vulnerability** (GitHub Security Advisories).
This opens a private channel with the maintainers.

Please include:

- A minimal, **synthetic** reproduction (never real credentials, private server configuration, or
  personal data).
- The affected version (`npx mcp-security-lab --version` or the `scanner.version` in a JSON report).
- The impact you believe it has.

What to expect:

- **Acknowledgement within 3 business days.**
- A remediation plan and, for confirmed issues, a coordinated disclosure once a fix is released.

## Safe harbor

Good-faith security research on this project — testing against your own synthetic fixtures, and
private reporting through the channel above — is welcome and will not be pursued as a violation of
this project's terms. Do not test against servers or data you do not own.
