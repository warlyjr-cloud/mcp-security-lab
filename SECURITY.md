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
`no-new-privileges`, `--ipc none`, and process/memory-capped, with the workspace bind-mounted
read-only. This removes network access and shrinks the blast radius, but does not eliminate the
risk of a determined container-escape exploit; the target still runs as the container's root user
(a non-root adapter is a planned follow-up). Run unknown servers inside a disposable VM when the
software is not trusted.

A Windows Sandbox execution adapter is not yet implemented; on Windows, use the Docker adapter or
a disposable VM instead. Future adapters must be opt-in and independently verifiable.

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
