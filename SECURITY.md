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
`--sandbox docker` runs the target inside a `--network none` container, which removes network
access but does not eliminate the risk of a determined container-escape exploit. Run unknown
servers inside a disposable VM when the software is not trusted.

A Windows Sandbox execution adapter is not yet implemented; on Windows, use the Docker adapter or
a disposable VM instead. Future adapters must be opt-in and independently verifiable.

## Reporting vulnerabilities

Do not include credentials, private server configuration, or personal data in a public issue.
Provide a minimal synthetic reproduction and identify the affected version.
