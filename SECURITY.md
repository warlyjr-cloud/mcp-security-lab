# Security model

MCP Security Lab treats a configured MCP server as untrusted code.

## What the MVP protects

- Dynamic scanning requires the explicit `--execute` flag.
- The target receives a small allowlist of inherited environment variables.
- Target startup and protocol discovery have a hard timeout.
- The scanner lists tools but never calls them.
- Findings are deterministic and contain no environment values.

## What the MVP does not protect

The current process runner is not an OS-level sandbox. A target process still runs with the
current user's operating-system permissions and may access the filesystem or network. Run
unknown servers inside a disposable VM or container.

Future releases may add platform adapters for Windows Sandbox, containers, and restricted
egress. Those adapters must be opt-in and independently verifiable.

## Reporting vulnerabilities

Do not include credentials, private server configuration, or personal data in a public issue.
Provide a minimal synthetic reproduction and identify the affected version.
