# Threat model

This document states what MCP Security Lab (MCP Verifier) treats as trusted,
what it treats as hostile, and what it does and does not guarantee. It complements
[SECURITY.md](SECURITY.md), which covers vulnerability reporting.

## Assets we protect

- The operator's workstation or CI runner (filesystem, network, credentials, environment).
- The integrity of the scan report itself (no secret leakage, no attacker-controlled content that
  can crash or mislead the scanner).

## Trust boundaries

| Component                         | Trust level | Rationale                                              |
| --------------------------------- | ----------- | ------------------------------------------------------ |
| The scanner code and its config   | Trusted     | Authored and reviewed by the operator.                 |
| The target MCP server binary/args | Untrusted   | May be third-party or malicious; running it is a risk. |
| Everything the server sends       | Untrusted   | Tool/prompt/resource metadata is attacker-controlled.  |
| The parent process environment    | Sensitive   | Must not leak into the target or the report.           |

Everything a target server returns — names, descriptions, schemas, annotations, instructions, prompt
and resource metadata — is untrusted input and is handled defensively. A target must never be able to
crash the scanner, exfiltrate the operator's environment, or inject content into the report.

## Adversaries and the mitigations against them

- **Malicious launcher (supply chain).** A config that runs a shell, a network installer
  (`npx`/`uvx`), inline interpreter code (`node -e`, `python -c`), or encoded payloads. Detected
  statically without execution (`LAUNCH001`–`LAUNCH004`).
- **Prompt injection via advertised metadata.** Hidden instructions in tool descriptions, parameter
  names, enum values, server instructions, prompts, or resources — including Unicode-obfuscated
  variants. Detected after NFKC normalization and invisible-character stripping (`TOOL003`,
  `TOOL012`).
- **Excessive agency / least-privilege violations.** Undeclared destructive tools, missing safety
  hints, read+write capability mixing (`TOOL005`–`TOOL008`, `TOOL011`).
- **Context-exhaustion / denial of service.** Unbounded read tools, tool flooding, or oversized
  discovery payloads (`TOOL010`, `DISC001`, `DISC002`). The scanner bounds process lifetime with a
  timeout and caps the size of discovery responses so a hostile server cannot exhaust the scanner.
- **Insecure remote transport.** Plaintext HTTP on non-local endpoints, credentials in the URL, or a
  remote server that accepts anonymous connections (`REMOTE002`–`REMOTE004`).
- **Weak OAuth authorization posture.** A protected remote server that omits its resource-metadata
  pointer, serves unreachable/malformed OAuth metadata, does not require PKCE, or exposes OAuth
  endpoints over plaintext HTTP (`AUTH001`–`AUTH004`, per RFC 9728 / RFC 8414).
- **Secret leakage into reports.** Credentials passed as arguments or in URLs are redacted; only an
  allowlist of environment variables is inherited by the target.
- **Uncontrolled active probing.** `--fuzz` executes tool code, so it requires an OS-level sandbox
  (`--sandbox docker`, `--network none`) and refuses to run on the host. Once sandboxed, malformed
  and injection-shaped arguments are sent to each tool: a tool that hangs or crashes the server
  process is flagged (`FUZZ001`) instead of silently accepted, and a tool that blindly fetches
  cloud-metadata or internal-network addresses on the fuzzer's behalf is flagged as a possible
  SSRF / data-exfiltration path (`FUZZ002`).
- **Sensitive data leakage via tool responses.** A tool response returned during fuzzing may
  contain AWS/GCP/NVIDIA/OpenAI/Stripe/Slack/Atlassian credentials or credit-card-shaped data that
  the target server should never have echoed back. Responses are pattern-matched for these
  signatures and flagged (`DATA001`) rather than silently forwarded.

## Explicit non-goals

- **No isolation without `--sandbox docker`.** A target started with `--execute` alone runs with the
  operator's OS permissions. The scanner never claims isolation it does not enforce.
- **No dynamic tool invocation by default.** Tools are only called when `--fuzz` is explicitly
  requested and a sandbox is active.
- **Not a substitute for code review.** Static launcher checks and advertised-metadata analysis
  reduce risk; they do not prove a server is safe.
- **No guarantee against a determined sandbox escape.** Container isolation reduces, but does not
  eliminate, the risk of running untrusted code. Use disposable runners for unknown software.
- **OAuth discovery follows server-controlled URLs (SSRF).** Auditing a remote server's authorization
  posture (`AUTH00x`) requires fetching the metadata URLs the server advertises. Before contacting any
  such URL the scanner resolves the host and refuses loopback, link-local (incl. `169.254.169.254`),
  and private addresses — reporting the attempt as `AUTH005` — requires https for non-local hosts, uses
  `redirect: "manual"` so a 3xx cannot bypass the check, caps the number of authorization servers
  contacted, and bounds every request with a timeout. Loopback metadata is followed only when the
  operator's own target is local (a dev scan). The scanner never forwards responses anywhere.
