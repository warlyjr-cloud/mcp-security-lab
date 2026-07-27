# Rule catalog

Every finding carries a stable `id`, a severity, and — where applicable — a CWE and an OWASP Top 10
for LLM Applications identifier. The taxonomy is emitted in the SARIF output (`rule.properties.tags`,
`result.properties.cwe`/`owasp`) and in the text report (`Taxonomy:` line).

Severity maps to SARIF levels as: `critical`/`high` → `error`, `medium` → `warning`, `low` → `note`,
`info` → `none`.

## Launch configuration (static, no execution)

| ID          | Severity | CWE     | Title                                              |
| ----------- | -------- | ------- | -------------------------------------------------- |
| `LAUNCH001` | high     | CWE-78  | Target is launched through a general-purpose shell |
| `LAUNCH002` | medium   | CWE-829 | Target may download executable code at startup     |
| `LAUNCH003` | high     | CWE-78  | Suspicious launcher argument                       |
| `LAUNCH004` | high     | CWE-95  | Target executes inline code from the command line  |

`LAUNCH003` covers recursive deletion, network downloads, nested shells, privilege escalation,
dynamic code execution (`iex`/`Invoke-Expression`), and base64-encoded payloads. `LAUNCH004` covers
interpreter inline-eval flags (`node -e`, `python -c`, `deno eval`, PowerShell `-EncodedCommand`).

## Advertised metadata (requires `--execute`)

| ID        | Severity | CWE      | OWASP | Title                                                  |
| --------- | -------- | -------- | ----- | ------------------------------------------------------ |
| `TOOL001` | high     | CWE-20   | —     | Tool name exceeds the compatibility limit              |
| `TOOL002` | medium   | —        | —     | Tool description is missing                            |
| `TOOL003` | high     | CWE-77   | LLM01 | Text contains a prompt-injection-like instruction      |
| `TOOL004` | medium   | —        | —     | Tool annotation title is missing                       |
| `TOOL005` | high     | CWE-1188 | —     | Tool safety hints are missing                          |
| `TOOL006` | high     | CWE-250  | LLM08 | Potentially destructive tool is not marked destructive |
| `TOOL007` | medium   | —        | —     | Read-like tool is explicitly marked as writable        |
| `TOOL008` | high     | CWE-250  | LLM08 | Tool mixes read and write HTTP operations              |
| `TOOL009` | low      | CWE-20   | —     | Input schema accepts undeclared properties             |
| `TOOL010` | medium   | CWE-400  | LLM10 | Context exhaustion risk: missing pagination limits     |
| `TOOL011` | high     | CWE-250  | LLM08 | Dangerous capability combination (least privilege)     |
| `TOOL012` | high     | CWE-1007 | LLM01 | Text contains invisible or control characters          |

`TOOL003` and `TOOL012` are evaluated over the full injection surface: tool descriptions, annotation
titles, parameter names, enum values, server instructions, and every advertised prompt and resource.
Matching runs after NFKC normalization and invisible-character stripping, so homoglyph, fullwidth,
zero-width, and bidirectional evasion is defeated. When one of these fires on a prompt or resource,
its `location` is `prompt:<name>` or `resource:<name>`.

## Capability lifecycle and confused deputy (requires `--execute`)

These target attack classes specific to the MCP lifecycle and capability model, not to static
text. `MUT001`, `AUTH006`, and `RES001` are evaluated from the handshake and discovery responses;
`SAMPLE001` and `ELICIT001` fire when the server actively issues a client-directed request during
discovery or probing (the scanner declares the `sampling` and `elicitation` client capabilities,
records any such request, and declines it — it never runs a completion or returns user input).

| ID          | Severity    | CWE              | OWASP | Title                                                                 |
| ----------- | ----------- | ---------------- | ----- | --------------------------------------------------------------------- |
| `MUT001`    | medium      | CWE-494          | LLM03 | Server can mutate its advertised surface after approval (rug pull)    |
| `AUTH006`   | high/medium | CWE-522          | LLM08 | Tool relays or accepts an upstream credential (confused deputy)       |
| `RES001`    | high        | CWE-918 / CWE-22 | LLM08 | Resource template interpolates a variable into a network or file path |
| `SAMPLE001` | high        | CWE-284          | LLM01 | Server requested a model completion via sampling (model steering)     |
| `ELICIT001` | medium      | CWE-1021         | LLM01 | Server requested user input via elicitation (social engineering)      |

`MUT001` fires when the server declares `listChanged` for tools, prompts, or resources: a surface
inspected (or user-approved) once can be silently redefined later via a `list_changed` notification.
`AUTH006` escalates to **high** when a tool takes both a credential parameter and a caller-controlled
destination (`url`/`host`/`endpoint`), and is **medium** for a bare credential parameter. `RES001`
uses CWE-918 for `http(s)` templates (SSRF) and CWE-22 for `file://` or path-shaped templates
(traversal); template names and descriptions are also scanned for prompt injection. `SAMPLE001` and
`ELICIT001` also scan the requested content for injection.

## Remote transport (URL targets)

Static checks (`REMOTE001`–`REMOTE003`) run without connecting; `REMOTE004` requires `--execute`.

| ID          | Severity | CWE     | OWASP | Title                                                 |
| ----------- | -------- | ------- | ----- | ----------------------------------------------------- |
| `REMOTE001` | medium   | CWE-20  | —     | Remote target URL is malformed                        |
| `REMOTE002` | high     | CWE-319 | LLM08 | Remote endpoint uses plaintext HTTP                   |
| `REMOTE003` | high     | CWE-522 | LLM08 | Credentials are embedded in the target URL            |
| `REMOTE004` | medium   | CWE-306 | LLM08 | Remote MCP server accepts unauthenticated connections |

`REMOTE002` is suppressed for local hosts (`localhost`, `127.0.0.1`, `::1`, `*.localhost`), where
plaintext HTTP is normal for development. Credentials found in the URL are redacted from the report.
Remote targets default to the modern **Streamable HTTP** transport; set `target.transport` to `"sse"`
for legacy servers.

## OAuth authorization posture (remote URL targets, requires `--execute`)

Audited per the MCP authorization spec (OAuth 2.1 + RFC 9728 Protected Resource Metadata + RFC 8414
Authorization Server Metadata). Only evaluated when the server challenges an unauthenticated request;
an open server is covered by `REMOTE004`.

| ID        | Severity | CWE      | OWASP | Title                                                      |
| --------- | -------- | -------- | ----- | ---------------------------------------------------------- |
| `AUTH001` | medium   | CWE-306  | LLM08 | Protected server does not advertise its resource metadata  |
| `AUTH002` | medium   | CWE-306  | LLM08 | OAuth metadata is unreachable or malformed                 |
| `AUTH003` | high     | CWE-1188 | LLM08 | Authorization server does not advertise PKCE (S256)        |
| `AUTH004` | high     | CWE-319  | LLM08 | OAuth endpoint uses plaintext HTTP                         |
| `AUTH005` | high     | CWE-918  | LLM08 | Server directed the scanner to a non-public address (SSRF) |

`AUTH004` inspects the authorization server URLs and the `authorization_endpoint` / `token_endpoint` /
`registration_endpoint` values, and (like `REMOTE002`) is suppressed for local hosts. Before fetching
any URL taken from a server response, the scanner resolves the host and refuses to contact loopback,
link-local (including the cloud metadata address `169.254.169.254`), or private addresses; such an
attempt is reported as `AUTH005` and the fetch is skipped. Requests use `redirect: "manual"` so a 3xx
hop cannot bypass that check.

## Discovery integrity (requires `--execute`)

| ID        | Severity | CWE     | OWASP | Title                                          |
| --------- | -------- | ------- | ----- | ---------------------------------------------- |
| `DISC001` | high     | CWE-400 | LLM10 | Server advertises an excessive number of tools |
| `DISC002` | high     | CWE-400 | LLM10 | Server returned oversized discovery metadata   |

These replace the previous behavior of aborting the scan: a hostile server that floods tools or
returns megabytes of metadata now produces a finding instead of crashing the scanner.

## Active probing (requires `--execute --sandbox docker --fuzz`)

| ID        | Severity | CWE     | OWASP | Title                                                                                |
| --------- | -------- | ------- | ----- | ------------------------------------------------------------------------------------ |
| `FUZZ001` | critical | CWE-20  | LLM10 | Tool crashes or hangs on malicious input                                             |
| `FUZZ002` | critical | CWE-918 | LLM06 | Tool fetched internal metadata or a sensitive file when fuzzed (SSRF / exfiltration) |
| `DATA001` | critical | varies  | LLM06 | Tool output matched a secret or PII signature (data leak)                            |

Fuzzing classifies each probe outcome by error type, not by matching error text: a well-formed MCP
error is treated as correct handling (no finding); a timeout or a transport/process failure is
reported. Probing stops early once a crash indicates the server process is down.

## Execution status

| ID        | Severity | Title                                                       |
| --------- | -------- | ----------------------------------------------------------- |
| `EXEC001` | info     | Dynamic discovery was not executed                          |
| `EXEC002` | info     | Remote server did not complete an unauthenticated handshake |
