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

## Discovery integrity (requires `--execute`)

| ID        | Severity | CWE     | OWASP | Title                                          |
| --------- | -------- | ------- | ----- | ---------------------------------------------- |
| `DISC001` | high     | CWE-400 | LLM10 | Server advertises an excessive number of tools |
| `DISC002` | high     | CWE-400 | LLM10 | Server returned oversized discovery metadata   |

These replace the previous behavior of aborting the scan: a hostile server that floods tools or
returns megabytes of metadata now produces a finding instead of crashing the scanner.

## Active probing (requires `--execute --sandbox docker --fuzz`)

| ID        | Severity | CWE    | OWASP | Title                                    |
| --------- | -------- | ------ | ----- | ---------------------------------------- |
| `FUZZ001` | critical | CWE-20 | LLM10 | Tool crashes or hangs on malicious input |

Fuzzing classifies each probe outcome by error type, not by matching error text: a well-formed MCP
error is treated as correct handling (no finding); a timeout or a transport/process failure is
reported. Probing stops early once a crash indicates the server process is down.

## Execution status

| ID        | Severity | Title                              |
| --------- | -------- | ---------------------------------- |
| `EXEC001` | info     | Dynamic discovery was not executed |
