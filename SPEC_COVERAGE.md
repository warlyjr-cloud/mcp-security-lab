# MCP spec coverage

MCP Verifier audits against the **Model Context Protocol specification, revision `2025-06-18`**
(OAuth authorization posture follows OAuth 2.1 + RFC 9728 + RFC 8414). This document maps the
security-relevant areas of the spec to the rules that cover them, and states — honestly — what is
not yet covered.

Rule details are in [docs/RULES.md](docs/RULES.md); trust boundaries are in
[THREAT_MODEL.md](THREAT_MODEL.md).

## Coverage map

| Spec area                                       | What it involves                          | Rules                                                  |
| ----------------------------------------------- | ----------------------------------------- | ------------------------------------------------------ |
| Launch / stdio transport                        | How a local server process is started     | `LAUNCH001`–`LAUNCH004`                                |
| Lifecycle — `initialize` / capabilities         | Declared server & client capabilities     | `MUT001` (listChanged), `DISC001`/`DISC002` (flooding) |
| Server → client `sampling`                      | Server-initiated model completions        | `SAMPLE001`                                            |
| Server → client `elicitation`                   | Server-initiated user input               | `ELICIT001`                                            |
| Tools — `tools/list` metadata                   | Names, descriptions, schemas, annotations | `TOOL001`–`TOOL012`                                    |
| Tools — safety annotations                      | `readOnlyHint` / `destructiveHint`        | `TOOL005`–`TOOL007`                                    |
| Tools — `tools/call` behavior                   | Runtime input handling (active)           | `FUZZ001`, `FUZZ002`, `DATA001`                        |
| Prompts — `prompts/list`                        | Prompt & argument metadata                | `TOOL003`/`TOOL012` over prompts                       |
| Resources — `resources/list`                    | Static resource metadata                  | `TOOL003`/`TOOL012` over resources                     |
| Resources — `resources/templates/list`          | URI templates with variables              | `RES001`                                               |
| Server `instructions`                           | Handshake instruction text                | `TOOL003`/`TOOL012` over instructions                  |
| Authorization — OAuth 2.1 / RFC 9728 / RFC 8414 | Protected-resource & AS metadata, PKCE    | `AUTH001`–`AUTH005`                                    |
| Authorization — credential handling             | Confused deputy / token passthrough       | `AUTH006`                                              |
| Streamable HTTP / SSE transport                 | Remote endpoint posture                   | `REMOTE001`–`REMOTE004`                                |

## Known gaps (not yet covered)

These are deliberate, documented gaps — surfaced so the coverage claim is honest and so the roadmap
is legible:

- **`roots` capability** — the scanner does not yet analyze client-root exposure.
- **`completions` capability** — argument-completion metadata is not inspected.
- **Resource `subscribe` / update notifications** — subscription-driven data flows are not exercised.
- **Logging (`logging` capability)** — server log messages are not inspected for leakage.
- **Actual post-approval drift** — `MUT001` flags the _capability_ to mutate; it does not yet re-list
  after a delay to detect a _realized_ rug pull. That is on the roadmap (synthetic mutation server).
- **`_meta` fields** — arbitrary metadata attached to results is not deeply inspected beyond size.

Contributions that close a gap should add a rule to `src/rules/`, a fixture, tests, an entry in
`docs/RULES.md`, and a row moved from this section into the coverage map above.
