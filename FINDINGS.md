# Real-world findings

Produced by `npm run scan:registry` against well-known public MCP servers. These are
**hygiene** findings (missing annotations, open schemas, missing pagination, mutable surfaces),
not confirmed vulnerabilities — but they are real, actionable signal from real servers, and they
exercise the detection engine outside its own fixtures.

| Server                                             | Connected | Tools | crit | high | med | low | Rules fired                                                       |
| -------------------------------------------------- | --------- | ----- | ---- | ---- | --- | --- | ----------------------------------------------------------------- |
| `@modelcontextprotocol/server-everything`          | yes       | 15    | 0    | 0    | 24  | 15  | LAUNCH002×1, MUT001×1, TOOL004×15, TOOL010×7, TOOL009×15          |
| `@modelcontextprotocol/server-memory`              | yes       | 9     | 0    | 1    | 13  | 9   | TOOL011×1, LAUNCH002×1, MUT001×1, TOOL004×9, TOOL010×2, TOOL009×9 |
| `@modelcontextprotocol/server-sequential-thinking` | yes       | 1     | 0    | 0    | 3   | 1   | LAUNCH002×1, MUT001×1, TOOL004×1, TOOL009×1                       |

Reproduce: `npm run scan:registry` (add `--sandbox docker` for untrusted servers). The server
list is `corpus/registry.json`.
