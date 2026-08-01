# Real-world findings

Produced by `npm run scan:registry` against well-known public MCP servers. These are
**hygiene** findings (missing annotations, open schemas, missing pagination, mutable surfaces),
not confirmed vulnerabilities — but they are real, actionable signal from real servers, and they
exercise the detection engine outside its own fixtures.

| Server                                             | Connected | Tools | crit | high | med | low | Rules fired                                                         |
| -------------------------------------------------- | --------- | ----- | ---- | ---- | --- | --- | ------------------------------------------------------------------- |
| `@modelcontextprotocol/server-everything`          | yes       | 15    | 0    | 0    | 24  | 15  | LAUNCH002×1, MUT001×1, TOOL004×15, TOOL010×7, TOOL009×15            |
| `@modelcontextprotocol/server-memory`              | yes       | 9     | 0    | 1    | 13  | 9   | TOOL011×1, LAUNCH002×1, MUT001×1, TOOL004×9, TOOL010×2, TOOL009×9   |
| `@modelcontextprotocol/server-sequential-thinking` | yes       | 1     | 0    | 0    | 3   | 1   | LAUNCH002×1, MUT001×1, TOOL004×1, TOOL009×1                         |
| `@modelcontextprotocol/server-filesystem`          | yes       | 14    | 0    | 1    | 25  | 14  | TOOL011×1, LAUNCH002×1, MUT001×1, TOOL004×14, TOOL010×9, TOOL009×14 |
| `@modelcontextprotocol/server-github`              | yes       | 26    | 0    | 27   | 34  | 0   | TOOL005×26, TOOL011×1, LAUNCH002×1, TOOL004×26, TOOL010×7           |
| `@modelcontextprotocol/server-gitlab`              | no        | -     | -    | -    | -   | -   | error: [                                                            |
| {                                                  |

    "code": "invalid_value",
    "values": [
      "object"
    ],
    "path": [
      "tools",
      0,
      "inputSchema",
      "type"
    ],
    "message": "Invalid input: expected \"object\""

},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
1,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
2,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
3,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
4,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
5,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
6,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
7,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
},
{
"code": "invalid_value",
"values": [
"object"
],
"path": [
"tools",
8,
"inputSchema",
"type"
],
"message": "Invalid input: expected \"object\""
}
] (target stderr: GitLab MCP Server running on stdio) |
| `@modelcontextprotocol/server-slack` | yes | 8 | 0 | 8 | 11 | 8 | TOOL005×8, LAUNCH002×1, TOOL004×8, TOOL010×2, TOOL009×8 |
| `@modelcontextprotocol/server-postgres` | yes | 1 | 0 | 1 | 2 | 1 | TOOL005×1, LAUNCH002×1, TOOL004×1, TOOL009×1 |
| `@modelcontextprotocol/server-brave-search` | yes | 2 | 0 | 2 | 4 | 2 | TOOL005×2, LAUNCH002×1, TOOL004×2, TOOL010×1, TOOL009×2 |
| `@modelcontextprotocol/server-google-maps` | yes | 7 | 0 | 7 | 9 | 7 | TOOL005×7, LAUNCH002×1, TOOL004×7, TOOL010×1, TOOL009×7 |
| `@modelcontextprotocol/server-puppeteer` | yes | 7 | 0 | 7 | 8 | 7 | TOOL005×7, LAUNCH002×1, TOOL004×7, TOOL009×7 |
| `@modelcontextprotocol/server-everart` | yes | 1 | 0 | 1 | 2 | 1 | TOOL005×1, LAUNCH002×1, TOOL004×1, TOOL009×1 |
| `@modelcontextprotocol/server-redis` | no | - | - | - | - | - | error: MCP error -32000: Connection closed (target stderr: at RedisSocket._RedisSocket_shouldReconnect (C:\Users\GABRIELA APSOL\AppData\Local\npm-cache\_npx\5c1b9cdedadb4486\node_modules\@redis\client\dist\lib\client\socket.js:140:16) | at RedisSocket._RedisSocket_connect (C:\Users\GABRIELA APSOL\AppData\Local\npm-cache\_npx\5c1b9cdedadb4486\node_modules\@redis\client\dist\lib\client\socket.js:162:117) | at process.processTicksAndRejections (node:internal) |
| `@modelcontextprotocol/server-aws-kb-retrieval` | yes | 1 | 0 | 1 | 2 | 1 | TOOL005×1, LAUNCH002×1, TOOL004×1, TOOL009×1 |
| `firecrawl-mcp` | yes | 26 | 0 | 1 | 8 | 0 | TOOL011×1, LAUNCH002×1, TOOL007×1, TOOL010×6 |
| `exa-mcp-server` | yes | 2 | 0 | 0 | 6 | 0 | LAUNCH002×1, MUT001×1, TOOL004×2, TOOL010×2 |
| `tavily-mcp` | yes | 5 | 0 | 5 | 6 | 5 | TOOL005×5, LAUNCH002×1, TOOL004×5, TOOL009×5 |
| `airtable-mcp-server` | yes | 16 | 0 | 1 | 24 | 16 | TOOL011×1, LAUNCH002×1, MUT001×1, TOOL004×16, TOOL010×6, TOOL009×16 |
| `@upstash/context7-mcp` | yes | 2 | 0 | 0 | 4 | 2 | LAUNCH002×1, MUT001×1, TOOL004×2, TOOL009×2 |
| `@playwright/mcp` | yes | 24 | 0 | 1 | 2 | 0 | TOOL011×1, LAUNCH002×1, TOOL010×1 |
| `@notionhq/notion-mcp-server` | yes | 24 | 0 | 1 | 7 | 24 | TOOL011×1, LAUNCH002×1, TOOL010×6, TOOL009×24 |
| `figma-developer-mcp` | yes | 2 | 0 | 1 | 5 | 0 | TOOL005×1, LAUNCH002×1, MUT001×1, TOOL004×2, TOOL010×1 |
| `@browsermcp/mcp` | yes | 12 | 0 | 12 | 14 | 0 | TOOL005×12, LAUNCH002×1, TOOL004×12, TOOL010×1 |
| `mcp-server-kubernetes` | no | - | - | - | - | - | error: MCP initialization exceeded 60000 ms. (target stderr: npm warn deprecated node-domexception@1.0.0: Use your platform's native DOMException instead | npm warn deprecated glob@10.5.0: Old versions of glob are not supported, and contain widely publicized security vulnerabilities, which have been fixed in the current version. Please update. Support for old versions may be purchased (at exorbitant rates) by contacting i@izs.me) |

Reproduce: `npm run scan:registry` (add `--sandbox docker` for untrusted servers). The server
list is `corpus/registry.json`.
