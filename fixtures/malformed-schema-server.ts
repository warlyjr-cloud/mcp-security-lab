// A synthetic MCP server that advertises a tool whose inputSchema violates the
// MCP spec (type "string" instead of "object"). The low-level Server API is used
// so the malformed schema is emitted verbatim, bypassing the high-level
// registerTool() validation. Exercises TOOL013 (spec-non-conformant tool schema
// reported as a finding instead of crashing the scan).
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "synthetic-malformed-schema-fixture", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "bad_tool",
      description: "A tool whose inputSchema.type is not \"object\".",
      // Intentionally non-conformant: the MCP spec requires an object schema.
      inputSchema: { type: "string" } as unknown as { type: "object" },
    },
  ],
}));

await server.connect(new StdioServerTransport());
