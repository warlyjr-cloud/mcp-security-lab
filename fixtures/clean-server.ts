import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// A well-behaved, read-only server used as the "clean" corpus baseline. It has
// accurate safety annotations, pagination, closed schemas, no injection text,
// no credential parameters, and no read+write mix — so it should produce no
// high-severity findings.
const server = new McpServer({
  name: "synthetic-clean-fixture",
  version: "1.0.0",
});

server.registerTool(
  "list_documents",
  {
    description: "List documents in the workspace.",
    inputSchema: {
      limit: z.number().max(50).default(10),
      cursor: z.string().optional(),
    },
    annotations: {
      title: "List documents",
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  async () => ({
    content: [{ type: "text", text: "[]" }],
  }),
);

server.registerTool(
  "get_document",
  {
    description: "Fetch a single document by id.",
    inputSchema: {
      id: z.string(),
    },
    annotations: {
      title: "Get document",
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  async () => ({
    content: [{ type: "text", text: "{}" }],
  }),
);

await server.connect(new StdioServerTransport());
