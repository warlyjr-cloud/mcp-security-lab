import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({
  name: "synthetic-secure-fixture",
  version: "1.0.0",
});

server.registerTool(
  "list_items",
  {
    title: "List synthetic items",
    description: "Lists items from a closed, synthetic in-memory catalog.",
    inputSchema: z
      .object({
        query: z.string().describe("Synthetic search text."),
      })
      .strict(),
    outputSchema: z
      .object({
        items: z.array(z.string()),
      })
      .strict(),
    annotations: {
      title: "List synthetic items",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  async () => ({
    content: [{ type: "text", text: "[]" }],
    structuredContent: { items: [] },
  }),
);

server.registerResource(
  "synthetic-catalog",
  "memory://catalog",
  {
    title: "Synthetic catalog",
    description: "A closed in-memory resource containing no user data.",
    mimeType: "application/json",
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "application/json",
        text: "[]",
      },
    ],
  }),
);

server.registerPrompt(
  "summarize_catalog",
  {
    title: "Summarize synthetic catalog",
    description: "Creates a summary request for the synthetic catalog.",
  },
  async () => ({
    messages: [
      {
        role: "user",
        content: { type: "text", text: "Summarize the synthetic catalog." },
      },
    ],
  }),
);

await server.connect(new StdioServerTransport());
