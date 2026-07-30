import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { z } from "zod";

import { scan } from "../src/scanner.js";

// A real, anonymous MCP server over Streamable HTTP (stateless JSON mode: a
// fresh server + transport per request, as the SDK requires).
async function withMcpHttpServer(run: (url: string) => Promise<void>): Promise<void> {
  const server = http.createServer((req, res) => {
    const mcp = new McpServer({ name: "integration-remote", version: "1.0.0" });
    mcp.registerTool(
      "list_things",
      {
        description: "List things.",
        inputSchema: { limit: z.number().optional() },
        annotations: { title: "List things", readOnlyHint: true, destructiveHint: false },
      },
      async () => ({ content: [{ type: "text", text: "[]" }] }),
    );
    // No sessionIdGenerator => stateless mode (a fresh transport per request).
    const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });
    // The SDK transport doesn't satisfy its own Transport type under
    // exactOptionalPropertyTypes; the cast is safe.
    void mcp.connect(transport as Transport).then(() => transport.handleRequest(req, res));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  try {
    await run(url);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

// A plain HTTP endpoint that does NOT speak MCP.
async function withPlainHttpServer(run: (url: string) => Promise<void>): Promise<void> {
  const server = http.createServer((_req, res) => {
    res.setHeader("content-type", "application/json");
    res.end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
  try {
    await run(url);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("a remote --execute scan connects and flags unauthenticated access (REMOTE004)", async () => {
  await withMcpHttpServer(async (url) => {
    const report = await scan(
      { target: { url, transport: "http" }, policy: { timeoutMs: 5_000, maxTools: 50 } },
      true,
    );
    assert.equal(report.execution.connected, true);
    assert.equal(report.execution.transport, "http");
    assert.equal(report.server?.toolCount, 1);
    assert.ok(report.findings.some((finding) => finding.id === "REMOTE004"));
  });
});

test("a remote scan never reports osSandboxed, even when --sandbox docker is passed", async () => {
  await withMcpHttpServer(async (url) => {
    // The Docker sandbox only wraps a local stdio process; a remote target is
    // reached over the network and is never OS-sandboxed. The report must say so
    // regardless of the sandbox argument.
    const report = await scan(
      { target: { url, transport: "http" }, policy: { timeoutMs: 5_000, maxTools: 50 } },
      true,
      "docker",
    );
    assert.equal(report.execution.connected, true);
    assert.equal(report.execution.osSandboxed, false);
    assert.equal(report.execution.toolsInvoked, 0);
    assert.ok(
      report.execution.limitations.some((line) => /not OS-sandboxed/.test(line)),
      "remote limitations must state the target is not OS-sandboxed",
    );
  });
});

test("--fuzz against a remote URL is refused (no sandbox can isolate it)", async () => {
  await assert.rejects(
    scan(
      { target: { url: "https://example.com/mcp", transport: "http" }, policy: { timeoutMs: 3_000, maxTools: 50 } },
      true,
      "docker",
      true,
    ),
    /--fuzz cannot target a remote URL/,
  );
});

test("a remote target that does not complete the handshake yields EXEC002, not a crash", async () => {
  await withPlainHttpServer(async (url) => {
    const report = await scan(
      { target: { url, transport: "http" }, policy: { timeoutMs: 3_000, maxTools: 50 } },
      true,
    );
    assert.equal(report.execution.connected, false);
    assert.ok(report.findings.some((finding) => finding.id === "EXEC002"));
    // An open, non-MCP endpoint is not challenged, so no anonymous-access finding.
    assert.equal(
      report.findings.some((finding) => finding.id === "REMOTE004"),
      false,
    );
  });
});
