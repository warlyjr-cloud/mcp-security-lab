import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import { scan } from "../src/scanner.js";

test("scanner discovers metadata without invoking fixture tools", async () => {
  const report = await scan(
    {
      target: {
        command: process.execPath,
        args: [resolve("dist/test/fixtures/insecure-server.js")],
        cwd: process.cwd(),
      },
      policy: {
        timeoutMs: 5_000,
        maxTools: 10,
      },
    },
    true,
  );

  assert.equal(report.execution.connected, true);
  assert.equal(report.execution.toolsInvoked, 0);
  assert.equal(report.execution.metadataMethods.includes("tools/list"), true);
  assert.equal(report.server?.toolCount, 2);
  assert.equal(report.server?.protocolVersion !== undefined, true);
  assert.ok(report.findings.some((finding) => finding.id === "TOOL003"));
  assert.ok(report.findings.some((finding) => finding.id === "TOOL006"));
});

test("scanner report never exposes sensitive launcher arguments", async () => {
  const report = await scan(
    {
      target: {
        command: "node",
        args: ["server.js", "--token", "sensitive-value"],
        cwd: process.cwd(),
      },
      policy: {
        timeoutMs: 5_000,
        maxTools: 10,
      },
    },
    false,
  );

  assert.equal(report.target.transport, "stdio");
  if (report.target.transport !== "stdio") {
    throw new Error("Expected stdio target.");
  }
  assert.deepEqual(report.target.args, ["server.js", "--token", "[REDACTED]"]);
  assert.equal(JSON.stringify(report).includes("sensitive-value"), false);
});

test("remote private-network block is returned as a bounded finding", async () => {
  const report = await scan(
    {
      target: {
        transport: "streamable-http",
        url: "https://10.0.0.1/mcp",
      },
      policy: {
        timeoutMs: 1_000,
        maxTools: 10,
        allowPrivateNetwork: false,
      },
    },
    true,
  );

  assert.equal(report.execution.connected, false);
  assert.equal(report.findings.some((finding) => finding.id === "EXEC002"), true);
  assert.match(
    report.findings.find((finding) => finding.id === "EXEC002")?.evidence ?? "",
    /private address/,
  );
});
