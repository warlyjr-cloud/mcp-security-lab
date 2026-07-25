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
  assert.equal(report.server?.toolCount, 2);
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

  assert.deepEqual(report.target.args, ["server.js", "--token", "[REDACTED]"]);
  assert.equal(JSON.stringify(report).includes("sensitive-value"), false);
});
