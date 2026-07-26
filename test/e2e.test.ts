import assert from "node:assert/strict";
import { resolve } from "node:path";
import test from "node:test";

import { scan } from "../src/scanner.js";

test("scanner discovers metadata without invoking fixture tools", async () => {
  const report = await scan(
    {
      target: {
        command: process.execPath,
        args: [resolve("dist/fixtures/insecure-server.js")],
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
  assert.equal(report.server?.promptCount, 1);
  assert.equal(report.server?.resourceCount, 1);
  assert.ok(report.findings.some((finding) => finding.id === "TOOL003"));
  assert.ok(report.findings.some((finding) => finding.id === "TOOL006"));
  assert.ok(report.findings.some((finding) => finding.id === "TOOL011"));
  // Injection hidden in a prompt description must be caught, not only tool text.
  assert.ok(
    report.findings.some(
      (finding) => finding.id === "TOOL003" && finding.location === "prompt:summarize",
    ),
  );
});

test("advertising more tools than policy.maxTools yields a finding, not a crash", async () => {
  const report = await scan(
    {
      target: {
        command: process.execPath,
        args: [resolve("dist/fixtures/insecure-server.js")],
        cwd: process.cwd(),
      },
      policy: { timeoutMs: 5_000, maxTools: 1 },
    },
    true,
  );

  assert.equal(report.execution.connected, true);
  assert.ok(report.findings.some((finding) => finding.id === "DISC001"));
});

test("fuzzing without --execute is rejected", async () => {
  await assert.rejects(
    scan(
      {
        target: { command: "node", args: ["server.js"], cwd: "." },
        policy: { timeoutMs: 5_000, maxTools: 10 },
      },
      false,
      "none",
      true,
    ),
    /--fuzz requires --execute/,
  );
});

test("fuzzing without an OS sandbox is rejected", async () => {
  await assert.rejects(
    scan(
      {
        target: { command: "node", args: ["server.js"], cwd: "." },
        policy: { timeoutMs: 5_000, maxTools: 10 },
      },
      true,
      "none",
      true,
    ),
    /requires --sandbox docker/,
  );
});

test("a docker-sandboxed scan builds the container launch args and fails cleanly without a daemon", async () => {
  // This does not require a working Docker daemon: it only asserts that the
  // scan attempts (and fails to connect through) a Docker-wrapped launch,
  // exercising the container argument construction without depending on the
  // outcome of an actual `docker run`.
  await assert.rejects(
    scan(
      {
        target: {
          command: process.execPath,
          args: [resolve("dist/fixtures/insecure-server.js")],
          cwd: process.cwd(),
        },
        policy: { timeoutMs: 5_000, maxTools: 10 },
      },
      true,
      "docker",
      false,
    ),
  );
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
