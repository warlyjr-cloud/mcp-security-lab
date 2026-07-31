import assert from "node:assert/strict";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { scan } from "../src/scanner.js";

test("without --execute the scanner never spawns the target process", async () => {
  const directory = mkdtempSync(join(tmpdir(), "mcp-safety-"));
  const sentinel = join(directory, "spawned.txt");
  await scan(
    {
      target: {
        command: process.execPath,
        args: ["-e", `require('fs').writeFileSync(${JSON.stringify(sentinel)}, 'x')`],
        cwd: directory,
      },
      policy: { timeoutMs: 5_000, maxTools: 10 },
    },
    false,
  );
  // If the launcher had run, the sentinel would exist. It must not.
  assert.equal(existsSync(sentinel), false);
});

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
  assert.equal(report.server?.toolCount, 3);
  assert.equal(report.server?.promptCount, 1);
  assert.equal(report.server?.resourceCount, 1);
  assert.ok(report.findings.some((finding) => finding.id === "TOOL003"));
  assert.ok(report.findings.some((finding) => finding.id === "TOOL006"));
  assert.ok(report.findings.some((finding) => finding.id === "TOOL011"));
  // The confused-deputy tool (credential + destination) must trip AUTH006 (high).
  const auth006 = report.findings.find((finding) => finding.id === "AUTH006");
  assert.ok(auth006);
  assert.equal(auth006?.severity, "high");
  assert.equal(auth006?.location, "tool:call_upstream");
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

test("a target that dies during initialize surfaces a redacted stderr tail", async () => {
  await assert.rejects(
    scan(
      {
        target: {
          command: process.execPath,
          args: [resolve("dist/fixtures/boot-failure-server.js")],
          cwd: process.cwd(),
        },
        policy: { timeoutMs: 5_000, maxTools: 10 },
      },
      true,
    ),
    (error: Error) => {
      // The actionable reason from the child's stderr is surfaced...
      assert.match(error.message, /target stderr:/);
      assert.match(error.message, /is required to start/);
      // ...but a secret-shaped value in that stderr is redacted, not leaked.
      assert.doesNotMatch(error.message, /figd_secret123/);
      return true;
    },
  );
});

test("the Docker sandbox pins the image by digest and drops privileges", async () => {
  const { SANDBOX_IMAGE, SANDBOX_HARDENING_FLAGS } = await import("../src/scanner.js");
  // Reproducible environment: a floating tag could be silently re-pointed.
  assert.match(SANDBOX_IMAGE, /@sha256:[0-9a-f]{64}$/);
  const flags = SANDBOX_HARDENING_FLAGS.join(" ");
  // Least privilege and a non-writable container: these must not regress.
  assert.match(flags, /--cap-drop ALL/);
  assert.match(flags, /--security-opt no-new-privileges/);
  assert.match(flags, /--read-only/);
  assert.match(flags, /--tmpfs \/tmp:rw,noexec,nosuid/);
  assert.match(flags, /--ipc none/);
  assert.match(flags, /--pids-limit/);
  assert.match(flags, /--memory/);
});
