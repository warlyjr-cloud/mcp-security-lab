import assert from "node:assert/strict";
import test from "node:test";

import {
  analyzeExerciseResults,
  exerciseTool,
} from "../src/exercise.js";
import type { ScanConfig } from "../src/types.js";

const baseConfig: ScanConfig = {
  target: {
    transport: "stdio",
    command: "node",
    args: ["server.js"],
    cwd: ".",
  },
  policy: {
    timeoutMs: 1_000,
    maxTools: 10,
  },
  sandbox: {
    adapter: "none",
    image: "node:24-bookworm-slim",
    network: "none",
    memoryMb: 256,
    cpus: 1,
    pidsLimit: 64,
  },
};

test("behavior analysis detects canary disclosure and idempotence mismatch", () => {
  const token = "mcpsl_synthetic_canary";
  const result = analyzeExerciseResults(
    [
      JSON.stringify({ value: token, sequence: 1 }),
      JSON.stringify({ value: token, sequence: 2 }),
    ],
    token,
    "unchanged",
    "unchanged",
    true,
    10_000,
  );
  const ids = new Set(result.findings.map((finding) => finding.id));

  assert.equal(result.canaryDisclosed, true);
  assert.equal(result.canaryModified, false);
  assert.equal(ids.has("BEHAVIOR001"), true);
  assert.equal(ids.has("BEHAVIOR002"), true);
  assert.equal(result.digests.length, 2);
});

test("behavior analysis detects canary modification and oversized output", () => {
  const result = analyzeExerciseResults(
    ["x".repeat(32)],
    "not-present",
    "before",
    "after",
    false,
    16,
  );
  const ids = new Set(result.findings.map((finding) => finding.id));

  assert.equal(result.canaryModified, true);
  assert.equal(ids.has("BEHAVIOR004"), true);
  assert.equal(ids.has("BEHAVIOR005"), true);
});

test("exercise rejects calls without consent or verified Docker configuration", async () => {
  await assert.rejects(
    exerciseTool(baseConfig, "read", {}, 1, false),
    /explicit --consent-call/,
  );
  await assert.rejects(
    exerciseTool(baseConfig, "", {}, 1, true),
    /explicit tool name/,
  );
  await assert.rejects(
    exerciseTool(baseConfig, "read", {}, 3, true),
    /must be 1 or 2/,
  );
  await assert.rejects(
    exerciseTool(baseConfig, "read", {}, 1, true),
    /requires sandbox\.adapter=docker/,
  );
});

test("exercise rejects remote targets before any tool call", async () => {
  const remoteConfig: ScanConfig = {
    ...baseConfig,
    target: {
      transport: "streamable-http",
      url: "https://example.test/mcp",
    },
    sandbox: { ...baseConfig.sandbox!, adapter: "docker" },
  };

  await assert.rejects(
    exerciseTool(remoteConfig, "read", {}, 1, true),
    /supports stdio targets only/,
  );
});
