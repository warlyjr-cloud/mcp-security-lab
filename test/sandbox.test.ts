import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDockerTarget,
  createExecutionPlan,
} from "../src/sandbox.js";
import type {
  SandboxConfig,
  StdioTargetConfig,
} from "../src/types.js";

const target: StdioTargetConfig = {
  transport: "stdio",
  command: "node",
  args: ["server.js"],
  cwd: "C:\\synthetic project",
};

const sandbox: SandboxConfig = {
  adapter: "docker",
  image: "node@sha256:synthetic",
  network: "none",
  memoryMb: 384,
  cpus: 0.5,
  pidsLimit: 64,
};

test("Docker target applies bounded read-only isolation and canary mounts", () => {
  const wrapped = buildDockerTarget(target, sandbox, {
    hostDirectory: "C:\\synthetic canary",
    token: "mcpsl_synthetic",
  });
  const joined = wrapped.args.join(" ");

  assert.equal(wrapped.command, "docker");
  assert.match(joined, /--network none/);
  assert.match(joined, /--read-only/);
  assert.match(joined, /--cap-drop ALL/);
  assert.match(joined, /no-new-privileges/);
  assert.match(joined, /--pids-limit 64/);
  assert.match(joined, /--memory 384m/);
  assert.match(joined, /--cpus 0\.5/);
  assert.match(joined, /C:\\synthetic project:\/workspace:ro/);
  assert.match(joined, /C:\\synthetic canary:\/mcp-security-lab-canary:ro/);
  assert.match(joined, /MCP_SECURITY_LAB_CANARY_TOKEN=mcpsl_synthetic/);
});

test("direct execution plan reports that OS isolation is not verified", async () => {
  const plan = await createExecutionPlan(
    target,
    { ...sandbox, adapter: "none" },
    1_000,
  );

  assert.equal(plan.target, target);
  assert.deepEqual(plan.sandbox, {
    adapter: "none",
    verified: false,
    network: "host",
  });
  assert.deepEqual(plan.findings.map((finding) => finding.id), ["SANDBOX001"]);
});
