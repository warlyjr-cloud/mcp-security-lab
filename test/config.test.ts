import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { loadConfig } from "../src/config.js";

async function writeConfig(value: unknown): Promise<{
  directory: string;
  path: string;
}> {
  const directory = await mkdtemp(join(tmpdir(), "mcpsl-config-"));
  const path = join(directory, "config.json");
  await writeFile(path, JSON.stringify(value), "utf8");
  return { directory, path };
}

test("legacy stdio config resolves paths and safe defaults", async (context) => {
  const fixture = await writeConfig({
    target: {
      command: "node",
      args: ["server.js"],
      cwd: "fixture",
    },
  });
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));

  const config = await loadConfig(fixture.path);

  assert.equal(config.target.transport, "stdio");
  assert.ok("command" in config.target);
  assert.equal(config.target.cwd, resolve(fixture.directory, "fixture"));
  assert.deepEqual(config.target.args, ["server.js"]);
  assert.equal(config.policy.timeoutMs, 5_000);
  assert.equal(config.policy.maxTools, 100);
  assert.equal(config.policy.profile, "balanced");
  assert.equal(config.policy.allowPrivateNetwork, false);
  assert.equal(config.sandbox?.adapter, "none");
  assert.equal(config.sandbox?.network, "none");
});

test("streamable HTTP config normalizes URL and custom limits", async (context) => {
  const fixture = await writeConfig({
    target: {
      transport: "streamable-http",
      url: "https://example.test/mcp",
    },
    policy: {
      timeoutMs: 12_000,
      maxTools: 20,
      maxResources: 30,
      maxPrompts: 40,
      maxResponseBytes: 65_536,
      profile: "strict",
      allowPrivateNetwork: true,
    },
  });
  context.after(() => rm(fixture.directory, { recursive: true, force: true }));

  const config = await loadConfig(fixture.path);

  assert.deepEqual(config.target, {
    transport: "streamable-http",
    url: "https://example.test/mcp",
  });
  assert.equal(config.policy.profile, "strict");
  assert.equal(config.policy.maxResources, 30);
  assert.equal(config.policy.allowPrivateNetwork, true);
});

test("config rejects unsupported transports and unsafe bounds", async (context) => {
  const badTransport = await writeConfig({
    target: { transport: "websocket", url: "https://example.test/mcp" },
  });
  const badLimit = await writeConfig({
    target: { command: "node" },
    policy: { maxTools: 1001 },
  });
  context.after(async () => {
    await Promise.all([
      rm(badTransport.directory, { recursive: true, force: true }),
      rm(badLimit.directory, { recursive: true, force: true }),
    ]);
  });

  await assert.rejects(
    loadConfig(badTransport.path),
    /target\.transport must be stdio or streamable-http/,
  );
  await assert.rejects(loadConfig(badLimit.path), /policy\.maxTools/);
});
