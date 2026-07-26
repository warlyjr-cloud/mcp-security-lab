import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadConfig } from "../src/config.js";

async function writeConfig(contents: unknown): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "mcp-security-lab-"));
  const configPath = join(directory, "config.json");
  await writeFile(configPath, JSON.stringify(contents), "utf8");
  return configPath;
}

test("target.env accepts additional variables", async () => {
  const configPath = await writeConfig({
    target: { command: "node", args: ["server.js"], env: { EXAMPLE_TOKEN: "value" } },
  });

  const config = await loadConfig(configPath);

  assert.deepEqual(config.target.env, { EXAMPLE_TOKEN: "value" });
});

test("target.env cannot override the sanitized environment", async () => {
  const reserved = ["PATH", "HOME", "MCP_SECURITY_LAB", "NODE_OPTIONS", "LD_PRELOAD"];

  for (const key of reserved) {
    const configPath = await writeConfig({
      target: { command: "node", env: { [key]: "injected" } },
    });

    await assert.rejects(loadConfig(configPath), /reserved by the sanitized environment/);
  }
});

test("target.env rejects invalid variable names", async () => {
  const configPath = await writeConfig({
    target: { command: "node", env: { "not a name": "value" } },
  });

  await assert.rejects(loadConfig(configPath), /not a valid environment variable name/);
});

test("target.env rejects non-string values", async () => {
  const configPath = await writeConfig({
    target: { command: "node", env: { EXAMPLE_TOKEN: 1 } },
  });

  await assert.rejects(loadConfig(configPath), /must be a string/);
});

test("remote target defaults to the http transport", async () => {
  const configPath = await writeConfig({ target: { url: "https://example.com/mcp" } });
  const config = await loadConfig(configPath);
  assert.equal(config.target.transport, "http");
});

test("remote target accepts the sse transport", async () => {
  const configPath = await writeConfig({
    target: { url: "https://example.com/mcp", transport: "sse" },
  });
  const config = await loadConfig(configPath);
  assert.equal(config.target.transport, "sse");
});

test("an invalid transport is rejected", async () => {
  const configPath = await writeConfig({
    target: { url: "https://example.com/mcp", transport: "grpc" },
  });
  await assert.rejects(loadConfig(configPath), /must be "http" or "sse"/);
});
