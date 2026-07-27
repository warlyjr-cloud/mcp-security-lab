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

test("malformed JSON is rejected with a clear error", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcp-security-lab-"));
  const configPath = join(directory, "config.json");
  await writeFile(configPath, "{ not valid json", "utf8");
  await assert.rejects(loadConfig(configPath), /Config is not valid JSON/);
});

test("a config that is not a JSON object is rejected", async () => {
  const configPath = await writeConfig(["not", "an", "object"]);
  await assert.rejects(loadConfig(configPath), /Config must be a JSON object/);
});

test("target.url must be a string when provided", async () => {
  const configPath = await writeConfig({ target: { url: 12345 } });
  await assert.rejects(loadConfig(configPath), /target.url must be a string/);
});

test("target.command is required when url is not provided", async () => {
  const configPath = await writeConfig({ target: { cwd: "." } });
  await assert.rejects(
    loadConfig(configPath),
    /target.command must be a non-empty string when url is not provided/,
  );
});

test("target.args must be an array of strings", async () => {
  const configPath = await writeConfig({ target: { command: "node", args: [1, 2] } });
  await assert.rejects(loadConfig(configPath), /target.args must be an array of strings/);
});

test("target.cwd must be a non-empty string", async () => {
  const configPath = await writeConfig({ target: { command: "node", cwd: "   " } });
  await assert.rejects(loadConfig(configPath), /target.cwd must be a non-empty string/);
});

test("policy.timeoutMs and policy.maxTools reject out-of-range values", async () => {
  const badTimeout = await writeConfig({
    target: { command: "node", args: [] },
    policy: { timeoutMs: -1 },
  });
  await assert.rejects(loadConfig(badTimeout), /policy.timeoutMs must be an integer between 1 and/);

  const badMaxTools = await writeConfig({
    target: { command: "node", args: [] },
    policy: { maxTools: 1.5 },
  });
  await assert.rejects(loadConfig(badMaxTools), /policy.maxTools must be an integer between 1 and/);
});
