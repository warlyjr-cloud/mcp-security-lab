import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const CLI = resolve("dist/src/cli.js");

function runCli(
  args: string[],
  options: { cwd?: string; env?: NodeJS.ProcessEnv } = {},
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    ...(options.env === undefined ? {} : { env: options.env }),
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("usage documents the --sandbox and --fuzz flags", () => {
  const result = runCli([]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--sandbox/);
  assert.match(result.stderr, /--fuzz/);
});

test("an unknown flag is rejected with usage", () => {
  const result = runCli(["scan", "--config", "x.json", "--nope"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unknown argument: --nope/);
});

test("--fuzz without --sandbox docker fails safely", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--execute",
    "--fuzz",
  ]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires --sandbox docker/);
});

test("a launch-only scan reports OS sandbox: no in text output", () => {
  const result = runCli(["scan", "--config", resolve("examples/insecure-server.json")]);
  // Launch-only scan of the example emits EXEC001 (info) only -> exit 0.
  assert.match(result.stdout, /OS sandbox: no/);
});

test("--config without a value is rejected", () => {
  const result = runCli(["scan", "--config"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--config requires a value/);
});

test("missing --config is rejected", () => {
  const result = runCli(["scan"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--config is required/);
});

test("an invalid --sandbox value is rejected", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--sandbox",
    "vm",
  ]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--sandbox must be docker or none/);
});

test("an invalid --format value is rejected", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--format",
    "yaml",
  ]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--format must be text, json, sarif, markdown, or dashboard/);
});

test("--format json emits a parseable report", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--format",
    "json",
  ]);
  const report = JSON.parse(result.stdout) as { schemaVersion: string };
  assert.equal(report.schemaVersion, "1.0");
});

test("--format sarif emits SARIF 2.1.0", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--format",
    "sarif",
  ]);
  const sarif = JSON.parse(result.stdout) as { version: string };
  assert.equal(sarif.version, "2.1.0");
});

test("--format markdown emits a markdown report", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--format",
    "markdown",
  ]);
  assert.match(result.stdout, /^# MCP Security Lab/);
});

test("--output writes the report to a file instead of stdout", () => {
  const directory = mkdtempSync(join(tmpdir(), "mcp-security-lab-cli-"));
  const outputPath = join(directory, "report.json");
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--format",
    "json",
    "--output",
    outputPath,
  ]);
  assert.match(result.stdout, /Report written to/);
  assert.ok(existsSync(outputPath));
  const report = JSON.parse(readFileSync(outputPath, "utf8")) as { schemaVersion: string };
  assert.equal(report.schemaVersion, "1.0");
});

test("--generate-firewall writes a firewall policy alongside the report", () => {
  const directory = mkdtempSync(join(tmpdir(), "mcp-security-lab-cli-"));
  const firewallPath = join(directory, "mcp-firewall.json");
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--generate-firewall",
    firewallPath,
  ]);
  assert.match(result.stdout, /Firewall policy generated at/);
  const policy = JSON.parse(readFileSync(firewallPath, "utf8")) as { generatedBy: string };
  assert.equal(policy.generatedBy, "MCP Security Lab (MCP Verifier)");
});

test("--sandbox none is accepted explicitly", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--sandbox",
    "none",
  ]);
  assert.equal(result.status, 0);
});

test("usage documents the --sandbox-network flag", () => {
  const result = runCli([]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--sandbox-network/);
});

test("an invalid --sandbox-network value is rejected", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--sandbox-network",
    "host",
  ]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--sandbox-network must be none or bridge/);
});

test("--sandbox-network none is accepted explicitly", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--sandbox-network",
    "none",
  ]);
  assert.equal(result.status, 0);
});

test("--sandbox-network bridge without --sandbox docker is rejected", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--execute",
    "--sandbox-network",
    "bridge",
  ]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--sandbox-network requires --sandbox docker/);
});

test("--fuzz with a relaxed --sandbox-network is rejected", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--execute",
    "--sandbox",
    "docker",
    "--sandbox-network",
    "bridge",
    "--fuzz",
  ]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /--sandbox-network must be none when --fuzz is set/);
});

test("--ai-fuzz is accepted without requiring --fuzz", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--ai-fuzz",
  ]);
  assert.equal(result.status, 0);
});

test("--auto-fix skips AI remediation gracefully without an API key", () => {
  const directory = mkdtempSync(join(tmpdir(), "mcp-security-lab-cli-"));
  const result = runCli(
    ["scan", "--config", resolve("examples/insecure-server.json"), "--auto-fix"],
    { cwd: directory, env: { ...process.env, ANTHROPIC_API_KEY: "" } },
  );
  assert.match(result.stdout, /Verified remediation saved to MCP_REMEDIATION.md/);
  const plan = readFileSync(join(directory, "MCP_REMEDIATION.md"), "utf8");
  assert.match(plan, /Skipping verified remediation: ANTHROPIC_API_KEY is not set/);
});

test("exit code is 2 when the scan finds high or critical issues", () => {
  const result = runCli([
    "scan",
    "--config",
    resolve("examples/insecure-server.json"),
    "--execute",
  ]);
  assert.equal(result.status, 2);
});
