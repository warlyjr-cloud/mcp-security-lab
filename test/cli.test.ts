import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

const CLI = resolve("dist/src/cli.js");

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
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
