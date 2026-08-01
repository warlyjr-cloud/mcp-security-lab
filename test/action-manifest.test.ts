import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

test("GitHub Action manifest is valid and uploads SARIF with the current major action", async () => {
  // The manifest is dynamic YAML; `any` lets the test assert its shape directly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const manifest = parse(await readFile("action.yml", "utf8")) as Record<string, any>;

  assert.equal(manifest.name, "MCP Security Lab");
  assert.equal(manifest.runs.using, "composite");
  // `config` is optional: a caller may instead use the zero-config `package` /
  // `command` shortcuts, which a resolve step turns into a synthesized config.
  assert.equal(manifest.inputs.config.required, false);
  assert.ok(manifest.inputs.package, "package input exists for zero-config runs");
  assert.ok(manifest.inputs.command, "command input exists for zero-config runs");
  assert.ok(
    manifest.runs.steps.some((step: Record<string, unknown>) => step.id === "resolve"),
    "a resolve-config step synthesizes the config from package/command",
  );
  assert.equal(manifest.inputs.execute.default, "false");
  assert.equal(manifest.inputs["upload-sarif"].default, "true");

  const uploadStep = manifest.runs.steps.find(
    (step: Record<string, unknown>) => step.uses === "github/codeql-action/upload-sarif@v4",
  );
  assert.ok(uploadStep, "upload-sarif@v4 step is required");
  assert.equal(uploadStep.with.sarif_file, "${{ steps.scan.outputs.sarif }}");
});
