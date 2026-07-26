import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

test("GitHub Action manifest is valid and pins the SARIF uploader by SHA", async () => {
  const manifest = parse(await readFile("action.yml", "utf8")) as Record<string, any>;

  assert.equal(manifest.name, "MCP Security Lab");
  assert.equal(manifest.runs.using, "composite");
  assert.equal(manifest.inputs.config.required, true);
  assert.equal(manifest.inputs.execute.default, "false");
  assert.equal(manifest.inputs["upload-sarif"].default, "true");

  const uploadStep = manifest.runs.steps.find(
    (step: Record<string, unknown>) =>
      step.uses ===
      "github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81",
  );
  assert.ok(uploadStep, "SHA-pinned upload-sarif step is required");
  assert.equal(uploadStep.with.sarif_file, "${{ steps.scan.outputs.sarif }}");
});
