import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

test("GitHub Action manifest is valid and uploads SARIF with the current major action", async () => {
  // The manifest is dynamic YAML; `any` lets the test assert its shape directly.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const manifest = parse(await readFile("action.yml", "utf8")) as Record<string, any>;

  assert.equal(manifest.name, "CyberConsult Advanced Security Suite");
  assert.equal(manifest.runs.using, "composite");
  assert.equal(manifest.inputs.config.required, true);
  assert.equal(manifest.inputs.execute.default, "false");
  assert.equal(manifest.inputs["upload-sarif"].default, "true");

  const uploadStep = manifest.runs.steps.find(
    (step: Record<string, unknown>) => step.uses === "github/codeql-action/upload-sarif@v4",
  );
  assert.ok(uploadStep, "upload-sarif@v4 step is required");
  assert.equal(uploadStep.with.sarif_file, "${{ steps.scan.outputs.sarif }}");
});
