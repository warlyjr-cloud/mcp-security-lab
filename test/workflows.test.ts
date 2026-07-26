import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

const SHA_PIN = /@[0-9a-f]{40}$/;

test("all GitHub workflows parse and pin external actions by immutable SHA", async () => {
  const workflowDirectory = ".github/workflows";
  const files = (await readdir(workflowDirectory))
    .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
    .sort();

  assert.ok(files.length >= 7);

  for (const file of files) {
    const workflow = parse(
      await readFile(`${workflowDirectory}/${file}`, "utf8"),
    ) as Record<string, any>;
    assert.equal(typeof workflow.name, "string", `${file} requires a name`);
    assert.equal(typeof workflow.jobs, "object", `${file} requires jobs`);

    for (const job of Object.values(workflow.jobs) as Array<Record<string, any>>) {
      assert.equal(
        typeof job["timeout-minutes"],
        "number",
        `${file} jobs require timeout-minutes`,
      );
      for (const step of job.steps ?? []) {
        if (
          typeof step.uses === "string" &&
          !step.uses.startsWith("./") &&
          !step.uses.startsWith("docker://")
        ) {
          assert.match(
            step.uses,
            SHA_PIN,
            `${file} must pin ${step.uses} to a full commit SHA`,
          );
        }
      }
    }
  }
});
