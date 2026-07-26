import assert from "node:assert/strict";
import test from "node:test";

import { runBenchmark } from "../src/benchmark.js";

test("public synthetic benchmark meets precision and recall thresholds", async () => {
  const report = await runBenchmark("benchmarks/manifest.json", true);

  assert.equal(report.thresholds.passed, true);
  assert.equal(report.metrics.precision, 1);
  assert.equal(report.metrics.recall, 1);
  assert.equal(report.metrics.falsePositives, 0);
  assert.equal(report.metrics.falseNegatives, 0);
});

test("benchmark refuses dynamic cases without separate consent", async () => {
  await assert.rejects(
    runBenchmark("benchmarks/manifest.json", false),
    /requires --consent-synthetic-execution/,
  );
});
