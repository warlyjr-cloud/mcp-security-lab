// Scan the labeled conformance corpus and report precision / recall.
//
//   expect  rule ids that MUST fire on this target (true positives when found)
//   forbid  rule ids that MUST NOT fire on this target (false positives if found)
//
// Precision = TP / (TP + FP), Recall = TP / (TP + FN). Exits non-zero if any
// expected finding is missing or any forbidden finding is present, so it also
// serves as a detection-regression gate in CI.

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { scan } from "../dist/src/scanner.js";

async function main() {
  const manifest = JSON.parse(await readFile(resolve("corpus/manifest.json"), "utf8"));

  let tp = 0;
  let fp = 0;
  let fn = 0;
  const rows = [];

  for (const entry of manifest.entries) {
    const report = await scan(
      {
        target: {
          command: process.execPath,
          args: [entry.fixture],
          cwd: process.cwd(),
        },
        policy: { timeoutMs: 5000, maxTools: 100 },
      },
      true,
    );
    const detected = new Set(report.findings.map((finding) => finding.id));

    const missing = entry.expect.filter((id) => !detected.has(id));
    const leaked = entry.forbid.filter((id) => detected.has(id));

    tp += entry.expect.length - missing.length;
    fn += missing.length;
    fp += leaked.length;

    rows.push({ name: entry.name, missing, leaked });
  }

  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);

  console.log("MCP Verifier detection benchmark");
  console.log("================================");
  for (const row of rows) {
    const status = row.missing.length === 0 && row.leaked.length === 0 ? "OK" : "FAIL";
    console.log(`  [${status}] ${row.name}`);
    if (row.missing.length) console.log(`     missing (false negatives): ${row.missing.join(", ")}`);
    if (row.leaked.length) console.log(`     leaked  (false positives): ${row.leaked.join(", ")}`);
  }
  console.log("--------------------------------");
  console.log(`  True positives:  ${tp}`);
  console.log(`  False negatives: ${fn}`);
  console.log(`  False positives: ${fp}`);
  console.log(`  Precision: ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall:    ${(recall * 100).toFixed(1)}%`);
  // Always print the sample size next to the rates: on a tiny synthetic corpus
  // "100%" is a regression gate, not a statistical accuracy claim.
  console.log(
    `  Sample:    ${rows.length} corpus cases, ${tp + fn} labeled detections (synthetic; not a statistical claim)`,
  );

  if (fn > 0 || fp > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
