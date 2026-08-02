// Fail CI when a CodeQL SARIF run reports a High or Critical severity finding.
//
//   node scripts/check-codeql-severity.js <sarif-dir> [--threshold 7.0]
//
// GitHub classifies CodeQL security findings by the numeric `security-severity`
// property attached to each rule (Critical >= 9.0, High 7.0-8.9, Medium 4.0-6.9,
// Low < 4.0) -- the same score the Security tab uses to color-code alerts.
// Findings without that property are quality/style rules, not exploit-risk
// findings, and are ignored here.

import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

function arg(flag, fallback) {
  const index = process.argv.indexOf(flag);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

async function main() {
  const dir = process.argv[2];
  if (!dir) {
    console.error("Usage: node scripts/check-codeql-severity.js <sarif-dir> [--threshold 7.0]");
    process.exit(1);
  }
  const threshold = Number(arg("--threshold", "7.0"));

  const files = (await readdir(dir)).filter((file) => file.endsWith(".sarif"));
  if (files.length === 0) {
    console.error(`No .sarif files found in ${dir}.`);
    process.exit(1);
  }

  const severe = [];
  for (const file of files) {
    const sarif = JSON.parse(await readFile(join(dir, file), "utf8"));
    for (const run of sarif.runs ?? []) {
      const rules = new Map();
      for (const rule of run.tool?.driver?.rules ?? []) {
        rules.set(rule.id, rule);
      }
      for (const result of run.results ?? []) {
        const rule = rules.get(result.ruleId);
        const score = Number(rule?.properties?.["security-severity"]);
        if (Number.isFinite(score) && score >= threshold) {
          const location = result.locations?.[0]?.physicalLocation;
          const path = location?.artifactLocation?.uri ?? "unknown";
          const line = location?.region?.startLine ?? "?";
          severe.push({
            rule: result.ruleId,
            score,
            message: result.message?.text ?? "(no message)",
            location: `${path}:${line}`,
          });
        }
      }
    }
  }

  if (severe.length > 0) {
    console.error(`Found ${severe.length} CodeQL finding(s) at or above severity ${threshold}:`);
    for (const finding of severe) {
      console.error(
        `- [${finding.score}] ${finding.rule} @ ${finding.location}: ${finding.message}`,
      );
    }
    process.exit(1);
  }

  console.log(`No CodeQL findings at or above severity ${threshold} in ${files.length} file(s).`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
