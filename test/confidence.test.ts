import assert from "node:assert/strict";
import test from "node:test";

import { applyConfidenceFilter } from "../src/cli.js";
import type { Finding, ScanReport } from "../src/types.js";

function reportWith(findings: Finding[]): ScanReport {
  const summary = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return {
    schemaVersion: "1.0",
    scanner: { name: "mcp-security-lab", version: "1.1.0" },
    target: { command: "node", args: [], cwd: "." },
    execution: {
      requested: true,
      connected: true,
      toolsInvoked: 0,
      transport: "stdio",
      environmentMode: "allowlist",
      osSandboxed: false,
      limitations: [],
    },
    summary,
    findings,
  };
}

const findings: Finding[] = [
  { id: "A", severity: "high", title: "a", evidence: "", recommendation: "", confidence: "high" },
  { id: "B", severity: "medium", title: "b", evidence: "", recommendation: "", confidence: "low" },
  { id: "C", severity: "low", title: "c", evidence: "", recommendation: "" },
];

test("applyConfidenceFilter drops findings below the threshold and keeps unscored ones", () => {
  const filtered = applyConfidenceFilter(reportWith(findings), "medium");
  const ids = filtered.findings.map((finding) => finding.id).sort();
  assert.deepEqual(ids, ["A", "C"]); // B (low) dropped; C (unscored) kept
});

test("applyConfidenceFilter recomputes the summary (unscored findings survive)", () => {
  const filtered = applyConfidenceFilter(reportWith(findings), "high");
  // A (high confidence) and C (unscored) survive; B (low confidence) is dropped.
  assert.deepEqual(
    filtered.findings.map((finding) => finding.id),
    ["A", "C"],
  );
  assert.equal(filtered.summary.high, 1); // A
  assert.equal(filtered.summary.medium, 0); // B dropped
  assert.equal(filtered.summary.low, 1); // C
});

test("applyConfidenceFilter at low keeps everything", () => {
  const filtered = applyConfidenceFilter(reportWith(findings), "low");
  assert.equal(filtered.findings.length, 3);
});
