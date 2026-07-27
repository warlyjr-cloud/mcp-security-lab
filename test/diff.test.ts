import assert from "node:assert/strict";
import test from "node:test";

import { diffReports } from "../src/diff.js";
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

function finding(id: string, location: string): Finding {
  return { id, severity: "high", title: id, evidence: "", recommendation: "", location };
}

test("diffReports classifies resolved, remaining, and introduced findings", () => {
  const baseline = reportWith([
    finding("TOOL003", "tool:a"),
    finding("AUTH006", "tool:b"),
  ]);
  const current = reportWith([
    finding("AUTH006", "tool:b"), // remaining
    finding("RES001", "resource-template:c"), // introduced
  ]);

  const diff = diffReports(baseline, current);
  assert.deepEqual(
    diff.resolved.map((f) => f.id),
    ["TOOL003"],
  );
  assert.deepEqual(
    diff.remaining.map((f) => f.id),
    ["AUTH006"],
  );
  assert.deepEqual(
    diff.introduced.map((f) => f.id),
    ["RES001"],
  );
});

test("diffReports keys on rule id plus location", () => {
  const baseline = reportWith([finding("TOOL004", "tool:a")]);
  const current = reportWith([finding("TOOL004", "tool:b")]);
  const diff = diffReports(baseline, current);
  // Same rule, different location => one resolved, one introduced.
  assert.equal(diff.resolved.length, 1);
  assert.equal(diff.introduced.length, 1);
  assert.equal(diff.remaining.length, 0);
});
