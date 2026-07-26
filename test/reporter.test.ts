import assert from "node:assert/strict";
import test from "node:test";

import { reportAsSarif } from "../src/reporter.js";
import type { ScanReport } from "../src/types.js";

const report: ScanReport = {
  schemaVersion: "1.0",
  scanner: {
    name: "mcp-security-lab",
    version: "0.2.0",
  },
  target: {
    command: "node",
    args: ["server.js"],
    cwd: ".",
  },
  execution: {
    requested: true,
    connected: true,
    toolsInvoked: 0,
    transport: "stdio",
    environmentMode: "allowlist",
    osSandboxed: false,
    limitations: [],
  },
  summary: {
    info: 0,
    low: 0,
    medium: 0,
    high: 2,
    critical: 0,
  },
  findings: [
    {
      id: "TOOL003",
      severity: "high",
      title: "Prompt-like instruction",
      evidence: "Matched override pattern.",
      recommendation: "Remove behavioral instructions.",
      location: "tool:unsafe",
    },
    {
      id: "TOOL003",
      severity: "high",
      title: "Prompt-like instruction",
      evidence: "Matched concealment pattern.",
      recommendation: "Remove behavioral instructions.",
      location: "tool:unsafe",
    },
  ],
};

test("SARIF output is version 2.1.0 with deduplicated rules and stable unique fingerprints", () => {
  const first = JSON.parse(reportAsSarif(report, "examples/server.json", process.cwd()));
  const second = JSON.parse(reportAsSarif(report, "examples/server.json", process.cwd()));

  assert.equal(first.version, "2.1.0");
  assert.equal(first.runs[0].tool.driver.rules.length, 1);
  assert.equal(first.runs[0].results.length, 2);
  assert.equal(
    first.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    "examples/server.json",
  );
  assert.notEqual(
    first.runs[0].results[0].partialFingerprints["mcpSecurityLab/v1"],
    first.runs[0].results[1].partialFingerprints["mcpSecurityLab/v1"],
  );
  assert.deepEqual(first, second);
});
