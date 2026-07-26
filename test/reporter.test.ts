import assert from "node:assert/strict";
import test from "node:test";

import { reportAsSarif, reportAsText } from "../src/reporter.js";
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
      cwe: "CWE-77",
      owasp: "LLM01",
    },
    {
      id: "TOOL003",
      severity: "high",
      title: "Prompt-like instruction",
      evidence: "Matched concealment pattern.",
      recommendation: "Remove behavioral instructions.",
      location: "tool:unsafe",
      cwe: "CWE-77",
      owasp: "LLM01",
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

test("SARIF emits CWE and OWASP taxonomy on rules and results", () => {
  const sarif = JSON.parse(reportAsSarif(report, "examples/server.json", process.cwd()));
  const rule = sarif.runs[0].tool.driver.rules[0];
  assert.ok(rule.properties.tags.includes("external/cwe/cwe-77"));
  assert.ok(rule.properties.tags.includes("external/owasp-llm/llm01"));
  assert.equal(rule.properties.cwe, "CWE-77");
  assert.equal(sarif.runs[0].results[0].properties.cwe, "CWE-77");
  assert.equal(sarif.runs[0].results[0].properties.owasp, "LLM01");
});

test("text report reflects the real sandbox state", () => {
  const withoutSandbox = reportAsText(report);
  assert.match(withoutSandbox, /OS sandbox: no/);

  const sandboxed = reportAsText({
    ...report,
    execution: { ...report.execution, osSandboxed: true },
  });
  assert.match(sandboxed, /OS sandbox: yes/);
  assert.match(sandboxed, /network-isolated Docker container/);
});
