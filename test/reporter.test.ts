import assert from "node:assert/strict";
import test from "node:test";

import {
  reportAsJson,
  reportAsSarif,
  reportAsText,
} from "../src/reporter.js";
import { createFinding } from "../src/rules/catalog.js";
import type { ScanReport } from "../src/types.js";

const report: ScanReport = {
  schemaVersion: "2.0",
  scanner: {
    name: "mcp-security-lab",
    version: "0.3.0",
    rulesVersion: "2026.07",
  },
  policy: {
    profile: "balanced",
    failureThreshold: "high",
  },
  target: {
    transport: "stdio",
    command: "node",
    args: ["server.js"],
    cwd: ".",
  },
  execution: {
    requested: true,
    connected: true,
    toolsInvoked: 0,
    environmentMode: "allowlist",
    osSandboxed: false,
    sandbox: {
      adapter: "none",
      verified: false,
      network: "host",
    },
    metadataMethods: ["initialize", "tools/list"],
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
    createFinding("TOOL003", "Matched override pattern.", "tool:unsafe"),
    createFinding("TOOL003", "Matched concealment pattern.", "tool:unsafe"),
  ],
};

test("SARIF output is version 2.1.0 with deduplicated rules and stable unique fingerprints", () => {
  const first = JSON.parse(reportAsSarif(report, "examples/server.json", process.cwd()));
  const second = JSON.parse(reportAsSarif(report, "examples/server.json", process.cwd()));

  assert.equal(first.version, "2.1.0");
  assert.equal(first.runs[0].automationDetails.id, "mcp-security-lab/2026.07/");
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

test("text and JSON reports expose policy and verified execution facts", () => {
  const text = reportAsText(report);
  const json = JSON.parse(reportAsJson(report));

  assert.match(text, /Policy: balanced \(fail at high\)/);
  assert.match(text, /Tools invoked: 0/);
  assert.match(text, /Sandbox: none \(not verified\)/);
  assert.equal(json.schemaVersion, "2.0");
  assert.equal(json.execution.toolsInvoked, 0);
});

test("text reports neutralize line injection in target arguments", () => {
  const injected: ScanReport = {
    ...report,
    target: {
      transport: "stdio",
      command: "node",
      args: ["server.js\nFAKE: clean"],
      cwd: ".",
    },
  };

  const text = reportAsText(injected);
  assert.doesNotMatch(text, /\nFAKE: clean/);
  assert.match(text, /server\.js FAKE: clean/);
});
