import assert from "node:assert/strict";
import test from "node:test";

import { generateFirewallPolicy } from "../src/firewall/generator.js";
import type { ScanReport } from "../src/types.js";

function reportWith(findings: ScanReport["findings"]): ScanReport {
  const summary = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return {
    schemaVersion: "1.0",
    scanner: { name: "mcp-security-lab", version: "1.0.0" },
    target: { command: "node", args: ["server.js"], cwd: "." },
    execution: {
      requested: true,
      connected: true,
      toolsInvoked: 1,
      transport: "stdio",
      environmentMode: "allowlist",
      osSandboxed: false,
      limitations: [],
    },
    summary,
    findings,
  };
}

test("firewall policy denies tools named in critical/high finding titles", () => {
  const report = reportWith([
    {
      id: "FUZZ001",
      severity: "critical",
      title: 'Server crash on malicious input for tool "delete_everything"',
      evidence: "crashed",
      recommendation: "validate input",
      location: "tool:delete_everything",
    },
  ]);

  const policy = generateFirewallPolicy(report);

  assert.equal(policy.$schema, "https://mcp-security-lab.github.io/schemas/firewall-v1.json");
  assert.equal(policy.version, "1.0");
  assert.equal(policy.generatedBy, "CyberConsult Advanced Security Suite (MCP Verifier)");
  assert.equal(policy.target, "node");
  const rules = policy.rules as { tools: { deny: string[]; allow: string[] } };
  assert.deepEqual(rules.tools.deny, ["delete_everything"]);
  assert.deepEqual(rules.tools.allow, ["*"]);
  const threatContext = policy.threatContext as { criticalFindings: number; highFindings: number };
  assert.equal(threatContext.criticalFindings, 1);
  assert.equal(threatContext.highFindings, 0);
});

test("firewall policy ignores medium/low findings and titles without a tool name", () => {
  const report = reportWith([
    {
      id: "TOOL010",
      severity: "medium",
      title: "Context Exhaustion Risk: Missing pagination limits",
      evidence: "missing pagination",
      recommendation: "add pagination",
      location: "tool:list_items",
    },
  ]);

  const policy = generateFirewallPolicy(report);
  const rules = policy.rules as { tools: { deny: string[] } };
  assert.deepEqual(rules.tools.deny, []);
});

test("firewall policy has no denied tools when there are no findings", () => {
  const policy = generateFirewallPolicy(reportWith([]));
  const rules = policy.rules as { tools: { deny: string[] }; rateLimit: { enabled: boolean } };
  assert.deepEqual(rules.tools.deny, []);
  assert.equal(rules.rateLimit.enabled, true);
});
