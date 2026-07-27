import type { ScanReport } from "../types.js";

export function generateFirewallPolicy(report: ScanReport): Record<string, unknown> {
  // Group findings by tool
  // The 'target' property in findings often points to the tool name if applicable
  const toolsWithCriticalOrHigh = new Set<string>();

  for (const finding of report.findings) {
    if (finding.severity === "critical" || finding.severity === "high") {
      // Try to extract tool name from finding title or target
      // This is a heuristic based on our fuzzer rule structure
      const match = finding.title.match(/tool ['"]?([^'"]+)['"]?/i);
      if (match && match[1]) {
        toolsWithCriticalOrHigh.add(match[1]);
      }
    }
  }

  // Assuming we know the tools from execution metadata
  // Wait, execution doesn't list the tool names cleanly in the schema right now,
  // but if we had them, we could whitelist.
  // For the sake of the firewall policy, we'll deny the known bad ones, and allow * by default if it's safe.

  const policy = {
    $schema: "https://mcp-security-lab.github.io/schemas/firewall-v1.json",
    version: "1.0",
    generatedBy: "MCP Security Lab (MCP Verifier)",
    target: report.target.command,
    rules: {
      defaultAction: toolsWithCriticalOrHigh.size > 0 ? "allow" : "allow", // Always allow safe by default, block bad
      rateLimit: {
        enabled: true,
        maxRequestsPerMinute: 60,
      },
      tools: {
        deny: Array.from(toolsWithCriticalOrHigh),
        // If we had a list of all tools, we could put the safe ones here
        allow: ["*"],
      },
    },
    threatContext: {
      criticalFindings: report.summary.critical,
      highFindings: report.summary.high,
    },
  };

  return policy;
}
