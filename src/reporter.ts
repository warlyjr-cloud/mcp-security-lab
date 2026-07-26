import { createHash } from "node:crypto";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";

import type { ScanReport, Severity } from "./types.js";

const ICONS: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function reportAsJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

type SarifLevel = "none" | "note" | "warning" | "error";

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: SarifLevel };
  help: { text: string; markdown: string };
}

function sarifLevel(severity: Severity): SarifLevel {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium") {
    return "warning";
  }
  if (severity === "low") {
    return "note";
  }
  return "none";
}

function artifactUri(configPath: string, workspaceRoot: string): string {
  const absoluteConfigPath = resolve(configPath);
  const absoluteWorkspaceRoot = resolve(workspaceRoot);
  const relativePath = relative(absoluteWorkspaceRoot, absoluteConfigPath);
  const outsideWorkspace =
    relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath);
  return (
    outsideWorkspace ? basename(absoluteConfigPath) : relativePath || basename(absoluteConfigPath)
  )
    .split(sep)
    .join("/");
}

function fingerprint(
  id: string,
  location: string | undefined,
  title: string,
  evidence: string,
): string {
  return createHash("sha256")
    .update([id, location ?? "", title, evidence].join("\u0000"))
    .digest("hex");
}

export function reportAsSarif(
  report: ScanReport,
  configPath: string,
  workspaceRoot = process.env.GITHUB_WORKSPACE ?? process.cwd(),
): string {
  const rules = new Map<string, SarifRule>();
  const uri = artifactUri(configPath, workspaceRoot);

  for (const finding of report.findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.recommendation },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
        help: {
          text: finding.recommendation,
          markdown: `**Recommendation:** ${finding.recommendation}`,
        },
      });
    }
  }

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: report.scanner.name,
            semanticVersion: report.scanner.version,
            rules: [...rules.values()],
          },
        },
        automationDetails: {
          id: "mcp-security-lab/",
        },
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              connected: report.execution.connected,
              toolsInvoked: report.execution.toolsInvoked,
              osSandboxed: report.execution.osSandboxed,
            },
          },
        ],
        results: report.findings.map((finding) => ({
          ruleId: finding.id,
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.title}\n\nEvidence: ${finding.evidence}\n\nRecommendation: ${finding.recommendation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri },
                region: { startLine: 1 },
              },
              logicalLocations:
                finding.location === undefined
                  ? []
                  : [{ fullyQualifiedName: finding.location, kind: "configuration" }],
            },
          ],
          partialFingerprints: {
            "mcpSecurityLab/v1": fingerprint(
              finding.id,
              finding.location,
              finding.title,
              finding.evidence,
            ),
          },
          properties: {
            severity: finding.severity,
            recommendation: finding.recommendation,
            scannerLocation: finding.location ?? "scan",
          },
        })),
      },
    ],
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export function reportAsText(report: ScanReport): string {
  const targetLabel =
    report.target.url !== undefined
      ? report.target.url
      : `${report.target.command} ${(report.target.args ?? []).join(" ")}`.trim();

  const lines = [
    "MCP Security Lab",
    `Target: ${targetLabel}`,
    `Connected: ${report.execution.connected ? "yes" : "no"} | Transport: ${report.execution.transport} | Tools invoked: 0 | OS sandbox: no`,
    `Findings: ${report.summary.critical} critical, ${report.summary.high} high, ${report.summary.medium} medium, ${report.summary.low} low, ${report.summary.info} info`,
    "",
  ];

  for (const finding of report.findings) {
    lines.push(`[${ICONS[finding.severity]}] ${finding.id} ${finding.title}`);
    lines.push(`  Evidence: ${finding.evidence}`);
    lines.push(`  Recommendation: ${finding.recommendation}`);
    if (finding.location !== undefined) {
      lines.push(`  Location: ${finding.location}`);
    }
    lines.push("");
  }

  lines.push("Limitation: target processes are not isolated from the host filesystem or network.");
  return `${lines.join("\n")}\n`;
}
