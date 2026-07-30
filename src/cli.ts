#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadConfig } from "./config.js";
import { diffReports, renderDiff } from "./diff.js";
import { reportAsJson, reportAsSarif, reportAsText, reportAsMarkdown } from "./reporter.js";
import { renderDashboard } from "./reporter/dashboard.js";
import { generateVerifiedRemediation } from "./remediator/agentic.js";
import { generateFirewallPolicy } from "./firewall/generator.js";
import { scan } from "./scanner.js";
import { writeFileSync } from "node:fs";
import type { Confidence, ScanReport, Severity } from "./types.js";

export interface CliOptions {
  configPath: string;
  execute: boolean;
  format: "text" | "json" | "sarif" | "markdown" | "dashboard";
  outputPath?: string;
  sandbox: "docker" | "none";
  sandboxNetwork: "none" | "bridge";
  fuzz: boolean;
  aiFuzz: boolean;
  autoFix: boolean;
  firewallPath?: string;
  minConfidence?: Confidence;
  baselinePath?: string;
}

const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

/**
 * Drop findings whose confidence is below the threshold. Findings that carry no
 * confidence are unscored and always kept, so raising the bar never hides a
 * finding the scanner did not rate. The summary is recomputed to match.
 */
export function applyConfidenceFilter(report: ScanReport, min: Confidence): ScanReport {
  const threshold = CONFIDENCE_RANK[min];
  const findings = report.findings.filter(
    (finding) =>
      finding.confidence === undefined || CONFIDENCE_RANK[finding.confidence] >= threshold,
  );
  const summary = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
    Severity,
    number
  >;
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return { ...report, findings, summary };
}

function usage(): string {
  return [
    "Usage:",
    "  mcp-security-lab scan --config <path> [--execute] [--sandbox docker|none]",
    "            [--sandbox-network none|bridge] [--fuzz]",
    "            [--ai-fuzz] [--format text|json|sarif|markdown|dashboard] [--output <path>]",
    "            [--min-confidence low|medium|high] [--baseline <report.json>]",
    "            [--auto-fix] [--generate-firewall <path>]",
    "",
    "Safety:",
    "  Without --execute, only the launch configuration is inspected.",
    "  With --execute, the target starts with a filtered environment; its tools are never called.",
    "  Use --sandbox docker to run the target inside a disposable Docker container.",
    "  --sandbox-network defaults to none; use bridge only to discover a server that",
    "    must reach the network at startup (a SANDBOX010 finding records the relaxation).",
    "  Use --fuzz to actively call discovered tools with malicious inputs (DANGEROUS).",
    "  --fuzz requires --execute and --sandbox docker so probing stays isolated,",
    "    and forces --sandbox-network none regardless of what is requested.",
  ].join("\n");
}

function parseArgs(args: string[]): CliOptions {
  if (args[0] !== "scan") {
    throw new Error(usage());
  }

  let configPath: string | undefined;
  let execute = false;
  let fuzz = false;
  let aiFuzz = false;
  let autoFix = false;
  let firewallPath: string | undefined;
  let format: "text" | "json" | "sarif" | "markdown" | "dashboard" = "text";
  let outputPath: string | undefined;
  let sandbox: "docker" | "none" = "none";
  let sandboxNetwork: "none" | "bridge" = "none";
  let minConfidence: Confidence | undefined;
  let baselinePath: string | undefined;

  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--execute") {
      execute = true;
      continue;
    }
    if (argument === "--fuzz") {
      fuzz = true;
      continue;
    }
    if (argument === "--ai-fuzz") {
      aiFuzz = true;
      continue;
    }
    if (argument === "--auto-fix") {
      autoFix = true;
      continue;
    }
    if (
      argument === "--config" ||
      argument === "--format" ||
      argument === "--output" ||
      argument === "--sandbox" ||
      argument === "--sandbox-network" ||
      argument === "--generate-firewall" ||
      argument === "--min-confidence" ||
      argument === "--baseline"
    ) {
      const value = args[index + 1];
      if (value === undefined) {
        throw new Error(`${argument} requires a value.`);
      }
      index += 1;
      if (argument === "--config") {
        configPath = value;
      } else if (argument === "--output") {
        outputPath = value;
      } else if (argument === "--sandbox") {
        if (value === "docker" || value === "none") {
          sandbox = value;
        } else {
          throw new Error("--sandbox must be docker or none.");
        }
      } else if (argument === "--sandbox-network") {
        if (value === "none" || value === "bridge") {
          sandboxNetwork = value;
        } else {
          throw new Error("--sandbox-network must be none or bridge.");
        }
      } else if (argument === "--generate-firewall") {
        firewallPath = value;
      } else if (argument === "--min-confidence") {
        if (value === "low" || value === "medium" || value === "high") {
          minConfidence = value;
        } else {
          throw new Error("--min-confidence must be low, medium, or high.");
        }
      } else if (argument === "--baseline") {
        baselinePath = value;
      } else if (argument === "--format") {
        if (
          value === "text" ||
          value === "json" ||
          value === "sarif" ||
          value === "markdown" ||
          value === "dashboard"
        ) {
          format = value;
        } else {
          throw new Error("--format must be text, json, sarif, markdown, or dashboard.");
        }
      }
      continue;
    }
    throw new Error(`Unknown argument: ${argument}\n\n${usage()}`);
  }

  if (configPath === undefined) {
    throw new Error(`--config is required.\n\n${usage()}`);
  }

  // Active probing must never get network access: --fuzz calls tools with
  // hostile inputs, so the container stays isolated regardless of the request.
  if (fuzz && sandboxNetwork !== "none") {
    throw new Error(
      "--sandbox-network must be none when --fuzz is set; active probing stays network-isolated.",
    );
  }
  // The network mode only exists inside the Docker sandbox; without it the flag
  // would be silently ignored, so reject the meaningless combination up front.
  if (sandboxNetwork !== "none" && sandbox !== "docker") {
    throw new Error("--sandbox-network requires --sandbox docker.");
  }

  return {
    configPath,
    execute,
    fuzz,
    aiFuzz,
    autoFix,
    format,
    sandbox,
    sandboxNetwork,
    ...(firewallPath === undefined ? {} : { firewallPath }),
    ...(outputPath === undefined ? {} : { outputPath }),
    ...(minConfidence === undefined ? {} : { minConfidence }),
    ...(baselinePath === undefined ? {} : { baselinePath }),
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const config = await loadConfig(options.configPath);

  if (options.aiFuzz) {
    config.policy = config.policy || { maxTools: 100, timeoutMs: 5000 };
    config.policy.aiFuzz = true;
  }

  const rawReport = await scan(
    config,
    options.execute,
    options.sandbox,
    options.fuzz,
    options.sandboxNetwork,
  );
  const report =
    options.minConfidence === undefined
      ? rawReport
      : applyConfidenceFilter(rawReport, options.minConfidence);

  if (options.firewallPath) {
    const firewall = generateFirewallPolicy(report);
    writeFileSync(options.firewallPath, JSON.stringify(firewall, null, 2), "utf8");
    console.log(`\n[+] Firewall policy generated at ${options.firewallPath}`);
  }

  if (options.autoFix) {
    console.log("[+] Generating verified AI remediation (Claude proposes, the engine verifies)...");
    const plan = await generateVerifiedRemediation(report);
    writeFileSync("MCP_REMEDIATION.md", plan, "utf8");
    console.log("[+] Verified remediation saved to MCP_REMEDIATION.md");
  }

  if (options.format === "dashboard") {
    renderDashboard(report);
    return; // dashboard takes over the process until user quits
  }

  const output =
    options.format === "json"
      ? reportAsJson(report)
      : options.format === "sarif"
        ? reportAsSarif(report, options.configPath)
        : options.format === "markdown"
          ? reportAsMarkdown(report)
          : reportAsText(report);

  if (options.outputPath === undefined) {
    process.stdout.write(output);
  } else {
    const absoluteOutputPath = resolve(options.outputPath);
    await mkdir(dirname(absoluteOutputPath), { recursive: true });
    await writeFile(absoluteOutputPath, output, "utf8");
    process.stdout.write(`Report written to ${absoluteOutputPath}\n`);
  }

  if (options.baselinePath !== undefined) {
    const baseline = JSON.parse(
      await readFile(resolve(options.baselinePath), "utf8"),
    ) as ScanReport;
    const diff = diffReports(baseline, report);
    process.stderr.write(renderDiff(diff));
    if (diff.introduced.length > 0) {
      process.exitCode = 2; // a regression against the baseline fails the gate
    }
  }

  if (report.summary.critical > 0 || report.summary.high > 0) {
    process.exitCode = 2;
  }
}

const invokedDirectly =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`Error: ${message}\n`);
    process.exitCode = 1;
  });
}
