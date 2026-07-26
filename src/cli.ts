#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { loadConfig } from "./config.js";
import { reportAsJson, reportAsSarif, reportAsText, reportAsMarkdown } from "./reporter.js";
import { renderDashboard } from "./reporter/dashboard.js";
import { scan } from "./scanner.js";

export interface CliOptions {
  configPath: string;
  execute: boolean;
  format: "text" | "json" | "sarif" | "markdown" | "dashboard";
  outputPath?: string;
  sandbox: "docker" | "none";
  fuzz: boolean;
  aiFuzz: boolean;
}

function usage(): string {
  return [
    "Usage:",
    "  mcpsl scan --config <path> [--execute] [--sandbox docker|none] [--fuzz] [--ai-fuzz]",
    "            [--format text|json|sarif|markdown|dashboard] [--output <path>]",
    "",
    "Safety:",
    "  Without --execute, only the launch configuration is inspected.",
    "  With --execute, the target starts with a filtered environment; its tools are never called.",
    "  Use --sandbox docker to run the target inside a disposable Docker container.",
    "  Use --fuzz to actively call discovered tools with malicious inputs (DANGEROUS).",
    "  --fuzz requires --execute and --sandbox docker so probing stays isolated.",
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
  let format: "text" | "json" | "sarif" | "markdown" | "dashboard" = "text";
  let outputPath: string | undefined;
  let sandbox: "docker" | "none" = "none";

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
    if (
      argument === "--config" ||
      argument === "--format" ||
      argument === "--output" ||
      argument === "--sandbox"
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

  return {
    configPath,
    execute,
    fuzz,
    aiFuzz,
    format,
    sandbox,
    ...(outputPath === undefined ? {} : { outputPath }),
  };
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const config = await loadConfig(options.configPath);

  if (options.aiFuzz) {
    config.policy = config.policy || { maxTools: 100, timeoutMs: 5000 };
    config.policy.aiFuzz = true;
  }

  const report = await scan(config, options.execute, options.sandbox, options.fuzz);

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

  if (report.summary.critical > 0 || report.summary.high > 0) {
    process.exitCode = 2;
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Error: ${message}\n`);
  process.exitCode = 1;
});
