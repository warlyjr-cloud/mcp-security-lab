#!/usr/bin/env node

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { runBenchmark } from "./benchmark.js";
import { loadConfig } from "./config.js";
import { redactUntrustedText } from "./environment.js";
import { exerciseTool } from "./exercise.js";
import { reportAsJson, reportAsSarif, reportAsText } from "./reporter.js";
import { RULES } from "./rules/catalog.js";
import { reportFailsPolicy, scan } from "./scanner.js";
import type {
  BenchmarkReport,
  ExerciseReport,
  ScanReport,
  Severity,
} from "./types.js";
import { VERSION } from "./version.js";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function usage(): string {
  return [
    "MCP Security Lab",
    "",
    "Usage:",
    "  mcpsl scan --config <path> [--execute] [--format text|json|sarif] [--output <path>]",
    "  mcpsl benchmark --manifest <path> --consent-synthetic-execution [--format text|json] [--output <path>]",
    "  mcpsl exercise --config <path> --tool <name> --input <json-path> --consent-call [--repeat 1|2] [--format text|json] [--output <path>]",
    "  mcpsl rules [--format text|json]",
    "  mcpsl --version",
    "",
    "Safety:",
    "  scan never invokes discovered tools.",
    "  exercise requires an exact tool name, explicit consent, and a verified Docker sandbox.",
    "  benchmark executes only cases marked synthetic and requires separate consent.",
  ].join("\n");
}

function valueAfter(args: string[], index: number): string {
  const value = args[index + 1];
  if (value === undefined) {
    throw new Error(`${args[index]} requires a value.`);
  }
  return value;
}

function readFormat(
  value: string,
  allowSarif: boolean,
): "text" | "json" | "sarif" {
  if (value === "text" || value === "json" || (allowSarif && value === "sarif")) {
    return value;
  }
  throw new Error(
    allowSarif ? "--format must be text, json, or sarif." : "--format must be text or json.",
  );
}

async function writeOutputFile(outputPath: string | undefined, output: string): Promise<void> {
  if (outputPath === undefined) {
    process.stdout.write(output);
    return;
  }
  const absoluteOutputPath = resolve(outputPath);
  await mkdir(dirname(absoluteOutputPath), { recursive: true });
  await writeFile(absoluteOutputPath, output, "utf8");
  process.stdout.write(`Report written to ${absoluteOutputPath}\n`);
}

function parseScanArgs(args: string[]): {
  configPath: string;
  execute: boolean;
  format: "text" | "json" | "sarif";
  outputPath?: string;
} {
  let configPath: string | undefined;
  let execute = false;
  let format: "text" | "json" | "sarif" = "text";
  let outputPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--execute") {
      execute = true;
      continue;
    }
    if (argument === "--config" || argument === "--format" || argument === "--output") {
      const value = valueAfter(args, index);
      index += 1;
      if (argument === "--config") {
        configPath = value;
      } else if (argument === "--output") {
        outputPath = value;
      } else {
        format = readFormat(value, true);
      }
      continue;
    }
    throw new Error(`Unknown scan argument: ${argument}`);
  }
  if (configPath === undefined) {
    throw new Error("scan requires --config.");
  }
  return {
    configPath,
    execute,
    format,
    ...(outputPath === undefined ? {} : { outputPath }),
  };
}

function benchmarkAsText(report: BenchmarkReport): string {
  const lines = [
    "MCP Security Lab Benchmark",
    `Cases: ${report.cases.length}`,
    `Precision: ${(report.metrics.precision * 100).toFixed(2)}%`,
    `Recall: ${(report.metrics.recall * 100).toFixed(2)}%`,
    `Thresholds: ${report.thresholds.passed ? "passed" : "failed"}`,
    "",
  ];
  for (const item of report.cases) {
    lines.push(
      `${redactUntrustedText(item.name, 200)}: TP=${item.truePositives.length} FP=${item.falsePositives.length} FN=${item.falseNegatives.length}`,
    );
  }
  return `${lines.join("\n")}\n`;
}

function exerciseAsText(report: ExerciseReport): string {
  return [
    "MCP Security Lab Exercise",
    `Tool: ${redactUntrustedText(report.tool, 200)}`,
    `Calls: ${report.callsCompleted}/${report.callsRequested}`,
    `Sandbox: ${report.sandbox.adapter} (${report.sandbox.verified ? "verified" : "not verified"})`,
    `Canary disclosed: ${report.canary.disclosed ? "yes" : "no"}`,
    `Canary modified: ${report.canary.modified ? "yes" : "no"}`,
    `Findings: ${report.findings.length}`,
    "",
  ].join("\n");
}

async function runScanCommand(args: string[]): Promise<void> {
  const options = parseScanArgs(args);
  const config = await loadConfig(options.configPath);
  const report = await scan(config, options.execute);
  const output =
    options.format === "json"
      ? reportAsJson(report)
      : options.format === "sarif"
        ? reportAsSarif(report, options.configPath)
        : reportAsText(report);
  await writeOutputFile(options.outputPath, output);
  if (reportFailsPolicy(report)) {
    process.exitCode = 2;
  }
}

async function runBenchmarkCommand(args: string[]): Promise<void> {
  let manifestPath: string | undefined;
  let consent = false;
  let format: "text" | "json" = "text";
  let outputPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--consent-synthetic-execution") {
      consent = true;
      continue;
    }
    if (argument === "--manifest" || argument === "--format" || argument === "--output") {
      const value = valueAfter(args, index);
      index += 1;
      if (argument === "--manifest") {
        manifestPath = value;
      } else if (argument === "--output") {
        outputPath = value;
      } else {
        format = readFormat(value, false) as "text" | "json";
      }
      continue;
    }
    throw new Error(`Unknown benchmark argument: ${argument}`);
  }
  if (manifestPath === undefined) {
    throw new Error("benchmark requires --manifest.");
  }

  const report = await runBenchmark(manifestPath, consent);
  const output =
    format === "json"
      ? `${JSON.stringify(report, null, 2)}\n`
      : benchmarkAsText(report);
  await writeOutputFile(outputPath, output);
  if (!report.thresholds.passed) {
    process.exitCode = 2;
  }
}

async function readInputObject(path: string): Promise<Record<string, unknown>> {
  const raw = await readFile(resolve(path), "utf8");
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Exercise input is not valid JSON: ${message}`);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Exercise input must be a JSON object.");
  }
  return value as Record<string, unknown>;
}

async function runExerciseCommand(args: string[]): Promise<void> {
  let configPath: string | undefined;
  let toolName: string | undefined;
  let inputPath: string | undefined;
  let consent = false;
  let calls = 1;
  let format: "text" | "json" = "text";
  let outputPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--consent-call") {
      consent = true;
      continue;
    }
    if (
      argument === "--config" ||
      argument === "--tool" ||
      argument === "--input" ||
      argument === "--repeat" ||
      argument === "--format" ||
      argument === "--output"
    ) {
      const value = valueAfter(args, index);
      index += 1;
      if (argument === "--config") {
        configPath = value;
      } else if (argument === "--tool") {
        toolName = value;
      } else if (argument === "--input") {
        inputPath = value;
      } else if (argument === "--repeat") {
        calls = Number(value);
      } else if (argument === "--output") {
        outputPath = value;
      } else {
        format = readFormat(value, false) as "text" | "json";
      }
      continue;
    }
    throw new Error(`Unknown exercise argument: ${argument}`);
  }
  if (configPath === undefined || toolName === undefined || inputPath === undefined) {
    throw new Error("exercise requires --config, --tool, and --input.");
  }

  const config = await loadConfig(configPath);
  const input = await readInputObject(inputPath);
  const report = await exerciseTool(config, toolName, input, calls, consent);
  const output =
    format === "json"
      ? `${JSON.stringify(report, null, 2)}\n`
      : exerciseAsText(report);
  await writeOutputFile(outputPath, output);
  if (
    report.findings.some(
      (finding) => SEVERITIES.indexOf(finding.severity) >= SEVERITIES.indexOf("high"),
    )
  ) {
    process.exitCode = 2;
  }
}

function runRulesCommand(args: string[]): void {
  let format: "text" | "json" = "text";
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== "--format") {
      throw new Error(`Unknown rules argument: ${args[index]}`);
    }
    format = readFormat(valueAfter(args, index), false) as "text" | "json";
    index += 1;
  }
  if (format === "json") {
    process.stdout.write(`${JSON.stringify(RULES, null, 2)}\n`);
    return;
  }
  for (const [id, rule] of Object.entries(RULES)) {
    process.stdout.write(
      `${id}\t${rule.severity}\t${rule.confidence}\t${rule.category}\t${rule.title}\n`,
    );
  }
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === undefined || command === "--help" || command === "-h") {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (command === "--version" || command === "-v") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (command === "scan") {
    await runScanCommand(args);
    return;
  }
  if (command === "benchmark") {
    await runBenchmarkCommand(args);
    return;
  }
  if (command === "exercise") {
    await runExerciseCommand(args);
    return;
  }
  if (command === "rules") {
    runRulesCommand(args);
    return;
  }
  throw new Error(`${usage()}\n\nUnknown command: ${command}`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Error: ${redactUntrustedText(message)}\n`);
  process.exitCode = 1;
});
