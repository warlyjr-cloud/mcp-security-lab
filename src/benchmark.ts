import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import { loadConfig } from "./config.js";
import { scan } from "./scanner.js";
import type {
  BenchmarkCaseResult,
  BenchmarkReport,
} from "./types.js";
import { VERSION } from "./version.js";

interface BenchmarkCase {
  name: string;
  config: string;
  execute: boolean;
  synthetic: boolean;
  expectedFindingIds: string[];
}

interface BenchmarkManifest {
  schemaVersion: "1.0";
  minimumPrecision: number;
  minimumRecall: number;
  cases: BenchmarkCase[];
}

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
}

function readRate(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be a number between 0 and 1.`);
  }
  return value;
}

function parseManifest(value: unknown): BenchmarkManifest {
  assertRecord(value, "Benchmark manifest");
  if (value.schemaVersion !== "1.0") {
    throw new Error('Benchmark manifest schemaVersion must be "1.0".');
  }
  if (!Array.isArray(value.cases) || value.cases.length === 0 || value.cases.length > 1_000) {
    throw new Error("Benchmark manifest cases must contain between 1 and 1000 entries.");
  }

  const cases = value.cases.map((candidate, index): BenchmarkCase => {
    assertRecord(candidate, `cases[${index}]`);
    if (typeof candidate.name !== "string" || candidate.name.trim() === "") {
      throw new Error(`cases[${index}].name must be a non-empty string.`);
    }
    if (typeof candidate.config !== "string" || candidate.config.trim() === "") {
      throw new Error(`cases[${index}].config must be a non-empty string.`);
    }
    if (typeof candidate.execute !== "boolean" || typeof candidate.synthetic !== "boolean") {
      throw new Error(`cases[${index}] execute and synthetic must be booleans.`);
    }
    if (
      !Array.isArray(candidate.expectedFindingIds) ||
      candidate.expectedFindingIds.some((id) => typeof id !== "string")
    ) {
      throw new Error(`cases[${index}].expectedFindingIds must be an array of strings.`);
    }
    return {
      name: candidate.name,
      config: candidate.config,
      execute: candidate.execute,
      synthetic: candidate.synthetic,
      expectedFindingIds: [...new Set(candidate.expectedFindingIds as string[])].sort(),
    };
  });

  return {
    schemaVersion: "1.0",
    minimumPrecision: readRate(value.minimumPrecision, "minimumPrecision"),
    minimumRecall: readRate(value.minimumRecall, "minimumRecall"),
    cases,
  };
}

function intersection(left: Set<string>, right: Set<string>): string[] {
  return [...left].filter((value) => right.has(value)).sort();
}

function difference(left: Set<string>, right: Set<string>): string[] {
  return [...left].filter((value) => !right.has(value)).sort();
}

export async function runBenchmark(
  manifestPath: string,
  consentSyntheticExecution: boolean,
): Promise<BenchmarkReport> {
  const absoluteManifestPath = resolve(manifestPath);
  const raw = await readFile(absoluteManifestPath, "utf8");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Benchmark manifest is not valid JSON: ${message}`);
  }
  const manifest = parseManifest(parsed);
  const manifestDirectory = dirname(absoluteManifestPath);
  const cases: BenchmarkCaseResult[] = [];

  for (const benchmarkCase of manifest.cases) {
    if (benchmarkCase.execute && !benchmarkCase.synthetic) {
      throw new Error(
        `Benchmark case "${benchmarkCase.name}" requests execution but is not marked synthetic.`,
      );
    }
    if (benchmarkCase.execute && !consentSyntheticExecution) {
      throw new Error(
        `Benchmark case "${benchmarkCase.name}" requires --consent-synthetic-execution.`,
      );
    }

    const configPath = resolve(manifestDirectory, benchmarkCase.config);
    const config = await loadConfig(configPath);
    const report = await scan(config, benchmarkCase.execute);
    const expected = new Set(benchmarkCase.expectedFindingIds);
    const actual = new Set(report.findings.map((finding) => finding.id));
    cases.push({
      name: benchmarkCase.name,
      expectedFindingIds: [...expected].sort(),
      actualFindingIds: [...actual].sort(),
      truePositives: intersection(actual, expected),
      falsePositives: difference(actual, expected),
      falseNegatives: difference(expected, actual),
    });
  }

  const truePositives = cases.reduce((sum, item) => sum + item.truePositives.length, 0);
  const falsePositives = cases.reduce((sum, item) => sum + item.falsePositives.length, 0);
  const falseNegatives = cases.reduce((sum, item) => sum + item.falseNegatives.length, 0);
  const precision =
    truePositives + falsePositives === 0
      ? 1
      : truePositives / (truePositives + falsePositives);
  const recall =
    truePositives + falseNegatives === 0
      ? 1
      : truePositives / (truePositives + falseNegatives);

  return {
    schemaVersion: "1.0",
    scannerVersion: VERSION,
    manifest: absoluteManifestPath,
    cases,
    metrics: {
      truePositives,
      falsePositives,
      falseNegatives,
      precision,
      recall,
    },
    thresholds: {
      minimumPrecision: manifest.minimumPrecision,
      minimumRecall: manifest.minimumRecall,
      passed:
        precision >= manifest.minimumPrecision &&
        recall >= manifest.minimumRecall,
    },
  };
}
