import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import type { ScanConfig } from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_TOOLS = 100;
const MAX_TIMEOUT_MS = 60_000;
const MAX_TOOLS = 1_000;

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
}

function readPositiveInteger(
  value: unknown,
  fallback: number,
  maximum: number,
  label: string,
): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isInteger(value) || (value as number) <= 0 || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
  }
  return value as number;
}

export async function loadConfig(configPath: string): Promise<ScanConfig> {
  const absoluteConfigPath = resolve(configPath);
  const raw = await readFile(absoluteConfigPath, "utf8");
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Config is not valid JSON: ${message}`);
  }

  assertRecord(parsed, "Config");
  assertRecord(parsed.target, "target");

  const { command, args = [], cwd = "." } = parsed.target;
  if (typeof command !== "string" || command.trim() === "") {
    throw new Error("target.command must be a non-empty string.");
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
    throw new Error("target.args must be an array of strings.");
  }
  if (typeof cwd !== "string" || cwd.trim() === "") {
    throw new Error("target.cwd must be a non-empty string.");
  }

  const policyValue = parsed.policy ?? {};
  assertRecord(policyValue, "policy");

  return {
    target: {
      command,
      args: [...args],
      cwd: resolve(dirname(absoluteConfigPath), cwd),
    },
    policy: {
      timeoutMs: readPositiveInteger(
        policyValue.timeoutMs,
        DEFAULT_TIMEOUT_MS,
        MAX_TIMEOUT_MS,
        "policy.timeoutMs",
      ),
      maxTools: readPositiveInteger(
        policyValue.maxTools,
        DEFAULT_MAX_TOOLS,
        MAX_TOOLS,
        "policy.maxTools",
      ),
    },
  };
}
