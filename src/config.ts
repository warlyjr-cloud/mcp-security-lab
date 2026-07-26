import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import type {
  HttpTargetConfig,
  SandboxConfig,
  ScanConfig,
  ScanPolicy,
  StdioTargetConfig,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_ITEMS = 100;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const MAX_TIMEOUT_MS = 60_000;
const MAX_ITEMS = 1_000;
const MAX_RESPONSE_BYTES = 10_485_760;

function assertRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object.`);
  }
}

function readPositiveNumber(
  value: unknown,
  fallback: number,
  maximum: number,
  label: string,
): number {
  if (value === undefined) {
    return fallback;
  }
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value <= 0 ||
    value > maximum
  ) {
    throw new Error(`${label} must be a number between 0 and ${maximum}.`);
  }
  return value;
}

function readPositiveInteger(
  value: unknown,
  fallback: number,
  maximum: number,
  label: string,
): number {
  const result = readPositiveNumber(value, fallback, maximum, label);
  if (!Number.isInteger(result)) {
    throw new Error(`${label} must be an integer.`);
  }
  return result;
}

function readBoolean(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "boolean") {
    throw new Error(`${label} must be a boolean.`);
  }
  return value;
}

function readStringEnum<const T extends readonly string[]>(
  value: unknown,
  fallback: T[number],
  values: T,
  label: string,
): T[number] {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== "string" || !values.includes(value)) {
    throw new Error(`${label} must be one of: ${values.join(", ")}.`);
  }
  return value;
}

function loadStdioTarget(
  value: Record<string, unknown>,
  configDirectory: string,
): StdioTargetConfig {
  const { command, args = [], cwd = "." } = value;
  if (typeof command !== "string" || command.trim() === "") {
    throw new Error("target.command must be a non-empty string.");
  }
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
    throw new Error("target.args must be an array of strings.");
  }
  if (typeof cwd !== "string" || cwd.trim() === "") {
    throw new Error("target.cwd must be a non-empty string.");
  }

  return {
    transport: "stdio",
    command,
    args: [...args],
    cwd: resolve(configDirectory, cwd),
  };
}

function loadHttpTarget(value: Record<string, unknown>): HttpTargetConfig {
  if (typeof value.url !== "string" || value.url.trim() === "") {
    throw new Error("target.url must be a non-empty URL.");
  }
  let url: URL;
  try {
    url = new URL(value.url);
  } catch {
    throw new Error("target.url must be an absolute URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("target.url must use http or https.");
  }
  return {
    transport: "streamable-http",
    url: url.toString(),
  };
}

function loadPolicy(value: unknown): ScanPolicy {
  const policy = value ?? {};
  assertRecord(policy, "policy");

  return {
    timeoutMs: readPositiveInteger(
      policy.timeoutMs,
      DEFAULT_TIMEOUT_MS,
      MAX_TIMEOUT_MS,
      "policy.timeoutMs",
    ),
    maxTools: readPositiveInteger(
      policy.maxTools,
      DEFAULT_MAX_ITEMS,
      MAX_ITEMS,
      "policy.maxTools",
    ),
    maxResources: readPositiveInteger(
      policy.maxResources,
      DEFAULT_MAX_ITEMS,
      MAX_ITEMS,
      "policy.maxResources",
    ),
    maxPrompts: readPositiveInteger(
      policy.maxPrompts,
      DEFAULT_MAX_ITEMS,
      MAX_ITEMS,
      "policy.maxPrompts",
    ),
    maxResponseBytes: readPositiveInteger(
      policy.maxResponseBytes,
      DEFAULT_MAX_RESPONSE_BYTES,
      MAX_RESPONSE_BYTES,
      "policy.maxResponseBytes",
    ),
    profile: readStringEnum(
      policy.profile,
      "balanced",
      ["strict", "balanced", "compatibility"] as const,
      "policy.profile",
    ),
    allowPrivateNetwork: readBoolean(
      policy.allowPrivateNetwork,
      false,
      "policy.allowPrivateNetwork",
    ),
  };
}

function loadSandbox(value: unknown): SandboxConfig {
  const sandbox = value ?? {};
  assertRecord(sandbox, "sandbox");
  const adapter = readStringEnum(
    sandbox.adapter,
    "none",
    ["none", "docker"] as const,
    "sandbox.adapter",
  );
  const image =
    sandbox.image === undefined
      ? "node:24.18.0-bookworm-slim"
      : sandbox.image;
  if (typeof image !== "string" || image.trim() === "") {
    throw new Error("sandbox.image must be a non-empty string.");
  }

  return {
    adapter,
    image,
    network: readStringEnum(
      sandbox.network,
      "none",
      ["none", "bridge"] as const,
      "sandbox.network",
    ),
    memoryMb: readPositiveInteger(sandbox.memoryMb, 256, 8_192, "sandbox.memoryMb"),
    cpus: readPositiveNumber(sandbox.cpus, 1, 32, "sandbox.cpus"),
    pidsLimit: readPositiveInteger(sandbox.pidsLimit, 128, 4_096, "sandbox.pidsLimit"),
  };
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
  const configDirectory = dirname(absoluteConfigPath);
  const transport = parsed.target.transport ?? (parsed.target.url === undefined ? "stdio" : "streamable-http");
  if (transport !== "stdio" && transport !== "streamable-http") {
    throw new Error("target.transport must be stdio or streamable-http.");
  }

  return {
    target:
      transport === "stdio"
        ? loadStdioTarget(parsed.target, configDirectory)
        : loadHttpTarget(parsed.target),
    policy: loadPolicy(parsed.policy),
    sandbox: loadSandbox(parsed.sandbox),
  };
}
