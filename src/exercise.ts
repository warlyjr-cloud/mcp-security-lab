import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  createSanitizedEnvironment,
  redactUntrustedText,
} from "./environment.js";
import { createFinding } from "./rules/catalog.js";
import { createExecutionPlan } from "./sandbox.js";
import type {
  ExerciseReport,
  Finding,
  ResolvedScanPolicy,
  ScanConfig,
} from "./types.js";
import { VERSION } from "./version.js";

function withTimeout<T>(operation: Promise<T>, timeoutMs: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`${label} exceeded ${timeoutMs} ms.`)),
      timeoutMs,
    );
    timer.unref();
    operation.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function canonicalize(value: unknown, depth = 0): unknown {
  if (depth > 30) {
    return "[MAX DEPTH]";
  }
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item, depth + 1));
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item, depth + 1)]),
    );
  }
  return value;
}

function serializeResult(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function analyzeExerciseResults(
  serializedResults: string[],
  canaryToken: string,
  canaryBefore: string,
  canaryAfter: string,
  idempotentHint: boolean,
  maximumBytes: number,
): {
  digests: string[];
  canaryDisclosed: boolean;
  canaryModified: boolean;
  findings: Finding[];
} {
  const findings: Finding[] = [];
  const oversized = serializedResults.some(
    (result) => Buffer.byteLength(result, "utf8") > maximumBytes,
  );
  if (oversized) {
    findings.push(
      createFinding(
        "BEHAVIOR005",
        `At least one serialized result exceeded ${maximumBytes} bytes.`,
        "exercise.result",
      ),
    );
  }
  const canaryDisclosed = serializedResults.some((result) => result.includes(canaryToken));
  if (canaryDisclosed) {
    findings.push(
      createFinding(
        "BEHAVIOR001",
        "The result contained the exact synthetic canary value.",
        "exercise.result",
      ),
    );
  }
  const canaryModified = canaryBefore !== canaryAfter;
  if (canaryModified) {
    findings.push(
      createFinding(
        "BEHAVIOR004",
        "The read-only canary digest changed during the exercise.",
        "exercise.canary",
      ),
    );
  }
  const digests = serializedResults.map(digest);
  if (
    idempotentHint &&
    digests.length > 1 &&
    new Set(digests).size > 1
  ) {
    findings.push(
      createFinding(
        "BEHAVIOR002",
        "Repeated calls with identical arguments produced different result digests.",
        "exercise.result",
      ),
    );
  }

  return { digests, canaryDisclosed, canaryModified, findings };
}

export async function exerciseTool(
  config: ScanConfig,
  toolName: string,
  input: Record<string, unknown>,
  calls: number,
  consent: boolean,
): Promise<ExerciseReport> {
  if (!consent) {
    throw new Error("Exercise requires explicit --consent-call.");
  }
  if (toolName.trim() === "") {
    throw new Error("Exercise requires an explicit tool name.");
  }
  if (!Number.isInteger(calls) || calls < 1 || calls > 2) {
    throw new Error("Exercise calls must be 1 or 2.");
  }
  if (config.target.transport === "streamable-http") {
    throw new Error("Behavioral exercise currently supports stdio targets only.");
  }
  if (config.sandbox?.adapter !== "docker") {
    throw new Error("Behavioral exercise requires sandbox.adapter=docker.");
  }

  const policy: ResolvedScanPolicy = {
    timeoutMs: config.policy.timeoutMs,
    maxTools: config.policy.maxTools,
    maxResources: config.policy.maxResources ?? 100,
    maxPrompts: config.policy.maxPrompts ?? 100,
    maxResponseBytes: config.policy.maxResponseBytes ?? 1_048_576,
    profile: config.policy.profile ?? "balanced",
    allowPrivateNetwork: config.policy.allowPrivateNetwork ?? false,
  };
  const canaryDirectory = await mkdtemp(join(tmpdir(), "mcp-security-lab-canary-"));
  const canaryPath = join(canaryDirectory, "canary.txt");
  const canaryToken = `mcpsl_${randomBytes(24).toString("hex")}`;
  const canaryContent = `Synthetic MCP Security Lab canary\n${canaryToken}\n`;
  await writeFile(canaryPath, canaryContent, { encoding: "utf8", flag: "wx" });

  const plan = await createExecutionPlan(
    config.target,
    config.sandbox,
    policy.timeoutMs,
    { hostDirectory: canaryDirectory, token: canaryToken },
  );
  if (!plan.sandbox.verified || plan.sandbox.adapter !== "docker") {
    throw new Error("Docker sandbox verification did not complete.");
  }

  const transport = new StdioClientTransport({
    command: plan.target.command,
    args: plan.target.args,
    cwd: plan.target.cwd,
    env: createSanitizedEnvironment(),
    stderr: "pipe",
  });
  transport.stderr?.on("data", () => undefined);
  const client = new Client({ name: "mcp-security-lab-exercise", version: VERSION });
  const serializedResults: string[] = [];
  const findings = [...plan.findings];
  let connected = false;

  try {
    await withTimeout(client.connect(transport), policy.timeoutMs, "MCP initialization");
    connected = true;
    const tools = await withTimeout(client.listTools(), policy.timeoutMs, "MCP tools/list");
    const tool = tools.tools.find((candidate) => candidate.name === toolName);
    if (tool === undefined) {
      throw new Error(`Server did not advertise the explicitly named tool "${toolName}".`);
    }

    for (let index = 0; index < calls; index += 1) {
      try {
        const result = await withTimeout(
          client.callTool({ name: toolName, arguments: input }),
          policy.timeoutMs,
          `MCP tools/call ${toolName}`,
        );
        serializedResults.push(serializeResult(result));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        findings.push(
          createFinding(
            "BEHAVIOR003",
            redactUntrustedText(message),
            `tool:${toolName}`,
          ),
        );
        break;
      }
    }

    const canaryAfter = await readFile(canaryPath, "utf8");
    const analysis = analyzeExerciseResults(
      serializedResults,
      canaryToken,
      canaryContent,
      canaryAfter,
      tool.annotations?.idempotentHint === true,
      policy.maxResponseBytes,
    );
    findings.push(...analysis.findings);

    return {
      schemaVersion: "1.0",
      scanner: { name: "mcp-security-lab", version: VERSION },
      tool: toolName,
      callsRequested: calls,
      callsCompleted: serializedResults.length,
      sandbox: {
        adapter: "docker",
        verified: true,
        network: plan.sandbox.network === "host" ? "none" : plan.sandbox.network,
      },
      resultDigests: analysis.digests,
      canary: {
        disclosed: analysis.canaryDisclosed,
        modified: analysis.canaryModified,
      },
      findings,
    };
  } finally {
    if (connected) {
      await withTimeout(client.close(), policy.timeoutMs, "MCP shutdown").catch(
        () => undefined,
      );
    } else {
      await client.close().catch(() => undefined);
    }
    await rm(canaryDirectory, { recursive: true, force: true });
  }
}
