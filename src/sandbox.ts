import { spawn } from "node:child_process";

import { createSanitizedEnvironment } from "./environment.js";
import { createFinding } from "./rules/catalog.js";
import type {
  Finding,
  SandboxConfig,
  StdioTargetConfig,
} from "./types.js";

export interface ExecutionPlan {
  target: StdioTargetConfig;
  sandbox: {
    adapter: "none" | "docker";
    verified: boolean;
    network: "host" | "none" | "bridge";
  };
  findings: Finding[];
}

export interface SandboxCanary {
  hostDirectory: string;
  token: string;
}

function runBounded(
  command: string,
  args: string[],
  timeoutMs: number,
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      windowsHide: true,
      env: createSanitizedEnvironment(),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    const maximumBytes = 64 * 1024;
    let bytes = 0;
    let settled = false;

    const timer = setTimeout(() => {
      child.kill();
      if (!settled) {
        settled = true;
        reject(new Error(`Sandbox preflight exceeded ${timeoutMs} ms.`));
      }
    }, timeoutMs);
    timer.unref();

    const collect = (chunks: Buffer[], chunk: Buffer): void => {
      if (bytes >= maximumBytes) {
        return;
      }
      const remaining = maximumBytes - bytes;
      chunks.push(chunk.subarray(0, remaining));
      bytes += Math.min(chunk.length, remaining);
    };
    child.stdout.on("data", (chunk: Buffer) => collect(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => collect(stderr, chunk));
    child.on("error", (error) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        resolve({
          exitCode: code ?? 1,
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
        });
      }
    });
  });
}

async function verifyDocker(timeoutMs: number): Promise<void> {
  let result: { exitCode: number; stdout: string; stderr: string };
  try {
    result = await runBounded(
      "docker",
      ["version", "--format", "{{.Server.Version}}"],
      timeoutMs,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Docker sandbox is unavailable: ${message}`);
  }
  if (result.exitCode !== 0 || result.stdout.trim() === "") {
    const detail = result.stderr.trim() || "Docker daemon did not return a server version.";
    throw new Error(`Docker sandbox verification failed: ${detail}`);
  }
}

export function buildDockerTarget(
  target: StdioTargetConfig,
  sandbox: SandboxConfig,
  canary?: SandboxCanary,
): StdioTargetConfig {
  const mount = `${target.cwd}:/workspace:ro`;
  const canaryArguments =
    canary === undefined
      ? []
      : [
          "--volume",
          `${canary.hostDirectory}:/mcp-security-lab-canary:ro`,
          "--env",
          "MCP_SECURITY_LAB_CANARY_PATH=/mcp-security-lab-canary/canary.txt",
          "--env",
          `MCP_SECURITY_LAB_CANARY_TOKEN=${canary.token}`,
        ];
  return {
    transport: "stdio",
    command: "docker",
    args: [
      "run",
      "--rm",
      "--interactive",
      "--network",
      sandbox.network,
      "--read-only",
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--pids-limit",
      String(sandbox.pidsLimit),
      "--memory",
      `${sandbox.memoryMb}m`,
      "--cpus",
      String(sandbox.cpus),
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      "--volume",
      mount,
      ...canaryArguments,
      "--workdir",
      "/workspace",
      sandbox.image,
      target.command,
      ...target.args,
    ],
    cwd: target.cwd,
  };
}

export async function createExecutionPlan(
  target: StdioTargetConfig,
  sandbox: SandboxConfig,
  timeoutMs: number,
  canary?: SandboxCanary,
): Promise<ExecutionPlan> {
  if (sandbox.adapter === "none") {
    return {
      target,
      sandbox: {
        adapter: "none",
        verified: false,
        network: "host",
      },
      findings: [
        createFinding(
          "SANDBOX001",
          "The target will run directly with the scanner user's operating-system permissions.",
          "sandbox.adapter",
        ),
      ],
    };
  }

  await verifyDocker(timeoutMs);
  const findings: Finding[] = [];
  if (!sandbox.image.includes("@sha256:")) {
    findings.push(
      createFinding(
        "SANDBOX002",
        `Configured image is "${sandbox.image}".`,
        "sandbox.image",
      ),
    );
  }

  return {
    target: buildDockerTarget(target, sandbox, canary),
    sandbox: {
      adapter: "docker",
      verified: true,
      network: sandbox.network,
    },
    findings,
  };
}
