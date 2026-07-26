import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { createSanitizedEnvironment, redactArguments } from "./environment.js";
import { inspectLaunch } from "./rules/launch.js";
import { inspectTool } from "./rules/tools.js";
import type {
  Finding,
  ScanConfig,
  ScanReport,
  ServerMetadata,
  Severity,
  ToolMetadata,
} from "./types.js";

const VERSION = "0.2.0";
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function summarize(findings: Finding[]): Record<Severity, number> {
  const summary = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])) as Record<
    Severity,
    number
  >;
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

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

async function discover(
  config: ScanConfig,
): Promise<{ server: ServerMetadata; findings: Finding[] }> {
  const client = new Client({ name: "mcp-security-lab", version: VERSION });
  const transport = new StdioClientTransport({
    command: config.target.command,
    args: config.target.args,
    cwd: config.target.cwd,
    env: { ...createSanitizedEnvironment(), ...(config.target.env ?? {}) },
    stderr: "pipe",
  });

  try {
    await withTimeout(client.connect(transport), config.policy.timeoutMs, "MCP initialization");
    const response = await withTimeout(
      client.listTools(),
      config.policy.timeoutMs,
      "MCP tools/list",
    );

    if (response.tools.length > config.policy.maxTools) {
      throw new Error(
        `Server advertised ${response.tools.length} tools, exceeding policy.maxTools (${config.policy.maxTools}).`,
      );
    }

    const tools: ToolMetadata[] = response.tools.map((tool) => ({
      name: tool.name,
      ...(tool.description === undefined ? {} : { description: tool.description }),
      inputSchema: tool.inputSchema as Record<string, unknown>,
      ...(tool.annotations === undefined
        ? {}
        : { annotations: tool.annotations as Record<string, unknown> }),
    }));
    const findings = tools.flatMap(inspectTool);
    const serverVersion = client.getServerVersion();

    return {
      server: {
        ...(serverVersion?.name === undefined ? {} : { name: serverVersion.name }),
        ...(serverVersion?.version === undefined ? {} : { version: serverVersion.version }),
        toolCount: tools.length,
      },
      findings,
    };
  } finally {
    await client.close().catch(() => undefined);
  }
}

export async function scan(config: ScanConfig, execute: boolean): Promise<ScanReport> {
  const findings = inspectLaunch(config.target);
  let server: ServerMetadata | undefined;

  if (!execute) {
    findings.push({
      id: "EXEC001",
      severity: "info",
      title: "Dynamic discovery was not executed",
      evidence: "The --execute flag was not provided; the target process was not started.",
      recommendation: "Review the launcher, then rerun with --execute in a disposable environment.",
      location: "execution",
    });
  } else {
    const discovery = await discover(config);
    server = discovery.server;
    findings.push(...discovery.findings);
  }

  findings.sort((left, right) => {
    const severityOrder = SEVERITIES.indexOf(right.severity) - SEVERITIES.indexOf(left.severity);
    return (
      severityOrder ||
      left.id.localeCompare(right.id) ||
      (left.location ?? "").localeCompare(right.location ?? "")
    );
  });

  return {
    schemaVersion: "1.0",
    scanner: {
      name: "mcp-security-lab",
      version: VERSION,
    },
    target: {
      command: config.target.command,
      args: redactArguments(config.target.args),
      cwd: config.target.cwd,
    },
    execution: {
      requested: execute,
      connected: server !== undefined,
      toolsInvoked: 0,
      environmentMode: "allowlist",
      osSandboxed: false,
      limitations: [
        "The target process is not isolated from the host filesystem or network.",
        "The scanner inspects advertised tool metadata but does not invoke tools.",
      ],
    },
    ...(server === undefined ? {} : { server }),
    summary: summarize(findings),
    findings,
  };
}
