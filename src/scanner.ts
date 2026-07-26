import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  JSONRPCMessage,
  MessageExtraInfo,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";

import {
  auditRemoteAuthentication,
  createTransportFetch,
} from "./auth-audit.js";
import {
  createSanitizedEnvironment,
  redactArguments,
  redactUntrustedText,
  redactUrl,
} from "./environment.js";
import { createFinding, RULES_VERSION } from "./rules/catalog.js";
import { inspectLaunch } from "./rules/launch.js";
import { inspectPrompt } from "./rules/prompts.js";
import { inspectResource } from "./rules/resources.js";
import { inspectServer } from "./rules/server.js";
import { inspectTool } from "./rules/tools.js";
import { createExecutionPlan } from "./sandbox.js";
import type {
  Finding,
  PromptMetadata,
  ResourceMetadata,
  ResolvedScanPolicy,
  SandboxConfig,
  ScanConfig,
  ScanReport,
  ServerMetadata,
  Severity,
  ToolMetadata,
} from "./types.js";
import { VERSION } from "./version.js";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

class ObservedTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void;
  protocolVersion?: string;

  constructor(
    private readonly inner: Transport,
    private readonly maximumResponseBytes: number,
  ) {}

  async start(): Promise<void> {
    this.inner.onclose = () => this.onclose?.();
    this.inner.onerror = (error) => this.onerror?.(error);
    this.inner.onmessage = (message, extra) => {
      const size = Buffer.byteLength(JSON.stringify(message), "utf8");
      if (size > this.maximumResponseBytes) {
        this.onerror?.(
          new Error(
            `MCP message exceeds ${this.maximumResponseBytes} bytes after decoding.`,
          ),
        );
        void this.inner.close().catch(() => undefined);
        return;
      }
      this.onmessage?.(message, extra);
    };
    await this.inner.start();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    await this.inner.send(message, options);
  }

  async close(): Promise<void> {
    await this.inner.close();
  }

  setProtocolVersion(version: string): void {
    this.protocolVersion = version;
    this.inner.setProtocolVersion?.(version);
  }
}

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

async function listTools(
  client: Client,
  policy: ResolvedScanPolicy,
): Promise<ToolMetadata[]> {
  const tools: ToolMetadata[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;

  while (true) {
    const response = await withTimeout(
      client.listTools(cursor === undefined ? undefined : { cursor }),
      policy.timeoutMs,
      "MCP tools/list",
    );
    for (const tool of response.tools) {
      tools.push({
        name: tool.name,
        ...(tool.title === undefined ? {} : { title: tool.title }),
        ...(tool.description === undefined ? {} : { description: tool.description }),
        inputSchema: tool.inputSchema as Record<string, unknown>,
        ...(tool.outputSchema === undefined
          ? {}
          : { outputSchema: tool.outputSchema as Record<string, unknown> }),
        ...(tool.annotations === undefined
          ? {}
          : { annotations: tool.annotations as Record<string, unknown> }),
        ...(tool.execution === undefined
          ? {}
          : { execution: tool.execution as Record<string, unknown> }),
      });
      if (tools.length > policy.maxTools) {
        throw new Error(
          `Server advertised more than policy.maxTools (${policy.maxTools}).`,
        );
      }
    }
    if (response.nextCursor === undefined) {
      return tools;
    }
    if (cursors.has(response.nextCursor)) {
      throw new Error("Server repeated a tools/list cursor.");
    }
    cursors.add(response.nextCursor);
    cursor = response.nextCursor;
  }
}

async function listResources(
  client: Client,
  policy: ResolvedScanPolicy,
): Promise<ResourceMetadata[]> {
  const resources: ResourceMetadata[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;

  while (true) {
    const response = await withTimeout(
      client.listResources(cursor === undefined ? undefined : { cursor }),
      policy.timeoutMs,
      "MCP resources/list",
    );
    for (const resource of response.resources) {
      resources.push({
        uri: resource.uri,
        name: resource.name,
        ...(resource.title === undefined ? {} : { title: resource.title }),
        ...(resource.description === undefined ? {} : { description: resource.description }),
        ...(resource.mimeType === undefined ? {} : { mimeType: resource.mimeType }),
        ...(resource.size === undefined ? {} : { size: resource.size }),
      });
      if (resources.length > policy.maxResources) {
        throw new Error(
          `Server advertised more than policy.maxResources (${policy.maxResources}).`,
        );
      }
    }
    if (response.nextCursor === undefined) {
      return resources;
    }
    if (cursors.has(response.nextCursor)) {
      throw new Error("Server repeated a resources/list cursor.");
    }
    cursors.add(response.nextCursor);
    cursor = response.nextCursor;
  }
}

async function listPrompts(
  client: Client,
  policy: ResolvedScanPolicy,
): Promise<PromptMetadata[]> {
  const prompts: PromptMetadata[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;

  while (true) {
    const response = await withTimeout(
      client.listPrompts(cursor === undefined ? undefined : { cursor }),
      policy.timeoutMs,
      "MCP prompts/list",
    );
    for (const prompt of response.prompts) {
      prompts.push({
        name: prompt.name,
        ...(prompt.title === undefined ? {} : { title: prompt.title }),
        ...(prompt.description === undefined ? {} : { description: prompt.description }),
        ...(prompt.arguments === undefined
          ? {}
          : {
              arguments: prompt.arguments.map((argument) => ({
                name: argument.name,
                ...(argument.description === undefined
                  ? {}
                  : { description: argument.description }),
                ...(argument.required === undefined ? {} : { required: argument.required }),
              })),
            }),
      });
      if (prompts.length > policy.maxPrompts) {
        throw new Error(
          `Server advertised more than policy.maxPrompts (${policy.maxPrompts}).`,
        );
      }
    }
    if (response.nextCursor === undefined) {
      return prompts;
    }
    if (cursors.has(response.nextCursor)) {
      throw new Error("Server repeated a prompts/list cursor.");
    }
    cursors.add(response.nextCursor);
    cursor = response.nextCursor;
  }
}

async function discover(
  transport: Transport,
  policy: ResolvedScanPolicy,
): Promise<{
  server: ServerMetadata;
  findings: Finding[];
  metadataMethods: string[];
}> {
  const client = new Client({ name: "mcp-security-lab", version: VERSION });
  const observed = new ObservedTransport(transport, policy.maxResponseBytes);
  let connected = false;

  try {
    await withTimeout(
      client.connect(observed),
      policy.timeoutMs,
      "MCP initialization",
    );
    connected = true;
    const capabilities = client.getServerCapabilities() ?? {};
    const capabilityNames = Object.keys(capabilities).sort();
    const metadataMethods = ["initialize"];
    const tools =
      capabilities.tools === undefined ? [] : await listTools(client, policy);
    if (capabilities.tools !== undefined) {
      metadataMethods.push("tools/list");
    }
    const resources =
      capabilities.resources === undefined ? [] : await listResources(client, policy);
    if (capabilities.resources !== undefined) {
      metadataMethods.push("resources/list");
    }
    const prompts =
      capabilities.prompts === undefined ? [] : await listPrompts(client, policy);
    if (capabilities.prompts !== undefined) {
      metadataMethods.push("prompts/list");
    }

    const serverVersion = client.getServerVersion();
    const instructions = client.getInstructions();
    const findings = [
      ...inspectServer(serverVersion?.version, observed.protocolVersion, instructions),
      ...tools.flatMap(inspectTool),
      ...resources.flatMap(inspectResource),
      ...prompts.flatMap(inspectPrompt),
    ];

    return {
      server: {
        ...(serverVersion?.name === undefined ? {} : { name: serverVersion.name }),
        ...(serverVersion?.version === undefined ? {} : { version: serverVersion.version }),
        ...(observed.protocolVersion === undefined
          ? {}
          : { protocolVersion: observed.protocolVersion }),
        capabilities: capabilityNames,
        instructionsPresent: instructions !== undefined && instructions.trim() !== "",
        toolCount: tools.length,
        resourceCount: resources.length,
        promptCount: prompts.length,
      },
      findings,
      metadataMethods,
    };
  } finally {
    if (connected) {
      await withTimeout(client.close(), policy.timeoutMs, "MCP shutdown").catch(
        () => undefined,
      );
    } else {
      await client.close().catch(() => undefined);
    }
  }
}

function profileFailureThreshold(
  profile: ResolvedScanPolicy["profile"],
): "medium" | "high" | "critical" {
  if (profile === "strict") {
    return "medium";
  }
  if (profile === "compatibility") {
    return "critical";
  }
  return "high";
}

export function reportFailsPolicy(report: ScanReport): boolean {
  const threshold = SEVERITIES.indexOf(report.policy.failureThreshold);
  return report.findings.some(
    (finding) => SEVERITIES.indexOf(finding.severity) >= threshold,
  );
}

export async function scan(config: ScanConfig, execute: boolean): Promise<ScanReport> {
  const policy: ResolvedScanPolicy = {
    timeoutMs: config.policy.timeoutMs,
    maxTools: config.policy.maxTools,
    maxResources: config.policy.maxResources ?? 100,
    maxPrompts: config.policy.maxPrompts ?? 100,
    maxResponseBytes: config.policy.maxResponseBytes ?? 1_048_576,
    profile: config.policy.profile ?? "balanced",
    allowPrivateNetwork: config.policy.allowPrivateNetwork ?? false,
  };
  const sandboxConfig: SandboxConfig = config.sandbox ?? {
    adapter: "none",
    image: "node:24.18.0-bookworm-slim",
    network: "none",
    memoryMb: 256,
    cpus: 1,
    pidsLimit: 128,
  };
  const findings: Finding[] =
    config.target.transport === "streamable-http" ? [] : inspectLaunch(config.target);
  let server: ServerMetadata | undefined;
  let authentication: ScanReport["authentication"];
  let metadataMethods: string[] = [];
  let sandbox: ScanReport["execution"]["sandbox"] = {
    adapter: "none",
    verified: false,
    network: "host",
  };

  if (!execute) {
    findings.push(
      createFinding(
        "EXEC001",
        "The --execute flag was not provided; no process or network request was started.",
        "execution",
      ),
    );
  } else {
    let transport: Transport | undefined;
    if (config.target.transport !== "streamable-http") {
      const plan = await createExecutionPlan(
        config.target,
        sandboxConfig,
        policy.timeoutMs,
      );
      findings.push(...plan.findings);
      sandbox = plan.sandbox;
      const stdioTransport = new StdioClientTransport({
        command: plan.target.command,
        args: plan.target.args,
        cwd: plan.target.cwd,
        env: createSanitizedEnvironment(),
        stderr: "pipe",
      });
      stdioTransport.stderr?.on("data", () => undefined);
      transport = stdioTransport as Transport;
    } else {
      try {
        const authResult = await auditRemoteAuthentication(
          config.target.url,
          policy,
        );
        findings.push(...authResult.findings);
        authentication = authResult.metadata;
        transport = new StreamableHTTPClientTransport(new URL(config.target.url), {
          fetch: createTransportFetch(policy),
        }) as Transport;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        findings.push(
          createFinding(
            "EXEC002",
            redactUntrustedText(message),
            "execution",
          ),
        );
      }
    }

    if (transport !== undefined) {
      try {
        const discovery = await discover(transport, policy);
        server = discovery.server;
        metadataMethods = discovery.metadataMethods;
        findings.push(...discovery.findings);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        findings.push(
          createFinding(
            "EXEC002",
            redactUntrustedText(message),
            "execution",
          ),
        );
      }
    }
  }

  findings.sort((left, right) => {
    const severityOrder = SEVERITIES.indexOf(right.severity) - SEVERITIES.indexOf(left.severity);
    return severityOrder ||
      left.id.localeCompare(right.id) ||
      (left.location ?? "").localeCompare(right.location ?? "");
  });

  const limitations = ["Discovered tools were not invoked."];
  if (config.target.transport !== "streamable-http" && !sandbox.verified) {
    limitations.push(
      "The target process was not isolated from the host filesystem or network.",
    );
  }
  if (config.target.transport === "streamable-http") {
    limitations.push(
      "Authentication checks were passive and did not request or send credentials.",
    );
  }

  return {
    schemaVersion: "2.0",
    scanner: {
      name: "mcp-security-lab",
      version: VERSION,
      rulesVersion: RULES_VERSION,
    },
    policy: {
      profile: policy.profile,
      failureThreshold: profileFailureThreshold(policy.profile),
    },
    target:
      config.target.transport !== "streamable-http"
        ? {
            transport: "stdio",
            command: config.target.command,
            args: redactArguments(config.target.args),
            cwd: config.target.cwd,
          }
        : {
            transport: "streamable-http",
            url: redactUrl(config.target.url),
          },
    execution: {
      requested: execute,
      connected: server !== undefined,
      toolsInvoked: 0,
      environmentMode:
        config.target.transport !== "streamable-http" ? "allowlist" : "not-applicable",
      osSandboxed: sandbox.verified,
      sandbox,
      metadataMethods,
      limitations,
    },
    ...(server === undefined ? {} : { server }),
    ...(authentication === undefined ? {} : { authentication }),
    summary: summarize(findings),
    findings,
  };
}
