export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Confidence = "low" | "medium" | "high";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  evidence: string;
  recommendation: string;
  remediationSnippet?: string;
  location?: string;
  /** CWE identifier, e.g. "CWE-77". */
  cwe?: string;
  /** OWASP Top 10 for LLM Applications identifier, e.g. "LLM01". */
  owasp?: string;
  /** Detection confidence, for downstream filtering and ranking. */
  confidence?: Confidence;
  /** External references (spec sections, advisories) for the finding. */
  references?: string[];
}

export interface TargetConfig {
  command?: string;
  args?: string[];
  cwd?: string;
  env?: Record<string, string>;
  url?: string;
  /** Remote transport. Defaults to "http" (Streamable HTTP); "sse" is legacy. */
  transport?: "http" | "sse";
}

export interface ScanPolicy {
  timeoutMs: number;
  maxTools: number;
  aiFuzz?: boolean;
}

export interface ScanConfig {
  target: TargetConfig;
  policy: ScanPolicy;
}

export interface ToolMetadata {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

export interface ServerMetadata {
  name?: string;
  version?: string;
  protocolVersion?: string;
  instructions?: string;
  toolCount: number;
  promptCount?: number;
  resourceCount?: number;
}

export interface ScanReport {
  schemaVersion: "1.0";
  scanner: {
    name: "mcp-security-lab";
    version: string;
  };
  target: {
    command?: string;
    args?: string[];
    cwd?: string;
    url?: string;
  };
  execution: {
    requested: boolean;
    connected: boolean;
    toolsInvoked: number;
    transport: "stdio" | "sse" | "http";
    environmentMode: "allowlist" | "none";
    osSandboxed: boolean;
    limitations: string[];
  };
  server?: ServerMetadata;
  summary: Record<Severity, number>;
  findings: Finding[];
}
