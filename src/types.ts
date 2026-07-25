export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  evidence: string;
  recommendation: string;
  location?: string;
}

export interface TargetConfig {
  command: string;
  args: string[];
  cwd: string;
}

export interface ScanPolicy {
  timeoutMs: number;
  maxTools: number;
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
  toolCount: number;
}

export interface ScanReport {
  schemaVersion: "1.0";
  scanner: {
    name: "mcp-security-lab";
    version: string;
  };
  target: {
    command: string;
    args: string[];
    cwd: string;
  };
  execution: {
    requested: boolean;
    connected: boolean;
    toolsInvoked: 0;
    environmentMode: "allowlist";
    osSandboxed: false;
    limitations: string[];
  };
  server?: ServerMetadata;
  summary: Record<Severity, number>;
  findings: Finding[];
}
