export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingCategory =
  | "authentication"
  | "behavior"
  | "execution"
  | "metadata"
  | "protocol"
  | "sandbox"
  | "schema"
  | "transport";

export interface RuleReference {
  label: string;
  url: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  confidence: Confidence;
  category: FindingCategory;
  title: string;
  evidence: string;
  recommendation: string;
  references: RuleReference[];
  location?: string;
}

export interface StdioTargetConfig {
  transport?: "stdio";
  command: string;
  args: string[];
  cwd: string;
}

export interface HttpTargetConfig {
  transport: "streamable-http";
  url: string;
}

export type TargetConfig = StdioTargetConfig | HttpTargetConfig;

export interface ScanPolicy {
  timeoutMs: number;
  maxTools: number;
  maxResources?: number;
  maxPrompts?: number;
  maxResponseBytes?: number;
  profile?: "strict" | "balanced" | "compatibility";
  allowPrivateNetwork?: boolean;
}

export type ResolvedScanPolicy = Required<ScanPolicy>;

export interface SandboxConfig {
  adapter: "none" | "docker";
  image: string;
  network: "none" | "bridge";
  memoryMb: number;
  cpus: number;
  pidsLimit: number;
}

export interface ScanConfig {
  target: TargetConfig;
  policy: ScanPolicy;
  sandbox?: SandboxConfig;
}

export interface ToolMetadata {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  execution?: Record<string, unknown>;
}

export interface ResourceMetadata {
  uri: string;
  name: string;
  title?: string;
  description?: string;
  mimeType?: string;
  size?: number;
}

export interface PromptMetadata {
  name: string;
  title?: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

export interface ServerMetadata {
  name?: string;
  version?: string;
  protocolVersion?: string;
  capabilities: string[];
  instructionsPresent: boolean;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
}

export interface AuthMetadataSummary {
  protectedResourceUrl?: string;
  resource?: string;
  authorizationServers: string[];
  scopesSupported: string[];
  authorizationServerMetadataUrl?: string;
  issuer?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  codeChallengeMethodsSupported: string[];
}

export interface ScanReport {
  schemaVersion: "2.0";
  scanner: {
    name: "mcp-security-lab";
    version: string;
    rulesVersion: string;
  };
  policy: {
    profile: "strict" | "balanced" | "compatibility";
    failureThreshold: "medium" | "high" | "critical";
  };
  target:
    | {
        transport: "stdio";
        command: string;
        args: string[];
        cwd: string;
      }
    | {
        transport: "streamable-http";
        url: string;
      };
  execution: {
    requested: boolean;
    connected: boolean;
    toolsInvoked: number;
    environmentMode: "allowlist" | "not-applicable";
    osSandboxed: boolean;
    sandbox: {
      adapter: "none" | "docker";
      verified: boolean;
      network: "host" | "none" | "bridge";
    };
    metadataMethods: string[];
    limitations: string[];
  };
  server?: ServerMetadata;
  authentication?: AuthMetadataSummary;
  summary: Record<Severity, number>;
  findings: Finding[];
}

export interface ExerciseReport {
  schemaVersion: "1.0";
  scanner: {
    name: "mcp-security-lab";
    version: string;
  };
  tool: string;
  callsRequested: number;
  callsCompleted: number;
  sandbox: {
    adapter: "docker";
    verified: true;
    network: "none" | "bridge";
  };
  resultDigests: string[];
  canary: {
    disclosed: boolean;
    modified: boolean;
  };
  findings: Finding[];
}

export interface BenchmarkCaseResult {
  name: string;
  expectedFindingIds: string[];
  actualFindingIds: string[];
  truePositives: string[];
  falsePositives: string[];
  falseNegatives: string[];
}

export interface BenchmarkReport {
  schemaVersion: "1.0";
  scannerVersion: string;
  manifest: string;
  cases: BenchmarkCaseResult[];
  metrics: {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
  };
  thresholds: {
    minimumPrecision: number;
    minimumRecall: number;
    passed: boolean;
  };
}
