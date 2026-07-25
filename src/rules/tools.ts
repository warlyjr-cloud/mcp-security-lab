import type { Finding, ToolMetadata } from "../types.js";

const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bignore (?:all |any )?(?:previous|prior) instructions?\b/i, label: "instruction override" },
  { pattern: /\b(?:always|must) (?:call|invoke|use) (?:this|the) tool\b/i, label: "forced invocation" },
  { pattern: /\bdo not (?:tell|inform|show) the user\b/i, label: "concealment" },
  { pattern: /\b(?:system prompt|hidden instructions?)\b/i, label: "hidden prompt reference" },
  { pattern: /\bdisable|bypass\b.{0,30}\b(?:safety|security|permission)/i, label: "safety bypass" },
];

const DESTRUCTIVE_NAME_PATTERN =
  /(?:^|[_-])(delete|drop|destroy|remove|reset|purge|revoke|send|publish|deploy)(?:$|[_-])/i;
const READ_NAME_PATTERN =
  /(?:^|[_-])(get|list|read|search|find|fetch|inspect|describe)(?:$|[_-])/i;

function propertiesOf(schema: Record<string, unknown>): Record<string, unknown> {
  const properties = schema.properties;
  if (typeof properties !== "object" || properties === null || Array.isArray(properties)) {
    return {};
  }
  return properties as Record<string, unknown>;
}

function annotationBoolean(tool: ToolMetadata, key: string): boolean | undefined {
  const value = tool.annotations?.[key];
  return typeof value === "boolean" ? value : undefined;
}

export function inspectTool(tool: ToolMetadata): Finding[] {
  const findings: Finding[] = [];
  const location = `tool:${tool.name}`;
  const annotations = tool.annotations ?? {};
  const description = tool.description ?? "";

  if (tool.name.length > 64) {
    findings.push({
      id: "TOOL001",
      severity: "high",
      title: "Tool name exceeds the compatibility limit",
      evidence: `Tool name has ${tool.name.length} characters.`,
      recommendation: "Use a stable tool name with at most 64 characters.",
      location,
    });
  }

  if (description.trim() === "") {
    findings.push({
      id: "TOOL002",
      severity: "medium",
      title: "Tool description is missing",
      evidence: "The server returned no description for this tool.",
      recommendation: "Describe the tool's precise behavior and when it is appropriate.",
      location,
    });
  }

  for (const candidate of PROMPT_INJECTION_PATTERNS) {
    if (candidate.pattern.test(description)) {
      findings.push({
        id: "TOOL003",
        severity: "high",
        title: "Tool description contains a prompt-injection-like instruction",
        evidence: `Description matched the ${candidate.label} pattern.`,
        recommendation: "Describe functionality only; remove behavioral or hidden instructions.",
        location,
      });
    }
  }

  if (typeof annotations.title !== "string" || annotations.title.trim() === "") {
    findings.push({
      id: "TOOL004",
      severity: "medium",
      title: "Tool annotation title is missing",
      evidence: "annotations.title is absent or empty.",
      recommendation: "Add a short human-readable title annotation.",
      location,
    });
  }

  const destructiveHint = annotationBoolean(tool, "destructiveHint");
  const readOnlyHint = annotationBoolean(tool, "readOnlyHint");
  if (destructiveHint === undefined && readOnlyHint === undefined) {
    findings.push({
      id: "TOOL005",
      severity: "high",
      title: "Tool safety hints are missing",
      evidence: "Neither destructiveHint nor readOnlyHint is explicitly declared.",
      recommendation: "Declare the applicable MCP safety annotations explicitly.",
      location,
    });
  }

  if (DESTRUCTIVE_NAME_PATTERN.test(tool.name) && destructiveHint !== true) {
    findings.push({
      id: "TOOL006",
      severity: "high",
      title: "Potentially destructive tool is not marked destructive",
      evidence: `Tool name "${tool.name}" implies an external side effect.`,
      recommendation: "Set destructiveHint to true and keep the operation narrowly scoped.",
      location,
    });
  }

  if (READ_NAME_PATTERN.test(tool.name) && readOnlyHint === false) {
    findings.push({
      id: "TOOL007",
      severity: "medium",
      title: "Read-like tool is explicitly marked as writable",
      evidence: `Tool name "${tool.name}" appears read-only but readOnlyHint is false.`,
      recommendation: "Split reading and mutation into separate tools with accurate hints.",
      location,
    });
  }

  const properties = propertiesOf(tool.inputSchema);
  const methodSchema = properties.method;
  if (typeof methodSchema === "object" && methodSchema !== null && !Array.isArray(methodSchema)) {
    const methodEnum = (methodSchema as Record<string, unknown>).enum;
    if (Array.isArray(methodEnum)) {
      const methods = new Set(
        methodEnum
          .filter((value): value is string => typeof value === "string")
          .map((value) => value.toUpperCase()),
      );
      const hasSafe = ["GET", "HEAD", "OPTIONS"].some((method) => methods.has(method));
      const hasUnsafe = ["POST", "PUT", "PATCH", "DELETE"].some((method) => methods.has(method));
      if (hasSafe && hasUnsafe) {
        findings.push({
          id: "TOOL008",
          severity: "high",
          title: "Tool mixes read and write HTTP operations",
          evidence: `method enum contains both safe and unsafe HTTP methods: ${[...methods].join(", ")}.`,
          recommendation: "Split read operations from create, update, and delete tools.",
          location,
        });
      }
    }
  }

  if (tool.inputSchema.additionalProperties !== false) {
    findings.push({
      id: "TOOL009",
      severity: "low",
      title: "Input schema accepts undeclared properties",
      evidence: "inputSchema.additionalProperties is not explicitly false.",
      recommendation: "Reject unknown input fields when the server framework supports it.",
      location,
    });
  }

  return findings;
}
