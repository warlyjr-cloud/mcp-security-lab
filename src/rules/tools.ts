import type { Finding, ToolMetadata } from "../types.js";
import { scanTextForInjection } from "./injection.js";

const DESTRUCTIVE_NAME_PATTERN =
  /(?:^|[_-])(delete|drop|destroy|remove|reset|purge|revoke|send|publish|deploy)(?:$|[_-])/i;
const READ_NAME_PATTERN = /(?:^|[_-])(get|list|read|search|find|fetch|inspect|describe)(?:$|[_-])/i;

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

/**
 * Collect every untrusted string a server places into the model's context for a
 * tool: the description, the annotation title, and each parameter's name,
 * description, and string-literal enum values. Injection can hide in any of
 * these, not only in the top-level description.
 */
function injectionSurface(tool: ToolMetadata): Array<{ text: string; sourceLabel: string }> {
  const surface: Array<{ text: string; sourceLabel: string }> = [];

  if (typeof tool.description === "string") {
    surface.push({ text: tool.description, sourceLabel: "description" });
  }

  const title = tool.annotations?.title;
  if (typeof title === "string") {
    surface.push({ text: title, sourceLabel: "annotation title" });
  }

  for (const [name, schema] of Object.entries(propertiesOf(tool.inputSchema))) {
    surface.push({ text: name, sourceLabel: `parameter name "${name}"` });
    if (typeof schema === "object" && schema !== null && !Array.isArray(schema)) {
      const record = schema as Record<string, unknown>;
      if (typeof record.description === "string") {
        surface.push({ text: record.description, sourceLabel: `parameter "${name}" description` });
      }
      if (Array.isArray(record.enum)) {
        for (const value of record.enum) {
          if (typeof value === "string") {
            surface.push({ text: value, sourceLabel: `parameter "${name}" enum value` });
          }
        }
      }
    }
  }

  return surface;
}

export function inspectServerCapabilities(tools: ToolMetadata[]): Finding[] {
  const findings: Finding[] = [];
  let hasRead = false;
  let hasWrite = false;

  for (const tool of tools) {
    if (READ_NAME_PATTERN.test(tool.name)) {
      hasRead = true;
    }
    if (
      DESTRUCTIVE_NAME_PATTERN.test(tool.name) ||
      tool.name.match(/^(?:write|update|set|put|post|create|insert)/i)
    ) {
      hasWrite = true;
    }
  }

  if (hasRead && hasWrite) {
    findings.push({
      id: "TOOL011",
      severity: "high",
      title: "Dangerous Capability Combination (Least Privilege Violation)",
      evidence: "The server exposes both broad READ tools and destructive WRITE tools.",
      recommendation:
        "Separate read and write capabilities into different MCP servers or require explicit user confirmation for write operations.",
      location: "server",
      cwe: "CWE-250",
      owasp: "LLM08",
    });
  }

  return findings;
}

/**
 * Inspect the server-level instructions returned during the MCP handshake.
 * These are injected verbatim into the model's context, so injection here is
 * as dangerous as in any tool description.
 */
export function inspectServerInstructions(instructions: string | undefined): Finding[] {
  if (typeof instructions !== "string") {
    return [];
  }
  return scanTextForInjection(instructions, "server", "server instructions").map((finding) => ({
    ...finding,
    title:
      finding.id === "TOOL003"
        ? "Server instructions contain a prompt-injection-like instruction"
        : finding.title,
  }));
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
      cwe: "CWE-20",
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

  for (const { text, sourceLabel } of injectionSurface(tool)) {
    findings.push(...scanTextForInjection(text, location, sourceLabel));
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
      cwe: "CWE-1188",
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
      cwe: "CWE-250",
      owasp: "LLM08",
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
          cwe: "CWE-250",
          owasp: "LLM08",
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
      cwe: "CWE-20",
    });
  }

  const paginationKeys = new Set(["limit", "offset", "cursor", "max_results", "page"]);
  const hasPagination = Object.keys(properties).some((key) =>
    paginationKeys.has(key.toLowerCase()),
  );

  if (!hasPagination && READ_NAME_PATTERN.test(tool.name)) {
    findings.push({
      id: "TOOL010",
      severity: "medium",
      title: "Context Exhaustion Risk: Missing pagination limits",
      evidence: "Tool name implies reading, but inputSchema lacks limit, cursor, or offset fields.",
      recommendation: "Implement pagination limits to prevent context window exhaustion attacks.",
      location,
      cwe: "CWE-400",
      owasp: "LLM10",
    });
  }

  return findings;
}
