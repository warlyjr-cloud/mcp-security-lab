import type { Finding, ToolMetadata } from "../types.js";
import { redactUntrustedText } from "../environment.js";
import { createFinding } from "./catalog.js";
import { injectionLabels } from "./text.js";

const DESTRUCTIVE_NAME_PATTERN =
  /(?:^|[_-])(delete|drop|destroy|remove|reset|purge|revoke|send|publish|deploy)(?:$|[_-])/i;
const READ_NAME_PATTERN =
  /(?:^|[_-])(get|list|read|search|find|fetch|inspect|describe)(?:$|[_-])/i;
const MAX_SCHEMA_DEPTH = 20;
const MAX_SCHEMA_NODES = 2_000;

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

function schemaComplexity(value: unknown): { depth: number; nodes: number } {
  let nodes = 0;
  let maximumDepth = 0;
  const seen = new Set<object>();
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }];

  while (stack.length > 0 && nodes <= MAX_SCHEMA_NODES) {
    const current = stack.pop();
    if (current === undefined) {
      continue;
    }
    nodes += 1;
    maximumDepth = Math.max(maximumDepth, current.depth);
    if (typeof current.value !== "object" || current.value === null) {
      continue;
    }
    if (seen.has(current.value)) {
      continue;
    }
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      for (const item of current.value) {
        stack.push({ value: item, depth: current.depth + 1 });
      }
    } else {
      for (const item of Object.values(current.value as Record<string, unknown>)) {
        stack.push({ value: item, depth: current.depth + 1 });
      }
    }
  }

  return { depth: maximumDepth, nodes };
}

export function inspectTool(tool: ToolMetadata): Finding[] {
  const findings: Finding[] = [];
  const safeName = redactUntrustedText(tool.name, 200);
  const location = `tool:${safeName}`;
  const annotations = tool.annotations ?? {};
  const description = tool.description ?? "";

  if (tool.name.length > 64) {
    findings.push(
      createFinding("TOOL001", `Tool name has ${tool.name.length} characters.`, location),
    );
  }

  if (description.trim() === "") {
    findings.push(
      createFinding("TOOL002", "The server returned no description for this tool.", location),
    );
  }

  const injectionMatches = injectionLabels(description);
  if (injectionMatches.length > 0) {
    findings.push(
      createFinding(
        "TOOL003",
        `Description matched: ${injectionMatches.join(", ")}.`,
        location,
      ),
    );
  }

  const topLevelTitle = tool.title?.trim();
  const annotationTitle =
    typeof annotations.title === "string" ? annotations.title.trim() : "";
  if ((topLevelTitle ?? "") === "" && annotationTitle === "") {
    findings.push(
      createFinding(
        "TOOL004",
        "Neither top-level title nor annotations.title is present.",
        location,
      ),
    );
  }

  const safetyKeys = [
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
  ];
  const missingHints = safetyKeys.filter(
    (key) => typeof annotations[key] !== "boolean",
  );
  if (missingHints.length > 0) {
    findings.push(
      createFinding(
        "TOOL005",
        `Missing explicit hints: ${missingHints.join(", ")}. MCP applies cautious defaults.`,
        location,
      ),
    );
  }

  const destructiveHint = annotationBoolean(tool, "destructiveHint");
  const readOnlyHint = annotationBoolean(tool, "readOnlyHint");
  const openWorldHint = annotationBoolean(tool, "openWorldHint");

  if (readOnlyHint === true && destructiveHint === true) {
    findings.push(
      createFinding(
        "TOOL010",
        "readOnlyHint and destructiveHint are both true.",
        location,
      ),
    );
  }

  if (DESTRUCTIVE_NAME_PATTERN.test(tool.name) && destructiveHint !== true) {
    findings.push(
      createFinding(
        "TOOL006",
        `Tool name "${safeName}" implies an external side effect.`,
        location,
      ),
    );
  }

  if (READ_NAME_PATTERN.test(tool.name) && readOnlyHint === false) {
    findings.push(
      createFinding(
        "TOOL007",
        `Tool name "${safeName}" appears read-only but readOnlyHint is false.`,
        location,
      ),
    );
  }

  if (openWorldHint === undefined) {
    findings.push(
      createFinding(
        "TOOL011",
        "openWorldHint is absent; the MCP default is true.",
        location,
      ),
    );
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
        findings.push(
          createFinding(
            "TOOL008",
            `method enum contains both safe and unsafe HTTP methods: ${redactUntrustedText([...methods].join(", "), 500)}.`,
            location,
          ),
        );
      }
    }
  }

  if (tool.inputSchema.additionalProperties !== false) {
    findings.push(
      createFinding(
        "TOOL009",
        "inputSchema.additionalProperties is not explicitly false.",
        location,
      ),
    );
  }

  if (tool.outputSchema === undefined) {
    findings.push(
      createFinding("TOOL012", "The server returned no outputSchema.", location),
    );
  }

  const required = tool.inputSchema.required;
  if (Array.isArray(required)) {
    const missingProperties = required.filter(
      (field): field is string =>
        typeof field === "string" && !Object.hasOwn(properties, field),
    );
    if (missingProperties.length > 0) {
      findings.push(
        createFinding(
          "TOOL013",
          `Required fields missing from properties: ${redactUntrustedText(missingProperties.join(", "), 500)}.`,
          location,
        ),
      );
    }
  }

  const complexity = schemaComplexity({
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema,
  });
  if (complexity.depth > MAX_SCHEMA_DEPTH || complexity.nodes > MAX_SCHEMA_NODES) {
    findings.push(
      createFinding(
        "TOOL014",
        `Schema depth is ${complexity.depth}; inspected node count is ${complexity.nodes}.`,
        location,
      ),
    );
  }

  return findings;
}
