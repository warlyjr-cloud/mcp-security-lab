import type { ToolMetadata } from "../types.js";
import { inspectTool } from "../rules/tools.js";
import { inspectCredentialPassthrough } from "../rules/lifecycle.js";

/**
 * Run the deterministic tool-scoped rules against a single (proposed) tool and
 * return the sorted, de-duplicated rule ids that still fire. An empty result
 * means the proposed tool metadata passes every tool-scoped rule.
 *
 * This is the verification oracle for the agentic remediation loop: the model
 * proposes a fixed tool definition, and this function — not the model — decides
 * whether the fix actually holds.
 */
export function residualFindingIds(tool: ToolMetadata): string[] {
  const ids = new Set<string>();
  for (const finding of inspectTool(tool)) {
    ids.add(finding.id);
  }
  for (const finding of inspectCredentialPassthrough([tool])) {
    ids.add(finding.id);
  }
  return [...ids].sort();
}

/** Type guard: a plausibly-shaped ToolMetadata parsed from model output. */
export function isToolMetadata(value: unknown): value is ToolMetadata {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.name === "string" &&
    typeof record.inputSchema === "object" &&
    record.inputSchema !== null &&
    !Array.isArray(record.inputSchema)
  );
}
