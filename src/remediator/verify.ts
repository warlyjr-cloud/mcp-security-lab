import type { ToolMetadata } from "../types.js";
import { inspectTool } from "../rules/tools.js";
import { inspectCredentialPassthrough } from "../rules/lifecycle.js";

/**
 * Rule ids that specifically detect prompt-injection-like text (TOOL003) or
 * text smuggled past a human reviewer via invisible/control characters
 * (TOOL012). Rule-clearance for these is a weaker signal than for ordinary
 * hygiene findings: the fixer model was shown the exact injected text while
 * drafting its proposal, so a model that has (even inadvertently) internalized
 * part of that payload could rephrase it just enough to dodge the same static
 * pattern list without removing the underlying malicious intent. Callers must
 * not present rule-clearance alone as proof an injection finding is resolved.
 */
export const INJECTION_RULE_IDS = new Set(["TOOL003", "TOOL012"]);

/**
 * Run the deterministic tool-scoped rules against a single (proposed) tool and
 * return the sorted, de-duplicated rule ids that still fire. An empty result
 * means the proposed tool metadata passes every tool-scoped rule.
 *
 * This is the verification oracle for the agentic remediation loop: the model
 * proposes a fixed tool definition, and this function — not the model — decides
 * whether the fix actually holds. `inspectTool` re-runs the full prompt-injection
 * scan (description, annotation title, parameter names/descriptions/enums) against
 * the *proposed* tool on every round, not just the specific rule ids the original
 * findings named — so a fix that resolves TOOL010 must not silently reintroduce
 * TOOL003 elsewhere in the definition.
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
