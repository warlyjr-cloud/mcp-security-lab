import Anthropic from "@anthropic-ai/sdk";

import type { Finding, ScanReport, ToolMetadata } from "../types.js";
import { isToolMetadata, residualFindingIds } from "./verify.js";

const MODEL = "claude-opus-4-8";
const MAX_ROUNDS = 5;

export interface VerifiedFix {
  toolName: string;
  findingIds: string[];
  /** The proposed corrected tool metadata (verified when `verified` is true). */
  fixedTool?: ToolMetadata;
  /** True when the deterministic engine confirmed the fix clears every rule. */
  verified: boolean;
  /** Rule ids still firing on the final proposal (empty when verified). */
  residual: string[];
  rounds: number;
}

const SUBMIT_FIX_TOOL: Anthropic.Tool = {
  name: "submit_fix",
  description:
    "Submit a proposed corrected tool definition. Returns the MCP Verifier rule ids that still fire on it; an empty list means every rule passes.",
  input_schema: {
    type: "object",
    properties: {
      tool: {
        type: "object",
        description:
          "The full corrected tool metadata: { name, description, inputSchema, annotations }. inputSchema must be a JSON Schema object.",
      },
    },
    required: ["tool"],
  },
};

function toolUseBlocks(
  content: Anthropic.ContentBlock[],
): Extract<Anthropic.ContentBlock, { type: "tool_use" }>[] {
  return content.filter(
    (block): block is Extract<Anthropic.ContentBlock, { type: "tool_use" }> =>
      block.type === "tool_use",
  );
}

/**
 * Agentic, self-verifying remediation for a single tool. The model proposes a
 * corrected tool definition; the deterministic engine (residualFindingIds)
 * decides whether it holds and feeds the remaining rule ids back; the model
 * iterates until nothing fires or the round budget is exhausted.
 */
export async function agenticFixTool(
  anthropic: Anthropic,
  toolName: string,
  findings: Finding[],
): Promise<VerifiedFix> {
  const findingSummary = findings
    .map(
      (finding) =>
        `- ${finding.id} (${finding.severity}): ${finding.title} — ${finding.recommendation}`,
    )
    .join("\n");

  const system =
    "You are a security engineer fixing an MCP tool definition so it passes every MCP Verifier rule. " +
    "Call submit_fix with a complete corrected tool definition (name, description, inputSchema, annotations). " +
    "The response lists rule ids that still fire. Keep revising and re-submitting until the list is empty. " +
    "Preserve the tool's original purpose; only change what the findings require. When the list is empty, " +
    "stop and briefly explain the fix in one paragraph.";

  const messages: Anthropic.MessageParam[] = [
    {
      role: "user",
      content:
        `Fix the MCP tool "${toolName}". These MCP Verifier findings must all be resolved:\n\n${findingSummary}\n\n` +
        "Call submit_fix with your corrected tool definition.",
    },
  ];

  let best: VerifiedFix = {
    toolName,
    findingIds: findings.map((finding) => finding.id),
    verified: false,
    residual: findings.map((finding) => finding.id),
    rounds: 0,
  };

  for (let round = 1; round <= MAX_ROUNDS; round += 1) {
    const response = await anthropic.messages.create({
      model: MODEL,
      max_tokens: 4096,
      system,
      tools: [SUBMIT_FIX_TOOL],
      messages,
    });
    best.rounds = round;

    const toolUses = toolUseBlocks(response.content);
    if (response.stop_reason !== "tool_use" || toolUses.length === 0) {
      break; // model produced a final (text) answer
    }

    messages.push({ role: "assistant", content: response.content });

    const toolResults: Anthropic.ToolResultBlockParam[] = [];
    for (const toolUse of toolUses) {
      const proposed = (toolUse.input as { tool?: unknown }).tool;
      let remaining: string[];
      if (isToolMetadata(proposed)) {
        remaining = residualFindingIds(proposed);
        if (remaining.length < best.residual.length) {
          best = {
            ...best,
            fixedTool: proposed,
            residual: remaining,
            verified: remaining.length === 0,
          };
        }
      } else {
        remaining = ["INVALID_TOOL_SHAPE"];
      }
      toolResults.push({
        type: "tool_result",
        tool_use_id: toolUse.id,
        content: JSON.stringify({ remaining_findings: remaining }),
      });
    }
    messages.push({ role: "user", content: toolResults });

    if (best.verified) {
      break;
    }
  }

  return best;
}

/**
 * Produce a remediation report where each tool-scoped fix is **verified** by the
 * deterministic engine, not merely suggested by the model. Requires an Anthropic
 * API key; returns a message if none is available.
 */
export async function generateVerifiedRemediation(
  report: ScanReport,
  apiKey?: string,
): Promise<string> {
  const key = apiKey || process.env.ANTHROPIC_API_KEY;
  if (!key) {
    return "Skipping verified remediation: ANTHROPIC_API_KEY is not set.";
  }

  // Group actionable, tool-scoped findings by tool.
  const byTool = new Map<string, Finding[]>();
  for (const finding of report.findings) {
    if (
      finding.location?.startsWith("tool:") &&
      (finding.severity === "high" || finding.severity === "critical")
    ) {
      const name = finding.location.slice("tool:".length);
      const list = byTool.get(name) ?? [];
      list.push(finding);
      byTool.set(name, list);
    }
  }

  if (byTool.size === 0) {
    return "# 🛡️ Rule-Verified MCP Remediation\n\nNo high or critical tool-scoped findings to remediate.";
  }

  const anthropic = new Anthropic({ apiKey: key });
  const sections: string[] = [
    "# 🛡️ Rule-Verified MCP Remediation",
    "",
    "> **Scope of verification:** each proposal below was re-scanned and clears every" +
      " deterministic MCP Verifier rule. This checks *rule compliance only* — it does" +
      " **not** verify that the fix preserves the tool's original behavior (a proposal" +
      " that drops parameters or loosens a schema can still pass). Review the diff and" +
      " run the tool's own tests before applying.",
    "",
  ];

  for (const [toolName, findings] of byTool) {
    const fix = await agenticFixTool(anthropic, toolName, findings);
    const status = fix.verified
      ? "✅ **Rule-verified** — re-running every MCP Verifier rule on the proposed definition clears all findings (rule compliance only; behavior not verified)."
      : `⚠️ **Unverified** after ${fix.rounds} round(s) — still firing: ${fix.residual.join(", ") || "unknown"}.`;
    sections.push(`## \`${toolName}\``);
    sections.push(`Resolves: ${fix.findingIds.join(", ")}`);
    sections.push(status);
    if (fix.fixedTool) {
      sections.push("", "```json", JSON.stringify(fix.fixedTool, null, 2), "```");
    }
    sections.push("");
  }

  return sections.join("\n");
}
