import assert from "node:assert/strict";
import test from "node:test";

import type Anthropic from "@anthropic-ai/sdk";
import { agenticFixTool, generateVerifiedRemediation } from "../src/remediator/agentic.js";
import { UNTRUSTED_DATA_TAG } from "../src/prompt-safety.js";
import type { Finding, ScanReport, ToolMetadata } from "../src/types.js";

const CLEAN_TOOL: ToolMetadata = {
  name: "list_documents",
  description: "List documents in the workspace.",
  annotations: { title: "List documents", readOnlyHint: true, destructiveHint: false },
  inputSchema: {
    type: "object",
    additionalProperties: false,
    properties: { limit: { type: "number" }, cursor: { type: "string" } },
  },
};

const STILL_BROKEN_TOOL: ToolMetadata = {
  name: "delete_everything",
  description: "Deletes everything.",
  inputSchema: { type: "object", properties: {} },
};

function fakeToolUseClient(tool: ToolMetadata): { client: Anthropic; calls: unknown[] } {
  const calls: unknown[] = [];
  const client = {
    messages: {
      create: async (params: unknown) => {
        calls.push(params);
        return {
          content: [{ type: "tool_use", id: "toolu_1", name: "submit_fix", input: { tool } }],
          stop_reason: "tool_use",
        };
      },
    },
  } as unknown as Anthropic;
  return { client, calls };
}

const NON_INJECTION_FINDING: Finding = {
  id: "TOOL009",
  severity: "high",
  title: "Input schema accepts undeclared properties",
  evidence: "inputSchema.additionalProperties is not explicitly false.",
  recommendation: "Reject unknown input fields.",
  location: "tool:list_documents",
};

const INJECTION_FINDING: Finding = {
  id: "TOOL003",
  severity: "high",
  title: "Text contains a prompt-injection-like instruction",
  evidence: "The description matched the instruction override pattern.",
  recommendation: "Describe functionality only.",
  location: "tool:list_documents",
};

test("agenticFixTool verifies a clean proposal on the first round and wraps findings in the untrusted-data tag", async () => {
  const { client, calls } = fakeToolUseClient(CLEAN_TOOL);
  const result = await agenticFixTool(client, "list_documents", [NON_INJECTION_FINDING]);

  assert.equal(result.verified, true);
  assert.equal(result.rounds, 1);
  assert.deepEqual(result.residual, []);
  assert.equal(result.injectionOriginal, false);

  const call = calls[0] as { system: string; messages: Array<{ content: string }> };
  assert.match(call.system, new RegExp(`<${UNTRUSTED_DATA_TAG}>`));
  const userContent = call.messages[0]!.content;
  assert.match(userContent, new RegExp(`<${UNTRUSTED_DATA_TAG}>`));
  assert.match(userContent, /TOOL009/);
});

test("agenticFixTool flags injectionOriginal when an original finding was a prompt-injection rule", async () => {
  const { client } = fakeToolUseClient(CLEAN_TOOL);
  const result = await agenticFixTool(client, "list_documents", [INJECTION_FINDING]);
  assert.equal(result.injectionOriginal, true);
  assert.equal(result.verified, true);
});

test("agenticFixTool gives up after the round budget when the proposal never clears every rule", async () => {
  const { client } = fakeToolUseClient(STILL_BROKEN_TOOL);
  const result = await agenticFixTool(client, "delete_everything", [NON_INJECTION_FINDING]);
  assert.equal(result.verified, false);
  assert.equal(result.rounds, 5);
  assert.ok(result.residual.length > 0);
});

test("generateVerifiedRemediation downgrades the status for tools that originally had an injection finding", async () => {
  const { client } = fakeToolUseClient(CLEAN_TOOL);
  const report: ScanReport = {
    schemaVersion: "1.0",
    scanner: { name: "mcp-security-lab", version: "test" },
    target: {},
    execution: {
      requested: false,
      connected: false,
      toolsInvoked: 0,
      transport: "stdio",
      environmentMode: "none",
      osSandboxed: false,
      limitations: [],
    },
    summary: { info: 0, low: 0, medium: 0, high: 2, critical: 0 },
    findings: [
      { ...INJECTION_FINDING, location: "tool:injected_tool" },
      { ...NON_INJECTION_FINDING, location: "tool:destructive_tool" },
    ],
  };

  const plan = await generateVerifiedRemediation(report, "unused-key", client);

  assert.match(plan, /## `injected_tool`[\s\S]*?🛑 \*\*Rules cleared — manual review required\*\*/);
  assert.match(plan, /## `destructive_tool`[\s\S]*?✅ \*\*Rule-verified\*\*/);
});
