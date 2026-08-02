import assert from "node:assert/strict";
import test from "node:test";

import type Anthropic from "@anthropic-ai/sdk";
import { generateRemediationPlan } from "../src/remediator/ai-fix.js";
import { UNTRUSTED_DATA_TAG } from "../src/prompt-safety.js";
import type { Finding } from "../src/types.js";

const HIGH_FINDING: Finding = {
  id: "TOOL006",
  severity: "high",
  title: "Potentially destructive tool is not marked destructive",
  evidence: 'Tool name "delete_everything" implies an external side effect.',
  recommendation: "Set destructiveHint to true.",
  location: "tool:delete_everything",
};

const LOW_FINDING: Finding = {
  id: "TOOL009",
  severity: "low",
  title: "Input schema accepts undeclared properties",
  evidence: "inputSchema.additionalProperties is not explicitly false.",
  recommendation: "Reject unknown input fields.",
  location: "tool:delete_everything",
};

function fakeClient(text: string): { client: Anthropic; calls: unknown[] } {
  const calls: unknown[] = [];
  const client = {
    messages: {
      create: async (params: unknown) => {
        calls.push(params);
        return { content: [{ type: "text", text }] };
      },
    },
  } as unknown as Anthropic;
  return { client, calls };
}

test("generateRemediationPlan skips without an API key or injected client", async () => {
  const plan = await generateRemediationPlan([HIGH_FINDING], undefined);
  assert.match(plan, /ANTHROPIC_API_KEY/);
});

test("generateRemediationPlan skips the model call when no high/critical findings exist", async () => {
  const { client, calls } = fakeClient("unused");
  const plan = await generateRemediationPlan([LOW_FINDING], "unused-key", client);
  assert.match(plan, /No critical AI patching required/);
  assert.equal(calls.length, 0);
});

test("generateRemediationPlan wraps findings in the untrusted-data tag and returns the model's text", async () => {
  const { client, calls } = fakeClient("# Remediation\n\nFix it.");
  const plan = await generateRemediationPlan([HIGH_FINDING], "unused-key", client);

  assert.equal(plan, "# Remediation\n\nFix it.");
  assert.equal(calls.length, 1);
  const call = calls[0] as { system: string; messages: Array<{ content: string }> };
  assert.match(call.system, new RegExp(`<${UNTRUSTED_DATA_TAG}>`));
  const userContent = call.messages[0]!.content;
  assert.match(userContent, new RegExp(`<${UNTRUSTED_DATA_TAG}>`));
  assert.match(userContent, /TOOL006/);
  // The low-severity finding was filtered out before ever reaching the prompt.
  assert.doesNotMatch(userContent, /TOOL009/);
});

test("generateRemediationPlan reports the error instead of throwing when the model call fails", async () => {
  const client = {
    messages: {
      create: async () => {
        throw new Error("network down");
      },
    },
  } as unknown as Anthropic;

  const plan = await generateRemediationPlan([HIGH_FINDING], "unused-key", client);
  assert.match(plan, /network down/);
});
