import assert from "node:assert/strict";
import test from "node:test";

import type Anthropic from "@anthropic-ai/sdk";
import { generateMaliciousPayloads } from "../src/fuzzer/ai.js";
import { UNTRUSTED_DATA_TAG } from "../src/prompt-safety.js";

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

test("generateMaliciousPayloads throws without an API key or injected client", async () => {
  await assert.rejects(
    () => generateMaliciousPayloads("fetch_url", { type: "object", properties: {} }),
    /ANTHROPIC_API_KEY/,
  );
});

test("generateMaliciousPayloads wraps the tool name and schema in the untrusted-data tag", async () => {
  const { client, calls } = fakeClient('[{"url": "http://evil"}, {}, {}]');
  const payloads = await generateMaliciousPayloads(
    "fetch_url",
    { type: "object", properties: { url: { type: "string" } } },
    "unused-key",
    client,
  );

  assert.deepEqual(payloads, [{ url: "http://evil" }, {}, {}]);
  const call = calls[0] as { system: string; messages: Array<{ content: string }> };
  assert.match(call.system, new RegExp(`<${UNTRUSTED_DATA_TAG}>`));
  const userContent = call.messages[0]!.content;
  assert.match(userContent, new RegExp(`<${UNTRUSTED_DATA_TAG}>`));
  assert.match(userContent, /fetch_url/);
});

test("generateMaliciousPayloads strips a markdown fence the model added despite instructions", async () => {
  const { client } = fakeClient('```json\n[{"a": 1}]\n```');
  const payloads = await generateMaliciousPayloads(
    "some_tool",
    { type: "object", properties: {} },
    "unused-key",
    client,
  );
  assert.deepEqual(payloads, [{ a: 1 }]);
});

test("generateMaliciousPayloads falls back to static payloads when the model call fails", async () => {
  const client = {
    messages: {
      create: async () => {
        throw new Error("network down");
      },
    },
  } as unknown as Anthropic;

  const payloads = await generateMaliciousPayloads(
    "some_tool",
    { type: "object", properties: {} },
    "unused-key",
    client,
  );
  assert.ok(payloads.length > 0);
  assert.ok("url" in payloads[0]!);
});

test("generateMaliciousPayloads falls back when the model returns something that is not a JSON array", async () => {
  const { client } = fakeClient("not json at all");
  const payloads = await generateMaliciousPayloads(
    "some_tool",
    { type: "object", properties: {} },
    "unused-key",
    client,
  );
  assert.ok(payloads.length > 0);
});
