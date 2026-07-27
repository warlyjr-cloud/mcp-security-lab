import assert from "node:assert/strict";
import test from "node:test";

import { scanForDataLeaks } from "../src/rules/data-leak.js";

test("scanForDataLeaks detects an AWS-shaped access key and reports remediation", () => {
  const findings = scanForDataLeaks(
    "Here is your key: AKIAABCDEFGHIJKLMNOP",
    "tool:fetch_secret",
    "fetch_secret",
  );

  const finding = findings.find((entry) => entry.title.includes("AWS Access Key"));
  assert.ok(finding);
  assert.equal(finding?.id, "DATA001");
  assert.equal(finding?.severity, "critical");
  assert.equal(finding?.owasp, "LLM06");
  assert.equal(finding?.cwe, "CWE-200");
  assert.equal(finding?.location, "tool:fetch_secret");
  assert.match(finding?.evidence ?? "", /fetch_secret/);
  assert.ok(finding?.remediationSnippet?.includes("REDACTED"));
});

test("scanForDataLeaks detects an NVIDIA NIM API key", () => {
  const nvidia = scanForDataLeaks(
    "key=nvapi-abcdefghijklmnopqrstuvwxyz123456",
    "tool:x",
    "call_api",
  );
  assert.ok(nvidia.some((entry) => entry.title.includes("NVIDIA NIM API Key")));
});

test("scanForDataLeaks returns no findings for benign content", () => {
  assert.deepEqual(scanForDataLeaks("The weather today is sunny.", "tool:x", "get_weather"), []);
});
