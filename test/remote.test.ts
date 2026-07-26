import assert from "node:assert/strict";
import test from "node:test";

import { redactUrl } from "../src/environment.js";
import { inspectRemote } from "../src/rules/remote.js";
import { scan } from "../src/scanner.js";

test("plaintext HTTP is flagged for a non-local endpoint", () => {
  const findings = inspectRemote({ url: "http://example.com/mcp" });
  assert.ok(findings.some((finding) => finding.id === "REMOTE002"));
});

test("plaintext HTTP on localhost is not flagged", () => {
  const findings = inspectRemote({ url: "http://localhost:3000/mcp" });
  assert.equal(
    findings.some((finding) => finding.id === "REMOTE002"),
    false,
  );
});

test("HTTPS endpoint without credentials is clean", () => {
  assert.deepEqual(inspectRemote({ url: "https://example.com/mcp" }), []);
});

test("credentials in userinfo are flagged", () => {
  const findings = inspectRemote({ url: "https://user:pass@example.com/mcp" });
  assert.ok(findings.some((finding) => finding.id === "REMOTE003"));
});

test("credentials in a query parameter are flagged", () => {
  const findings = inspectRemote({ url: "https://example.com/mcp?token=abc123" });
  assert.ok(findings.some((finding) => finding.id === "REMOTE003"));
});

test("a malformed URL is reported", () => {
  const findings = inspectRemote({ url: "not a url" });
  assert.ok(findings.some((finding) => finding.id === "REMOTE001"));
});

test("redactUrl strips userinfo and sensitive query values", () => {
  assert.equal(
    redactUrl("https://user:secret@example.com/mcp?token=abc&page=2"),
    "https://[REDACTED]@example.com/mcp?token=[REDACTED]&page=2",
  );
});

test("a remote scan redacts the URL and reports the http transport", async () => {
  const report = await scan(
    {
      target: { url: "https://user:secret@example.com/mcp", transport: "http" },
      policy: { timeoutMs: 5_000, maxTools: 10 },
    },
    false,
  );

  assert.equal(report.execution.transport, "http");
  assert.equal(report.target.url?.includes("secret"), false);
  assert.ok(report.findings.some((finding) => finding.id === "REMOTE003"));
});
