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

test("a strong credential query parameter is flagged", () => {
  const findings = inspectRemote({ url: "https://example.com/mcp?access_token=abc123" });
  assert.ok(findings.some((finding) => finding.id === "REMOTE003"));
});

test("client_secret and refresh_token are flagged", () => {
  assert.ok(
    inspectRemote({ url: "https://example.com/mcp?client_secret=x" }).some(
      (f) => f.id === "REMOTE003",
    ),
  );
  assert.ok(
    inspectRemote({ url: "https://example.com/mcp?refresh_token=x" }).some(
      (f) => f.id === "REMOTE003",
    ),
  );
});

test("a credential in the URL fragment is flagged (implicit flow)", () => {
  const findings = inspectRemote({ url: "https://example.com/mcp#access_token=abc" });
  assert.ok(findings.some((finding) => finding.id === "REMOTE003"));
});

test("a benign opaque query parameter does not cry wolf", () => {
  // Bare ?token= / ?key= are common opaque cursors, not necessarily credentials.
  assert.equal(
    inspectRemote({ url: "https://example.com/mcp?token=next-page-cursor" }).some(
      (f) => f.id === "REMOTE003",
    ),
    false,
  );
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

test("redactUrl redacts compound credential parameters and fragment tokens", () => {
  const redacted = redactUrl(
    "https://example.com/mcp?client_secret=SECRET&refresh_token=RT&page=2#access_token=IMPLICIT",
  );
  assert.equal(redacted.includes("SECRET"), false);
  assert.equal(redacted.includes("RT"), false);
  assert.equal(redacted.includes("IMPLICIT"), false);
  assert.ok(redacted.includes("page=2"));
});

test("redactUrl falls back to coarse redaction for an unparseable URL", () => {
  // A space in the host makes new URL() throw, exercising the catch branch.
  const redacted = redactUrl("https://user:hunter2@exa mple.com/mcp");
  assert.equal(redacted.includes("hunter2"), false);
  assert.ok(redacted.includes("[REDACTED]"));
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
