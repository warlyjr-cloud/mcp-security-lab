import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { assessServerUrl, inspectRemoteAuth } from "../src/rules/oauth.js";

interface MockConfig {
  challenge?: boolean; // respond with a challenge to the MCP probe (default true)
  challengeStatus?: number; // status used for the challenge (default 401)
  withPointer?: boolean; // include WWW-Authenticate resource_metadata (default true)
  pointerOverride?: (base: string) => string; // full WWW-Authenticate header value
  prm?: (base: string) => unknown; // protected resource metadata, or omit for 404
  asMeta?: (base: string) => unknown; // authorization server metadata, or omit for 404
  probeDelayMs?: number; // delay before responding to the /mcp probe, to exercise timeouts
}

async function withMockServer(
  config: MockConfig,
  run: (mcpUrl: string) => Promise<void>,
): Promise<void> {
  const server = http.createServer((req, res) => {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const path = (req.url ?? "").split("?")[0];

    if (req.method === "POST" && path === "/mcp") {
      const respond = (): void => {
        if (config.challenge === false) {
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
          return;
        }
        if (config.pointerOverride !== undefined) {
          res.setHeader("WWW-Authenticate", config.pointerOverride(base));
        } else if (config.withPointer !== false) {
          res.setHeader(
            "WWW-Authenticate",
            `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`,
          );
        }
        res.statusCode = config.challengeStatus ?? 401;
        res.end();
      };
      if (config.probeDelayMs !== undefined) {
        setTimeout(respond, config.probeDelayMs);
      } else {
        respond();
      }
      return;
    }

    if (path === "/.well-known/oauth-protected-resource") {
      if (config.prm === undefined) {
        res.statusCode = 404;
        res.end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(config.prm(base)));
      return;
    }

    if (path === "/.well-known/oauth-authorization-server") {
      if (config.asMeta === undefined) {
        res.statusCode = 404;
        res.end();
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(config.asMeta(base)));
      return;
    }

    res.statusCode = 404;
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run(`${base}/mcp`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const compliantPrm = (base: string): unknown => ({
  resource: `${base}/mcp`,
  authorization_servers: [base],
});
const compliantAsMeta = (base: string): unknown => ({
  issuer: base,
  authorization_endpoint: `${base}/authorize`,
  token_endpoint: `${base}/token`,
  code_challenge_methods_supported: ["S256"],
});

test("a fully compliant OAuth posture yields no findings", async () => {
  await withMockServer({ prm: compliantPrm, asMeta: compliantAsMeta }, async (mcpUrl) => {
    const findings = await inspectRemoteAuth(mcpUrl, 3000);
    assert.deepEqual(findings, []);
  });
});

test("missing resource_metadata pointer is flagged (AUTH001)", async () => {
  await withMockServer(
    { prm: compliantPrm, asMeta: compliantAsMeta, withPointer: false },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.ok(findings.some((finding) => finding.id === "AUTH001"));
    },
  );
});

test("unreachable resource metadata is flagged (AUTH002)", async () => {
  // prm omitted -> the mock returns 404 for the resource metadata document.
  await withMockServer({ asMeta: compliantAsMeta }, async (mcpUrl) => {
    const findings = await inspectRemoteAuth(mcpUrl, 3000);
    assert.ok(findings.some((finding) => finding.id === "AUTH002"));
  });
});

test("missing PKCE S256 is flagged (AUTH003) with high severity and CWE", async () => {
  await withMockServer(
    {
      prm: compliantPrm,
      asMeta: (base) => ({
        issuer: base,
        token_endpoint: `${base}/token`,
        code_challenge_methods_supported: ["plain"],
      }),
    },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      const auth3 = findings.find((finding) => finding.id === "AUTH003");
      assert.ok(auth3);
      assert.equal(auth3.severity, "high");
      assert.equal(auth3.cwe, "CWE-1188");
      assert.equal(auth3.owasp, "LLM08");
    },
  );
});

test("a 403 challenge is audited the same as a 401", async () => {
  await withMockServer(
    { challengeStatus: 403, withPointer: false, prm: compliantPrm, asMeta: compliantAsMeta },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.ok(findings.some((finding) => finding.id === "AUTH001"));
    },
  );
});

test("an empty authorization_servers list is flagged (AUTH002)", async () => {
  await withMockServer(
    { prm: (base) => ({ resource: `${base}/mcp`, authorization_servers: [] }) },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.ok(findings.some((finding) => finding.id === "AUTH002"));
    },
  );
});

test("unreachable authorization server metadata is flagged (AUTH002)", async () => {
  // Valid PRM listing the base, but the AS metadata document 404s (asMeta omitted).
  await withMockServer({ prm: compliantPrm }, async (mcpUrl) => {
    const findings = await inspectRemoteAuth(mcpUrl, 3000);
    assert.ok(findings.some((finding) => finding.id === "AUTH002"));
  });
});

test("a non-local plaintext authorization server URL is flagged (AUTH004)", async () => {
  await withMockServer(
    {
      // IP literal keeps the test hermetic (no DNS); it is public + plaintext.
      prm: (base) => ({ resource: `${base}/mcp`, authorization_servers: ["http://93.184.216.34"] }),
    },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.ok(findings.some((finding) => finding.id === "AUTH004"));
    },
  );
});

test("a plaintext OAuth endpoint on a non-local host is flagged (AUTH004)", async () => {
  await withMockServer(
    {
      prm: compliantPrm,
      asMeta: (base) => ({
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: "http://auth.example.com/token",
        code_challenge_methods_supported: ["S256"],
      }),
    },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.ok(findings.some((finding) => finding.id === "AUTH004"));
    },
  );
});

test("an unprotected server produces no auth findings (openness is REMOTE004)", async () => {
  await withMockServer({ challenge: false }, async (mcpUrl) => {
    const findings = await inspectRemoteAuth(mcpUrl, 3000);
    assert.deepEqual(findings, []);
  });
});

test("assessServerUrl blocks SSRF to private and reserved addresses", async () => {
  // Loopback is allowed only when the operator's own target is local.
  assert.equal(await assessServerUrl("http://127.0.0.1:3000/x", true), "ok");
  assert.equal(await assessServerUrl("http://127.0.0.1:3000/x", false), "ssrf");
  // Cloud metadata / link-local is blocked even for a local target.
  assert.equal(await assessServerUrl("http://169.254.169.254/latest/meta-data", true), "ssrf");
  // RFC 1918 private ranges are blocked regardless of scheme.
  assert.equal(await assessServerUrl("https://10.0.0.5/x", false), "ssrf");
  assert.equal(await assessServerUrl("https://192.168.1.1/x", false), "ssrf");
  // Public host over plaintext is refused; over https it is allowed.
  assert.equal(await assessServerUrl("http://93.184.216.34/x", false), "unsafe");
  assert.equal(await assessServerUrl("https://93.184.216.34/x", false), "ok");
  // Non-http(s) schemes are refused.
  assert.equal(await assessServerUrl("ftp://example.com/x", false), "unsafe");
  assert.equal(await assessServerUrl("file:///etc/passwd", false), "unsafe");
});

test("assessServerUrl reports unsafe for unparseable URLs and unresolvable hosts", async () => {
  assert.equal(await assessServerUrl("not a url", false), "unsafe");
  assert.equal(
    await assessServerUrl("https://definitely-not-a-real-host-xyz123.invalid/x", false),
    "unsafe",
  );
});

test("inspectRemoteAuth returns no findings for an unparseable target URL", async () => {
  assert.deepEqual(await inspectRemoteAuth("not a url", 3000), []);
});

test("a malformed OAuth endpoint URL is tolerated instead of flagged as plaintext", async () => {
  await withMockServer(
    {
      prm: compliantPrm,
      asMeta: (base) => ({
        issuer: base,
        authorization_endpoint: "not a valid url",
        token_endpoint: `${base}/token`,
        code_challenge_methods_supported: ["S256"],
      }),
    },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.equal(
        findings.some((finding) => finding.evidence.includes("authorization_endpoint")),
        false,
      );
    },
  );
});

test("an authorization server pointing at a link-local address is flagged (AUTH005)", async () => {
  await withMockServer(
    {
      prm: (base) => ({
        resource: `${base}/mcp`,
        authorization_servers: ["http://169.254.169.254"],
      }),
    },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      const auth5 = findings.find((finding) => finding.id === "AUTH005");
      assert.ok(auth5);
      assert.match(auth5?.evidence ?? "", /authorization server metadata/);
    },
  );
});

test("a probe that times out is treated the same as no response", async () => {
  await withMockServer(
    // The mock delays its response well past the timeout, forcing safeFetch's
    // own abort/catch path deterministically instead of racing the mock.
    { probeDelayMs: 200 },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 20);
      assert.deepEqual(findings, []);
    },
  );
});

test("a server steering the scanner to a private address is flagged (AUTH005)", async () => {
  await withMockServer(
    {
      // Point resource_metadata at the cloud metadata endpoint.
      pointerOverride: () =>
        'Bearer resource_metadata="http://169.254.169.254/.well-known/oauth-protected-resource"',
    },
    async (mcpUrl) => {
      const findings = await inspectRemoteAuth(mcpUrl, 3000);
      assert.ok(findings.some((finding) => finding.id === "AUTH005"));
    },
  );
});
