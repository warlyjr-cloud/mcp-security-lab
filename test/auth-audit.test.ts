import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";

import {
  assertNetworkDestinationAllowed,
  auditRemoteAuthentication,
} from "../src/auth-audit.js";
import type { ResolvedScanPolicy } from "../src/types.js";

const POLICY: ResolvedScanPolicy = {
  timeoutMs: 5_000,
  maxTools: 10,
  maxResources: 10,
  maxPrompts: 10,
  maxResponseBytes: 64 * 1024,
  profile: "balanced",
  allowPrivateNetwork: false,
};

test("remote auth audit validates protected resource metadata and PKCE", async () => {
  let origin = "";
  let resource = "";
  const server = createServer((request, response) => {
    const path = request.url ?? "/";
    response.setHeader("content-type", "application/json");
    if (path.includes("oauth-protected-resource")) {
      response.end(
        JSON.stringify({
          resource,
          authorization_servers: [origin],
          scopes_supported: ["mcp:read"],
        }),
      );
      return;
    }
    if (
      path.includes("oauth-authorization-server") ||
      path.includes("openid-configuration")
    ) {
      response.end(
        JSON.stringify({
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          response_types_supported: ["code"],
          code_challenge_methods_supported: ["S256"],
        }),
      );
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  try {
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Expected a TCP listener.");
    }
    origin = `http://127.0.0.1:${address.port}`;
    resource = `${origin}/mcp`;
    const result = await auditRemoteAuthentication(resource, POLICY);

    assert.deepEqual(result.findings, []);
    assert.equal(result.metadata?.resource, resource);
    assert.deepEqual(result.metadata?.codeChallengeMethodsSupported, ["S256"]);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
});

test("remote auth audit flags resource mismatch and missing PKCE", async () => {
  let origin = "";
  const server = createServer((request, response) => {
    const path = request.url ?? "/";
    response.setHeader("content-type", "application/json");
    if (path.includes("oauth-protected-resource")) {
      response.end(
        JSON.stringify({
          resource: `${origin}/other?token=resource-secret`,
          authorization_servers: [`${origin}?token=auth-secret`],
        }),
      );
      return;
    }
    response.end(
      JSON.stringify({
        issuer: `${origin}?token=issuer-secret`,
        authorization_endpoint: `${origin}/authorize?token=authorization-secret`,
        token_endpoint: `${origin}/token?token=token-secret`,
        response_types_supported: ["code"],
      }),
    );
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  try {
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Expected a TCP listener.");
    }
    origin = `http://127.0.0.1:${address.port}`;
    const result = await auditRemoteAuthentication(`${origin}/mcp`, POLICY);
    const ids = new Set(result.findings.map((finding) => finding.id));

    assert.equal(ids.has("AUTH004"), true);
    assert.equal(ids.has("AUTH006"), true);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(
      serialized,
      /resource-secret|auth-secret|issuer-secret|authorization-secret|token-secret/,
    );
    assert.match(serialized, /%5BREDACTED%5D/);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
});

test("URL credentials never bypass private-network blocking", async () => {
  await assert.rejects(
    assertNetworkDestinationAllowed(
      new URL("https://user:password@10.0.0.1/mcp"),
      false,
    ),
    /private address/,
  );
});
