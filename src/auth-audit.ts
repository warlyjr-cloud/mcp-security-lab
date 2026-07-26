import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

import {
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
} from "@modelcontextprotocol/sdk/client/auth.js";
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import {
  redactUntrustedText,
  redactUrl,
} from "./environment.js";
import { createFinding } from "./rules/catalog.js";
import type {
  AuthMetadataSummary,
  Finding,
  ResolvedScanPolicy,
} from "./types.js";

interface AuthAuditResult {
  metadata?: AuthMetadataSummary;
  findings: Finding[];
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "::1" || normalized.startsWith("127.");
}

function isPrivateIpv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) {
    return false;
  }
  const [first = -1, second = -1] = parts;
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    first >= 224
  );
}

function isPrivateIp(address: string): boolean {
  const normalized = address.toLowerCase();
  if (isIP(normalized) === 4) {
    return isPrivateIpv4(normalized);
  }
  if (isIP(normalized) !== 6) {
    return false;
  }
  if (normalized === "::" || normalized === "::1") {
    return true;
  }
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }
  if (/^fe[89ab]/.test(normalized)) {
    return true;
  }
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped?.[1] !== undefined && isPrivateIpv4(mapped[1]);
}

export async function assertNetworkDestinationAllowed(
  url: URL,
  allowPrivateNetwork: boolean,
): Promise<void> {
  if (allowPrivateNetwork || isLoopbackHostname(url.hostname)) {
    return;
  }
  if (url.hostname.toLowerCase().endsWith(".local")) {
    throw new Error("Private .local destinations require policy.allowPrivateNetwork=true.");
  }

  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(url.hostname, { all: true, verbatim: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to resolve remote MCP hostname: ${message}`);
  }
  if (addresses.some((entry) => isPrivateIp(entry.address))) {
    throw new Error(
      "Remote MCP hostname resolves to a private address; set policy.allowPrivateNetwork=true to opt in.",
    );
  }
}

async function boundedResponse(response: Response, maximumBytes: number): Promise<Response> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > maximumBytes) {
    throw new Error(`HTTP metadata response exceeds ${maximumBytes} bytes.`);
  }
  if (response.body === null) {
    return response;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) {
        break;
      }
      size += result.value.byteLength;
      if (size > maximumBytes) {
        throw new Error(`HTTP metadata response exceeds ${maximumBytes} bytes.`);
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export function createMetadataFetch(policy: ResolvedScanPolicy): FetchLike {
  return async (input, init) => {
    const url = new URL(input);
    if (url.username !== "" || url.password !== "") {
      throw new Error("HTTP metadata requests never send URLs containing credentials.");
    }
    await assertNetworkDestinationAllowed(url, policy.allowPrivateNetwork);

    const headers = new Headers(init?.headers);
    headers.set("accept", "application/json");
    headers.set("mcp-protocol-version", "2025-11-25");
    const timeoutSignal = AbortSignal.timeout(policy.timeoutMs);
    const signal =
      init?.signal === undefined || init.signal === null
        ? timeoutSignal
        : AbortSignal.any([init.signal, timeoutSignal]);
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      signal,
      headers,
    });
    if (response.status >= 300 && response.status < 400) {
      throw new Error(`HTTP metadata redirect was blocked (${response.status}).`);
    }
    return boundedResponse(response, policy.maxResponseBytes);
  };
}

export function createTransportFetch(policy: ResolvedScanPolicy): FetchLike {
  return async (input, init) => {
    const url = new URL(input);
    if (url.username !== "" || url.password !== "") {
      throw new Error("MCP transport requests never send URLs containing credentials.");
    }
    await assertNetworkDestinationAllowed(url, policy.allowPrivateNetwork);

    const timeoutSignal = AbortSignal.timeout(policy.timeoutMs);
    const signal =
      init?.signal === undefined || init.signal === null
        ? timeoutSignal
        : AbortSignal.any([init.signal, timeoutSignal]);
    const response = await fetch(url, {
      ...init,
      redirect: "manual",
      signal,
    });
    if (response.status >= 300 && response.status < 400) {
      throw new Error(`MCP transport redirect was blocked (${response.status}).`);
    }
    if (response.body === null) {
      return response;
    }

    let size = 0;
    const limitedBody = response.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
          size += chunk.byteLength;
          if (size > policy.maxResponseBytes) {
            controller.error(
              new Error(`MCP transport response exceeds ${policy.maxResponseBytes} bytes.`),
            );
            return;
          }
          controller.enqueue(chunk);
        },
      }),
    );
    return new Response(limitedBody, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  };
}

function isSecureEndpoint(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || isLoopbackHostname(url.hostname);
  } catch {
    return false;
  }
}

export async function auditRemoteAuthentication(
  targetUrl: string,
  policy: ResolvedScanPolicy,
): Promise<AuthAuditResult> {
  const findings: Finding[] = [];
  const serverUrl = new URL(targetUrl);
  if (serverUrl.username !== "" || serverUrl.password !== "") {
    findings.push(
      createFinding(
        "AUTH002",
        "The configured URL contains a username or password component.",
        "target.url",
      ),
    );
  }
  if (serverUrl.protocol !== "https:" && !isLoopbackHostname(serverUrl.hostname)) {
    findings.push(
      createFinding(
        "AUTH001",
        `Configured endpoint uses ${serverUrl.protocol}.`,
        "target.url",
      ),
    );
  }

  await assertNetworkDestinationAllowed(serverUrl, policy.allowPrivateNetwork);
  const safeFetch = createMetadataFetch(policy);
  let resourceMetadata;
  try {
    resourceMetadata = await discoverOAuthProtectedResourceMetadata(
      serverUrl,
      { protocolVersion: "2025-11-25" },
      safeFetch,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    findings.push(
      createFinding(
        "AUTH003",
        `Protected resource discovery failed: ${redactUntrustedText(message)}`,
        "authentication.protectedResource",
      ),
    );
    return { findings };
  }

  const authorizationServers = resourceMetadata.authorization_servers ?? [];
  const summary: AuthMetadataSummary = {
    resource: redactUrl(resourceMetadata.resource),
    authorizationServers: authorizationServers.map(redactUrl),
    scopesSupported: (resourceMetadata.scopes_supported ?? []).map((scope) =>
      redactUntrustedText(scope, 200)
    ),
    codeChallengeMethodsSupported: [],
  };

  let resourceMatches = false;
  try {
    resourceMatches =
      new URL(resourceMetadata.resource).toString() === serverUrl.toString();
  } catch {
    resourceMatches = false;
  }
  if (!resourceMatches) {
    findings.push(
      createFinding(
        "AUTH004",
        `Metadata resource is "${redactUrl(resourceMetadata.resource)}", expected "${redactUrl(serverUrl.toString())}".`,
        "authentication.resource",
      ),
    );
  }

  if (authorizationServers.length === 0) {
    findings.push(
      createFinding(
        "AUTH007",
        "authorization_servers is absent or empty.",
        "authentication.authorizationServers",
      ),
    );
    return { metadata: summary, findings };
  }

  for (const authorizationServer of authorizationServers) {
    if (!isSecureEndpoint(authorizationServer)) {
      findings.push(
        createFinding(
          "AUTH005",
          `Authorization server is "${redactUrl(authorizationServer)}".`,
          "authentication.authorizationServers",
        ),
      );
    }
  }

  const selectedAuthorizationServer = authorizationServers[0];
  if (selectedAuthorizationServer === undefined) {
    return { metadata: summary, findings };
  }

  let authorizationMetadata;
  try {
    authorizationMetadata = await discoverAuthorizationServerMetadata(
      selectedAuthorizationServer,
      {
        fetchFn: safeFetch,
        protocolVersion: "2025-11-25",
      },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    findings.push(
      createFinding(
        "AUTH008",
        `Authorization server discovery failed: ${redactUntrustedText(message)}`,
        "authentication.authorizationServerMetadata",
      ),
    );
    return { metadata: summary, findings };
  }

  if (authorizationMetadata === undefined) {
    findings.push(
      createFinding(
        "AUTH008",
        "No RFC 8414 or OpenID Connect metadata document was returned.",
        "authentication.authorizationServerMetadata",
      ),
    );
    return { metadata: summary, findings };
  }

  summary.issuer = redactUrl(authorizationMetadata.issuer);
  summary.authorizationEndpoint = redactUrl(authorizationMetadata.authorization_endpoint);
  summary.tokenEndpoint = redactUrl(authorizationMetadata.token_endpoint);
  summary.codeChallengeMethodsSupported = [
    ...(authorizationMetadata.code_challenge_methods_supported ?? []),
  ].map((method) => redactUntrustedText(method, 100));

  for (const endpoint of [
    authorizationMetadata.issuer,
    authorizationMetadata.authorization_endpoint,
    authorizationMetadata.token_endpoint,
  ]) {
    if (!isSecureEndpoint(endpoint)) {
      findings.push(
        createFinding(
          "AUTH005",
          `Authorization metadata endpoint is "${redactUrl(endpoint)}".`,
          "authentication.authorizationServerMetadata",
        ),
      );
    }
  }

  if (!summary.codeChallengeMethodsSupported.includes("S256")) {
    findings.push(
      createFinding(
        "AUTH006",
        `Advertised code challenge methods: ${summary.codeChallengeMethodsSupported.join(", ") || "none"}.`,
        "authentication.codeChallengeMethodsSupported",
      ),
    );
  }

  return { metadata: summary, findings };
}
