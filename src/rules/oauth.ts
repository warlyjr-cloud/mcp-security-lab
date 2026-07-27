import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import type { Finding } from "../types.js";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

// The scanner follows server-controlled OAuth metadata URLs. Bound how many
// authorization servers it will fetch so a hostile server cannot use a long
// authorization_servers list to amplify requests (SSRF/DoS) from the scanner.
const MAX_AUTH_SERVERS = 5;

function isLocal(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return LOCAL_HOSTS.has(host) || host.endsWith(".localhost");
}

/** True for a plaintext http:// URL whose host is not local. */
function isPlaintextNonLocal(rawUrl: string): boolean {
  try {
    const url = new URL(rawUrl);
    return url.protocol === "http:" && !isLocal(url.hostname);
  } catch {
    return false;
  }
}

function ipv4Of(ip: string): string {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  return mapped && mapped[1] !== undefined ? mapped[1] : ip;
}

function isLoopback(ip: string): boolean {
  const v4 = ipv4Of(ip);
  return /^127\./.test(v4) || ip.toLowerCase() === "::1";
}

/**
 * True for any address the scanner must not be steered toward by an untrusted
 * server: RFC 1918 private ranges, loopback, link-local (incl. the cloud
 * metadata address 169.254.169.254), unique-local IPv6, and unspecified.
 */
function isPrivateOrReserved(ip: string): boolean {
  const v4 = ipv4Of(ip);
  if (/^(0|10|127)\./.test(v4)) return true;
  if (/^169\.254\./.test(v4)) return true;
  if (/^192\.168\./.test(v4)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v4)) return true;
  if (v4 === "0.0.0.0" || v4 === "255.255.255.255") return true;
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (/^f[cd]/.test(lower)) return true; // fc00::/7 unique local
  if (/^fe[89ab]/.test(lower)) return true; // fe80::/10 link local
  return false;
}

async function resolveHost(host: string): Promise<string[]> {
  if (isIP(host) !== 0) {
    return [host];
  }
  try {
    const records = await lookup(host, { all: true });
    return records.map((record) => record.address);
  } catch {
    return [];
  }
}

/**
 * Decide whether it is safe for the scanner to fetch a URL taken from an
 * untrusted server response.
 * - "ok": public https (or loopback http when the operator's own target is local).
 * - "ssrf": the host resolves to a private/loopback/link-local address the
 *   server should not be able to steer the scanner toward.
 * - "unsafe": unparseable, non-http(s), unresolvable, or plaintext to a
 *   non-loopback host.
 * `allowLoopback` is true only when the operator's target is itself local, so a
 * local dev scan may follow local metadata.
 */
export async function assessServerUrl(
  rawUrl: string,
  allowLoopback: boolean,
): Promise<"ok" | "ssrf" | "unsafe"> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return "unsafe";
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return "unsafe";
  }

  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = await resolveHost(host);
  if (addresses.length === 0) {
    return "unsafe";
  }

  let allLoopback = true;
  for (const address of addresses) {
    if (isLoopback(address)) {
      if (!allowLoopback) {
        return "ssrf";
      }
      continue;
    }
    allLoopback = false;
    if (isPrivateOrReserved(address)) {
      return "ssrf";
    }
  }

  // Plaintext is only tolerated for a loopback dev target; anything else must be https.
  if (url.protocol === "http:" && !(allLoopback && allowLoopback)) {
    return "unsafe";
  }
  return "ok";
}

interface FetchResult {
  status: number;
  headers: Headers;
  json: Record<string, unknown> | undefined;
}

async function safeFetch(
  url: string,
  timeoutMs: number,
  init?: RequestInit,
): Promise<FetchResult | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref();
  try {
    // redirect: "manual" so a server cannot 3xx-hop past the SSRF pre-check.
    const response = await fetch(url, { ...init, signal: controller.signal, redirect: "manual" });
    let json: Record<string, unknown> | undefined;
    try {
      const parsed: unknown = await response.json();
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
        json = parsed as Record<string, unknown>;
      }
    } catch {
      json = undefined;
    }
    return { status: response.status, headers: response.headers, json };
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

/**
 * Audit the OAuth 2.1 authorization posture of a remote MCP endpoint, following
 * the MCP authorization spec (RFC 9728 Protected Resource Metadata + RFC 8414
 * Authorization Server Metadata). Only meaningful for a server that challenges
 * unauthenticated requests; an open server is covered by REMOTE004. Every URL
 * taken from a server response is SSRF-checked before it is fetched.
 */
export async function inspectRemoteAuth(rawUrl: string, timeoutMs: number): Promise<Finding[]> {
  const findings: Finding[] = [];
  let base: URL;
  try {
    base = new URL(rawUrl);
  } catch {
    return findings;
  }
  const targetIsLocal = isLocal(base.hostname);

  const probe = await safeFetch(rawUrl, timeoutMs, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
  });

  // No response, or the server did not challenge: openness is REMOTE004's job.
  if (probe === undefined || (probe.status !== 401 && probe.status !== 403)) {
    return findings;
  }

  // RFC 9728: a protected resource must point to its metadata via WWW-Authenticate.
  const wwwAuthenticate = probe.headers.get("www-authenticate") ?? "";
  const pointer = /resource_metadata="?([^",\s]+)"?/i.exec(wwwAuthenticate);
  let prmUrl: string;
  if (pointer && pointer[1] !== undefined) {
    prmUrl = pointer[1];
  } else {
    findings.push({
      id: "AUTH001",
      severity: "medium",
      title: "Protected server does not advertise its resource metadata",
      evidence: `The server returned ${probe.status} without a WWW-Authenticate "resource_metadata" pointer (RFC 9728).`,
      recommendation:
        'Return WWW-Authenticate: Bearer resource_metadata="<url>" so clients can discover how to authenticate.',
      location: "server",
      cwe: "CWE-306",
      owasp: "LLM08",
    });
    prmUrl = new URL("/.well-known/oauth-protected-resource", base).toString();
  }

  const prmSafety = await assessServerUrl(prmUrl, targetIsLocal);
  if (prmSafety === "ssrf") {
    findings.push(ssrfFinding("resource metadata", prmUrl));
    return findings;
  }
  const prm = prmSafety === "ok" ? await safeFetch(prmUrl, timeoutMs) : undefined;
  if (prm === undefined || prm.status >= 400 || prm.json === undefined) {
    findings.push({
      id: "AUTH002",
      severity: "medium",
      title: "OAuth Protected Resource Metadata is unreachable or malformed",
      evidence: `Could not retrieve valid Protected Resource Metadata from ${prmUrl}.`,
      recommendation:
        "Serve a valid RFC 9728 metadata document listing the authorization server(s).",
      location: "server",
      cwe: "CWE-306",
      owasp: "LLM08",
    });
    return findings;
  }

  const authorizationServers = stringArray(prm.json.authorization_servers);
  if (authorizationServers.length === 0) {
    findings.push({
      id: "AUTH002",
      severity: "medium",
      title: "Protected Resource Metadata lists no authorization server",
      evidence: "The resource metadata does not contain a non-empty authorization_servers array.",
      recommendation: "List at least one authorization server in the resource metadata.",
      location: "server",
      cwe: "CWE-306",
      owasp: "LLM08",
    });
    return findings;
  }

  for (const authServer of authorizationServers.slice(0, MAX_AUTH_SERVERS)) {
    if (isPlaintextNonLocal(authServer)) {
      findings.push(plaintextEndpointFinding("authorization server", authServer));
    }

    const asMetaUrl = new URL("/.well-known/oauth-authorization-server", authServer).toString();
    const asSafety = await assessServerUrl(asMetaUrl, targetIsLocal);
    if (asSafety === "ssrf") {
      findings.push(ssrfFinding("authorization server metadata", asMetaUrl));
      continue;
    }
    const asMeta = asSafety === "ok" ? await safeFetch(asMetaUrl, timeoutMs) : undefined;
    if (asMeta === undefined || asMeta.status >= 400 || asMeta.json === undefined) {
      findings.push({
        id: "AUTH002",
        severity: "medium",
        title: "Authorization Server Metadata is unreachable or malformed",
        evidence: `Could not retrieve valid Authorization Server Metadata from ${asMetaUrl}.`,
        recommendation: "Serve a valid RFC 8414 authorization server metadata document.",
        location: "server",
        cwe: "CWE-306",
        owasp: "LLM08",
      });
      continue;
    }

    const pkceMethods = stringArray(asMeta.json.code_challenge_methods_supported);
    if (!pkceMethods.includes("S256")) {
      findings.push({
        id: "AUTH003",
        severity: "high",
        title: "Authorization server does not advertise PKCE (S256)",
        evidence: 'code_challenge_methods_supported does not include "S256".',
        recommendation:
          "Require PKCE with S256; it is mandatory under OAuth 2.1 and the MCP authorization spec.",
        location: "server",
        cwe: "CWE-1188",
        owasp: "LLM08",
      });
    }

    for (const key of ["authorization_endpoint", "token_endpoint", "registration_endpoint"]) {
      const endpoint = asMeta.json[key];
      if (typeof endpoint === "string" && isPlaintextNonLocal(endpoint)) {
        findings.push(plaintextEndpointFinding(key, endpoint));
      }
    }
  }

  return findings;
}

function ssrfFinding(label: string, url: string): Finding {
  return {
    id: "AUTH005",
    severity: "high",
    title: "Server directed the scanner to a non-public address (possible SSRF)",
    evidence: `The ${label} URL resolves to a loopback, link-local, or private address and was not fetched: ${url}`,
    recommendation:
      "A remote server's OAuth metadata must reference publicly resolvable https endpoints, not internal addresses.",
    location: "server",
    cwe: "CWE-918",
    owasp: "LLM08",
  };
}

function plaintextEndpointFinding(label: string, endpoint: string): Finding {
  return {
    id: "AUTH004",
    severity: "high",
    title: "OAuth endpoint uses plaintext HTTP",
    evidence: `The ${label} is served over plaintext HTTP: ${endpoint}`,
    recommendation: "Serve all OAuth endpoints over https://.",
    location: "server",
    cwe: "CWE-319",
    owasp: "LLM08",
  };
}
