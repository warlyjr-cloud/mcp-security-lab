import type { Finding, TargetConfig } from "../types.js";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);
const SENSITIVE_QUERY_KEY_PATTERN =
  /^(api[-_]?key|access[-_]?token|auth|authorization|credential|key|password|secret|token)$/i;

function isLocal(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return LOCAL_HOSTS.has(host) || host.endsWith(".localhost");
}

/**
 * Static checks on a remote target URL, evaluated without connecting — the
 * remote counterpart of the launch-configuration rules for stdio targets.
 */
export function inspectRemote(target: TargetConfig): Finding[] {
  if (target.url === undefined) {
    return [];
  }

  const findings: Finding[] = [];
  let url: URL;
  try {
    url = new URL(target.url);
  } catch {
    findings.push({
      id: "REMOTE001",
      severity: "medium",
      title: "Remote target URL is malformed",
      evidence: "target.url could not be parsed as a URL.",
      recommendation: "Provide a valid absolute URL for the MCP endpoint.",
      location: "target.url",
      cwe: "CWE-20",
    });
    return findings;
  }

  if (url.protocol === "http:" && !isLocal(url.hostname)) {
    findings.push({
      id: "REMOTE002",
      severity: "high",
      title: "Remote endpoint uses plaintext HTTP",
      evidence: `The endpoint "${url.host}" is served over http://, so traffic and any tokens travel unencrypted.`,
      recommendation: "Use https:// for any non-local MCP endpoint.",
      location: "target.url",
      cwe: "CWE-319",
      owasp: "LLM08",
    });
  }

  const hasUserInfo = url.username !== "" || url.password !== "";
  const hasSensitiveQuery = [...url.searchParams.keys()].some((key) =>
    SENSITIVE_QUERY_KEY_PATTERN.test(key),
  );
  if (hasUserInfo || hasSensitiveQuery) {
    findings.push({
      id: "REMOTE003",
      severity: "high",
      title: "Credentials are embedded in the target URL",
      evidence: hasUserInfo
        ? "The URL contains userinfo (user:password@), which leaks into logs and history."
        : "The URL carries a credential in a query parameter, which leaks into logs and history.",
      recommendation:
        "Pass credentials through an authentication header or OAuth flow, never in the URL.",
      location: "target.url",
      cwe: "CWE-522",
      owasp: "LLM08",
    });
  }

  return findings;
}

/**
 * Finding for a remote server that accepted our connection without any
 * authentication. Evaluated only after a successful `--execute` connect, since
 * the scanner never supplies credentials.
 */
export function unauthenticatedAccessFinding(): Finding {
  return {
    id: "REMOTE004",
    severity: "medium",
    title: "Remote MCP server accepts unauthenticated connections",
    evidence: "The server completed the MCP handshake and listed tools without any credentials.",
    recommendation:
      "Require authentication (e.g. OAuth) for remote MCP servers unless anonymous access is intended.",
    location: "server",
    cwe: "CWE-306",
    owasp: "LLM08",
  };
}
