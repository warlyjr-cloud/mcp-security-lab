import type { Finding, ToolMetadata } from "../types.js";
import { scanTextForInjection } from "./injection.js";

/**
 * Capability-lifecycle and confused-deputy rules.
 *
 * These target attack classes specific to the MCP protocol lifecycle rather than
 * to static text: post-approval mutation (rug pull), server-initiated model
 * control (sampling), server-initiated user prompts (elicitation), injectable
 * resource templates, and upstream-credential passthrough (confused deputy).
 */

/** Minimal shape of the server capabilities object from the MCP handshake. */
export interface ServerCapabilitiesLike {
  tools?: { listChanged?: boolean } | undefined;
  prompts?: { listChanged?: boolean } | undefined;
  resources?: { listChanged?: boolean; subscribe?: boolean } | undefined;
}

/** Minimal shape of a resource template entry from resources/templates/list. */
export interface ResourceTemplateLike {
  name?: string;
  uriTemplate: string;
  description?: string;
}

const SPEC = "https://modelcontextprotocol.io/specification/2025-06-18";

/**
 * MUT001 - the server declares that it can change its advertised surface after
 * the client has already inspected (and a user may have already approved) it.
 * This is the rug pull: a tool approved as benign is silently redefined via a
 * list_changed notification. The capability is legitimate, but a client that
 * does not re-validate on change is exposed, so we surface it.
 */
export function inspectLifecycleCapabilities(
  capabilities: ServerCapabilitiesLike | undefined,
): Finding[] {
  if (!capabilities) {
    return [];
  }

  const mutable: string[] = [];
  if (capabilities.tools?.listChanged === true) {
    mutable.push("tools");
  }
  if (capabilities.prompts?.listChanged === true) {
    mutable.push("prompts");
  }
  if (capabilities.resources?.listChanged === true) {
    mutable.push("resources");
  }

  if (mutable.length === 0) {
    return [];
  }

  return [
    {
      id: "MUT001",
      severity: "medium",
      title: "Server can mutate its advertised surface after approval (rug-pull risk)",
      evidence:
        "Server declares listChanged for: " +
        mutable.join(", ") +
        ". Definitions inspected or approved now may be replaced later via a list_changed notification.",
      recommendation:
        "Re-validate and (where appropriate) re-prompt for approval whenever a list_changed notification arrives; do not trust a one-time inspection of a mutable surface.",
      location: "server",
      cwe: "CWE-494",
      owasp: "LLM03",
      confidence: "medium",
      references: [SPEC + "/server/tools#list-changed-notification"],
    },
  ];
}

const CREDENTIAL_PARAM_PATTERN =
  /^(?:access_?token|api_?key|apikey|bearer|authorization|auth_?token|client_?secret|refresh_?token|session_?token|password|passwd|secret|private_?key)$/i;
const OUTBOUND_PARAM_PATTERN = /^(?:url|uri|endpoint|host|hostname|base_?url|target|webhook)$/i;

function propertiesOf(schema: Record<string, unknown>): Record<string, unknown> {
  const properties = schema.properties;
  if (typeof properties !== "object" || properties === null || Array.isArray(properties)) {
    return {};
  }
  return properties as Record<string, unknown>;
}

/**
 * AUTH006 - confused-deputy / token passthrough. A tool that accepts an upstream
 * credential as an input parameter invites the model (or a malicious server) to
 * relay a user token to a third party. It is far worse when the same tool also
 * takes an arbitrary destination (url/host/endpoint): the credential and the sink
 * are both attacker-influenceable in one call.
 */
export function inspectCredentialPassthrough(tools: ToolMetadata[]): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const keys = Object.keys(propertiesOf(tool.inputSchema));
    const credentialParam = keys.find((key) => CREDENTIAL_PARAM_PATTERN.test(key));
    if (credentialParam === undefined) {
      continue;
    }
    const hasOutbound = keys.some((key) => OUTBOUND_PARAM_PATTERN.test(key));

    findings.push({
      id: "AUTH006",
      severity: hasOutbound ? "high" : "medium",
      title: hasOutbound
        ? "Tool relays an upstream credential to an arbitrary destination (confused deputy)"
        : "Tool accepts an upstream credential as an input parameter (token passthrough)",
      evidence: hasOutbound
        ? "Tool " +
          tool.name +
          " takes a credential parameter (" +
          credentialParam +
          ") together with a caller-controlled destination, so a user token can be forwarded anywhere."
        : "Tool " +
          tool.name +
          " takes a credential parameter (" +
          credentialParam +
          "), inviting passthrough of a user token to the server.",
      recommendation:
        "Never accept upstream tokens as tool inputs. Authenticate the tool with its own scoped credential (OAuth on the MCP server), and derive the caller identity from the session - do not let the model choose the token or the destination.",
      location: "tool:" + tool.name,
      cwe: "CWE-522",
      owasp: "LLM08",
      confidence: hasOutbound ? "high" : "medium",
      references: [SPEC + "/basic/authorization"],
    });
  }

  return findings;
}

/**
 * RES001 - resource templates whose variables are interpolated directly into a
 * network scheme (SSRF) or a filesystem path (traversal). Template variables are
 * model- or caller-controlled, so an unvalidated host or path is a sink. Template
 * names and descriptions are also scanned for prompt injection, since they enter
 * the model context like any other advertised metadata.
 */
export function inspectResourceTemplates(templates: ResourceTemplateLike[]): Finding[] {
  const findings: Finding[] = [];

  for (const template of templates) {
    const label = typeof template.name === "string" ? template.name : template.uriTemplate;
    const location = "resource-template:" + label;

    if (typeof template.name === "string") {
      findings.push(...scanTextForInjection(template.name, location, "resource template name"));
    }
    if (typeof template.description === "string") {
      findings.push(
        ...scanTextForInjection(template.description, location, "resource template description"),
      );
    }

    const uri = template.uriTemplate;
    const hasVariable = /\{[^}]+\}/.test(uri);
    if (!hasVariable) {
      continue;
    }

    if (/^https?:\/\//i.test(uri)) {
      findings.push({
        id: "RES001",
        severity: "high",
        title: "Resource template interpolates a variable into a network request (SSRF risk)",
        evidence:
          "Template " +
          uri +
          " builds an http(s) URL from caller-controlled variables; without host allowlisting this is a server-side request forgery sink.",
        recommendation:
          "Allowlist the resolvable hosts and reject private, loopback, and link-local addresses (including 169.254.169.254) before fetching a templated URL.",
        location,
        cwe: "CWE-918",
        owasp: "LLM08",
        confidence: "medium",
      });
    } else if (/^file:\/\//i.test(uri) || /\{[^}]*(?:path|file|dir)[^}]*\}/i.test(uri)) {
      findings.push({
        id: "RES001",
        severity: "high",
        title: "Resource template interpolates a variable into a filesystem path (traversal risk)",
        evidence:
          "Template " +
          uri +
          " builds a filesystem path from caller-controlled variables; without canonicalization this permits path traversal.",
        recommendation:
          "Resolve the templated path and verify it stays within an intended root before reading; reject dot-dot segments, absolute paths, and symlinks that escape the root.",
        location,
        cwe: "CWE-22",
        owasp: "LLM08",
        confidence: "medium",
      });
    }
  }

  return findings;
}

/**
 * SAMPLE001 - the server asked the client to run an LLM completion on its behalf
 * (sampling/createMessage). A server that drives the model can steer or
 * exfiltrate through the completion it requests, so the scanner declines the
 * request and reports it, scanning the requested messages for injection.
 */
export function samplingRequestFinding(requestedText: string): Finding[] {
  const injection = scanTextForInjection(requestedText, "server", "sampling request");
  return [
    {
      id: "SAMPLE001",
      severity: "high",
      title: "Server requested a model completion via sampling (model-steering surface)",
      evidence:
        "During discovery the server issued a sampling/createMessage request, asking the client to run an LLM completion it controls. This lets a server steer or exfiltrate through the model.",
      recommendation:
        "Require explicit, per-request human approval of any server sampling call; show the exact prompt to the user, and never auto-approve sampling from an untrusted server.",
      location: "server",
      cwe: "CWE-284",
      owasp: "LLM01",
      confidence: "high",
      references: [SPEC + "/client/sampling"],
    },
    ...injection,
  ];
}

/**
 * ELICIT001 - the server asked the client to collect input from the user
 * (elicitation/create). This is a social-engineering surface: a malicious server
 * can phish for credentials or approvals mid-flow. Reported and scanned.
 */
export function elicitationRequestFinding(requestedText: string): Finding[] {
  const injection = scanTextForInjection(requestedText, "server", "elicitation request");
  return [
    {
      id: "ELICIT001",
      severity: "medium",
      title: "Server requested user input via elicitation (social-engineering surface)",
      evidence:
        "During discovery the server issued an elicitation/create request, prompting the user for input mid-flow. A malicious server can use this to phish for credentials or approvals.",
      recommendation:
        "Present elicitation prompts with clear server attribution, never pre-fill or forward sensitive values, and treat any request for credentials or approvals as suspicious.",
      location: "server",
      cwe: "CWE-1021",
      owasp: "LLM01",
      confidence: "medium",
      references: [SPEC + "/client/elicitation"],
    },
    ...injection,
  ];
}
