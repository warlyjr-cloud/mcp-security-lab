import type { Finding, ResourceMetadata } from "../types.js";
import {
  redactUntrustedText,
  redactUrl,
} from "../environment.js";
import { createFinding } from "./catalog.js";

const MAX_DECLARED_RESOURCE_BYTES = 10 * 1024 * 1024;

export function inspectResource(resource: ResourceMetadata): Finding[] {
  const findings: Finding[] = [];
  const safeUri = redactUntrustedText(redactUrl(resource.uri), 300);
  const location = `resource:${safeUri}`;

  if (resource.description === undefined || resource.description.trim() === "") {
    findings.push(
      createFinding("RESOURCE001", "The resource returned no description.", location),
    );
  }

  let parsed: URL | undefined;
  try {
    parsed = new URL(resource.uri);
  } catch {
    parsed = undefined;
  }

  if (parsed?.protocol === "file:") {
    findings.push(
      createFinding("RESOURCE002", `Resource URI is "${safeUri}".`, location),
    );
  }

  if (parsed !== undefined && (parsed.username !== "" || parsed.password !== "")) {
    findings.push(
      createFinding("RESOURCE003", "The resource URI contains user information.", location),
    );
  }

  if (resource.size !== undefined && resource.size > MAX_DECLARED_RESOURCE_BYTES) {
    findings.push(
      createFinding(
        "RESOURCE004",
        `Declared size is ${resource.size} bytes.`,
        location,
      ),
    );
  }

  return findings;
}
