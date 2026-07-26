import type { Finding } from "../types.js";
import { redactUntrustedText } from "../environment.js";
import { createFinding } from "./catalog.js";
import { injectionLabels } from "./text.js";

const PUBLISHED_PROTOCOL_VERSIONS = new Set([
  "2024-10-07",
  "2024-11-05",
  "2025-03-26",
  "2025-06-18",
  "2025-11-25",
]);

export function inspectServer(
  version: string | undefined,
  protocolVersion: string | undefined,
  instructions: string | undefined,
): Finding[] {
  const findings: Finding[] = [];

  if (version === undefined || version.trim() === "") {
    findings.push(
      createFinding("SERVER002", "The initialize response did not include serverInfo.version.", "server.version"),
    );
  }

  if (
    protocolVersion !== undefined &&
    !PUBLISHED_PROTOCOL_VERSIONS.has(protocolVersion)
  ) {
    findings.push(
      createFinding(
        "SERVER003",
        `The negotiated protocol version is "${redactUntrustedText(protocolVersion, 100)}".`,
        "server.protocolVersion",
      ),
    );
  }

  if (instructions !== undefined) {
    const labels = injectionLabels(instructions);
    if (labels.length > 0) {
      findings.push(
        createFinding(
          "SERVER001",
          `Server instructions matched: ${labels.join(", ")}.`,
          "server.instructions",
        ),
      );
    }
  }

  return findings;
}
