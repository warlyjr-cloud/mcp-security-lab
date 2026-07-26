import type { Finding, PromptMetadata } from "../types.js";
import { redactUntrustedText } from "../environment.js";
import { createFinding } from "./catalog.js";
import { injectionLabels } from "./text.js";

export function inspectPrompt(prompt: PromptMetadata): Finding[] {
  const findings: Finding[] = [];
  const location = `prompt:${redactUntrustedText(prompt.name, 200)}`;

  if (prompt.description === undefined || prompt.description.trim() === "") {
    findings.push(
      createFinding("PROMPT001", "The prompt returned no description.", location),
    );
  }

  const candidates = [
    prompt.description ?? "",
    ...(prompt.arguments ?? []).map((argument) => argument.description ?? ""),
  ];
  const labels = [...new Set(candidates.flatMap(injectionLabels))];
  if (labels.length > 0) {
    findings.push(
      createFinding(
        "PROMPT002",
        `Prompt metadata matched: ${labels.join(", ")}.`,
        location,
      ),
    );
  }

  return findings;
}
