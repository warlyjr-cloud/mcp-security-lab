import Anthropic from "@anthropic-ai/sdk";
import type { Finding } from "../types.js";
import { UNTRUSTED_DATA_INSTRUCTION, wrapUntrusted } from "../prompt-safety.js";

/**
 * @param client Optional pre-built Anthropic client, injected in tests to avoid
 *   real network calls. Production callers omit it and let this function build
 *   one from `apiKey`/`ANTHROPIC_API_KEY`.
 */
export async function generateRemediationPlan(
  findings: Finding[],
  apiKey?: string,
  client?: Anthropic,
): Promise<string> {
  const key = apiKey || process.env.ANTHROPIC_API_KEY;
  if (!client && !key) {
    return "Skipping AI Remediation: ANTHROPIC_API_KEY environment variable is missing.";
  }

  if (findings.length === 0) {
    return "# 🛡️ MCP Remediation Plan\n\nNo vulnerabilities found! Your server is secure.";
  }

  const anthropic = client ?? new Anthropic({ apiKey: key });

  // Filter only HIGH and CRITICAL findings for remediation to save context
  const criticalFindings = findings.filter(
    (f) => f.severity === "critical" || f.severity === "high",
  );
  if (criticalFindings.length === 0) {
    return "# 🛡️ MCP Remediation Plan\n\nOnly medium/low severity findings detected. No critical AI patching required.";
  }

  const findingsJson = JSON.stringify(criticalFindings, null, 2);

  const prompt = `You are a world-class cybersecurity engineer specializing in the Model Context Protocol (MCP).
A security scan has just found the following CRITICAL and HIGH vulnerabilities in an MCP server:

${wrapUntrusted(findingsJson)}

Generate a comprehensive Remediation Plan in Markdown format.
For each finding:
1. Briefly explain the risk in 1 sentence.
2. Provide a concrete code snippet demonstrating how to fix the issue. Assume the server is written in TypeScript using the official @modelcontextprotocol/sdk.
3. Suggest a security best practice to prevent this in the future.

Ensure the output is pure Markdown and highly professional.`;

  try {
    const response = await anthropic.messages.create({
      model: "claude-opus-4-8",
      max_tokens: 4096,
      system: `You are an expert AppSec engineer. Output only Markdown. ${UNTRUSTED_DATA_INSTRUCTION}`,
      messages: [{ role: "user", content: prompt }],
    });

    const content = response.content[0];
    if (!content || content.type !== "text") {
      throw new Error("Unexpected response type from Anthropic API.");
    }

    return content.text;
  } catch (error: unknown) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error("AI Remediation failed:", msg);
    return `# 🛡️ MCP Remediation Plan\n\nFailed to generate plan via AI. Error: ${msg}`;
  }
}
