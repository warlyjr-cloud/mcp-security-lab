import type { Finding } from "../types.js";

// A collection of regex patterns to detect sensitive data leakage in tool responses
const LEAK_PATTERNS = [
  {
    name: "AWS Access Key",
    regex: /(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])/,
    recommendation:
      "Never return AWS Access Keys in tool responses. Filter them out before returning data to the LLM.",
    cwe: "CWE-200",
  },
  {
    name: "Google Cloud Service Account Key (JSON Fragment)",
    regex: /"private_key":\s*"-----BEGIN PRIVATE KEY-----/,
    recommendation:
      "Never return GCP Service Account keys. Ensure your tools do not read or dump credential files.",
    cwe: "CWE-200",
  },
  {
    name: "NVIDIA NIM API Key",
    regex: /nvapi-[a-zA-Z0-9_-]{32,}/,
    recommendation:
      "NVIDIA NIM API Keys were found in the output. This poses a severe risk of AI resource hijacking.",
    cwe: "CWE-200",
  },
  {
    name: "OpenAI API Key",
    regex: /sk-(?:proj-|ant-)?[a-zA-Z0-9_-]{32,}/,
    recommendation:
      "OpenAI API Keys were found in the output. This is a severe risk of quota hijacking.",
    cwe: "CWE-200",
  },
  {
    name: "Stripe Secret Key",
    regex: /sk_live_[a-zA-Z0-9]{24,}/,
    recommendation:
      "Stripe payment keys were found in the output. This could lead to financial fraud.",
    cwe: "CWE-200",
  },
  {
    name: "Slack Bot Token",
    regex: /xoxb-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24}/,
    recommendation:
      "Slack workspace tokens were found. Attackers could read private company messages.",
    cwe: "CWE-200",
  },
  {
    name: "Atlassian (Jira/Confluence) API Token",
    regex: /(?<![A-Za-z0-9])[a-zA-Z0-9]{24}(?![A-Za-z0-9])/, // Note: Atlassian tokens are 24-char alphanumeric. This is a generic high-entropy matcher.
    recommendation:
      "Potential Atlassian API tokens detected. Ensure Jira/Confluence secrets are redacted.",
    cwe: "CWE-200",
  },
  {
    name: "Credit Card (Basic format detection)",
    // Extremely basic matcher for 16-digit cards to avoid high false positives in test IDs
    regex: /\b(?:\d[ -]*?){13,16}\b/,
    recommendation:
      "Potential Credit Card number detected in tool output. Ensure PII/PCI data is redacted.",
    cwe: "CWE-359",
  },
];

/**
 * Detects a leaked secret but never echoes the matched substring back into
 * the finding: `evidence` names the pattern that fired, not the value that
 * matched it. Findings feed the AI remediation prompts (ai-fix.ts, agentic.ts),
 * which are sent to Claude and rendered in a Markdown report -- reproducing
 * the actual secret there would forward it to a third party and persist it to
 * disk. Keep any new pattern's evidence string free of `content`.
 */
export function scanForDataLeaks(content: string, location: string, toolName: string): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of LEAK_PATTERNS) {
    if (pattern.regex.test(content)) {
      findings.push({
        id: "DATA001",
        severity: "critical",
        title: `Sensitive Data Leak Detected: ${pattern.name}`,
        evidence: `The tool ${toolName} returned data matching a ${pattern.name} signature.`,
        recommendation: pattern.recommendation,
        location,
        cwe: pattern.cwe,
        owasp: "LLM06", // Sensitive Information Disclosure
        remediationSnippet: `// Example: Redacting output before returning
const result = doDangerousWork();
return {
  content: [{ 
    type: "text", 
    text: result.replace(/nvapi-[a-zA-Z0-9_-]+/g, "[REDACTED]") 
  }]
};`,
      });
    }
  }

  return findings;
}
