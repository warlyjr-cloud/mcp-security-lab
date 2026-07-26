import type { Finding } from "../types.js";

const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern: /\bignore (?:all |any )?(?:previous|prior) instructions?\b/i,
    label: "instruction override",
  },
  {
    pattern: /\b(?:always|must) (?:call|invoke|use) (?:this|the) tool\b/i,
    label: "forced invocation",
  },
  { pattern: /\bdo not (?:tell|inform|show) the user\b/i, label: "concealment" },
  { pattern: /\b(?:system prompt|hidden instructions?)\b/i, label: "hidden prompt reference" },
  { pattern: /\bdisable|bypass\b.{0,30}\b(?:safety|security|permission)/i, label: "safety bypass" },
];

// Characters an author never needs in a human-readable description but that an
// attacker uses to smuggle instructions past a naive substring scan. Built from
// explicit code-point ranges so this source file itself stays free of invisible
// characters and remains reviewable.
//   C0 controls (keep \t=0x09, \n=0x0A, \r=0x0D), DEL + C1 controls
//   soft hyphen, zero-width space..RLM, bidi overrides, word joiner..BOM
const INVISIBLE_CODEPOINT_RANGES: Array<[number, number]> = [
  [0x0, 0x8],
  [0xb, 0xc],
  [0xe, 0x1f],
  [0x7f, 0x9f],
  [0xad, 0xad], // soft hyphen
  [0x200b, 0x200f], // zero-width space, ZWNJ, ZWJ, LRM, RLM
  [0x202a, 0x202e], // bidirectional embedding/override controls
  [0x2060, 0x2064], // word joiner, invisible operators
  [0xfeff, 0xfeff], // zero-width no-break space / BOM
];

function buildInvisibleCharPattern(flags: string): RegExp {
  const body = INVISIBLE_CODEPOINT_RANGES.map(([start, end]) =>
    start === end
      ? `\\u{${start.toString(16)}}`
      : `\\u{${start.toString(16)}}-\\u{${end.toString(16)}}`,
  ).join("");
  return new RegExp(`[${body}]`, flags);
}

const INVISIBLE_CHAR_TEST = buildInvisibleCharPattern("u");
const INVISIBLE_CHAR_STRIP = buildInvisibleCharPattern("gu");

/**
 * Normalize untrusted text before pattern matching. NFKC folds homoglyph and
 * fullwidth variants onto their canonical form so that, for example, fullwidth
 * "ｉｇｎｏｒｅ" collapses to "ignore"; invisible characters are then stripped so
 * they cannot break up a keyword mid-word.
 */
export function normalizeText(text: string): string {
  return text.normalize("NFKC").replace(INVISIBLE_CHAR_STRIP, "");
}

export function hasInvisibleCharacters(text: string): boolean {
  return INVISIBLE_CHAR_TEST.test(text);
}

/**
 * Scan a single untrusted string for prompt-injection-like instructions.
 * Matching runs against the normalized form so evasion via Unicode tricks is
 * defeated. `sourceLabel` names where the text came from (e.g. "description",
 * "parameter data.query") for actionable evidence.
 */
export function scanTextForInjection(
  text: string,
  location: string,
  sourceLabel: string,
): Finding[] {
  const findings: Finding[] = [];
  if (text.trim() === "") {
    return findings;
  }

  if (hasInvisibleCharacters(text)) {
    findings.push({
      id: "TOOL012",
      severity: "high",
      title: "Text contains invisible or control characters",
      evidence: `The ${sourceLabel} contains zero-width, bidirectional, or control characters that are invisible to a human reviewer.`,
      recommendation:
        "Remove invisible and control characters; server-injected text must be exactly what a human reviewer sees.",
      location,
      cwe: "CWE-1007",
      owasp: "LLM01",
    });
  }

  const normalized = normalizeText(text);
  for (const candidate of PROMPT_INJECTION_PATTERNS) {
    if (candidate.pattern.test(normalized)) {
      findings.push({
        id: "TOOL003",
        severity: "high",
        title: "Text contains a prompt-injection-like instruction",
        evidence: `The ${sourceLabel} matched the ${candidate.label} pattern.`,
        recommendation: "Describe functionality only; remove behavioral or hidden instructions.",
        location,
        cwe: "CWE-77",
        owasp: "LLM01",
      });
    }
  }

  return findings;
}
