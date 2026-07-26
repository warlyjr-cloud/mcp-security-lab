const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern: /\bignore (?:all |any )?(?:previous|prior) instructions?\b/i,
    label: "instruction override",
  },
  {
    pattern: /\b(?:always|must) (?:call|invoke|use) (?:this|the) tool\b/i,
    label: "forced invocation",
  },
  {
    pattern: /\bdo not (?:tell|inform|show) the user\b/i,
    label: "concealment",
  },
  {
    pattern: /\b(?:system prompt|hidden instructions?)\b/i,
    label: "hidden prompt reference",
  },
  {
    pattern: /\b(?:disable|bypass)\b.{0,30}\b(?:safety|security|permission)\b/i,
    label: "safety bypass",
  },
  {
    pattern: /\b(?:exfiltrate|send|upload)\b.{0,40}\b(?:secret|token|credential|private)\b/i,
    label: "data exfiltration",
  },
];

export function injectionLabels(text: string): string[] {
  return PROMPT_INJECTION_PATTERNS
    .filter((candidate) => candidate.pattern.test(text))
    .map((candidate) => candidate.label);
}
