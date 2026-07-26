import { basename } from "node:path";

import type { Finding, TargetConfig } from "../types.js";

const SHELL_NAMES = new Set([
  "bash",
  "bash.exe",
  "cmd",
  "cmd.exe",
  "pwsh",
  "pwsh.exe",
  "powershell",
  "powershell.exe",
  "sh",
  "sh.exe",
]);

const NETWORK_INSTALLERS = new Set(["npx", "npx.cmd", "pipx", "uvx"]);

const SUSPICIOUS_ARGUMENTS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\brm\s+-rf\b/i, label: "recursive deletion" },
  { pattern: /\bremove-item\b.*\b-recurse\b/i, label: "recursive deletion" },
  { pattern: /\bcurl\b|\bwget\b|invoke-webrequest/i, label: "network download" },
  { pattern: /(?:^|[;&|])\s*(?:cmd|powershell|pwsh|bash|sh)\b/i, label: "nested shell" },
  { pattern: /\b(?:sudo|runas)\b/i, label: "privilege escalation" },
  { pattern: /\b(?:iex|invoke-expression)\b/i, label: "dynamic code execution" },
  { pattern: /\bfrombase64string\b|base64\s+-d\b|base64\s+--decode\b/i, label: "encoded payload" },
];

// Interpreters paired with the flags that make them execute inline source
// supplied on the command line, bypassing any reviewable script file.
const INLINE_EVAL_RULES: Array<{ executables: Set<string>; flags: RegExp }> = [
  {
    executables: new Set(["node", "node.exe", "deno", "deno.exe", "bun", "bun.exe"]),
    flags: /^(?:-e|--eval|-p|--print|eval)$/i,
  },
  {
    executables: new Set(["python", "python.exe", "python3", "python3.exe"]),
    flags: /^-c$/,
  },
  {
    executables: new Set(["ruby", "ruby.exe", "perl", "perl.exe"]),
    flags: /^-e$/,
  },
  {
    executables: new Set(["pwsh", "pwsh.exe", "powershell", "powershell.exe"]),
    flags: /^-(?:e|ec|enc|encodedcommand|command|c)$/i,
  },
];

export function inspectLaunch(target: TargetConfig): Finding[] {
  const findings: Finding[] = [];
  if (target.command === undefined || target.args === undefined) {
    return findings;
  }

  const executable = basename(target.command).toLowerCase();
  const joinedArguments = target.args.join(" ");

  if (SHELL_NAMES.has(executable)) {
    findings.push({
      id: "LAUNCH001",
      severity: "high",
      title: "Target is launched through a general-purpose shell",
      evidence: `Configured executable is "${executable}".`,
      recommendation: "Launch a fixed executable directly and pass arguments as an array.",
      location: "target.command",
      cwe: "CWE-78",
    });
  }

  if (NETWORK_INSTALLERS.has(executable)) {
    findings.push({
      id: "LAUNCH002",
      severity: "medium",
      title: "Target may download executable code at startup",
      evidence: `Configured executable is "${executable}".`,
      recommendation: "Pin and install the package before scanning, then execute the local binary.",
      location: "target.command",
      cwe: "CWE-829",
    });
  }

  for (const candidate of SUSPICIOUS_ARGUMENTS) {
    if (candidate.pattern.test(joinedArguments)) {
      findings.push({
        id: "LAUNCH003",
        severity: "high",
        title: "Suspicious launcher argument",
        evidence: `Arguments contain a pattern associated with ${candidate.label}.`,
        recommendation: "Replace the launcher with a fixed, reviewable command.",
        location: "target.args",
        cwe: "CWE-78",
      });
    }
  }

  for (const rule of INLINE_EVAL_RULES) {
    if (rule.executables.has(executable) && target.args.some((arg) => rule.flags.test(arg))) {
      findings.push({
        id: "LAUNCH004",
        severity: "high",
        title: "Target executes inline code from the command line",
        evidence: `"${executable}" is invoked with an inline evaluation flag instead of a reviewable script file.`,
        recommendation:
          "Move the code into a committed, reviewable script and launch that file directly.",
        location: "target.args",
        cwe: "CWE-95",
      });
      break;
    }
  }

  return findings;
}
