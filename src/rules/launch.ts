import { basename } from "node:path";

import type { Finding, StdioTargetConfig } from "../types.js";
import { createFinding } from "./catalog.js";

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
];

export function inspectLaunch(target: StdioTargetConfig): Finding[] {
  const findings: Finding[] = [];
  const executable = basename(target.command).toLowerCase();
  const joinedArguments = target.args.join(" ");

  if (SHELL_NAMES.has(executable)) {
    findings.push(
      createFinding(
        "LAUNCH001",
        `Configured executable is "${executable}".`,
        "target.command",
      ),
    );
  }

  if (NETWORK_INSTALLERS.has(executable)) {
    findings.push(
      createFinding(
        "LAUNCH002",
        `Configured executable is "${executable}".`,
        "target.command",
      ),
    );
  }

  for (const candidate of SUSPICIOUS_ARGUMENTS) {
    if (candidate.pattern.test(joinedArguments)) {
      findings.push(
        createFinding(
          "LAUNCH003",
          `Arguments contain a pattern associated with ${candidate.label}.`,
          "target.args",
        ),
      );
    }
  }

  return findings;
}
