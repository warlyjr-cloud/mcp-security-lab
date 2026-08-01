// Audit a list of well-known public MCP servers and write FINDINGS.md.
//
//   node scripts/scan-registry.js [--sandbox docker] [--out FINDINGS.md]
//
// SECURITY: with no sandbox this starts each server on the host via npx. Pass
// --sandbox docker (requires Docker) for untrusted servers. The committed
// FINDINGS.md was produced against Anthropic's own reference servers.

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { scan } from "../dist/src/scanner.js";

function arg(flag, fallback) {
  const index = process.argv.indexOf(flag);
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

async function main() {
  const sandbox = arg("--sandbox", "none");
  const outPath = resolve(arg("--out", "FINDINGS.md"));
  const registry = JSON.parse(await readFile(resolve("corpus/registry.json"), "utf8"));

  const rows = [];
  for (const server of registry.servers) {
    process.stderr.write(`Scanning ${server.name} ...\n`);
    try {
      const report = await scan(
        {
          target: {
            command: server.command,
            args: server.args,
            cwd: process.cwd(),
            // Optional placeholder env so credential-gated servers complete the MCP
            // handshake and advertise their tools. Values are fake and never valid;
            // tools are never invoked, so no real API call is ever made.
            ...(server.env ? { env: server.env } : {}),
          },
          policy: { timeoutMs: 60000, maxTools: 100 },
        },
        true,
        sandbox,
      );
      const counts = {};
      for (const finding of report.findings) {
        counts[finding.id] = (counts[finding.id] || 0) + 1;
      }
      rows.push({
        name: server.name,
        connected: report.execution.connected,
        tools: report.server?.toolCount ?? 0,
        summary: report.summary,
        counts,
      });
    } catch (error) {
      rows.push({ name: server.name, connected: false, error: String(error && error.message) });
    }
  }

  const lines = [
    "# Real-world findings",
    "",
    "Produced by `npm run scan:registry` against well-known public MCP servers. These are",
    "**hygiene** findings (missing annotations, open schemas, missing pagination, mutable surfaces),",
    "not confirmed vulnerabilities — but they are real, actionable signal from real servers, and they",
    "exercise the detection engine outside its own fixtures.",
    "",
    "| Server | Connected | Tools | crit | high | med | low | Rules fired |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const row of rows) {
    if (row.error) {
      lines.push(`| \`${row.name}\` | no | - | - | - | - | - | error: ${row.error} |`);
      continue;
    }
    const fired = Object.entries(row.counts)
      .map(([id, n]) => `${id}×${n}`)
      .join(", ");
    lines.push(
      `| \`${row.name}\` | ${row.connected ? "yes" : "no"} | ${row.tools} | ${row.summary.critical} | ${row.summary.high} | ${row.summary.medium} | ${row.summary.low} | ${fired} |`,
    );
  }
  lines.push("");
  lines.push(
    "Reproduce: `npm run scan:registry` (add `--sandbox docker` for untrusted servers). The server",
    "list is `corpus/registry.json`.",
  );

  await writeFile(outPath, lines.join("\n") + "\n", "utf8");
  process.stderr.write(`Wrote ${outPath}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
