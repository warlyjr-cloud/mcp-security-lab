// A fixture that fails during initialize the way a real server does when a
// required credential is missing: it writes an explanatory line to stderr and
// exits before the MCP handshake. The line embeds a secret-shaped assignment so
// the scanner's stderr-tail redaction is exercised — the value must never leak.
process.stderr.write("FATAL: FIGMA_API_KEY=figd_secret123 is required to start\n");
process.exit(1);
