# MCP Security Lab contributor instructions

## Scope

- Keep the scanner model-agnostic and compatible with the MCP specification.
- Prefer deterministic checks that can run without an API key.
- Treat every target server and every value it returns as untrusted input.

## Safety invariants

- Never invoke a discovered MCP tool unless the operator explicitly opts in (`--fuzz`) AND an
  OS-level sandbox is active (`--sandbox docker`). Passive scanning never calls tools.
- Never inherit the full parent environment when spawning a target.
- Never claim filesystem or network isolation unless an OS-level sandbox is active and verified.
- Bound process lifetime and report size; a target must never be able to crash the scanner.
- Keep this file, THREAT_MODEL.md, and the code in agreement — if one changes, update the others.

## Verification

- Run `npm.cmd test` on Windows before describing a change as working.
- Add a regression test for every rule or parser bug.
- Keep fixtures synthetic; never use real credentials or personal data.
