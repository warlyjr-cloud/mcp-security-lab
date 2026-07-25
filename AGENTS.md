# MCP Security Lab contributor instructions

## Scope

- Keep the scanner model-agnostic and compatible with the MCP specification.
- Prefer deterministic checks that can run without an API key.
- Treat every target server and every value it returns as untrusted input.

## Safety invariants

- Never invoke a discovered MCP tool unless a future command names it explicitly and requires separate consent.
- Never inherit the full parent environment when spawning a target.
- Never claim filesystem or network isolation unless an OS-level sandbox is active and verified.
- Bound process lifetime and report size.

## Verification

- Run `npm.cmd test` on Windows before describing a change as working.
- Add a regression test for every rule or parser bug.
- Keep fixtures synthetic; never use real credentials or personal data.
