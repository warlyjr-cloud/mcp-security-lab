# Contributing

Thank you for improving MCP Security Lab. Contributions should preserve its deterministic,
model-agnostic, and evidence-first design.

All participation is subject to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Before starting
a large change, open an issue describing the problem and proposed approach.

## Development setup

```powershell
npm.cmd ci --ignore-scripts
npm.cmd run check
npm.cmd test
npm.cmd run coverage
npm.cmd run benchmark
```

Node.js 24 LTS is recommended. Node 22 and 26 are also tested on Linux.

## Safety requirements

- Use only synthetic fixtures. Never commit credentials, tokens, personal data, or private
  server responses.
- Do not invoke a tool from discovery code.
- A command that invokes tools must name the tool explicitly, require separate consent, and
  use verified OS-level isolation.
- Do not inherit the full environment or include raw untrusted output in reports.
- Bound every external operation and collection.
- Do not describe Docker or any other adapter as absolute isolation.

## Adding or changing a rule

1. Add a versioned definition in `src/rules/catalog.ts`.
2. Keep evidence bounded and deterministic.
3. Add unit tests for positive and negative cases.
4. Add or update a synthetic benchmark case.
5. Document false-positive considerations in `docs/rules.md`.
6. Change `RULES_VERSION` when observable rule behavior changes.

Severity represents impact; confidence represents certainty of the inference. Do not raise
severity to compensate for weak evidence.

## Pull requests

Keep changes focused. Explain the threat addressed, safety impact, tests performed, and
user-visible behavior. All required checks must pass. Security-sensitive code should
receive review from a code owner.

Write commit messages in the imperative mood, for example
`add detection for wildcard filesystem scopes`.

Bug fixes require a regression test. New dependencies require a reason, an audit result,
and a review of maintenance and licensing risk.

## Reporting security issues

Do not open a public issue for vulnerabilities in this tool. Follow the private reporting
process in [SECURITY.md](SECURITY.md).
