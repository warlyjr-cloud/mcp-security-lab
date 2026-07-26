# MCP compatibility and conformance

MCP Security Lab uses `@modelcontextprotocol/sdk` and accepts the published protocol
versions currently supported by the scanner:

- `2024-10-07`
- `2024-11-05`
- `2025-03-26`
- `2025-06-18`
- `2025-11-25`

It supports stdio and Streamable HTTP discovery. Capability-aware metadata collection
covers tools, resources, and prompts, including pagination and loop detection.

## What is tested

- SDK client interoperability with synthetic stdio servers;
- negotiated protocol capture;
- exact discovery methods used;
- no tool invocation during scanning;
- bounded pagination and metadata counts;
- OAuth discovery structures for remote endpoints.

## What is not claimed

The project is not an official MCP conformance suite or certification authority. It does
not test every protocol state, sampling, elicitation, roots, notifications, resumability,
or task lifecycle. A server passing this scanner may still fail protocol conformance.

Official conformance results, when integrated, must be reported separately from MCP
Security Lab findings so that security heuristics and protocol compliance are not
conflated.
