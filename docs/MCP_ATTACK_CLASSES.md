# MCP-specific attack classes

Most "AI security" tooling scans _text_ — it looks for prompt injection in a description and stops
there. The Model Context Protocol has a richer attack surface that comes from its **capabilities and
lifecycle**, not from any single string. This document explains the attack classes that are specific
to MCP, why the protocol enables each one, how MCP Verifier detects it, and how to mitigate it.

It is written to be useful to MCP server authors and reviewers regardless of whether they use this
tool. Each class links to the rule that implements the check and to the relevant part of the MCP
specification (revision `2025-06-18`).

---

## 1. Rug pull (post-approval mutation) — `MUT001`

**What it is.** A server advertises a benign tool, the user (or an agent's approval policy) approves
it, and the server later **redefines that tool** — a different description, new parameters, new
behavior — by emitting a `notifications/tools/list_changed` message. The approval was granted against
a definition that no longer exists.

**Why MCP enables it.** The protocol deliberately supports dynamic surfaces: `tools`, `prompts`, and
`resources` can each declare `listChanged`, and servers are expected to notify clients when the list
changes. The capability is legitimate and useful; the risk is a client that inspects (or a human who
approves) once and then trusts the surface forever.

**Detection.** `MUT001` fires whenever the server declares `listChanged` for any of tools, prompts,
or resources — surfacing that the advertised surface is mutable and that one-time inspection is
insufficient. (It fired on all three official reference servers in our real-world run.)

**Mitigation.** Re-validate — and, for sensitive tools, re-prompt for approval — on every
`list_changed` notification. Never cache an approval decision across a mutation of a mutable surface.

**References.** MCP spec → Server → Tools → _List Changed Notification_.

---

## 2. Server-driven model steering via sampling — `SAMPLE001`

**What it is.** A server asks the _client_ to run an LLM completion on its behalf
(`sampling/createMessage`). A malicious or compromised server can use this to steer the model, inject
instructions into the model's context, or exfiltrate data through the content of the completion it
requests.

**Why MCP enables it.** Sampling is a first-class client capability: it lets servers build agentic
behavior without shipping their own model. But it inverts the usual trust flow — now the _server_
drives the _model_.

**Detection.** MCP Verifier declares the `sampling` client capability during discovery and installs a
handler that **records and declines** any `sampling/createMessage` the server issues, scanning the
requested messages for injection. A server that tries to sample an unattended scanner is a strong
signal worth surfacing (`SAMPLE001`).

**Mitigation.** Require explicit, per-request human approval of any server sampling call; show the
exact prompt to the user; never auto-approve sampling from an untrusted server.

**References.** MCP spec → Client → Sampling.

---

## 3. Elicitation phishing — `ELICIT001`

**What it is.** A server asks the client to collect input from the **user** mid-flow
(`elicitation/create`). This is a social-engineering surface: a malicious server can phish for
credentials, MFA codes, or blanket approvals inside an otherwise-trusted agent interaction.

**Why MCP enables it.** Elicitation exists so servers can ask for missing information conversationally.
The danger is that the request appears to come from the trusted agent, not from the third-party
server behind it.

**Detection.** As with sampling, the scanner declares the `elicitation` capability, records and
declines any `elicitation/create` the server issues, and scans the requested message for injection
(`ELICIT001`).

**Mitigation.** Present elicitation prompts with clear server attribution; never pre-fill or forward
sensitive values; treat any request for credentials or approvals as suspicious.

**References.** MCP spec → Client → Elicitation.

---

## 4. Confused deputy / token passthrough — `AUTH006`

**What it is.** A tool accepts an **upstream credential** (an access token, API key, bearer) as an
input parameter. The model — or a malicious server — can then relay a user's token to a third party.
It is worse when the same tool also takes a caller-controlled destination (`url`/`host`/`endpoint`):
the credential and the sink are both attacker-influenceable in a single call, the classic confused
deputy.

**Why MCP enables it.** Tools declare arbitrary input schemas, and it is tempting to "pass through"
the caller's token so the server can act on their behalf. That temptation is the vulnerability.

**Detection.** `AUTH006` flags any tool whose input schema contains a credential-shaped parameter,
escalating to **high** severity when a caller-controlled destination is present alongside it.

**Mitigation.** Never accept upstream tokens as tool inputs. Authenticate the tool with its own scoped
credential (OAuth on the MCP server per the authorization spec), and derive the caller's identity from
the session — do not let the model choose the token or the destination.

**References.** MCP spec → Basic → Authorization (OAuth 2.1 + RFC 9728 + RFC 8414).

---

## 5. Resource-template SSRF and path traversal — `RES001`

**What it is.** A resource template (`resources/templates/list`) interpolates a caller- or
model-controlled variable directly into a network scheme (`https://{host}/{path}` → SSRF) or a
filesystem path (`file:///{path}` → traversal). The template variable is a sink.

**Why MCP enables it.** URI templates are a convenient way to expose parameterized resources. Without
validation, `{host}` and `{path}` become the same unvalidated-input problem that SSRF and traversal
have always been — now reachable through the model.

**Detection.** `RES001` inspects every advertised resource template: `http(s)` templates with a
variable are flagged as SSRF (CWE-918), `file://`/path-shaped templates as traversal (CWE-22). Template
names and descriptions are also scanned for prompt injection.

**Mitigation.** Allowlist resolvable hosts and reject private, loopback, and link-local addresses
(including the cloud metadata address `169.254.169.254`) before fetching a templated URL. For paths,
canonicalize and verify containment within an intended root before reading.

**References.** MCP spec → Server → Resources → Resource Templates.

---

## Why static text scanning is not enough

Classes 1–3 are invisible to a pure text scan: nothing in a tool's _description_ tells you the server
can mutate it, drive the model, or prompt the user. They live in the **capability declarations and the
message lifecycle**. Class 4 is a _schema_ property, and class 5 is a _template_ property — again, not
text in a description. Auditing MCP well means auditing the protocol's structure, not just its strings.

MCP Verifier implements all five as deterministic rules with CWE/OWASP-LLM taxonomy and SARIF output;
see [docs/RULES.md](RULES.md) for the full catalog and [SPEC_COVERAGE.md](../SPEC_COVERAGE.md) for the
spec-to-rule map (including the gaps that are not yet covered).
