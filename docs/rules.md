# Rule catalog

The catalog version is `2026.07`. Run `mcpsl rules --format json` to obtain the complete
machine-readable rule set with severity, confidence, category, recommendation, and
references.

## Families

| Family | Count | Scope |
| --- | ---: | --- |
| `EXEC` | 2 | Consent and bounded discovery outcome |
| `LAUNCH` | 3 | Shells, download-on-start, and suspicious arguments |
| `TOOL` | 14 | Names, descriptions, annotations, schemas, and mixed operations |
| `SERVER` | 3 | Instructions, implementation version, and protocol version |
| `RESOURCE` | 4 | Description, filesystem exposure, credentials, and size |
| `PROMPT` | 2 | Description and injection-like metadata |
| `AUTH` | 8 | HTTPS, resource binding, discovery metadata, and PKCE |
| `SANDBOX` | 2 | Verified OS isolation and immutable images |
| `BEHAVIOR` | 5 | Canary, idempotence, failure, integrity, and result size |

## Severity and confidence

Severity estimates potential impact:

- `critical`: direct synthetic secret disclosure or isolation integrity failure;
- `high`: likely unsafe execution, authorization, destructive behavior, or policy bypass;
- `medium`: meaningful hardening or interoperability weakness;
- `low`: hygiene and metadata completeness;
- `info`: execution state without a vulnerability claim.

Confidence estimates evidence quality independently of impact. Pattern-based semantic
inferences normally use medium confidence; direct structural contradictions use high
confidence.

## Versioning policy

`RULES_VERSION` changes when a rule is added, removed, or materially changes detection,
severity, confidence, or recommendation. Scanner patch releases may improve implementation
without changing the rule version when findings remain equivalent.

Consumers should key suppressions by rule ID and review them whenever `rulesVersion`
changes. A suppression format is intentionally not included yet; hiding findings without an
auditable rationale would weaken the evidence model.

## False positives

Open an issue with:

- rule ID and rules version;
- minimal synthetic metadata;
- why the evidence is legitimate;
- proposed narrower condition;
- a negative regression test.

Do not submit production secrets or private server responses.
