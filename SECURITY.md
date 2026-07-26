# Security policy

## Supported versions

Security fixes are released for the latest minor release. Critical fixes may be backported
when a supported deployment cannot upgrade immediately.

| Version | Support |
| --- | --- |
| 0.3.x | Active |
| 0.2.x and earlier | Upgrade required |

## Reporting a vulnerability

Use a private GitHub Security Advisory in this repository. Do not open a public issue for a
suspected vulnerability and do not include credentials, private server configurations,
personal data, or proprietary source code.

Include:

- affected MCP Security Lab version and operating system;
- minimal synthetic configuration or fixture;
- expected and observed behavior;
- impact and any known preconditions;
- whether disclosure timing is sensitive.

Maintainers should acknowledge a report within three business days, provide an initial
assessment within seven business days, and coordinate remediation and disclosure with the
reporter. These are targets, not contractual service-level guarantees.

## Security invariants

- Discovered tools are never invoked by `scan`.
- `exercise` invokes only an exact tool name after explicit consent and verified Docker.
- Child processes receive an allowlisted environment, never the full parent environment.
- Reports redact common secrets, URL credentials, sensitive query values, and untrusted
  error text.
- Timeouts, item counts, pagination, response bodies, and report evidence are bounded.
- Remote DNS results are checked against private, loopback, link-local, and metadata
  service ranges before connection.
- Redirects are not followed automatically during metadata discovery.
- The project never claims OS isolation unless the Docker daemon preflight succeeds.

## Important limitations

Direct stdio execution (`sandbox.adapter=none`) runs with the current user's operating
system permissions. The scanner reports this as `SANDBOX001`, but cannot prevent filesystem
or network access.

Docker reduces risk but does not prove containment against kernel, daemon, runtime, or
configuration vulnerabilities. Do not mount secrets, the Docker socket, home directories,
or production source into the target container.

Remote metadata can be malicious. The scanner bounds and redacts it, but operators should
still run untrusted assessments on disposable hosts.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full trust-boundary analysis.
