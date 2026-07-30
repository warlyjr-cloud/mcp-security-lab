# Changelog

## [1.1.0](https://github.com/warlyjr-cloud/mcp-security-lab/compare/v1.0.0...v1.1.0) (2026-07-30)


### Features

* agentic, self-verifying remediation (Claude proposes, the engine verifies) ([#30](https://github.com/warlyjr-cloud/mcp-security-lab/issues/30)) ([0407ebf](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0407ebf0013fcb0ab41922276a36bd9e6a34eca8))
* baseline diff (remediation loop) plus safety and integration tests ([#24](https://github.com/warlyjr-cloud/mcp-security-lab/issues/24)) ([0c5460d](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0c5460dfc0b8e344ffc9ec25cc573b525f859239))
* confidence filtering, spec-coverage map, and comparison table ([#23](https://github.com/warlyjr-cloud/mcp-security-lab/issues/23)) ([69d004c](https://github.com/warlyjr-cloud/mcp-security-lab/commit/69d004c3e44d30147bca2a7fd59f96ff68ca6f0f))
* detect MCP lifecycle and confused-deputy attack classes ([#22](https://github.com/warlyjr-cloud/mcp-security-lab/issues/22)) ([1f1406d](https://github.com/warlyjr-cloud/mcp-security-lab/commit/1f1406dc816aec2dcdd6377f4f1898fb17c499e1))
* labeled conformance corpus with a precision/recall benchmark ([#28](https://github.com/warlyjr-cloud/mcp-security-lab/issues/28)) ([0dd8e70](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0dd8e70feffc7fc0bd8a34b76eecac1ecc837bcd))
* real-world validation against public MCP servers ([#31](https://github.com/warlyjr-cloud/mcp-security-lab/issues/31)) ([8be4d7b](https://github.com/warlyjr-cloud/mcp-security-lab/commit/8be4d7b28a39cad6c6fcfd70b738c0ae48bbbb95))
* run the real verifier from the web UI, and typecheck the web app ([#26](https://github.com/warlyjr-cloud/mcp-security-lab/issues/26)) ([d60470d](https://github.com/warlyjr-cloud/mcp-security-lab/commit/d60470d1aa3026f5e78c9175d00d84f67a886ad2))
* **sandbox:** add --sandbox-network opt-in and surface redacted stderr on boot failure ([#39](https://github.com/warlyjr-cloud/mcp-security-lab/issues/39)) ([b8ff100](https://github.com/warlyjr-cloud/mcp-security-lab/commit/b8ff1005cece1cda7772fdbb5cccc50875c46f5f))
* **scanner:** harden docker sandbox with cap-drop, pids and memory limits ([#38](https://github.com/warlyjr-cloud/mcp-security-lab/issues/38)) ([2c67c59](https://github.com/warlyjr-cloud/mcp-security-lab/commit/2c67c59b47dc4137c29a3e8871e9d0a57549d8f7))


### Bug Fixes

* **backend:** remove RCE surface from /api/scan ([#27](https://github.com/warlyjr-cloud/mcp-security-lab/issues/27)) ([66bc555](https://github.com/warlyjr-cloud/mcp-security-lab/commit/66bc5553bc04797751aa7e1c8bd19ab902d81189))
* update @hono/node-server in backend to 2.0.11 for security ([#37](https://github.com/warlyjr-cloud/mcp-security-lab/issues/37)) ([67bd57c](https://github.com/warlyjr-cloud/mcp-security-lab/commit/67bd57ce5c23cdeb1a1988b54505bd93bda05855))
