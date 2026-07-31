# Changelog

## [1.4.3](https://github.com/warlyjr-cloud/mcp-security-lab/compare/mcp-security-lab-v1.4.2...mcp-security-lab-v1.4.3) (2026-07-31)


### Bug Fixes

* add repository/bugs/homepage so npm provenance publish succeeds ([#51](https://github.com/warlyjr-cloud/mcp-security-lab/issues/51)) ([f2941b3](https://github.com/warlyjr-cloud/mcp-security-lab/commit/f2941b3671f9004799559a2b2ee13af88462781c))

## [1.4.2](https://github.com/warlyjr-cloud/mcp-security-lab/compare/mcp-security-lab-v1.4.1...mcp-security-lab-v1.4.2) (2026-07-31)


### Bug Fixes

* **scanner:** run the Docker sandbox as an unprivileged user (uid 1000) ([#48](https://github.com/warlyjr-cloud/mcp-security-lab/issues/48)) ([7bd3210](https://github.com/warlyjr-cloud/mcp-security-lab/commit/7bd32107a451c108e0ea172a423c821d1774b22e))

## [1.4.1](https://github.com/warlyjr-cloud/mcp-security-lab/compare/mcp-security-lab-v1.4.0...mcp-security-lab-v1.4.1) (2026-07-31)


### Bug Fixes

* **scanner:** harden the Docker sandbox (digest pin, read-only, tmpfs, ipc, ro mount) ([#47](https://github.com/warlyjr-cloud/mcp-security-lab/issues/47)) ([64b3679](https://github.com/warlyjr-cloud/mcp-security-lab/commit/64b3679957229cb727a667228bd7489174d1191f))
* **scanner:** refuse remote fuzzing and never claim osSandboxed for remote targets ([#44](https://github.com/warlyjr-cloud/mcp-security-lab/issues/44)) ([fe1fbf5](https://github.com/warlyjr-cloud/mcp-security-lab/commit/fe1fbf5fa0233856dd656cb6673432469dc437cc))

## [1.4.0](https://github.com/warlyjr-cloud/mcp-security-lab/compare/mcp-security-lab-v1.3.0...mcp-security-lab-v1.4.0) (2026-07-30)


### Features

* add chaos monkey fuzzer, honeypot and least privilege rule ([#4](https://github.com/warlyjr-cloud/mcp-security-lab/issues/4)) ([f7d29ad](https://github.com/warlyjr-cloud/mcp-security-lab/commit/f7d29ada8eb4e1a4be5b824422e6a46a679c0cac))
* add Streamable HTTP transport and remote-server security checks ([#6](https://github.com/warlyjr-cloud/mcp-security-lab/issues/6)) ([529257b](https://github.com/warlyjr-cloud/mcp-security-lab/commit/529257be219381193b5c4b90e82872499db79be7))
* agentic, self-verifying remediation (Claude proposes, the engine verifies) ([#30](https://github.com/warlyjr-cloud/mcp-security-lab/issues/30)) ([0407ebf](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0407ebf0013fcb0ab41922276a36bd9e6a34eca8))
* baseline diff (remediation loop) plus safety and integration tests ([#24](https://github.com/warlyjr-cloud/mcp-security-lab/issues/24)) ([0c5460d](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0c5460dfc0b8e344ffc9ec25cc573b525f859239))
* confidence filtering, spec-coverage map, and comparison table ([#23](https://github.com/warlyjr-cloud/mcp-security-lab/issues/23)) ([69d004c](https://github.com/warlyjr-cloud/mcp-security-lab/commit/69d004c3e44d30147bca2a7fd59f96ff68ca6f0f))
* detect MCP lifecycle and confused-deputy attack classes ([#22](https://github.com/warlyjr-cloud/mcp-security-lab/issues/22)) ([1f1406d](https://github.com/warlyjr-cloud/mcp-security-lab/commit/1f1406dc816aec2dcdd6377f4f1898fb17c499e1))
* elevate project to first-class standards ([#1](https://github.com/warlyjr-cloud/mcp-security-lab/issues/1)) ([0bb8f46](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0bb8f46285523175887d43012f74408cb09a0e93))
* harden scanner, expand detection surface, and add security docs ([#5](https://github.com/warlyjr-cloud/mcp-security-lab/issues/5)) ([eebb6d9](https://github.com/warlyjr-cloud/mcp-security-lab/commit/eebb6d980fe1df9630be4a21a03569c647872089))
* implement sse transport, context exhaustion rule, and docker sandbox ([#2](https://github.com/warlyjr-cloud/mcp-security-lab/issues/2)) ([b139051](https://github.com/warlyjr-cloud/mcp-security-lab/commit/b13905188ff4b968ea9f00ba042aef9d2bda2cf8))
* labeled conformance corpus with a precision/recall benchmark ([#28](https://github.com/warlyjr-cloud/mcp-security-lab/issues/28)) ([0dd8e70](https://github.com/warlyjr-cloud/mcp-security-lab/commit/0dd8e70feffc7fc0bd8a34b76eecac1ecc837bcd))
* real-world validation against public MCP servers ([#31](https://github.com/warlyjr-cloud/mcp-security-lab/issues/31)) ([8be4d7b](https://github.com/warlyjr-cloud/mcp-security-lab/commit/8be4d7b28a39cad6c6fcfd70b738c0ae48bbbb95))
* run the real verifier from the web UI, and typecheck the web app ([#26](https://github.com/warlyjr-cloud/mcp-security-lab/issues/26)) ([d60470d](https://github.com/warlyjr-cloud/mcp-security-lab/commit/d60470d1aa3026f5e78c9175d00d84f67a886ad2))
* **sandbox:** add --sandbox-network opt-in and surface redacted stderr on boot failure ([#39](https://github.com/warlyjr-cloud/mcp-security-lab/issues/39)) ([b8ff100](https://github.com/warlyjr-cloud/mcp-security-lab/commit/b8ff1005cece1cda7772fdbb5cccc50875c46f5f))
* **scanner:** harden docker sandbox with cap-drop, pids and memory limits ([#38](https://github.com/warlyjr-cloud/mcp-security-lab/issues/38)) ([2c67c59](https://github.com/warlyjr-cloud/mcp-security-lab/commit/2c67c59b47dc4137c29a3e8871e9d0a57549d8f7))


### Bug Fixes

* **backend:** remove RCE surface from /api/scan ([#27](https://github.com/warlyjr-cloud/mcp-security-lab/issues/27)) ([66bc555](https://github.com/warlyjr-cloud/mcp-security-lab/commit/66bc5553bc04797751aa7e1c8bd19ab902d81189))
* describe remote scanning and ship rule docs in the npm package ([#8](https://github.com/warlyjr-cloud/mcp-security-lab/issues/8)) ([8a4a793](https://github.com/warlyjr-cloud/mcp-security-lab/commit/8a4a7937aaf2e8d2249ef4ae8e925b93c7cb2ddd))
* update @hono/node-server in backend to 2.0.11 for security ([#37](https://github.com/warlyjr-cloud/mcp-security-lab/issues/37)) ([67bd57c](https://github.com/warlyjr-cloud/mcp-security-lab/commit/67bd57ce5c23cdeb1a1988b54505bd93bda05855))
