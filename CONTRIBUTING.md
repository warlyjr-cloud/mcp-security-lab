# Contributing to MCP Security Lab

Thanks for your interest in improving this project. This document explains how to set up the project, what kinds of contributions are welcome, and how changes are reviewed.

## Ground rules

This project audits software that may be untrusted. Never commit real credentials, tokens, private server configurations, or scan reports produced against third-party systems. Example configurations must point only at fixtures inside this repository.

All participation is subject to the CODE_OF_CONDUCT.md file in the root of this repository.

## Getting started

Requirements: Node.js 20 or newer and npm.

Install dependencies with `npm install`, build with `npm run build`, and run the test suite with `npm test`. A quick manual check is `node dist/src/cli.js scan --config examples/insecure-server.json`, which performs launch-configuration checks only. Adding `--execute` starts the target server, so only use it against the fixtures in this repository or inside a disposable environment.

## Ways to contribute

Useful contributions include new detection rules for risky launcher patterns or unsafe tool advertisements, additional fixtures that reproduce real-world MCP server behaviour, improvements to the SARIF and JSON output, documentation fixes, and bug reports with a reproducible configuration.

Before starting a large change, open an issue describing the problem and the approach so we can agree on direction first.

## Pull requests

Work on a branch off `main` and keep each pull request focused on a single concern. Every pull request should build cleanly, pass the test suite, and include tests for new detections. Describe what changed and why, and mention any new finding IDs or severity levels you introduced so the report format stays predictable.

Commit messages should describe the change in the imperative mood, for example "add detection for wildcard filesystem scopes".

## Reporting security issues

Do not open a public issue for vulnerabilities in this tool. Use the private reporting channel described in SECURITY.md.
