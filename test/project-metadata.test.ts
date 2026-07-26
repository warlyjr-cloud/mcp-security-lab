import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { parse } from "yaml";

import { RULES } from "../src/rules/catalog.js";
import { VERSION } from "../src/version.js";

test("package, runtime, and catalog metadata stay synchronized", async () => {
  const packageJson = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(packageJson.version, VERSION);
  assert.equal(packageJson.engines.node, ">=22.14.0");
  assert.equal(packageJson.repository.url, "git+https://github.com/warlyjr-cloud/mcp-security-lab.git");
  assert.equal(Object.keys(RULES).length, 43);

  for (const [id, rule] of Object.entries(RULES)) {
    assert.match(id, /^[A-Z]+[0-9]{3}$/);
    assert.ok(rule.references.length > 0, `${id} requires a primary reference`);
    for (const reference of rule.references) {
      assert.match(reference.url, /^https:\/\//, `${id} references must use HTTPS`);
    }
  }
});

test("container base is pinned and community metadata is valid YAML", async () => {
  const dockerfile = await readFile("Dockerfile", "utf8");
  const pinnedBase =
    /node:24\.18\.0-bookworm-slim@sha256:[0-9a-f]{64}/g;
  assert.equal(dockerfile.match(pinnedBase)?.length, 2);
  assert.match(dockerfile, /\r?\nUSER node\r?\n/);

  for (const path of [
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/rule-proposal.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
  ]) {
    const document = parse(await readFile(path, "utf8"));
    assert.equal(typeof document, "object", `${path} must contain YAML`);
  }
});
