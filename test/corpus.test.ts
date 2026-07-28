import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { scan } from "../src/scanner.js";

interface CorpusEntry {
  name: string;
  fixture: string;
  expect: string[];
  forbid: string[];
}

const manifest = JSON.parse(readFileSync(resolve("corpus/manifest.json"), "utf8")) as {
  entries: CorpusEntry[];
};

for (const entry of manifest.entries) {
  test(`corpus: ${entry.name} matches its labeled expectations`, async () => {
    const report = await scan(
      {
        target: {
          command: process.execPath,
          args: [entry.fixture],
          cwd: process.cwd(),
        },
        policy: { timeoutMs: 5_000, maxTools: 100 },
      },
      true,
    );
    const detected = new Set(report.findings.map((finding) => finding.id));

    for (const id of entry.expect) {
      assert.ok(detected.has(id), `expected ${id} to fire on ${entry.name}`);
    }
    for (const id of entry.forbid) {
      assert.ok(!detected.has(id), `${id} must not fire on ${entry.name}`);
    }
  });
}
