import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { scan } from "../src/scanner.js";

test("scanner report version matches package.json (no drift)", async () => {
  const pkg = JSON.parse(readFileSync(resolve("package.json"), "utf8")) as { version: string };
  const report = await scan(
    { target: { command: "node", args: ["server.js"], cwd: "." }, policy: { timeoutMs: 5_000, maxTools: 10 } },
    false,
  );
  assert.equal(report.scanner.version, pkg.version);
});
