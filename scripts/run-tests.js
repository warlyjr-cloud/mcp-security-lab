import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";

// Node 20 expands a directory passed to --test, Node 22+ expects files or globs,
// and no shell expands ** portably. Resolving the list here works everywhere.
const testDirectory = join("dist", "test");
const files = readdirSync(testDirectory, { recursive: true })
  .map((entry) => entry.toString())
  .filter((entry) => entry.endsWith(".test.js"))
  .map((entry) => join(testDirectory, entry))
  .sort();

if (files.length === 0) {
  console.error(`No compiled test files were found in ${testDirectory}.`);
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...files], { stdio: "inherit" });
process.exit(result.status ?? 1);
