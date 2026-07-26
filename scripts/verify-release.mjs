import { readFile } from "node:fs/promises";

const releaseTag = process.argv[2] ?? process.env.GITHUB_REF_NAME;
if (releaseTag === undefined || releaseTag.trim() === "") {
  throw new Error("A release tag is required.");
}

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const expectedTag = `v${packageJson.version}`;
if (releaseTag !== expectedTag) {
  throw new Error(`Release tag ${releaseTag} does not match package version ${expectedTag}.`);
}

const { VERSION } = await import("../dist/src/version.js");
if (VERSION !== packageJson.version) {
  throw new Error(
    `Runtime version ${VERSION} does not match package version ${packageJson.version}.`,
  );
}

process.stdout.write(`Release metadata verified for ${expectedTag}.\n`);
