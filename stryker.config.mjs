/** @type {import("@stryker-mutator/api/core").PartialStrykerOptions} */
const config = {
  mutate: [
    "dist/src/environment.js",
    "dist/src/rules/**/*.js",
    "!dist/src/rules/catalog.js",
  ],
  testRunner: "command",
  commandRunner: {
    command: "npm run test:compiled",
  },
  coverageAnalysis: "off",
  reporters: ["clear-text", "progress", "json", "html"],
  thresholds: {
    high: 85,
    low: 70,
    break: 70,
  },
  concurrency: process.platform === "win32" ? 1 : 2,
  timeoutMS: 10_000,
  ignorePatterns: [
    ".npm-cache",
    ".stryker-tmp",
    "coverage",
    "reports",
    "tsconfig.json",
  ],
};

export default config;
