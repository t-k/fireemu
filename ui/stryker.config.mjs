// Mutation testing for the UI's pure logic and the field editor. Pages that need a daemon are
// covered by Playwright, not here.
/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  testRunner: "vitest",
  plugins: ["@stryker-mutator/vitest-runner"],
  mutate: ["src/lib/**/*.ts", "src/lib/**/*.tsx", "src/api/client.ts", "src/api/firestore.ts", "!src/**/*.test.*"],
  // TypeScript 7 (tsgo) has no `parseConfigFileTextToJson`, which Stryker's tsconfig rewrite
  // needs; the vitest runner does not need the rewrite, so point it at no file.
  tsconfigFile: "tsconfig.stryker-none.json",
  reporters: ["clear-text", "progress", "json"],
  jsonReporter: { fileName: "test-results/mutation.json" },
  tempDirName: "test-results/.stryker-tmp",
  // Solid compiles JSX into static template strings; per-test coverage misreports mutants in
  // them as uncovered, so run every test against every mutant.
  coverageAnalysis: "off",
  concurrency: 6,
  thresholds: { high: 90, low: 80, break: null },
};
