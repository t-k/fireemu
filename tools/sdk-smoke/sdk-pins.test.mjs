import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const packageJson = JSON.parse(await readFile(new URL("./package.json", import.meta.url)));
const lockfile = JSON.parse(await readFile(new URL("./package-lock.json", import.meta.url)));
const coverage = JSON.parse(await readFile(new URL("./sdk-listen-coverage.json", import.meta.url)));

const expected = Object.freeze({
  "@firebase/rules-unit-testing": "5.0.2",
  "@google-cloud/pubsub": "4.11.0",
  firebase: "12.18.0",
  "firebase-admin": "14.3.0",
  "firebase-functions": "7.3.2",
});

test("the SDK smoke declares exact versions for every Firebase client path", () => {
  assert.deepEqual(packageJson.dependencies, expected);
  assert.deepEqual(lockfile.packages[""].dependencies, expected);
  for (const [name, version] of Object.entries(expected)) {
    assert.equal(lockfile.packages[`node_modules/${name}`]?.version, version, name);
  }
});

test("browser SDK imports use the same pinned Firebase release", async () => {
  const files = ["web/index.html", "web/listener-lifecycle.js", "web/listen-reconnect.js"];
  for (const file of files) {
    const text = await readFile(new URL(`./${file}`, import.meta.url), "utf8");
    const versions = [...text.matchAll(/gstatic\.com\/firebasejs\/(\d+\.\d+\.\d+)\//g)].map(
      (match) => match[1],
    );
    assert.ok(versions.length > 0, `${file} has no pinned Firebase import`);
    assert.deepEqual([...new Set(versions)], [expected.firebase], file);
  }
});

test("the local feature ledger points at existing runners and controls", async () => {
  assert.equal(coverage.scope, "local-sdk-harness");
  assert.equal(coverage.production, "unobserved");
  assert.ok(coverage.scenarios.length >= 5);
  for (const scenario of coverage.scenarios) {
    assert.ok(scenario.id.length > 0);
    assert.ok(scenario.obligations.length > 0, scenario.id);
    const runnerRoot = scenario.runner.startsWith("conformance/") ? "../../" : "./";
    await readFile(new URL(`${runnerRoot}${scenario.runner}`, import.meta.url));
    for (const field of ["resetControl", "adminControl", "transactionControl"]) {
      if (scenario[field]) await readFile(new URL(`../../${scenario[field]}`, import.meta.url));
    }
  }
});
