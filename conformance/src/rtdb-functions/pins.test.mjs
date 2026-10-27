// The reviewed sources of the CV14 run: the digest of each fixture file is fixed in the code, so a run
// refuses a fixture that was changed after it was reviewed. The packet repeats the digests.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { FIXTURE_PINS, requiredInstalledDependencies, requiredStage2Sources } from "./pins.mjs";

const here = (file) => new URL(`./${file}`, import.meta.url);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

test("the pinned digests are those of the files in the repository", async () => {
  assert.deepEqual(Object.keys(FIXTURE_PINS), [
    "firebase.json",
    "fixtures/frames.js",
    "fixtures/index.js",
    "fixtures/package-lock.json",
    "fixtures/package.json",
  ]);
  for (const [file, expected] of Object.entries(FIXTURE_PINS)) {
    assert.equal(sha256(await readFile(here(file))), expected, file);
  }
  await assert.doesNotReject(() => requiredStage2Sources());
});

test("a changed file, or another Firebase CLI version, is refused", async () => {
  const real = async (file) => readFile(here(file));
  const cli = (version) => async (file) =>
    file.endsWith("firebase-tools/package.json")
      ? Buffer.from(JSON.stringify({ version }))
      : real(file);
  await assert.doesNotReject(() => requiredStage2Sources(cli("15.28.2")));
  await assert.rejects(() => requiredStage2Sources(cli("15.28.1")), /15\.28\.2/);
  for (const file of Object.keys(FIXTURE_PINS)) {
    const changed = async (name) =>
      name === file ? Buffer.concat([await real(name), Buffer.from(" ")]) : cli("15.28.2")(name);
    await assert.rejects(
      () => requiredStage2Sources(changed),
      new RegExp(`reviewed source changed: ${file.replace(/[./]/gu, "\\$&")}`),
    );
  }
});

test("the installed fixture dependencies are the pinned versions, and a missing or other one is refused", async () => {
  const installed =
    (overrides = {}) =>
    async (file) => {
      const packages = {
        "fixtures/node_modules/firebase-functions/package.json": {
          name: "firebase-functions",
          version: "7.3.2",
        },
        "fixtures/node_modules/firebase-admin/package.json": {
          name: "firebase-admin",
          version: "14.3.0",
        },
        ...overrides,
      };
      if (!(file in packages) || packages[file] === null) throw new Error("ENOENT");
      return Buffer.from(JSON.stringify(packages[file]));
    };
  await assert.doesNotReject(() => requiredInstalledDependencies(installed()));
  await assert.rejects(
    () =>
      requiredInstalledDependencies(
        installed({ "fixtures/node_modules/firebase-functions/package.json": null }),
      ),
    /firebase-functions is not installed/,
  );
  await assert.rejects(
    () =>
      requiredInstalledDependencies(
        installed({
          "fixtures/node_modules/firebase-admin/package.json": {
            name: "firebase-admin",
            version: "14.3.1",
          },
        }),
      ),
    /firebase-admin 14\.3\.0 is required/,
  );
  await assert.rejects(
    () =>
      requiredInstalledDependencies(
        installed({
          "fixtures/node_modules/firebase-functions/package.json": {
            name: "other",
            version: "7.3.2",
          },
        }),
      ),
    /firebase-functions 7\.3\.2 is required/,
  );
});
