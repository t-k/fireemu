import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { PRINCIPALS, PROGRAMS, validateCorpus } from "./auth-fs-cross/corpus.mjs";
import { markerOf, rulesetSource } from "./auth-fs-cross/rulesets.mjs";
import { PROGRAMS as FS_RULES_PROGRAMS } from "./fs-rules/corpus.mjs";
import {
  harnessDigest as fsRulesHarness,
  programDigest as fsRulesProgram,
} from "./fs-rules/run.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const read = (path) => readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

test("the AUTH-FS-CROSS harness leaves every FS-RULES row current", async () => {
  // FS-RULES rows are bound to its harness digest and to digests of its programs and rulesets;
  // this lane copies and imports, and must never make one stale.
  const fixtureText = read("../fs-rules-production.json");
  const fixture = JSON.parse(fixtureText);
  const harness = await fsRulesHarness();
  for (const program of FS_RULES_PROGRAMS) {
    const saved = fixture.programs[program.id];
    assert.ok(saved, program.id);
    assert.equal(saved.harnessDigest, harness, `${program.id}: harness digest`);
    assert.equal(saved.corpusDigest, fsRulesProgram(program), `${program.id}: program digest`);
  }
  const comparison = JSON.parse(
    read("../../spec/compatibility/closure/evidence/FS-RULES-comparison.json"),
  );
  assert.equal(comparison.fixtureSha256, sha256(fixtureText), "the FS-RULES fixture is unchanged");
});

test("the copied session and runner name the FS-RULES file they were copied from", () => {
  // A change to either FS-RULES file must be looked at here too: re-copy the change or record
  // why it does not apply, then update the pinned SHA.
  for (const [copy, source] of [
    ["./auth-fs-cross/session.mjs", "./fs-rules/session.mjs"],
    ["./auth-fs-cross/run.mjs", "./fs-rules/run.mjs"],
  ]) {
    const pinned = /file SHA-256\n\/\/ ([0-9a-f]{64})/.exec(read(copy))?.[1];
    assert.ok(pinned, `${copy} names its source SHA`);
    assert.equal(sha256(read(source)), pinned, `${source} changed since ${copy} was copied`);
  }
});

test("the stage-1 corpus is valid and within its cap", () => {
  assert.equal(validateCorpus(PROGRAMS), 89);
  assert.deepEqual(
    PROGRAMS.map(({ id }) => id),
    [
      "auth-fs-cross/tenant-same-uid/separation",
      "auth-fs-cross/read-only-transaction/binding",
      "auth-fs-cross/foreign-project/token",
      "auth-fs-cross/tenant-same-uid/deleted-tenant",
    ],
  );
  const same = Object.entries(PRINCIPALS).filter(([, spec]) => spec.sameUid);
  assert.deepEqual(
    same.map(([, spec]) => spec.tenant ?? null),
    [null, "t1", "t2"],
    "one local id in the project and in both tenants",
  );
});

test("the corpus guard refuses what the lane may not do", () => {
  const program = (steps, extra = {}) => ({
    id: "auth-fs-cross/x/y",
    ruleset: "cross",
    steps,
    ...extra,
  });
  const get = (as, doc) => ({ id: `g-${as}-${doc}`, as, rpc: "get", doc });
  const cases = [
    [[program([get("owner", "fsr-open/d")])], /this lane's/],
    [[program([get("owner", "/afc-open/d")])], /relative|this lane's/],
    [[program([get("mallory", "afc-open/d")])], /unknown principal/],
    [[program([{ action: "wipe-everything" }])], /unknown action/],
    [[program([{ action: "delete-tenant", tenant: "t9" }])], /unknown tenant slot/],
    [[program([get("owner", "afc-open/d")], { ruleset: "main" })], /unknown ruleset/],
    [
      [
        program([{ action: "delete-tenant", tenant: "t1" }]),
        { ...program([get("same-t1", "afc-open/d")]), id: "auth-fs-cross/x/z" },
      ],
      /used after its deletion/,
    ],
  ];
  for (const [programs, pattern] of cases) assert.throws(() => validateCorpus(programs), pattern);
  assert.throws(
    () => validateCorpus([], { a: { provider: "password", sameUid: true } }),
    /only the administrator/,
  );
  assert.throws(() => validateCorpus([], { a: { provider: "custom" } }), /unknown provider/);
});

test("the lane's ruleset carries its own marker and tells tenants apart", () => {
  const source = rulesetSource("cross");
  assert.match(source, new RegExp(`allow get: if label == '${markerOf("cross")}'`));
  assert.match(
    source,
    /request\.auth\.token\.firebase\.get\('tenant', null\) == resource\.data\.tenant/,
  );
  assert.throws(() => rulesetSource("main"), /unknown ruleset/);
});

test("the other project's key file must be private and name the other project", async () => {
  const { writeFileSync, chmodSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { foreignWebConfig, FOREIGN_PROJECT } = await import("./auth-fs-cross/run.mjs");
  const dir = tempDir("afc-foreign-");
  const project = join(dir, "project.json");
  const key = join(dir, "key.json");
  const write = (path, value, mode = 0o600) => {
    writeFileSync(path, JSON.stringify(value));
    chmodSync(path, mode);
  };
  const saved = { ...process.env };
  try {
    process.env.FIREEMU_AUTH_FOREIGN_PROJECT_FILE = project;
    process.env.FIREEMU_AUTH_FOREIGN_KEY_FILE = key;
    write(project, { projectId: FOREIGN_PROJECT, projectNumber: "1234567" });
    write(key, { keyString: "k".repeat(39) });
    assert.deepEqual(await foreignWebConfig(), {
      projectId: FOREIGN_PROJECT,
      projectNumber: "1234567",
      apiKey: "k".repeat(39),
    });
    write(key, { keyString: "k".repeat(39) }, 0o644);
    await assert.rejects(foreignWebConfig(), /readable by others/);
    write(key, { keyString: "short" });
    await assert.rejects(foreignWebConfig(), /has no key/);
    write(key, { keyString: "k".repeat(39) });
    write(project, { projectId: "fireemu-oracle-idp", projectNumber: "1234567" });
    await assert.rejects(foreignWebConfig(), /is not fireemu-oracle-query/);
  } finally {
    process.env = saved;
  }
});
