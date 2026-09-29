// The command line of the lean recorder: which environment it needs, how it builds the packet and
// review records the approval check reads, and what it prints and exits with. The recorder itself
// is replaced by a fake, so nothing here sends anything.

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { recordCommand, pinsCommand, requiredEnvironment } from "./storage-object/record-cli.mjs";

const PINS = ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"];
const COMMIT = "b".repeat(40);
const pinValues = Object.fromEntries(PINS.map((key, index) => [key, `${index + 3}`.repeat(64)]));
const packetFile = {
  packetName: "lean-v1",
  packetSha256: "1".repeat(64),
  sourceCommit: COMMIT,
  ...pinValues,
};
const reviewFile = {
  verdict: "APPROVE",
  must: [],
  should: [],
  packetSha256: packetFile.packetSha256,
  sourceCommit: COMMIT,
  ...pinValues,
  envelopeId: null,
  withinEnvelope: false,
};

function fixture(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), "storage-object-cli-"));
  const write = (name, value) => {
    const path = join(dir, name);
    writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value), { mode: 0o600 });
    return path;
  };
  mkdirSync(join(dir, "private"), { mode: 0o700 });
  const ledger = write("sandbox-ledger.jsonl", "");
  const env = {
    FIREEMU_SANDBOX_LEDGER: ledger,
    FIREEMU_OWNER_DECISIONS: write("owner-decisions.md", "approval text\n"),
    FIREEMU_STORAGE_OBJECT_PACKET: write("packet.json", overrides.packet ?? packetFile),
    FIREEMU_STORAGE_OBJECT_REVIEW: write("review.json", overrides.review ?? reviewFile),
    FIREEMU_STORAGE_OBJECT_PRIVATE_DIR: join(dir, "private"),
    FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE: write(
      "key.json",
      overrides.key ?? { keyString: "AIzaSyD-synthetic-web-api-key-value-000000" },
    ),
    ...overrides.env,
  };
  for (const [name, value] of Object.entries(env)) if (value === undefined) delete env[name];
  const out = [];
  const err = [];
  let received;
  const deps = {
    stdout: (text) => out.push(text),
    stderr: (text) => err.push(text),
    nodeVersion: "v24.14.0",
    pins: async () => ({ ...pinValues, files: [] }),
    git: async () => ({ clean: true, commit: COMMIT }),
    randomRunIds: () => ({ runId: "0123456789abcdef0123", otherRunId: "fedcba9876543210fedc" }),
    now: () => new Date("2026-10-01T09:00:00Z"),
    gcloud: async () => "ya29.synthetic-owner-access-token-value",
    fetch: async () => new Response("{}"),
    recordRun:
      overrides.recordRun ??
      (async (options) => {
        received = options;
        return { outcome: "recorded", requests: 2100 };
      }),
  };
  return { dir, env, deps, out, err, received: () => received, ledger };
}

test("the environment a recording needs is exactly these six names", () => {
  assert.deepEqual(
    [...requiredEnvironment],
    [
      "FIREEMU_SANDBOX_LEDGER",
      "FIREEMU_OWNER_DECISIONS",
      "FIREEMU_STORAGE_OBJECT_PACKET",
      "FIREEMU_STORAGE_OBJECT_REVIEW",
      "FIREEMU_STORAGE_OBJECT_PRIVATE_DIR",
      "FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE",
    ],
  );
});

test("the environment a recording needs is named when any of it is missing", async () => {
  for (const name of requiredEnvironment) {
    const f = fixture({ env: { [name]: undefined } });
    const code = await recordCommand(["1"], f.env, f.deps);
    assert.equal(code, 2, name);
    assert.match(f.err.join(""), new RegExp(name));
    assert.equal(f.received(), undefined, "the recorder is not called");
  }
});

test("the recording number must be 1 or 2", async () => {
  for (const argv of [[], ["0"], ["3"], ["one"], ["1", "2"], ["1.5"]]) {
    const f = fixture();
    assert.equal(await recordCommand(argv, f.env, f.deps), 2, JSON.stringify(argv));
    assert.match(f.err.join(""), /recording/);
    assert.equal(f.received(), undefined);
  }
});

test("a recording with nothing else given refuses before it reads any credential", async () => {
  const f = fixture();
  let asked = 0;
  f.deps.gcloud = async () => {
    asked++;
    return "ya29.synthetic-owner-access-token-value";
  };
  assert.equal(await recordCommand([], {}, f.deps), 2);
  assert.equal(asked, 0);
  assert.doesNotMatch(f.err.join(""), /token|key string|password/i);
});

test("the recorder gets the packet, the review, the paths and the actual pins", async () => {
  const f = fixture();
  f.deps.nodeVersion = "v24.99.0";
  assert.equal(await recordCommand(["2"], f.env, f.deps), 0);
  const options = f.received();
  assert.equal(options.recording, 2);
  assert.deepEqual(options.packet, {
    taskId: "STORAGE-OBJECT",
    packetName: "lean-v1",
    projectId: "fireemu-oracle-query",
    maxRequests: 6000,
    reserveUsd: 1,
    packetSha256: packetFile.packetSha256,
    sourceCommit: COMMIT,
    ...pinValues,
  });
  assert.deepEqual(options.review, reviewFile);
  assert.deepEqual(options.actualPins, pinValues);
  assert.equal(options.ownerDecisionsText, "approval text\n");
  assert.equal(options.apiKey, "AIzaSyD-synthetic-web-api-key-value-000000");
  assert.equal(options.locks.lockDir, join(f.dir, "sandbox-locks"));
  assert.equal(options.locks.legacyLockPath, `${f.ledger}.lock`);
  assert.equal(options.locks.pid, process.pid);
  assert.equal(options.nodeVersion, "v24.99.0");
  assert.deepEqual(options.ids, {
    runId: "0123456789abcdef0123",
    otherRunId: "fedcba9876543210fedc",
  });
  assert.equal(await options.getToken(), "ya29.synthetic-owner-access-token-value");
  for (const name of ["ledger", "git", "admission", "privateRun", "fetch", "replay", "now"]) {
    assert.ok(options[name], name);
  }
});

test("the lock directory can be set explicitly", async () => {
  const f = fixture({ env: { FIREEMU_STORAGE_OBJECT_LOCK_DIR: "/somewhere/locks" } });
  await recordCommand(["1"], f.env, f.deps);
  assert.equal(f.received().locks.lockDir, "/somewhere/locks");
});

test("the packet file holds exactly the name and the pins", async () => {
  for (const packet of [
    { ...packetFile, maxRequests: 9999 },
    { ...packetFile, projectId: "another-project" },
    { ...packetFile, extra: 1 },
    (({ runnerSha256, ...rest }) => ({ ...rest, runnerShaX: runnerSha256 }))(packetFile),
    { ...packetFile, packetSha256: 5 },
    { ...packetFile, sourceCommit: null },
    (({ runnerSha256: _dropped, ...rest }) => rest)(packetFile),
    { ...packetFile, packetName: "Bad Name" },
    "not json",
    [],
  ]) {
    const f = fixture({ packet });
    assert.equal(await recordCommand(["1"], f.env, f.deps), 2, JSON.stringify(packet).slice(0, 50));
    assert.match(f.err.join(""), /packet/);
    assert.equal(f.received(), undefined);
  }
});

test("a key file without a key string is refused without printing the file", async () => {
  for (const key of [
    {},
    { keyString: 5 },
    { keyString: "short" },
    { keyString: ["AIzaSyD-synthetic-web-api-key-value-000000"] },
    "not json",
  ]) {
    const f = fixture({ key });
    assert.equal(await recordCommand(["1"], f.env, f.deps), 2);
    assert.match(f.err.join(""), /key file/);
    assert.equal(f.received(), undefined);
  }
});

test("the exit code and the printed summary follow the outcome, and print no secret", async () => {
  for (const [outcome, code] of [
    ["recorded", 0],
    ["stopped-clean", 3],
    ["needs-recovery", 4],
    ["something-new", 4],
  ]) {
    const f = fixture({ recordRun: async () => ({ outcome, requests: 12 }) });
    assert.equal(await recordCommand(["2"], f.env, f.deps), code, outcome);
    const summary = JSON.parse(f.out.join(""));
    assert.deepEqual(summary, {
      outcome,
      requests: 12,
      recording: 2,
      runId: "0123456789abcdef0123",
    });
  }
});

test("a refusal or a failure prints its message, never a secret, and exits 2", async () => {
  const f = fixture({
    recordRun: async () => {
      throw new Error("ledger admission: another lane is open");
    },
  });
  assert.equal(await recordCommand(["1"], f.env, f.deps), 2);
  assert.match(f.err.join(""), /ledger admission: another lane is open/);
  assert.equal(f.out.join(""), "");
});

test("the pins command reports a dirty tree as dirty", async () => {
  const out = [];
  await pinsCommand({
    stdout: (text) => out.push(text),
    pins: async () => ({ ...pinValues, files: [] }),
    git: async () => ({ clean: false, commit: COMMIT }),
  });
  assert.equal(JSON.parse(out.join("")).treeClean, false);
});

test("the pins command prints the packet's pins and the commit, and nothing secret", async () => {
  const out = [];
  const code = await pinsCommand({
    stdout: (text) => out.push(text),
    pins: async () => ({ ...pinValues, files: [{ file: "a.mjs", sha256: "9".repeat(64) }] }),
    git: async () => ({ clean: true, commit: COMMIT }),
  });
  assert.equal(code, 0);
  assert.deepEqual(JSON.parse(out.join("")), {
    sourceCommit: COMMIT,
    treeClean: true,
    ...pinValues,
    sourceFiles: 1,
  });
});
