// The identity of the fireemu binary a local event run executed: hashed from the file by run.mjs, carried to the sessions by
// the environment, written into each session.json, and checked against the artifact the comparison names.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  checkSessionIdentities,
  identityEnv,
  identityFromEnv,
  identityOf,
} from "./functions-events/binary-identity.mjs";

const HEX64 = "a".repeat(64);
const COMMIT = "c".repeat(40);
const TREE = "7".repeat(40);
const RUNNER = {
  runnerPath: "/repo/tools/runner-node/index.mjs",
  runnerSha256: "9".repeat(64),
  runnerTree: TREE,
};

test("the identity of a binary is the sha256 of the file it was read from, the harness commit, the tree state and the runner", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fe-identity-"));
  try {
    const binary = join(dir, "fireemu");
    await writeFile(binary, "fake binary bytes");
    // the harness checkout: its runner is a file of its own, committed as the git tree TREE
    const repo = join(dir, "repo");
    await mkdir(join(repo, "tools/runner-node"), { recursive: true });
    await writeFile(join(repo, "tools/runner-node/index.mjs"), "runner bytes");
    const gitWith = (status) => (args) => {
      if (args[0] === "rev-parse" && args[1] === "HEAD") return `${COMMIT}\n`;
      if (args[0] === "rev-parse") return `${TREE}\n`;
      return status;
    };
    const identity = identityOf({ binary, repoRoot: repo, git: gitWith("") });
    assert.deepEqual(identity, {
      binarySha256: createHash("sha256").update("fake binary bytes").digest("hex"),
      sourceCommit: COMMIT,
      dirty: false,
      runnerPath: join(repo, "tools/runner-node/index.mjs"),
      runnerSha256: createHash("sha256").update("runner bytes").digest("hex"),
      runnerTree: TREE,
    });
    assert.equal(identityOf({ binary, repoRoot: repo, git: gitWith(" M a.txt\n") }).dirty, true);
    assert.throws(
      () => identityOf({ binary: join(dir, "missing"), repoRoot: repo, git: gitWith("") }),
      /ENOENT/,
    );
    assert.throws(
      () => identityOf({ binary, repoRoot: join(dir, "no-repo"), git: gitWith("") }),
      /ENOENT/,
    );
    assert.throws(
      () => identityOf({ binary, repoRoot: repo, git: () => "not a commit\n" }),
      /source commit/,
    );
    assert.throws(
      () =>
        identityOf({
          binary,
          repoRoot: repo,
          git: (args) => (args[1] === "HEAD" ? `${COMMIT}\n` : "nope\n"),
        }),
      /runner tree/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the identity travels by the environment and is read back whole or refused", () => {
  const identity = { binarySha256: HEX64, sourceCommit: COMMIT, dirty: false, ...RUNNER };
  const env = identityEnv(identity);
  assert.deepEqual(identityFromEnv(env), identity);
  assert.deepEqual(identityFromEnv({ ...env, FE_EVENTS_TREE_DIRTY: "1" }).dirty, true);
  for (const name of Object.keys(env)) {
    const missing = { ...env };
    delete missing[name];
    assert.throws(() => identityFromEnv(missing), /binary identity/, name);
  }
  assert.throws(
    () => identityFromEnv({ ...env, FE_EVENTS_BINARY_SHA256: "A".repeat(64) }),
    /binary identity/,
  );
  assert.throws(
    () => identityFromEnv({ ...env, FE_EVENTS_BINARY_SHA256: "a".repeat(63) }),
    /binary identity/,
  );
  assert.throws(
    () => identityFromEnv({ ...env, FE_EVENTS_SOURCE_COMMIT: "c".repeat(39) }),
    /binary identity/,
  );
  assert.throws(() => identityFromEnv({ ...env, FE_EVENTS_TREE_DIRTY: "yes" }), /binary identity/);
  assert.throws(() => identityFromEnv({ ...env, FE_EVENTS_RUNNER_SHA256: "x" }), /binary identity/);
  assert.throws(() => identityFromEnv({ ...env, FE_EVENTS_RUNNER_TREE: "x" }), /binary identity/);
  assert.throws(
    () => identityFromEnv({ ...env, FE_EVENTS_RUNNER_PATH: "relative/index.mjs" }),
    /binary identity/,
  );
});

const session = (fireemu) => ({ schemaVersion: 1, ...(fireemu === undefined ? {} : { fireemu }) });
const good = { binarySha256: HEX64, sourceCommit: COMMIT, dirty: false, ...RUNNER };

test("both sessions must name the same binary, and it must be the artifact", () => {
  assert.deepEqual(
    checkSessionIdentities({ emulator: session(good), strict: session({ ...good }) }, HEX64),
    { sha256: HEX64, sourceCommit: COMMIT, dirty: false, ...RUNNER },
  );
  const refuse = (sessions, artifact, pattern) =>
    assert.throws(() => checkSessionIdentities(sessions, artifact), pattern);
  refuse({ emulator: session(good), strict: session() }, HEX64, /strict session names no binary/);
  refuse({ emulator: session(), strict: session(good) }, HEX64, /emulator session names no binary/);
  refuse(
    { emulator: session({ ...good, binarySha256: "b".repeat(64) }), strict: session(good) },
    HEX64,
    /different binaries/,
  );
  refuse(
    { emulator: session(good), strict: session(good) },
    "b".repeat(64),
    /is not the artifact the comparison names/,
  );
  refuse(
    { emulator: session({ ...good, sourceCommit: "d".repeat(40) }), strict: session(good) },
    HEX64,
    /different harness commits/,
  );
  refuse(
    {
      emulator: session({ ...good, binarySha256: "x" }),
      strict: session({ ...good, binarySha256: "x" }),
    },
    HEX64,
    /binary identity/,
  );
  refuse(
    { emulator: session(good), strict: session({ ...good, dirty: "no" }) },
    HEX64,
    /binary identity/,
  );
  refuse(
    { emulator: session("a string"), strict: session(good) },
    HEX64,
    /emulator session names no binary/,
  );
  // a dirty tree is carried through, so the generator can refuse it
  assert.equal(
    checkSessionIdentities(
      { emulator: session({ ...good, dirty: true }), strict: session({ ...good, dirty: true }) },
      HEX64,
    ).dirty,
    true,
  );
  refuse(
    { emulator: session({ ...good, dirty: true }), strict: session(good) },
    HEX64,
    /different tree states/,
  );
});

test("the two sessions must have run the same runner: its path, its file and its tree, each on its own", () => {
  for (const change of [
    { runnerPath: "/other/tools/runner-node/index.mjs" },
    { runnerSha256: "8".repeat(64) },
    { runnerTree: "6".repeat(40) },
  ])
    assert.throws(
      () =>
        checkSessionIdentities(
          { emulator: session({ ...good, ...change }), strict: session(good) },
          HEX64,
        ),
      /different runners/,
      JSON.stringify(change),
    );
  // each runner field is required in each session
  for (const key of ["runnerPath", "runnerSha256", "runnerTree"]) {
    const without = { ...good };
    delete without[key];
    for (const sessions of [
      { emulator: session(without), strict: session(good) },
      { emulator: session(good), strict: session(without) },
    ])
      assert.throws(() => checkSessionIdentities(sessions, HEX64), /binary identity/, key);
  }
  for (const [key, value] of [
    ["runnerPath", "relative/index.mjs"],
    ["runnerSha256", "z".repeat(64)],
    ["runnerTree", "z".repeat(40)],
  ])
    assert.throws(
      () =>
        checkSessionIdentities(
          {
            emulator: session({ ...good, [key]: value }),
            strict: session({ ...good, [key]: value }),
          },
          HEX64,
        ),
      /binary identity/,
      key,
    );
});
