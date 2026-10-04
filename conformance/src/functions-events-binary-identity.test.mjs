// The identity of the fireemu binary a local event run executed: hashed from the file by run.mjs, carried to the sessions by
// the environment, written into each session.json, and checked against the artifact the comparison names.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
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

test("the identity of a binary is the sha256 of the file it was read from, the harness commit and whether the tree was dirty", async () => {
  const dir = await mkdtemp(join(tmpdir(), "fe-identity-"));
  try {
    const binary = join(dir, "fireemu");
    await writeFile(binary, "fake binary bytes");
    const git = (args) => {
      assert.deepEqual(args.slice(0, 1), args.slice(0, 1));
      return args[0] === "rev-parse" ? `${COMMIT}\n` : "";
    };
    const identity = identityOf({ binary, repoRoot: "/repo", git });
    assert.deepEqual(identity, {
      binarySha256: createHash("sha256").update("fake binary bytes").digest("hex"),
      sourceCommit: COMMIT,
      dirty: false,
    });
    const dirty = identityOf({
      binary,
      repoRoot: "/repo",
      git: (args) => (args[0] === "rev-parse" ? `${COMMIT}\n` : " M a.txt\n"),
    });
    assert.equal(dirty.dirty, true);
    assert.throws(
      () => identityOf({ binary: join(dir, "missing"), repoRoot: "/repo", git }),
      /ENOENT/,
    );
    assert.throws(
      () => identityOf({ binary, repoRoot: "/repo", git: () => "not a commit\n" }),
      /source commit/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the identity travels by the environment and is read back whole or refused", () => {
  const identity = { binarySha256: HEX64, sourceCommit: COMMIT, dirty: false };
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
});

const session = (fireemu) => ({ schemaVersion: 1, ...(fireemu === undefined ? {} : { fireemu }) });
const good = { binarySha256: HEX64, sourceCommit: COMMIT, dirty: false };

test("both sessions must name the same binary, and it must be the artifact", () => {
  assert.deepEqual(
    checkSessionIdentities({ emulator: session(good), strict: session({ ...good }) }, HEX64),
    { sha256: HEX64, sourceCommit: COMMIT, dirty: false },
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
