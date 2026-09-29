// The command line of the lean recorder: which environment it needs, how it builds the packet and
// review records the approval check reads, and what it prints and exits with. The recorder itself
// is replaced by a fake, so nothing here sends anything.

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  mainRepositoryRoot,
  pinnedPaths,
  pinsCommand,
  probeCommand,
  probeRequiredEnvironment,
  recordCommand,
  requiredEnvironment,
} from "./storage-object/record-cli.mjs";

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
  // The main checkout the recorder resolves its ledger, owner ledger and locks from.
  mkdirSync(join(dir, "docs.local", "runs"), { recursive: true });
  mkdirSync(join(dir, "docs.local", "instructions"), { recursive: true });
  const ledger = join(dir, "docs.local", "runs", "sandbox-ledger.jsonl");
  writeFileSync(ledger, "", { mode: 0o600 });
  writeFileSync(join(dir, "docs.local", "instructions", "owner-decisions.md"), "approval text\n", {
    mode: 0o600,
  });
  const env = {
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
    mainCheckout: () => dir,
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

test("the environment a recording needs is exactly these four names, and no path of the ledger or the lock", () => {
  assert.deepEqual(
    [...requiredEnvironment],
    [
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
    maxRequests: 6004,
    reserveUsd: 1,
    packetSha256: packetFile.packetSha256,
    sourceCommit: COMMIT,
    ...pinValues,
  });
  assert.deepEqual(options.review, reviewFile);
  assert.deepEqual(options.actualPins, pinValues);
  assert.equal(options.ownerDecisionsText, "approval text\n");
  assert.equal(options.apiKey, "AIzaSyD-synthetic-web-api-key-value-000000");
  assert.equal(options.locks.lockDir, join(f.dir, "docs.local", "runs", "sandbox-locks"));
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

test("the ledger, the owner ledger and the locks are pinned to the main checkout, and the environment cannot move them", async () => {
  const f = fixture({
    env: {
      FIREEMU_STORAGE_OBJECT_LOCK_DIR: "/somewhere/locks",
      FIREEMU_SANDBOX_LEDGER: "/somewhere/ledger.jsonl",
      FIREEMU_OWNER_DECISIONS: "/somewhere/owner.md",
    },
  });
  await recordCommand(["1"], f.env, f.deps);
  const paths = pinnedPaths(f.dir);
  assert.equal(f.received().locks.lockDir, paths.lockDir);
  assert.equal(f.received().locks.legacyLockPath, paths.legacyLock);
  assert.equal(await f.received().ledger.read(), "");
  assert.equal(f.received().ownerDecisionsText, "approval text\n");
});

test("the pinned paths are under docs.local of the checkout", () => {
  assert.deepEqual(pinnedPaths("/main"), {
    ledger: "/main/docs.local/runs/sandbox-ledger.jsonl",
    legacyLock: "/main/docs.local/runs/sandbox-ledger.jsonl.lock",
    lockDir: "/main/docs.local/runs/sandbox-locks",
    ownerLedger: "/main/docs.local/instructions/owner-decisions.md",
  });
});

test("the main checkout is found through a linked worktree, and a directory in no repository refuses", () => {
  const base = mkdtempSync(join(tmpdir(), "storage-object-root-"));
  const main = join(base, "main");
  mkdirSync(main);
  const git = (...args) => execFileSync("git", args, { cwd: main, stdio: "ignore" });
  git("init", "-q");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  git("config", "commit.gpgsign", "false");
  writeFileSync(join(main, "a.txt"), "a");
  git("add", ".");
  git("commit", "-q", "-m", "init");
  const linked = join(main, ".worktree", "linked");
  git("worktree", "add", "-q", linked);
  mkdirSync(join(linked, "conformance", "src"), { recursive: true });
  assert.equal(mainRepositoryRoot(join(linked, "conformance", "src")), main);
  assert.equal(mainRepositoryRoot(join(main, "sub", "..")), main);
  const outside = mkdtempSync(join(tmpdir(), "storage-object-none-"));
  assert.throws(() => mainRepositoryRoot(outside), /main repository root not found/);
});

test("the owner ledger must be a regular file of this user that nobody else can write", async () => {
  const cases = [
    ["a group-writable file", (path) => chmodSync(path, 0o664)],
    ["a world-writable file", (path) => chmodSync(path, 0o666)],
  ];
  for (const [label, change] of cases) {
    const f = fixture();
    change(join(f.dir, "docs.local", "instructions", "owner-decisions.md"));
    assert.equal(await recordCommand(["1"], f.env, f.deps), 2, label);
    assert.match(f.err.join(""), /owner ledger refused/);
    assert.equal(f.received(), undefined);
  }
  const link = fixture();
  const real = join(link.dir, "elsewhere.md");
  writeFileSync(real, "approval text\n", { mode: 0o600 });
  const path = join(link.dir, "docs.local", "instructions", "owner-decisions.md");
  execFileSync("rm", [path]);
  symlinkSync(real, path);
  assert.equal(await recordCommand(["1"], link.env, link.deps), 2);
  assert.match(link.err.join(""), /owner ledger refused/);
  const missing = fixture();
  execFileSync("rm", [join(missing.dir, "docs.local", "instructions", "owner-decisions.md")]);
  assert.equal(await recordCommand(["1"], missing.env, missing.deps), 2);
  assert.match(missing.err.join(""), /owner ledger refused/);
  const notUtf8 = fixture();
  writeFileSync(
    join(notUtf8.dir, "docs.local", "instructions", "owner-decisions.md"),
    Buffer.from([0xff, 0xfe, 0x41]),
    { mode: 0o600 },
  );
  assert.equal(await recordCommand(["1"], notUtf8.env, notUtf8.deps), 2);
});

test("an error other than a missing .git while looking for the main checkout is not swallowed", () => {
  const base = mkdtempSync(join(tmpdir(), "storage-object-notdir-"));
  writeFileSync(join(base, "afile"), "x");
  // A path below a regular file cannot be read as a directory: ENOTDIR, not ENOENT.
  assert.throws(() => mainRepositoryRoot(join(base, "afile", "below")), /ENOTDIR/);
});

test("an owner ledger that only another user can write, or that is over the size cap, is refused", async () => {
  for (const [label, prepare] of [
    ["other-writable only", (path) => chmodSync(path, 0o602)],
    ["group-writable only", (path) => chmodSync(path, 0o620)],
    [
      "over 8 MiB",
      (path) => writeFileSync(path, Buffer.alloc(8 * 1024 * 1024 + 1, 0x61), { mode: 0o600 }),
    ],
  ]) {
    const f = fixture();
    prepare(join(f.dir, "docs.local", "instructions", "owner-decisions.md"));
    assert.equal(await recordCommand(["1"], f.env, f.deps), 2, label);
    assert.match(f.err.join(""), /owner ledger refused/, label);
  }
  const exact = fixture();
  writeFileSync(
    join(exact.dir, "docs.local", "instructions", "owner-decisions.md"),
    Buffer.alloc(8 * 1024 * 1024, 0x61),
    { mode: 0o600 },
  );
  assert.equal(await recordCommand(["1"], exact.env, exact.deps), 0, "exactly the cap is allowed");
});

test("a run that had started and then failed exits 4, prints its message once, and no stack", async () => {
  const f = fixture({
    recordRun: async () => {
      const error = new Error("aggregate exploded");
      error.afterStart = true;
      throw error;
    },
  });
  assert.equal(await recordCommand(["1"], f.env, f.deps), 4);
  assert.equal(f.err.join(""), "aggregate exploded\n");
  assert.equal(f.out.join(""), "");
  const g = fixture({
    recordRun: async () => {
      throw new Error("refused");
    },
  });
  assert.equal(await recordCommand(["1"], g.env, g.deps), 2);
  assert.doesNotMatch(g.err.join(""), /\n\s+at /);
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

// ---- probe-production ----------------------------------------------------------------------------

function probeFixture(overrides = {}) {
  let received;
  const f = fixture({
    ...overrides,
    packet: overrides.packet ?? { ...packetFile, packetName: "probe-v1" },
  });
  f.deps.probeRun =
    overrides.probeRun ??
    (async (options) => {
      received = options;
      return { outcome: "recorded", requests: 9, answers: [{ id: "a", status: 404 }] };
    });
  return { ...f, probeReceived: () => received };
}

test("the probe needs three names of the environment: no key file", () => {
  assert.deepEqual(
    [...probeRequiredEnvironment],
    [
      "FIREEMU_STORAGE_OBJECT_PACKET",
      "FIREEMU_STORAGE_OBJECT_REVIEW",
      "FIREEMU_STORAGE_OBJECT_PRIVATE_DIR",
    ],
  );
});

test("the probe names the environment it lacks, takes no argument, and calls nothing then", async () => {
  for (const name of probeRequiredEnvironment) {
    const f = probeFixture({ env: { [name]: undefined } });
    assert.equal(await probeCommand([], f.env, f.deps), 2, name);
    assert.match(f.err.join(""), new RegExp(name));
    assert.equal(f.probeReceived(), undefined);
  }
  const f = probeFixture();
  assert.equal(await probeCommand(["1"], f.env, f.deps), 2);
  assert.match(f.err.join(""), /no argument/);
  assert.equal(f.probeReceived(), undefined);
});

test("the probe gets its own limits, the packet, the review, the pinned paths and no key", async () => {
  const f = probeFixture({ env: { FIREEMU_STORAGE_OBJECT_AUTH_KEY_FILE: "/does/not/exist" } });
  assert.equal(await probeCommand([], f.env, f.deps), 0);
  const options = f.probeReceived();
  assert.deepEqual(options.packet, {
    taskId: "STORAGE-OBJECT",
    packetName: "probe-v1",
    projectId: "fireemu-oracle-query",
    maxRequests: 17,
    reserveUsd: 0.05,
    packetSha256: packetFile.packetSha256,
    sourceCommit: COMMIT,
    ...pinValues,
  });
  assert.deepEqual(options.review, reviewFile);
  assert.deepEqual(options.actualPins, pinValues);
  assert.equal(options.ownerDecisionsText, "approval text\n");
  assert.equal(options.locks.lockDir, join(f.dir, "docs.local", "runs", "sandbox-locks"));
  assert.equal(options.locks.legacyLockPath, `${f.ledger}.lock`);
  assert.equal(await options.getToken(), "ya29.synthetic-owner-access-token-value");
  assert.deepEqual(options.ids, {
    runId: "0123456789abcdef0123",
    otherRunId: "fedcba9876543210fedc",
  });
  for (const name of ["ledger", "git", "admission", "privateRun", "fetch", "now"]) {
    assert.ok(options[name], name);
  }
  for (const name of ["apiKey", "replay", "recording"]) {
    assert.equal(name in options, false, name);
  }
});

test("the probe's exit code and its one line of output follow the outcome", async () => {
  const f = probeFixture();
  assert.equal(await probeCommand([], f.env, f.deps), 0);
  assert.deepEqual(JSON.parse(f.out.join("")), {
    outcome: "recorded",
    requests: 9,
    runId: "0123456789abcdef0123",
    answers: [{ id: "a", status: 404 }],
  });
  const g = probeFixture({ probeRun: async () => ({ outcome: "something-new", requests: 3 }) });
  assert.equal(await probeCommand([], g.env, g.deps), 4);
});

test("a probe that had started and then failed exits 4, and a refusal exits 2, with no stack", async () => {
  const f = probeFixture({
    probeRun: async () => {
      const error = new Error("fetch failed");
      error.afterStart = true;
      throw error;
    },
  });
  assert.equal(await probeCommand([], f.env, f.deps), 4);
  assert.equal(f.err.join(""), "fetch failed\n");
  assert.equal(f.out.join(""), "");
  const g = probeFixture({
    probeRun: async () => {
      throw new Error("ledger admission: another lane is open");
    },
  });
  assert.equal(await probeCommand([], g.env, g.deps), 2);
  assert.match(g.err.join(""), /ledger admission/);
  assert.doesNotMatch(g.err.join(""), /\n\s+at /);
});

test("a probe packet file holds exactly the name and the pins", async () => {
  const f = probeFixture({ packet: { ...packetFile, packetName: "probe-v1", extra: "x" } });
  assert.equal(await probeCommand([], f.env, f.deps), 2);
  assert.match(f.err.join(""), /packet file must hold exactly/);
  assert.equal(f.probeReceived(), undefined);
});
