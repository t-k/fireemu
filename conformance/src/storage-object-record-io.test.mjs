// The real files behind the lean recorder: the private run directory, the ledger file, the git
// state and the pins. Each test works in a temporary directory.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  computePins,
  createLedgerFile,
  createPrivateRunFactory,
  readGitState,
} from "./storage-object/record-io.mjs";

const RUN = "0123456789abcdef0123";
const tmp = () => mkdtempSync(join(tmpdir(), "storage-object-io-"));
const mode = (path) => statSync(path).mode & 0o777;

function ignoredRepo() {
  const repo = tmp();
  execFileSync("git", ["init", "-q"], { cwd: repo });
  execFileSync("git", ["config", "user.email", "t@example.com"], { cwd: repo });
  execFileSync("git", ["config", "user.name", "t"], { cwd: repo });
  execFileSync("git", ["config", "commit.gpgsign", "false"], { cwd: repo });
  writeFileSync(join(repo, ".gitignore"), "private/\n");
  writeFileSync(join(repo, "a.txt"), "a\n");
  execFileSync("git", ["add", "."], { cwd: repo });
  execFileSync("git", ["commit", "-q", "-m", "init"], { cwd: repo });
  return repo;
}

// ---- private run --------------------------------------------------------------------------------

test("a private run is a new 0700 directory whose files are 0600 JSON lines", async () => {
  const repo = ignoredRepo();
  const root = join(repo, "private");
  const open = createPrivateRunFactory({ root });
  const run = await open(RUN);
  assert.equal(run.dir, join(root, `storage-object-${RUN}`));
  assert.equal(mode(run.dir), 0o700);
  await run.capture({ sequence: 1, a: "x" });
  await run.capture({ sequence: 2, a: "y" });
  await run.event({ type: "started" });
  await run.meta({ runId: RUN, outcome: "recorded" });
  assert.equal(mode(join(run.dir, "captures.jsonl")), 0o600);
  assert.equal(mode(join(run.dir, "events.jsonl")), 0o600);
  assert.equal(mode(join(run.dir, "meta.json")), 0o600);
  const captures = readFileSync(join(run.dir, "captures.jsonl"), "utf8").trimEnd().split("\n");
  assert.deepEqual(
    captures.map((line) => JSON.parse(line).sequence),
    [1, 2],
  );
  assert.deepEqual(JSON.parse(readFileSync(join(run.dir, "meta.json"), "utf8")), {
    runId: RUN,
    outcome: "recorded",
  });
});

test("a private run refuses an existing run directory", async () => {
  const repo = ignoredRepo();
  const root = join(repo, "private");
  const open = createPrivateRunFactory({ root });
  await open(RUN);
  await assert.rejects(open(RUN));
});

test("a private root inside a repository must be ignored by git", async () => {
  const repo = ignoredRepo();
  const root = join(repo, "tracked-dir");
  await assert.rejects(createPrivateRunFactory({ root })(RUN), /ignored/);
  assert.equal(existsSync(join(root, `storage-object-${RUN}`)), false);
});

test("a private root outside any repository is accepted", async () => {
  const run = await createPrivateRunFactory({ root: join(tmp(), "private") })(RUN);
  assert.equal(mode(run.dir), 0o700);
});

test("a private root that is a symbolic link, or too open, is refused", async () => {
  const base = tmp();
  const real = join(base, "real");
  mkdirSync(real, { mode: 0o700 });
  const { symlinkSync, chmodSync } = await import("node:fs");
  symlinkSync(real, join(base, "link"));
  await assert.rejects(
    createPrivateRunFactory({ root: join(base, "link") })(RUN),
    /real directory/,
  );
  const open = join(base, "open");
  mkdirSync(open, { mode: 0o755 });
  chmodSync(open, 0o755);
  await assert.rejects(createPrivateRunFactory({ root: open })(RUN), /mode/);
  const group = join(base, "group");
  mkdirSync(group, { mode: 0o750 });
  chmodSync(group, 0o750);
  await assert.rejects(createPrivateRunFactory({ root: group })(RUN), /mode/);
  const filePath = join(base, "afile");
  writeFileSync(filePath, "x");
  await assert.rejects(createPrivateRunFactory({ root: filePath })(RUN));
});

test("a run ID that is not 20 hex characters is refused", async () => {
  await assert.rejects(createPrivateRunFactory({ root: join(tmp(), "p") })("../escape"), /run ID/);
});

test("a capture that cannot be serialised stops the writer instead of writing part of a line", async () => {
  const run = await createPrivateRunFactory({ root: join(tmp(), "p") })(RUN);
  const circular = {};
  circular.self = circular;
  await assert.rejects(run.capture(circular));
  await run.capture({ ok: true });
  const lines = readFileSync(join(run.dir, "captures.jsonl"), "utf8").trimEnd().split("\n");
  assert.deepEqual(
    lines.map((line) => JSON.parse(line)),
    [{ ok: true }],
  );
});

test("run IDs of the wrong length or alphabet are refused", async () => {
  const open = createPrivateRunFactory({ root: join(tmp(), "p") });
  for (const id of [
    "abc",
    "0123456789abcdef012",
    "0123456789abcdef01234",
    "0123456789ABCDEF0123",
    "",
    undefined,
    null,
  ]) {
    await assert.rejects(open(id), /run ID/, String(id));
  }
});

test("every private and ledger record is made durable before the call returns", async () => {
  const { open: openFile } = await import("node:fs/promises");
  const probe = await openFile(join(tmp(), "probe"), "w");
  const proto = Object.getPrototypeOf(probe);
  await probe.close();
  const realSync = proto.sync;
  let syncs = 0;
  proto.sync = function (...args) {
    syncs++;
    return realSync.apply(this, args);
  };
  try {
    const run = await createPrivateRunFactory({ root: join(tmp(), "p") })(RUN);
    await run.capture({ a: 1 });
    assert.equal(syncs, 1);
    await run.event({ a: 1 });
    assert.equal(syncs, 2);
    await run.meta({ a: 1 });
    assert.equal(syncs, 3);
    const path = join(tmp(), "ledger.jsonl");
    writeFileSync(path, "");
    await createLedgerFile(path).append({ a: 1 });
    assert.equal(syncs, 4);
  } finally {
    proto.sync = realSync;
  }
});

test("a short write is an error, never a half line accepted as written", async () => {
  const { open: openFile } = await import("node:fs/promises");
  const probe = await openFile(join(tmp(), "probe"), "w");
  const proto = Object.getPrototypeOf(probe);
  await probe.close();
  const realWrite = proto.write;
  const path = join(tmp(), "ledger.jsonl");
  writeFileSync(path, "");
  const run = await createPrivateRunFactory({ root: join(tmp(), "p") })(RUN);
  proto.write = async () => ({ bytesWritten: 1 });
  try {
    await assert.rejects(run.capture({ a: 1 }), /incomplete/);
    await assert.rejects(createLedgerFile(path).append({ a: 1 }), /incomplete/);
  } finally {
    proto.write = realWrite;
  }
});

test("the pins are the documented digests of the fixed-ID plan, corpus and Rules source", async () => {
  const { createHash } = await import("node:crypto");
  const { buildStage3DraftPlan } = await import("./storage-object/stage3-plan.mjs");
  const { FIXED_PRODUCTION_RULES_SHA256 } = await import("./storage-object/auth-plan.mjs");
  const dir = tmp();
  writeFileSync(join(dir, "a.mjs"), "x\n");
  const plan = buildStage3DraftPlan({
    projectId: "fireemu-oracle-query",
    bucket: "fireemu-oracle-query.firebasestorage.app",
    runIds: ["0".repeat(20), "1".repeat(20)],
  });
  const sha = (text) => createHash("sha256").update(text).digest("hex");
  const pins = await computePins({ sourceDir: dir });
  assert.equal(pins.planSha256, sha(JSON.stringify(plan)));
  assert.equal(
    pins.corpusSha256,
    sha(`${plan.recordings[0].corpusDigest}:${plan.recordings[0].authCorpusDigest}`),
  );
  assert.equal(pins.rulesSourceSha256, FIXED_PRODUCTION_RULES_SHA256);
  assert.equal(pins.runnerSha256, sha(JSON.stringify([{ file: "a.mjs", sha256: sha("x\n") }])));
});

test("the summary file is replaced whole by a later summary", async () => {
  const run = await createPrivateRunFactory({ root: join(tmp(), "p") })(RUN);
  await run.meta({ text: "a much longer first summary than the second one", n: 1 });
  await run.meta({ n: 2 });
  assert.deepEqual(JSON.parse(readFileSync(join(run.dir, "meta.json"), "utf8")), { n: 2 });
});

test("a link planted in the run directory is not followed", async () => {
  const { symlinkSync } = await import("node:fs");
  const outside = join(tmp(), "outside.txt");
  writeFileSync(outside, "");
  for (const [name, write] of [
    ["captures.jsonl", (run) => run.capture({ a: 1 })],
    ["events.jsonl", (run) => run.event({ a: 1 })],
    ["meta.json", (run) => run.meta({ a: 1 })],
  ]) {
    const run = await createPrivateRunFactory({ root: join(tmp(), "p") })(RUN);
    symlinkSync(outside, join(run.dir, name));
    await assert.rejects(write(run), name);
  }
  assert.equal(readFileSync(outside, "utf8"), "");
});

// ---- ledger file -------------------------------------------------------------------------------------

test("the ledger file appends whole lines and reads the whole text", async () => {
  const dir = tmp();
  const path = join(dir, "sandbox-ledger.jsonl");
  writeFileSync(path, '{"a":1}\n', { mode: 0o600 });
  const ledger = createLedgerFile(path);
  await ledger.append({ b: 2 });
  await ledger.append({ c: 3 });
  assert.equal(await ledger.read(), '{"a":1}\n{"b":2}\n{"c":3}\n');
  assert.equal(mode(path), 0o600);
});

test("the ledger file is not created, and a missing file reads as empty", async () => {
  const dir = tmp();
  const ledger = createLedgerFile(join(dir, "missing.jsonl"));
  assert.equal(await ledger.read(), "");
  await assert.rejects(ledger.append({ a: 1 }));
  assert.equal(existsSync(join(dir, "missing.jsonl")), false);
});

test("the ledger file refuses a symbolic link", async () => {
  const dir = tmp();
  writeFileSync(join(dir, "real.jsonl"), "");
  const { symlinkSync } = await import("node:fs");
  symlinkSync(join(dir, "real.jsonl"), join(dir, "link.jsonl"));
  await assert.rejects(createLedgerFile(join(dir, "link.jsonl")).append({ a: 1 }));
});

// ---- git ---------------------------------------------------------------------------------------------

test("the git state reports a clean tree and the commit, and a dirty tree", async () => {
  const repo = ignoredRepo();
  const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8" }).trim();
  assert.deepEqual(await readGitState(repo), { clean: true, commit: head });
  writeFileSync(join(repo, "a.txt"), "changed\n");
  assert.deepEqual(await readGitState(repo), { clean: false, commit: head });
  writeFileSync(join(repo, "a.txt"), "a\n");
  writeFileSync(join(repo, "untracked.txt"), "x\n");
  assert.equal((await readGitState(repo)).clean, false);
});

test("an ignored file does not make the tree dirty", async () => {
  const repo = ignoredRepo();
  mkdirSync(join(repo, "private"));
  writeFileSync(join(repo, "private", "x"), "x");
  assert.equal((await readGitState(repo)).clean, true);
});

// ---- pins --------------------------------------------------------------------------------------------

test("the pins are the digests of the sources, the plan shape, the corpus and the Rules", async () => {
  const dir = tmp();
  writeFileSync(join(dir, "a.mjs"), "export const a = 1;\n");
  writeFileSync(join(dir, "b.mjs"), "export const b = 2;\n");
  writeFileSync(join(dir, "notes.md"), "not a source");
  const pins = await computePins({ sourceDir: dir });
  for (const key of ["runnerSha256", "planSha256", "corpusSha256", "rulesSourceSha256"]) {
    assert.match(pins[key], /^[0-9a-f]{64}$/, key);
  }
  assert.deepEqual(
    pins.files.map((row) => row.file),
    ["a.mjs", "b.mjs"],
  );
  assert.deepEqual(await computePins({ sourceDir: dir }), pins);
  writeFileSync(join(dir, "b.mjs"), "export const b = 3;\n");
  const changed = await computePins({ sourceDir: dir });
  assert.notEqual(changed.runnerSha256, pins.runnerSha256);
  assert.equal(
    changed.planSha256,
    pins.planSha256,
    "the plan shape does not depend on the sources",
  );
  assert.equal(changed.corpusSha256, pins.corpusSha256);
});

test("the plan and corpus pins do not depend on the run IDs of a run", async () => {
  const dir = tmp();
  writeFileSync(join(dir, "a.mjs"), "x\n");
  const a = await computePins({ sourceDir: dir });
  const b = await computePins({ sourceDir: dir });
  assert.equal(a.planSha256, b.planSha256);
  assert.equal(a.corpusSha256, b.corpusSha256);
});
