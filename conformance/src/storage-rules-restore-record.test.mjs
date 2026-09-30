import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { linkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runRestoreCommand } from "./storage-rules-restore/record.mjs";
import { runRestorePrintPins } from "./storage-rules-restore/print-pins.mjs";
import { restoreCorpus } from "./storage-rules-restore/plan.mjs";
import { parseState } from "./storage-rules-restore/state.mjs";
import { restoreCodeDigests } from "./storage-rules-restore/pins.mjs";
import { STATE, ownerDigest, restoreLocal, scratchCode } from "./storage-rules-restore-support.mjs";

const commit = "a".repeat(40);
const approval = { packet: { taskId: "STORAGE-RULES", sourceCommit: commit, packetName: "stage2e-restore-v9" }, review: { verdict: "APPROVE" } };

async function scratch(t, { text = JSON.stringify(approval), mode = 0o600 } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-restore-record-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "approval.json");
  await writeFile(path, text, { mode });
  await chmod(path, mode);
  return { root, path };
}
function harness(behavior) {
  const calls = [];
  const seen = { out: "", err: "" };
  const entry = async (options) => { calls.push(options); return behavior(options); };
  const run = async (args) => ({ code: await runRestoreCommand({ args, entry, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }), out: seen.out, err: seen.err });
  return { calls, run };
}

test("a finished run prints the status, the request count and whether the lock was released, and hands the entry exactly the closed options", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => ({ status: "finished", changed: false, requests: 39, released: true, secret: "not printed" }));
  const result = await h.run(["/x/local.json", path, "restore-one"]);
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.out), { runId: "restore-one", status: "finished", requests: 39, locksReleased: true });
  assert.equal(result.out.includes("not printed"), false);
  assert.deepEqual(Object.keys(h.calls[0]), ["localPath", "runId", "sourceCommit", "packet", "review"]);
  assert.deepEqual([h.calls[0].localPath, h.calls[0].runId, h.calls[0].sourceCommit, h.calls[0].packet, h.calls[0].review], ["/x/local.json", "restore-one", commit, approval.packet, approval.review]);
  const held = harness(async () => ({ status: "finished", requests: 39, released: false }));
  assert.equal(JSON.parse((await held.run(["/x/local.json", path, "restore-two"])).out).locksReleased, false);
});

test("an entry that refuses or fails ends with exit 3 and the message only, and a stopped run is not a success", async (t) => {
  const { path } = await scratch(t);
  const failed = harness(async () => { throw new Error("outbound attempt failed; project locks retained"); });
  const result = await failed.run(["/x/local.json", path, "restore-three"]);
  assert.equal(result.code, 3);
  assert.deepEqual(JSON.parse(result.out), { runId: "restore-three", status: "not-finished", locksReleased: false });
  assert.match(result.err, /project locks retained/);
  const stopped = harness(async () => ({ status: "stopped", requests: 3, released: false }));
  assert.equal((await stopped.run(["/x/local.json", path, "restore-four"])).code, 3);
});

test("the arguments and the approval file are checked before the entry is reached", async (t) => {
  const { path, root } = await scratch(t);
  for (const args of [[], ["/x/l.json"], ["/x/l.json", path], ["/x/l.json", path, "Bad Id"], ["/x/l.json", path, "ok-run", "extra"], [5, path, "ok-run"], ["/x/l.json", 5, "ok-run"]]) {
    const h = harness(async () => ({}));
    const result = await h.run(args);
    assert.equal(result.code, 2, JSON.stringify(args));
    assert.match(result.err, /usage: node record.mjs <local inputs file> <approval file> <run ID>/);
    assert.equal(result.out, "");
    assert.equal(h.calls.length, 0);
  }
  const link = join(root, "link.json");
  await symlink(path, link);
  const hard = join(root, "hard.json");
  linkSync(path, hard);
  const files = [
    (await scratch(t, { mode: 0o644 })).path, link, hard, join(root, "missing.json"),
    (await scratch(t, { text: JSON.stringify({ packet: approval.packet }) })).path, (await scratch(t, { text: JSON.stringify({ ...approval, extra: 1 }) })).path,
    (await scratch(t, { text: JSON.stringify({ packet: { ...approval.packet, sourceCommit: "abc" }, review: approval.review }) })).path, (await scratch(t, { text: "not json" })).path, ...(await Promise.all(["null", "[]", "5", "\"x\"", "true"].map(async (text) => (await scratch(t, { text })).path))), (await scratch(t, { text: JSON.stringify({ packet: approval.packet, review: "x" }) })).path, (await scratch(t, { text: JSON.stringify({ packet: "x", review: approval.review }) })).path, (await scratch(t, { text: JSON.stringify({ packet: [], review: approval.review }) })).path, (await scratch(t, { text: JSON.stringify({ packet: approval.packet, review: [] }) })).path,
    (await scratch(t, { text: JSON.stringify({ ...approval, pad: "x".repeat(64 * 1024) }) })).path,
    (await scratch(t, { text: Buffer.concat([Buffer.from(JSON.stringify(approval).replace(/"}}$/, "\"}}").slice(0, -3)), Buffer.from([0xff]), Buffer.from('"}}')]) })).path,
  ];
  for (const file of files) {
    const h = harness(async () => ({}));
    const result = await h.run(["/x/l.json", file, "ok-run"]);
    assert.equal(result.code, 1, file);
    assert.match(result.err, /approval file refused/);
    assert.equal(h.calls.length, 0);
  }
  const good = harness(async () => ({ status: "finished", requests: 1, released: true }));
  assert.equal((await good.run(["/x/l.json", (await scratch(t)).path, "ok-run"])).code, 0);
});

test("the command line prints usage and refuses a missing approval file without reaching the entry", () => {
  const script = fileURLToPath(new URL("./storage-rules-restore/record.mjs", import.meta.url));
  const usage = spawnSync("node", [script], { encoding: "utf8" });
  assert.deepEqual([usage.status, usage.stdout], [2, ""]);
  const missing = spawnSync("node", [script, "/nonexistent/l.json", "/nonexistent/a.json", "some-run"], { encoding: "utf8" });
  assert.deepEqual([missing.status, missing.stdout], [1, ""]);
  assert.match(missing.stderr, /approval file refused/);
});

test("the pin printer prints the four pins of a clean checkout and refuses an unclean one, a bad file and bad arguments without echoing the file", async (t) => {
  const root = scratchCode();
  t.after(() => rm(root, { recursive: true, force: true }));
  const dir = await mkdtemp("/private/tmp/storage-rules-restore-printpins-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = async (name, value, fileMode = 0o600) => { const path = join(dir, name); await writeFile(path, typeof value === "string" ? value : JSON.stringify(value), { mode: fileMode }); await chmod(path, fileMode); return path; };
  const statePath = await file("state.json", STATE);
  const good = await file("local.json", restoreLocal("/x/adc.json", statePath));
  const head = "d".repeat(40);
  const gitFor = (status = "", extra = "", extraProbe = "") => async (where, args) => { assert.equal(where, root); return args[0] === "rev-parse" ? `${head}\n` : args.includes("--ignored") ? (args.includes("conformance/src/storage-rules-restore") ? extraProbe : extra) : status; };
  const run = async (args, git) => { const seen = { out: "", err: "" }; const code = await runRestorePrintPins({ args, codeRoot: root, git, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }); return { code, ...seen }; };
  const digests = await restoreCodeDigests(root);
  const ok = await run([good], gitFor());
  assert.equal(ok.code, 0);
  assert.equal(ok.err, "");
  assert.deepEqual(JSON.parse(ok.out), { sourceCommit: head, runnerSha256: digests.runnerSha256, manifestSha256: restoreCorpus({ state: parseState(STATE), ownerEmailSha256: ownerDigest }).sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 });
  assert.match(ok.out, /^\{\n  "sourceCommit": "d{40}",\n/);
  for (const [git, message] of [[gitFor(" M x\n"), /working tree not clean/], [gitFor("", "?? conformance/src/storage-rules/driver.mjs\n"), /untracked or ignored runner files/], [gitFor("", "", "!! conformance/src/storage-rules-restore/x.mjs\n"), /untracked or ignored runner files/]]) {
    const refused = await run([good], git);
    assert.equal(refused.code, 1);
    assert.equal(refused.out, "");
    assert.match(refused.err, message);
  }
  for (const args of [[], [good, "extra"], [5]]) { const usage = await run(args, gitFor()); assert.deepEqual([usage.code, usage.out], [2, ""]); assert.match(usage.err, /usage: node print-pins.mjs <local inputs file>/); }
  const bad = await file("bad.json", { ...restoreLocal("/x/adc.json", statePath), extra: "SECRET-VALUE-XYZ" });
  const failed = await run([bad], gitFor());
  assert.deepEqual([failed.code, failed.out], [1, ""]);
  assert.match(failed.err, /local inputs file refused/);
  assert.equal(failed.err.includes("SECRET-VALUE-XYZ"), false);
});
