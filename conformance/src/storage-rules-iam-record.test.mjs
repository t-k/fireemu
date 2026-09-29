import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runIamCommand } from "./storage-rules-iam/record.mjs";

const commit = "a".repeat(40);
const approval = { packet: { taskId: "STORAGE-RULES", sourceCommit: commit, packetName: "stage2b-v9" }, review: { verdict: "APPROVE" } };

async function scratch(t, { text = JSON.stringify(approval), mode = 0o600 } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-prep-record-");
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
  const run = async (args) => ({ code: await runIamCommand({ args, entry, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }), out: seen.out, err: seen.err });
  return { calls, run };
}

test("a finished run prints the status, whether it changed anything, the request count and that the lock was released, and hands the entry exactly the closed options", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => ({ status: "finished", changed: true, requests: 5, released: true, secret: "not printed" }));
  const result = await h.run(["/x/local.json", path, "prep-one"]);
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.out), { runId: "prep-one", status: "finished", changed: true, requests: 5, locksReleased: true });
  assert.equal(result.out.includes("not printed"), false);
  assert.deepEqual(Object.keys(h.calls[0]), ["localPath", "runId", "sourceCommit", "packet", "review"]);
  assert.deepEqual([h.calls[0].localPath, h.calls[0].runId, h.calls[0].sourceCommit, h.calls[0].packet, h.calls[0].review], ["/x/local.json", "prep-one", commit, approval.packet, approval.review]);
});

test("a run that a recovery ended, an entry that refuses or fails: exit 3, the message only, and the lock is reported released only after a proven recovery", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => { throw new Error("outbound attempt failed; project locks retained"); });
  const result = await h.run(["/x/local.json", path, "prep-two"]);
  assert.equal(result.code, 3);
  assert.deepEqual(JSON.parse(result.out), { runId: "prep-two", status: "not-finished", locksReleased: false });
  assert.match(result.err, /project locks retained/);
});

test("a recovery that proved the grant absent again is reported as such, with exit 3 because the grant is not there", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => ({ status: "recovered", changed: false, requests: 8, released: true }));
  const result = await h.run(["/x/local.json", path, "iam-two"]);
  assert.equal(result.code, 3);
  assert.deepEqual(JSON.parse(result.out), { runId: "iam-two", status: "recovered", changed: false, requests: 8, locksReleased: true });
  const unchanged = harness(async () => ({ status: "finished", changed: false, requests: 3, released: true }));
  const already = await unchanged.run(["/x/local.json", path, "iam-two"]);
  assert.equal(already.code, 0);
  assert.equal(JSON.parse(already.out).changed, false);
});

test("the arguments and the approval file are checked before the entry is reached", async (t) => {
  const { path, root } = await scratch(t);
  for (const args of [[], ["/x/l.json"], ["/x/l.json", path], ["/x/l.json", path, "Bad Id"], ["/x/l.json", path, "ok-run", "extra"], [5, path, "ok-run"], ["/x/l.json", 5, "ok-run"]]) {
    const h = harness(async () => ({}));
    const result = await h.run(args);
    assert.equal(result.code, 2, JSON.stringify(args));
    assert.match(result.err, /usage/);
    assert.equal(result.out, "");
    assert.equal(h.calls.length, 0);
  }
  const link = join(root, "link.json");
  await symlink(path, link);
  const files = [
    (await scratch(t, { mode: 0o644 })).path, link, join(root, "missing.json"),
    (await scratch(t, { text: JSON.stringify({ packet: approval.packet }) })).path, (await scratch(t, { text: JSON.stringify({ ...approval, extra: 1 }) })).path,
    (await scratch(t, { text: JSON.stringify({ packet: { ...approval.packet, sourceCommit: "abc" }, review: approval.review }) })).path, (await scratch(t, { text: "not json" })).path,
  ];
  for (const file of files) {
    const h = harness(async () => ({}));
    const result = await h.run(["/x/l.json", file, "ok-run"]);
    assert.equal(result.code, 1, file);
    assert.match(result.err, /approval file refused/);
    assert.equal(h.calls.length, 0);
  }
});

test("the command line prints usage and refuses a missing approval file without reaching the entry", () => {
  const script = fileURLToPath(new URL("./storage-rules-iam/record.mjs", import.meta.url));
  const usage = spawnSync("node", [script], { encoding: "utf8" });
  assert.deepEqual([usage.status, usage.stdout], [2, ""]);
  const missing = spawnSync("node", [script, "/nonexistent/l.json", "/nonexistent/a.json", "some-run"], { encoding: "utf8" });
  assert.deepEqual([missing.status, missing.stdout], [1, ""]);
  assert.match(missing.stderr, /approval file refused/);
});

test("the pin printer prints the four pins of a clean checkout and refuses an unclean one, a bad file and bad arguments without echoing the file", async (t) => {
  const { mkdtemp: makeDir, rm: remove, writeFile: write, chmod: mode } = await import("node:fs/promises");
  const { runIamPrintPins } = await import("./storage-rules-iam/print-pins.mjs");
  const { iamCodeDigests } = await import("./storage-rules-iam/pins.mjs");
  const { iamCorpus } = await import("./storage-rules-iam/plan.mjs");
  const { scratchCode, localInputs, ownerDigest, NUMBERS } = await import("./storage-rules-iam-support.mjs");
  const root = scratchCode();
  t.after(() => remove(root, { recursive: true, force: true }));
  const dir = await makeDir("/private/tmp/storage-rules-iam-printpins-");
  t.after(() => remove(dir, { recursive: true, force: true }));
  const file = async (name, value, fileMode = 0o600) => { const path = join(dir, name); await write(path, typeof value === "string" ? value : JSON.stringify(value), { mode: fileMode }); await mode(path, fileMode); return path; };
  const good = await file("local.json", localInputs("/x/adc.json"));
  const commit = "d".repeat(40);
  const gitFor = (status = "", extra = "", extraIam = "") => async (where, args) => { assert.equal(where, root); return args[0] === "rev-parse" ? `${commit}\n` : args.includes("--ignored") ? (args.includes("conformance/src/storage-rules-iam") ? extraIam : extra) : status; };
  const run = async (args, git) => { const seen = { out: "", err: "" }; const code = await runIamPrintPins({ args, codeRoot: root, git, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }); return { code, ...seen }; };
  const ok = await run([good], gitFor());
  assert.equal(ok.code, 0);
  assert.equal(ok.err, "");
  const digests = await iamCodeDigests(root);
  const corpus = iamCorpus({ projectNumber: NUMBERS.query, ownerEmailSha256: ownerDigest });
  assert.deepEqual(JSON.parse(ok.out), { sourceCommit: commit, runnerSha256: digests.runnerSha256, manifestSha256: corpus.sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 });
  assert.match(ok.out, /^\{\n  "sourceCommit": "d{40}",\n/);
  for (const [git, message] of [[gitFor(" M x\n"), /working tree not clean/], [gitFor("", "?? conformance/src/storage-rules/driver.mjs\n"), /untracked or ignored runner files/], [gitFor("", "", "!! conformance/src/storage-rules-iam/x.mjs\n"), /untracked or ignored runner files/]]) {
    const refused = await run([good], git);
    assert.equal(refused.code, 1);
    assert.equal(refused.out, "");
    assert.match(refused.err, message);
  }
  for (const args of [[], [good, "extra"]]) { const usage = await run(args, gitFor()); assert.deepEqual([usage.code, usage.out], [2, ""]); assert.match(usage.err, /usage/); }
  const bad = await file("bad.json", { ...localInputs("/x/adc.json"), extra: "SECRET-VALUE-XYZ" });
  const failed = await run([bad], gitFor());
  assert.deepEqual([failed.code, failed.out], [1, ""]);
  assert.match(failed.err, /local inputs file refused/);
  assert.equal(failed.err.includes("SECRET-VALUE-XYZ"), false);
});
