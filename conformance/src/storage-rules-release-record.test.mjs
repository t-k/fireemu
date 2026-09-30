import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { linkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runReleaseCommand } from "./storage-rules-release/record.mjs";
import { runReleasePrintPins } from "./storage-rules-release/print-pins.mjs";
import { corpusOf, readLocalInputs } from "./storage-rules-release/release-entry.mjs";
import { releaseCodeDigests } from "./storage-rules-release/pins.mjs";
import { canonicalDigest, makeSaved } from "./storage-rules-release/release.mjs";
import { BUCKET, SOURCE_SHA, ownerDigest, postLocal, preLocal, releaseBody, scratchCode } from "./storage-rules-release-support.mjs";

const commit = "a".repeat(40);
const approval = { packet: { taskId: "STORAGE-RULES", sourceCommit: commit, packetName: "stage2c-pre-v9" }, review: { verdict: "APPROVE" } };

async function scratch(t, { text = JSON.stringify(approval), mode = 0o600 } = {}) {
  const root = await mkdtemp("/private/tmp/storage-rules-release-record-");
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
  const run = async (args) => ({ code: await runReleaseCommand({ args, entry, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }), out: seen.out, err: seen.err });
  return { calls, run };
}

test("a finished run prints the mode, the status, whether it changed anything, the request count, that the lock was released and the saved record's digest, and hands the entry exactly the closed options", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => ({ status: "finished", changed: true, requests: 8, released: true, savedSha256: "c".repeat(64), secret: "not printed" }));
  const result = await h.run(["pre", "/x/local.json", path, "rel-one"]);
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.out), { runId: "rel-one", mode: "pre", status: "finished", changed: true, requests: 8, locksReleased: true, savedSha256: "c".repeat(64) });
  assert.equal(result.out.includes("not printed"), false);
  assert.deepEqual(Object.keys(h.calls[0]), ["mode", "localPath", "runId", "sourceCommit", "packet", "review"]);
  assert.deepEqual([h.calls[0].mode, h.calls[0].localPath, h.calls[0].runId, h.calls[0].sourceCommit, h.calls[0].packet, h.calls[0].review], ["pre", "/x/local.json", "rel-one", commit, approval.packet, approval.review]);
  const post = harness(async () => ({ status: "finished", changed: false, requests: 5, released: true }));
  const again = await post.run(["post", "/x/local.json", path, "rel-two"]);
  assert.equal(again.code, 0);
  assert.deepEqual(JSON.parse(again.out), { runId: "rel-two", mode: "post", status: "finished", changed: false, requests: 5, locksReleased: true });
  assert.equal(post.calls[0].mode, "post");
});

test("a run that a recovery ended, an entry that refuses or fails: exit 3, the message only, and the lock is reported released only after a proven recovery", async (t) => {
  const { path } = await scratch(t);
  const failed = harness(async () => { throw new Error("outbound attempt failed; project locks retained"); });
  const result = await failed.run(["post", "/x/local.json", path, "rel-three"]);
  assert.equal(result.code, 3);
  assert.deepEqual(JSON.parse(result.out), { runId: "rel-three", mode: "post", status: "not-finished", locksReleased: false });
  assert.match(result.err, /project locks retained/);
  const recovered = harness(async () => ({ status: "recovered", changed: false, requests: 8, released: true }));
  const done = await recovered.run(["pre", "/x/local.json", path, "rel-four"]);
  assert.equal(done.code, 3);
  assert.deepEqual(JSON.parse(done.out), { runId: "rel-four", mode: "pre", status: "recovered", changed: false, requests: 8, locksReleased: true });
  const held = harness(async () => ({ status: "recovered", changed: false, requests: 8, released: false }));
  assert.equal(JSON.parse((await held.run(["pre", "/x/local.json", path, "rel-four"])).out).locksReleased, false);
});

test("the arguments and the approval file are checked before the entry is reached", async (t) => {
  const { path, root } = await scratch(t);
  for (const args of [[], ["pre"], ["pre", "/x/l.json"], ["pre", "/x/l.json", path], ["both", "/x/l.json", path, "ok-run"], ["pre", "/x/l.json", path, "Bad Id"], ["pre", "/x/l.json", path, "ok-run", "extra"], ["pre", 5, path, "ok-run"], ["pre", "/x/l.json", 5, "ok-run"], ["/x/l.json", path, "ok-run"]]) {
    const h = harness(async () => ({}));
    const result = await h.run(args);
    assert.equal(result.code, 2, JSON.stringify(args));
    assert.match(result.err, /usage: node record.mjs <pre\|post>/);
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
    const result = await h.run(["pre", "/x/l.json", file, "ok-run"]);
    assert.equal(result.code, 1, file);
    assert.match(result.err, /approval file refused/);
    assert.equal(h.calls.length, 0);
  }
});

test("the command line prints usage and refuses a missing approval file without reaching the entry", () => {
  const script = fileURLToPath(new URL("./storage-rules-release/record.mjs", import.meta.url));
  const usage = spawnSync("node", [script], { encoding: "utf8" });
  assert.deepEqual([usage.status, usage.stdout], [2, ""]);
  const missing = spawnSync("node", [script, "post", "/nonexistent/l.json", "/nonexistent/a.json", "some-run"], { encoding: "utf8" });
  assert.deepEqual([missing.status, missing.stdout], [1, ""]);
  assert.match(missing.stderr, /approval file refused/);
});

test("the pin printer prints the four pins of a clean checkout for either mode and refuses an unclean one, a bad file and bad arguments without echoing the file", async (t) => {
  const root = scratchCode();
  t.after(() => rm(root, { recursive: true, force: true }));
  const dir = await mkdtemp("/private/tmp/storage-rules-release-printpins-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = async (name, value, fileMode = 0o600) => { const path = join(dir, name); await writeFile(path, typeof value === "string" ? value : JSON.stringify(value), { mode: fileMode }); await chmod(path, fileMode); return path; };
  const saved = makeSaved({ bucket: BUCKET, release: { ...releaseBody(), bodySha256: canonicalDigest(releaseBody()) }, ruleset: { sourceSha256: SOURCE_SHA } });
  const savedPath = await file("saved.json", saved);
  const pre = await file("pre.json", preLocal("/x/adc.json"));
  const post = await file("post.json", postLocal("/x/adc.json", savedPath));
  const head = "d".repeat(40);
  const gitFor = (status = "", extra = "", extraRelease = "") => async (where, args) => { assert.equal(where, root); return args[0] === "rev-parse" ? `${head}\n` : args.includes("--ignored") ? (args.includes("conformance/src/storage-rules-release") ? extraRelease : extra) : status; };
  const run = async (args, git) => { const seen = { out: "", err: "" }; const code = await runReleasePrintPins({ args, codeRoot: root, git, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }); return { code, ...seen }; };
  const digests = await releaseCodeDigests(root);
  for (const [mode, path] of [["pre", pre], ["post", post]]) {
    const ok = await run([mode, path], gitFor());
    assert.equal(ok.code, 0, mode);
    assert.equal(ok.err, "");
    const local = await readLocalInputs(path, mode);
    assert.deepEqual(JSON.parse(ok.out), { sourceCommit: head, runnerSha256: digests.runnerSha256, manifestSha256: corpusOf(local).sha256, fixtureSchemaSha256: digests.fixtureSchemaSha256 });
    assert.match(ok.out, /^\{\n  "sourceCommit": "d{40}",\n/);
  }
  assert.notEqual(JSON.parse((await run(["pre", pre], gitFor())).out).manifestSha256, JSON.parse((await run(["post", post], gitFor())).out).manifestSha256);
  for (const [git, message] of [[gitFor(" M x\n"), /working tree not clean/], [gitFor("", "?? conformance/src/storage-rules/driver.mjs\n"), /untracked or ignored runner files/], [gitFor("", "", "!! conformance/src/storage-rules-release/x.mjs\n"), /untracked or ignored runner files/]]) {
    const refused = await run(["pre", pre], git);
    assert.equal(refused.code, 1);
    assert.equal(refused.out, "");
    assert.match(refused.err, message);
  }
  for (const args of [[], ["pre"], [pre], ["pre", pre, "extra"], ["both", pre]]) { const usage = await run(args, gitFor()); assert.deepEqual([usage.code, usage.out], [2, ""]); assert.match(usage.err, /usage/); }
  const bad = await file("bad.json", { ...preLocal("/x/adc.json"), extra: "SECRET-VALUE-XYZ" });
  const failed = await run(["pre", bad], gitFor());
  assert.deepEqual([failed.code, failed.out], [1, ""]);
  assert.match(failed.err, /local inputs file refused/);
  assert.equal(failed.err.includes("SECRET-VALUE-XYZ"), false);
  // A file of the other mode's shape is refused.
  const crossed = await run(["post", pre], gitFor());
  assert.deepEqual([crossed.code, crossed.out], [1, ""]);
});

test("the approval file must be a small, single-link, valid UTF-8 file", async (t) => {
  const { path, root } = await scratch(t);
  const link = join(root, "hard.json");
  linkSync(path, link);
  const big = await scratch(t, { text: JSON.stringify({ ...approval, pad: "x".repeat(64 * 1024) }) });
  const bytes = await scratch(t, { text: "" });
  await writeFile(bytes.path, Buffer.concat([Buffer.from(JSON.stringify({ packet: { ...approval.packet, packetName: "stage2c-pre-v9" }, review: { note: "" } }).replace('"note":""', '"note":"')), Buffer.from([0xff]), Buffer.from('"}}')]), { mode: 0o600 });
  for (const file of [link, big.path, bytes.path]) {
    const h = harness(async () => ({}));
    const result = await h.run(["pre", "/x/l.json", file, "ok-run"]);
    assert.equal(result.code, 1, file);
    assert.match(result.err, /approval file refused/);
    assert.equal(h.calls.length, 0);
  }
  const good = harness(async () => ({ status: "finished", changed: true, requests: 1, released: true }));
  assert.equal((await good.run(["pre", "/x/l.json", (await scratch(t)).path, "ok-run"])).code, 0);
});

test("the local inputs reader knows only the two modes, and each mode reads only its own shape", async (t) => {
  const dir = await mkdtemp("/private/tmp/storage-rules-release-local-");
  t.after(() => rm(dir, { recursive: true, force: true }));
  const saved = makeSaved({ bucket: BUCKET, release: { ...releaseBody(), bodySha256: canonicalDigest(releaseBody()) }, ruleset: { sourceSha256: SOURCE_SHA } });
  const savedPath = join(dir, "saved.json");
  await writeFile(savedPath, JSON.stringify(saved), { mode: 0o600 });
  const prePath = join(dir, "pre.json");
  const postPath = join(dir, "post.json");
  await writeFile(prePath, JSON.stringify(preLocal("/x/adc.json")), { mode: 0o600 });
  await writeFile(postPath, JSON.stringify(postLocal("/x/adc.json", savedPath)), { mode: 0o600 });
  assert.equal((await readLocalInputs(prePath, "pre")).mode, "pre");
  assert.equal((await readLocalInputs(postPath, "post")).mode, "post");
  for (const [path, mode] of [[prePath, "post"], [postPath, "pre"], [prePath, "both"], [postPath, "both"], [postPath, undefined], [prePath, ""], [postPath, "toString"]]) {
    await assert.rejects(readLocalInputs(path, mode), /local inputs file refused/, `${path} ${mode}`);
  }
});
