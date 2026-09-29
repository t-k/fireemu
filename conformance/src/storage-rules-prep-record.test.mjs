import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runPrepCommand } from "./storage-rules-prep/record.mjs";

const realRoot = fileURLToPath(new URL("../..", import.meta.url));
const closure = JSON.parse(readFileSync(join(realRoot, "spec/compatibility/closure/STORAGE-RULES.json"), "utf8"));
const commit = "a".repeat(40);
const approval = { packet: { taskId: "STORAGE-RULES", sourceCommit: commit, packetName: "stage2a-v9" }, review: { verdict: "APPROVE" } };

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
  const run = async (args) => ({ code: await runPrepCommand({ args, codeRoot: realRoot, entry, out: (text) => { seen.out += text; }, err: (text) => { seen.err += text; } }), out: seen.out, err: seen.err });
  return { calls, run };
}

test("a clean run prints the status, the request count and where the inputs file is, and hands the entry exactly the closed options", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => ({ status: "finished", requests: 13, inputsPath: "/runs/x/private-inputs.json", secret: "not printed" }));
  const result = await h.run(["/x/local.json", path, "prep-one"]);
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.out), { runId: "prep-one", status: "finished", requests: 13, inputsPath: "/runs/x/private-inputs.json" });
  assert.equal(result.out.includes("not printed"), false);
  assert.deepEqual(Object.keys(h.calls[0]), ["localPath", "closure", "runId", "sourceCommit", "packet", "review"]);
  assert.deepEqual([h.calls[0].localPath, h.calls[0].runId, h.calls[0].sourceCommit, h.calls[0].packet, h.calls[0].review], ["/x/local.json", "prep-one", commit, approval.packet, approval.review]);
  assert.deepEqual(h.calls[0].closure, closure);
});

test("an entry that refuses or fails leaves the locks, prints only the message, and exits 3", async (t) => {
  const { path } = await scratch(t);
  const h = harness(async () => { throw new Error("outbound attempt failed; project locks retained"); });
  const result = await h.run(["/x/local.json", path, "prep-two"]);
  assert.equal(result.code, 3);
  assert.deepEqual(JSON.parse(result.out), { runId: "prep-two", status: "not-clean", locksReleased: false });
  assert.match(result.err, /project locks retained/);
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
  const script = fileURLToPath(new URL("./storage-rules-prep/record.mjs", import.meta.url));
  const usage = spawnSync("node", [script], { encoding: "utf8" });
  assert.deepEqual([usage.status, usage.stdout], [2, ""]);
  const missing = spawnSync("node", [script, "/nonexistent/l.json", "/nonexistent/a.json", "some-run"], { encoding: "utf8" });
  assert.deepEqual([missing.status, missing.stdout], [1, ""]);
  assert.match(missing.stderr, /approval file refused/);
});
