import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { runRecordCommand } from "./storage-rules/record.mjs";

// The recording command: what it decides after a run, and what it prints. The entry it calls is injected here; the command
// line itself always uses the real one.
const realRoot = fileURLToPath(new URL("../..", import.meta.url));
const closure = JSON.parse(
  readFileSync(join(realRoot, "spec/compatibility/closure/STORAGE-RULES.json"), "utf8"),
);
const commit = "a".repeat(40);
const approval = {
  packet: { taskId: "STORAGE-RULES", sourceCommit: commit, packetName: "stage3-v9" },
  review: { verdict: "APPROVE" },
};

async function scratch(t, { text = JSON.stringify(approval), mode = 0o600 } = {}) {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-record-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "approval.json");
  await writeFile(path, text, { mode });
  await chmod(path, mode);
  return { root, path };
}
function harness({
  first,
  recovered,
  confirm = () => {},
  reject = null,
  rejectAfter = null,
  runError = null,
  recoverError = null,
} = {}) {
  const calls = [];
  const entry = async (options, use) => {
    calls.push(["entry", options]);
    if (reject !== null) throw reject;
    const recording = {
      run: async () => {
        calls.push(["run"]);
        if (runError !== null) throw runError;
        return first;
      },
      recover: async () => {
        calls.push(["recover"]);
        if (recoverError !== null) throw recoverError;
        return recovered;
      },
      confirmCleanClose: (result) => {
        calls.push(["confirm", result]);
        return confirm(result);
      },
    };
    const value = await use(recording);
    if (rejectAfter !== null) throw rejectAfter;
    return value;
  };
  const seen = { out: "", err: "" };
  const run = async (args) => {
    const code = await runRecordCommand({
      args,
      codeRoot: realRoot,
      entry,
      out: (text) => {
        seen.out += text;
      },
      err: (text) => {
        seen.err += text;
      },
    });
    return { code, out: seen.out, err: seen.err };
  };
  return { calls, run, seen };
}
const clean = Object.freeze({ status: "finished", requests: 6172, skipped: Object.freeze([]) });

test("a clean run is closed with the controller's own result, and the locks are reported released", async (t) => {
  const { path } = await scratch(t);
  const h = harness({ first: clean });
  const result = await h.run(["/x/inputs.json", path, "run-one"]);
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.out), {
    runId: "run-one",
    locksReleased: true,
    entered: true,
    run: { status: "finished", requests: 6172 },
  });
  assert.equal(result.err, "");
  assert.deepEqual(
    h.calls.map(([name]) => name),
    ["entry", "run", "confirm"],
  );
  assert.equal(h.calls[2][1], clean);
  // The entry receives exactly the closed options: the inputs path, the closure from the checkout, the run ID, the commit of the packet, and the approval's own objects.
  const options = h.calls[0][1];
  assert.deepEqual(Object.keys(options), [
    "inputsPath",
    "closure",
    "runId",
    "sourceCommit",
    "packet",
    "review",
  ]);
  assert.deepEqual(
    [options.inputsPath, options.runId, options.sourceCommit, options.packet, options.review],
    ["/x/inputs.json", "run-one", commit, approval.packet, approval.review],
  );
  assert.deepEqual(options.closure, closure);
});

test("a stop that needs recovery is recovered once, and only a proven recovery is closed", async (t) => {
  const { path } = await scratch(t);
  const stopped = Object.freeze({
    status: "stopped",
    reason: "unexpected verdict",
    detail: Object.freeze({ rowId: "compile/release/before", tokens: ["secret-looking"] }),
    requests: 40,
    needsRecovery: true,
  });
  const recovered = Object.freeze({ status: "recovered", requests: 12 });
  const ok = harness({ first: stopped, recovered });
  const done = await ok.run(["/x/i.json", path, "run-two"]);
  assert.equal(done.code, 0);
  assert.deepEqual(
    ok.calls.map(([name]) => name),
    ["entry", "run", "recover", "confirm"],
  );
  assert.equal(ok.calls[3][1], recovered);
  assert.deepEqual(JSON.parse(done.out), {
    runId: "run-two",
    locksReleased: true,
    entered: true,
    run: {
      status: "stopped",
      reason: "unexpected verdict",
      needsRecovery: true,
      requests: 40,
      rowId: "compile/release/before",
    },
    recovery: { status: "recovered", requests: 12 },
  });
  assert.equal(done.out.includes("secret-looking"), false);
  const failed = Object.freeze({
    status: "stopped",
    reason: "owned-prefix check skipped",
    detail: Object.freeze({}),
    requests: 3,
    needsRecovery: true,
  });
  const bad = harness({ first: stopped, recovered: failed });
  const notDone = await bad.run(["/x/i.json", path, "run-two"]);
  assert.equal(notDone.code, 3);
  assert.deepEqual(
    bad.calls.map(([name]) => name),
    ["entry", "run", "recover"],
  );
  assert.equal(JSON.parse(notDone.out).locksReleased, false);
});

test("a stop that needs no recovery, a refusal and a stop with recovery unneeded leave the locks and are not closed", async (t) => {
  const { path } = await scratch(t);
  for (const first of [
    Object.freeze({
      status: "stopped",
      reason: "preflight refused",
      detail: Object.freeze({ rowId: "preflight/owner/identity" }),
      requests: 4,
      needsRecovery: false,
    }),
    Object.freeze({
      status: "stopped",
      reason: "admission refused",
      detail: Object.freeze({}),
      requests: 0,
    }),
    Object.freeze({ status: "refused", reason: "x" }),
  ]) {
    const h = harness({ first });
    const result = await h.run(["/x/i.json", path, "run-three"]);
    assert.equal(result.code, 3);
    assert.deepEqual(
      h.calls.map(([name]) => name),
      ["entry", "run"],
    );
    assert.equal(JSON.parse(result.out).locksReleased, false);
  }
});

test("a close the lease refuses, or an entry that fails after the run, is not reported as released", async (t) => {
  const { path } = await scratch(t);
  const refused = harness({
    first: clean,
    confirm: () => {
      throw new Error("cannot confirm project lock closure");
    },
  });
  const one = await refused.run(["/x/i.json", path, "run-four"]);
  assert.equal(one.code, 3);
  assert.deepEqual(JSON.parse(one.out), {
    runId: "run-four",
    locksReleased: false,
    entered: true,
    run: { status: "finished", requests: 6172 },
    closeRefused: true,
  });
  const after = harness({
    first: clean,
    rejectAfter: new Error("outbound attempt failed; project locks retained"),
  });
  const two = await after.run(["/x/i.json", path, "run-four"]);
  assert.equal(two.code, 3);
  assert.equal(JSON.parse(two.out).locksReleased, false);
  assert.match(two.err, /project locks retained/);
  const before = harness({ reject: new Error("pin mismatch: runnerSha256") });
  const three = await before.run(["/x/i.json", path, "run-four"]);
  assert.equal(three.code, 1);
  assert.deepEqual(JSON.parse(three.out), { runId: "run-four", locksReleased: false });
  assert.match(three.err, /pin mismatch: runnerSha256/);
  assert.deepEqual(
    before.calls.map(([name]) => name),
    ["entry"],
  );
});

test("a failure after the recording was entered is never reported as a refusal before a run", async (t) => {
  const { path } = await scratch(t);
  // run() throws after sending (a terminal journal write failure): exit 3 with the recording marked as entered, not exit 1.
  const thrown = harness({ runError: new Error("journal state is uncertain") });
  const one = await thrown.run(["/x/i.json", path, "run-five"]);
  assert.equal(one.code, 3);
  assert.deepEqual(JSON.parse(one.out), { runId: "run-five", locksReleased: false, entered: true });
  assert.match(one.err, /journal state is uncertain/);
  assert.deepEqual(
    thrown.calls.map(([name]) => name),
    ["entry", "run"],
  );
  // recover() throws after the run needed one.
  const stopped = Object.freeze({
    status: "stopped",
    reason: "unexpected verdict",
    detail: Object.freeze({}),
    requests: 5,
    needsRecovery: true,
  });
  const recoverThrown = harness({
    first: stopped,
    recoverError: new Error("journal state is uncertain"),
  });
  const two = await recoverThrown.run(["/x/i.json", path, "run-five"]);
  assert.equal(two.code, 3);
  assert.deepEqual(JSON.parse(two.out), {
    runId: "run-five",
    locksReleased: false,
    entered: true,
    run: { status: "stopped", reason: "unexpected verdict", needsRecovery: true, requests: 5 },
  });
  // An entry that refuses before the callback is the only exit 1, and its output does not say entered.
  const refused = harness({ reject: new Error("pin mismatch: runnerSha256") });
  const three = await refused.run(["/x/i.json", path, "run-five"]);
  assert.equal(three.code, 1);
  assert.equal(Object.hasOwn(JSON.parse(three.out), "entered"), false);
});

test("the arguments and the approval file are checked before the entry is reached", async (t) => {
  const { path, root } = await scratch(t);
  for (const args of [
    [],
    ["/x/i.json"],
    ["/x/i.json", path],
    ["/x/i.json", path, "Bad Id"],
    ["/x/i.json", path, "ok-run", "extra"],
    [5, path, "ok-run"],
    ["/x/i.json", 5, "ok-run"],
  ]) {
    const h = harness({ first: clean });
    const result = await h.run(args);
    assert.equal(result.code, 2, JSON.stringify(args));
    assert.match(result.err, /usage/);
    assert.equal(result.out, "");
    assert.equal(h.calls.length, 0);
  }
  const wide = await scratch(t, { mode: 0o644 });
  const link = join(root, "link.json");
  await symlink(path, link);
  const cases = [
    wide.path,
    link,
    join(root, "missing.json"),
    (await scratch(t, { text: JSON.stringify({ packet: approval.packet }) })).path,
    (await scratch(t, { text: JSON.stringify({ ...approval, extra: 1 }) })).path,
    (
      await scratch(t, {
        text: JSON.stringify({
          packet: { ...approval.packet, sourceCommit: "abc" },
          review: approval.review,
        }),
      })
    ).path,
    (await scratch(t, { text: "not json" })).path,
    (await scratch(t, { text: JSON.stringify({ packet: [], review: approval.review }) })).path,
  ];
  for (const file of cases) {
    const h = harness({ first: clean });
    const result = await h.run(["/x/i.json", file, "ok-run"]);
    assert.equal(result.code, 1, file);
    assert.match(result.err, /approval file refused/);
    assert.equal(result.out, "");
    assert.equal(h.calls.length, 0);
  }
});

test("the command line prints usage for missing arguments and refuses a missing approval file, without reaching the entry", () => {
  const script = fileURLToPath(new URL("./storage-rules/record.mjs", import.meta.url));
  const usage = spawnSync("node", [script], { encoding: "utf8" });
  assert.deepEqual([usage.status, usage.stdout], [2, ""]);
  assert.match(usage.stderr, /usage/);
  const missing = spawnSync(
    "node",
    [script, "/nonexistent/inputs.json", "/nonexistent/approval.json", "some-run"],
    { encoding: "utf8" },
  );
  assert.deepEqual([missing.status, missing.stdout], [1, ""]);
  assert.match(missing.stderr, /approval file refused/);
});
