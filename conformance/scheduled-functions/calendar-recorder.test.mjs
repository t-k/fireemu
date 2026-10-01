import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRecorder, readRecords } from "./calendar-recorder.mjs";
import { validateRecords } from "./calendar-accounting.mjs";

async function scratch(t) {
  const directory = await mkdtemp(join(tmpdir(), "calendar-recorder-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

const header = {
  role: "measure",
  pid: process.pid,
  started: "Fri Oct  2 06:00:00 2026",
  harnessVersion: "test",
};

test("a recorded child gets one birth and one exit row from its parent's own wait", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const ok = await recorder.execFile("/usr/bin/true", [], {}, "probe");
  const failed = await recorder.execFile("/bin/sh", ["-c", "exit 3"], {}, "probe");
  assert.equal(ok.code, 0);
  assert.equal(failed.code, 3);
  const rows = await readRecords(path);
  assert.deepEqual(
    rows.map((row) => row.type),
    ["header", "birth", "exit", "birth", "exit"],
  );
  assert.equal(rows[1].handle, rows[2].handle);
  assert.notEqual(rows[1].handle, rows[3].handle);
  assert.equal(rows[4].code, 3);
  assert.ok(!JSON.stringify(rows).includes("exit 3"), "argv is stored as a digest only");
  assert.equal(validateRecords({ "measure.jsonl": rows }).ok, true);
});

test("a spawn that fails records spawn-failed with no PID and no exit", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const answer = await recorder.execFile("/nonexistent/calendar-binary", [], {}, "probe");
  assert.equal(answer.spawnFailed, true);
  const rows = await readRecords(path);
  assert.deepEqual(
    rows.map((row) => row.type),
    ["header", "spawn-failed"],
  );
  assert.equal(rows[1].pid, null);
  assert.equal(validateRecords({ "measure.jsonl": rows }).ok, true);
});

test("a timed-out child is killed with a recorded signal row before the kill", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const answer = await recorder.execFile("/bin/sleep", ["5"], { timeoutMs: 100 }, "probe");
  assert.equal(answer.timedOut, true);
  assert.equal(answer.signal, "SIGKILL");
  const rows = await readRecords(path);
  assert.deepEqual(
    rows.map((row) => row.type),
    ["header", "birth", "signal", "exit"],
  );
  assert.equal(rows[2].target.pid, rows[1].pid);
  const result = validateRecords({ "measure.jsonl": rows });
  assert.equal(result.ok, true);
  assert.equal(result.signals.length, 1);
});

test("identity rows and caller-sent signals are recorded before the signal is sent", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const order = [];
  const child = recorder.spawn("/bin/sleep", ["5"], {}, "outer");
  recorder.identity(child.recordHandle, child.pid, "Fri Oct  2 06:00:01 2026");
  await recorder.signal(
    { pid: child.pid, uid: 501, started: "Fri Oct  2 06:00:01 2026" },
    "SIGTERM",
    async () => {
      order.push((await readRecords(path)).at(-1).type);
      process.kill(child.pid, "SIGTERM");
    },
  );
  await child.recordExit;
  assert.deepEqual(order, ["signal"]);
  const rows = await readRecords(path);
  assert.deepEqual(
    rows.map((row) => row.type),
    ["header", "birth", "identity", "signal", "exit"],
  );
  assert.equal(rows.at(-1).signal, "SIGTERM");
});

test("rows are appended as they happen, so a crash keeps the earlier ones", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const child = recorder.spawn("/bin/sleep", ["5"], {}, "probe");
  const text = await readFile(path, "utf8");
  assert.equal(text.trim().split("\n").length, 2, "header and birth are on disk before the exit");
  process.kill(child.pid, "SIGKILL");
  await child.recordExit;
});
