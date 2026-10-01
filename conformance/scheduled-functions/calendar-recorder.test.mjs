import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { createRecorder, createSelfRecorder, psEnv, readRecords } from "./calendar-recorder.mjs";
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

test("a lane-owned process records its own start time with a recorded ps of itself", async (t) => {
  const path = join(await scratch(t), "outer.jsonl");
  const recorder = await createSelfRecorder({ path, role: "outer", harnessVersion: "test" });
  const rows = await readRecords(path);
  assert.deepEqual(
    rows.map((row) => row.type),
    ["header", "birth", "exit"],
  );
  assert.equal(rows[0].pid, process.pid);
  assert.match(rows[0].started, /^\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/);
  assert.equal(rows[1].purpose, "self-start");
  assert.equal(rows[2].code, 0);
  // The same normalised start time a parent records in its identity row.
  assert.equal(await recorder.startedOf(process.pid), rows[0].started);
  const header = rows[0];
  const parent = [
    { type: "header", role: "measure", pid: 1234, started: "x", harnessVersion: "test" },
    {
      type: "birth",
      handle: "measure:1",
      pid: header.pid,
      uid: process.getuid(),
      purpose: "outer",
      file: "node",
      argvSha256: "a".repeat(64),
      spawnMonoNs: "1",
    },
    { type: "identity", handle: "measure:1", pid: header.pid, started: header.started },
    {
      type: "exit",
      handle: "measure:1",
      code: 0,
      signal: null,
      exitMonoNs: String(process.hrtime.bigint()),
    },
  ];
  const result = validateRecords({
    "measure.jsonl": parent,
    "outer.jsonl": await readRecords(path),
  });
  assert.deepEqual(result.problems, []);
});

test("only the measuring entry may start a session, and only for the outer launcher", async (t) => {
  const directory = await scratch(t);
  const started = [];
  const spawnImpl = (file, args, options) => {
    started.push(options);
    const child = new EventEmitter();
    child.pid = 4242;
    return child;
  };
  const measure = createRecorder({ path: join(directory, "m.jsonl"), ...header, spawnImpl });
  measure.spawn("node", ["x"], { detached: true }, "outer");
  assert.throws(() => measure.spawn("node", ["x"], { detached: true }, "inner"), /session/);
  const inner = createRecorder({
    path: join(directory, "i.jsonl"),
    ...header,
    role: "inner",
    spawnImpl,
  });
  assert.throws(() => inner.spawn("node", ["x"], { detached: true }, "outer"), /session/);
  assert.throws(() => inner.spawn("node", ["x"], { ...{ detached: 1 } }, "daemon"), /session/);
  inner.spawn("node", ["x"], { detached: false }, "daemon");
  assert.equal(started.length, 2, "a refused spawn starts nothing");
  const rows = await readRecords(join(directory, "i.jsonl"));
  assert.equal(rows.filter((row) => row.type === "birth").length, 1);
});

test("every ps the harness runs reads start times in UTC", () => {
  assert.deepEqual(psEnv(), { PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C", TZ: "UTC" });
});

// Mutation round 1 (validator mutation of harness H): the recorder's observable contract.
test("record files are private, handles count from one, and the child carries its handle", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const first = recorder.spawn("/usr/bin/true", [], {}, "probe");
  const second = recorder.spawn("/usr/bin/true", [], {}, "probe");
  await Promise.all([first.recordExit, second.recordExit]);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.deepEqual([first.recordHandle, second.recordHandle], ["measure:1", "measure:2"]);
  const births = (await readRecords(path)).filter((row) => row.type === "birth");
  assert.deepEqual(
    births.map((row) => row.handle),
    ["measure:1", "measure:2"],
  );
});

test("a failed spawn answers with no code, no signal, no timeout and its error code", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const child = recorder.spawn("/nonexistent/calendar-binary", [], {}, "probe");
  assert.deepEqual(await child.recordExit, { code: null, signal: null, spawnFailed: true });
  const answer = await recorder.execFile("/nonexistent/calendar-binary", [], {}, "probe");
  assert.deepEqual(answer, {
    code: null,
    signal: null,
    stdout: "",
    stderr: "",
    timedOut: false,
    spawnFailed: true,
  });
  const failed = (await readRecords(path)).filter((row) => row.type === "spawn-failed");
  assert.deepEqual(
    failed.map((row) => row.error),
    ["ENOENT", "ENOENT"],
  );
  // A spawn error without a code is still recorded, as "error".
  const codedPath = join(await scratch(t), "m.jsonl");
  const coded = createRecorder({
    path: codedPath,
    ...header,
    spawnImpl: () => {
      const child = new EventEmitter();
      process.nextTick(() => child.emit("error", new Error("no code")));
      return child;
    },
  });
  await coded.spawn("x", [], {}, "probe").recordExit;
  coded.close();
  assert.equal((await readRecords(codedPath))[1].error, "error");
});

test("execFile collects both streams in full, within maxBuffer, and reports no timeout", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  const answer = await recorder.execFile(
    "/bin/sh",
    ["-c", "printf out; printf err >&2; sleep 0.3"],
    {},
    "probe",
  );
  assert.deepEqual(
    [answer.code, answer.stdout, answer.stderr, answer.timedOut],
    [0, "out", "err", false],
    "a 0.3 s child is not killed by the default timeout",
  );
  assert.equal(answer.handle, "measure:1");
  const large = await recorder.execFile(
    "/bin/sh",
    ["-c", "head -c 1048576 /dev/zero | tr '\\0' a"],
    {},
    "probe",
  );
  assert.equal(large.stdout.length, 1048576, "output is read until the pipes close");
  const bounded = await recorder.execFile(
    "/bin/sh",
    ["-c", "printf a; printf c >&2; sleep 0.2; printf b; printf d >&2"],
    { maxBuffer: 1 },
    "probe",
  );
  assert.deepEqual([bounded.stdout, bounded.stderr], ["a", "c"]);
});

test("a finished child's timer is cleared, so no late signal row appears", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  await recorder.execFile("/usr/bin/true", [], { timeoutMs: 150 }, "probe");
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.ok(!(await readRecords(path)).some((row) => row.type === "signal"));
});

test("startedOf refuses a process it cannot read, and signal propagates a failed send", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  await assert.rejects(recorder.startedOf(2 ** 22 + 12345), /start time of \d+ is unreadable/);
  await assert.rejects(
    recorder.signal({ pid: 2, uid: 0, started: "x" }, "SIGTERM", async () => {
      throw new Error("send failed");
    }),
    /send failed/,
  );
});

test("close is idempotent, and a closed recorder writes nothing more", async (t) => {
  const path = join(await scratch(t), "measure.jsonl");
  const recorder = createRecorder({ path, ...header });
  recorder.close();
  recorder.close();
  assert.throws(() => recorder.identity("measure:1", 4242, "x"));
  assert.equal((await readRecords(path)).length, 1);
});

test("a self recorder refuses an unreadable own start time and a ps that cannot start", async (t) => {
  const directory = await scratch(t);
  const fake =
    ({ code = 0, text = "", error } = {}) =>
    () => {
      const child = new EventEmitter();
      child.pid = 4242;
      child.stdout = new EventEmitter();
      child.stdout.setEncoding = () => {};
      process.nextTick(() => {
        if (error) return child.emit("error", error);
        if (text) child.stdout.emit("data", text);
        child.emit("close", code, null);
      });
      return child;
    };
  const make = (spawnImpl) =>
    createSelfRecorder({
      path: join(directory, "o.jsonl"),
      role: "outer",
      harnessVersion: "t",
      spawnImpl,
    });
  await assert.rejects(make(fake({ code: 1, text: "Fri Oct 2 06:00:00 2026\n" })), /unreadable/);
  await assert.rejects(make(fake({ code: 0, text: "  \n" })), /unreadable/);
  await assert.rejects(make(fake({ error: new Error("spawn ps ENOENT") })), /ENOENT/);
  const ok = await make(fake({ text: "Fri Oct  2 06:00:00 2026\n" }));
  ok.close();
  const rows = await readRecords(join(directory, "o.jsonl"));
  assert.equal(rows.at(-2).file, "ps");
  assert.equal(rows.at(-3).started, "Fri Oct 2 06:00:00 2026");
});

// Mutation round 2 survivors that a test can tell apart.
test("execFile decodes a character split across reads, and waits for the pipes to close", async (t) => {
  const recorder = createRecorder({ path: join(await scratch(t), "measure.jsonl"), ...header });
  const split = await recorder.execFile(
    "/bin/sh",
    [
      "-c",
      "printf '\\342\\202'; printf '\\342\\202' >&2; sleep 0.2; printf '\\254'; printf '\\254' >&2",
    ],
    {},
    "probe",
  );
  assert.deepEqual([split.stdout, split.stderr], ["€", "€"]);
  const late = await recorder.execFile(
    "/bin/sh",
    ["-c", "(sleep 0.3; printf late) & printf early"],
    {},
    "probe",
  );
  assert.equal(late.stdout, "earlylate");
});

test("startedOf refuses an empty answer even when ps exits 0", async (t) => {
  const recorder = createRecorder({
    path: join(await scratch(t), "measure.jsonl"),
    ...header,
    spawnImpl: () => {
      const child = new EventEmitter();
      child.pid = 4242;
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.stdout.setEncoding = child.stderr.setEncoding = () => {};
      process.nextTick(() => {
        child.emit("exit", 0, null);
        child.emit("close", 0, null);
      });
      return child;
    },
  });
  await assert.rejects(recorder.startedOf(4242), /unreadable/);
});

test("ps falls back to the system PATH, and the self-start row digests the ps argv", async (t) => {
  const saved = process.env.PATH;
  delete process.env.PATH;
  try {
    assert.equal(psEnv().PATH, "/usr/bin:/bin");
  } finally {
    process.env.PATH = saved;
  }
  const directory = await scratch(t);
  const self = await createSelfRecorder({
    path: join(directory, "o.jsonl"),
    role: "outer",
    harnessVersion: "t",
  });
  self.close();
  const plain = createRecorder({ path: join(directory, "m.jsonl"), ...header });
  await plain.execFile("ps", ["-o", "lstart=", "-p", String(process.pid)], {}, "probe");
  plain.close();
  const [selfBirth] = (await readRecords(join(directory, "o.jsonl"))).filter(
    (row) => row.type === "birth",
  );
  const [plainBirth] = (await readRecords(join(directory, "m.jsonl"))).filter(
    (row) => row.type === "birth",
  );
  assert.equal(selfBirth.argvSha256, plainBirth.argvSha256);
});
