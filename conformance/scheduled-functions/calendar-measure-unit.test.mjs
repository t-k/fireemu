import assert from "node:assert/strict";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import { cleanupTargets, ownedSender, stopRecordedChild } from "./calendar-measure.mjs";

// Unit tests of the measuring entry's decision code with injected fakes; nothing is spawned and
// no signal is sent (review round 2, M2 and M5).

const launchTime = Date.parse("2026-10-02T06:00:00Z");
const row = (overrides) => ({
  pid: 5000,
  ppid: 1,
  pgid: 5000,
  uid: 501,
  started: "Fri Oct 2 06:00:05 2026",
  stat: "S",
  args: "/usr/bin/other",
  sid: 77,
  ...overrides,
});
const chain = { rootSid: 50, outerPid: 300, outerSid: 300 };

test("post-verdict cleanup targets only session members, recorded identities and the injected helper", () => {
  const recorded = [{ pid: 400, uid: 501, started: "Fri Oct 2 06:00:03 2026" }];
  const injected = { pid: 600, started: "Fri Oct 2 06:00:06 2026" };
  const rows = [
    row({ pid: 100, sid: 50, args: "node measure" }),
    row({ pid: 201, sid: 300 }),
    row({ pid: 400, started: "Fri Oct 2 06:00:03 2026", sid: 9 }),
    row({ pid: 600, started: "Fri Oct 2 06:00:06 2026", sid: 600 }),
    // By path alone: never (a run path is evidence for the verdict, not ownership).
    row({ pid: 700, args: "python3 /private/run-1/helper" }),
    // A recycled PID: a recorded or injected PID with another start time.
    row({ pid: 401, started: "Fri Oct 2 06:00:09 2026" }),
    row({ pid: 400 + 0, uid: 0, started: "Fri Oct 2 06:00:03 2026", sid: 9 }),
    row({ pid: 600, started: "Fri Oct 2 06:00:07 2026", sid: 600 }),
    // A zombie session member and a member older than the launch: never.
    row({ pid: 202, sid: 300, stat: "Z" }),
    row({ pid: 203, sid: 300, started: "Fri Oct 2 05:59:59 2026" }),
    row({ pid: 204, sid: 300, started: "unreadable" }),
  ];
  const targets = cleanupTargets({ rows, chain, launchTime, recorded, injected, selfPid: 100 });
  assert.deepEqual(
    targets.map((target) => [target.pid, target.started]),
    [
      [201, "Fri Oct 2 06:00:05 2026"],
      [400, "Fri Oct 2 06:00:03 2026"],
      [600, "Fri Oct 2 06:00:06 2026"],
    ],
  );
  // Without a usable outer session, no row is a member.
  for (const broken of [
    { ...chain, outerSid: undefined },
    { ...chain, outerSid: "ESRCH" },
    { ...chain, outerSid: 50 },
  ])
    assert.deepEqual(
      cleanupTargets({
        rows,
        chain: broken,
        launchTime,
        recorded: [],
        injected: null,
        selfPid: 100,
      }),
      [],
    );
});

function fakeRecorder() {
  const calls = [];
  return {
    calls,
    verifiedSignal: async (target, kind, send) => {
      calls.push({ target, kind });
      await send();
      return true;
    },
  };
}

function fakeChild(pid) {
  const child = new EventEmitter();
  child.pid = pid;
  child.recordExited = false;
  child.kills = [];
  child.kill = (kind) => child.kills.push(kind);
  child.recordExit = new Promise((resolve) => {
    child.exit = () => {
      child.recordExited = true;
      resolve({ code: 0, signal: null });
    };
  });
  return child;
}

test("an owned sender signals through the verified path, a direct child by its handle", async () => {
  const recorder = fakeRecorder();
  const child = fakeChild(300);
  const send = ownedSender(recorder, [child]);
  const identity = { pid: 300, uid: 501, started: "Fri Oct 2 06:00:01 2026", comm: "node" };
  assert.equal(await send(300, "SIGTERM", identity), true);
  assert.deepEqual(child.kills, ["SIGTERM"]);
  assert.deepEqual(recorder.calls, [
    { target: { pid: 300, uid: 501, started: "Fri Oct 2 06:00:01 2026" }, kind: "SIGTERM" },
  ]);
  // A reaped direct child, or no recorded identity: nothing is asked or sent.
  child.exit();
  await child.recordExit;
  assert.equal(await send(300, "SIGKILL", identity), false);
  assert.equal(await send(301, "SIGKILL", undefined), false);
  assert.equal(await send(301, "SIGKILL", { pid: 301, uid: 501 }), false);
  assert.equal(recorder.calls.length, 1);
  assert.deepEqual(child.kills, ["SIGTERM"]);
});

test("stopping a recorded child never signals one that has exited, and waits for the exit", async () => {
  const recorder = fakeRecorder();
  const exited = fakeChild(300);
  exited.exit();
  await stopRecordedChild(recorder, exited, "Fri Oct 2 06:00:01 2026", async () => {});
  assert.deepEqual(recorder.calls, []);
  // Live: SIGTERM, then (still not gone) SIGKILL, then the exit is awaited.
  const live = fakeChild(301);
  const waits = [];
  const stopped = stopRecordedChild(recorder, live, "Fri Oct 2 06:00:02 2026", async (ms) => {
    waits.push(ms);
    if (waits.length === 2) live.exit();
  });
  await stopped;
  assert.deepEqual(
    recorder.calls.map((call) => call.kind),
    ["SIGTERM", "SIGKILL"],
  );
  assert.deepEqual(live.kills, ["SIGTERM", "SIGKILL"]);
  // An unknown start time means no verifiable identity: no signal, only the wait.
  const unknown = fakeChild(302);
  const waiting = stopRecordedChild(recorder, unknown, undefined, async () => {});
  unknown.exit();
  await waiting;
  assert.equal(recorder.calls.length, 2);
});

test("the daemon's stderr tail keeps only the last bytes", async () => {
  const { stderrTail } = await import("./calendar-run-local.mjs");
  assert.equal(stderrTail("", "abc", 4), "abc");
  assert.equal(stderrTail("abc", "def", 4), "cdef");
  assert.equal(stderrTail("abcd", "0123456789", 4), "6789");
  assert.equal(stderrTail("", "", 4), "");
});
