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

// Review round 2, M5: the measuring entry's decisions as pure functions, each pinned exactly.
import {
  assembleRun,
  boundBefore,
  helperIdentity,
  pinProblems,
  recordedIdentities,
  supervisionOf,
} from "./calendar-measure.mjs";
import { calendarFixture } from "./calendar-local.mjs";
import { calendarConfig } from "./calendar-session.mjs";
import { createHash } from "node:crypto";

const sha = (text) => createHash("sha256").update(text).digest("hex");
const INPUT = {
  schedule: "every 5 minutes",
  timeZone: "Invalid/CalendarZone",
  scheduleTime: "2026-10-02T00:05:00Z",
};
const ANCHOR = "2026-10-02T00:00:00Z";
const PINS = {
  sourceCommit: "a".repeat(40),
  binarySha256: "b".repeat(64),
  runnerSha256: "c".repeat(64),
  portctlSha256: "f".repeat(64),
  harnessVersion: "h".repeat(64),
  fixtureSha256: sha(calendarFixture(INPUT)),
  configSha256: sha(calendarConfig(ANCHOR)),
  exitCode: 1,
  refusalLine:
    'error: manifest: function "calendarProbe": time zone: unknown time zone "Invalid/CalendarZone"',
};
const pinInput = (overrides = {}) => ({
  plan: {
    pins: { ...PINS },
    session: {
      sourceCommit: PINS.sourceCommit,
      binarySha256: PINS.binarySha256,
      runnerSha256: PINS.runnerSha256,
      input: INPUT,
      anchor: ANCHOR,
    },
  },
  certificate: true,
  version: PINS.harnessVersion,
  portctlSha256: PINS.portctlSha256,
  refusalCheck: { ok: true, problems: [] },
  binaryDigest: PINS.binarySha256,
  runnerDigest: PINS.runnerSha256,
  ...overrides,
});

test("the pre-launch pin check names each pin that differs, before any launch", () => {
  assert.deepEqual(pinProblems(pinInput()), []);
  const session = (change) => {
    const input = pinInput();
    Object.assign(input.plan.session, change);
    return input;
  };
  for (const [name, input, problem] of [
    [
      "plan source commit",
      session({ sourceCommit: "0".repeat(40) }),
      "sourceCommit differs from its pin",
    ],
    ["plan binary", session({ binarySha256: "0" }), "binarySha256 differs from its pin"],
    ["binary on disk", pinInput({ binaryDigest: "0" }), "binarySha256 differs from its pin"],
    ["binary unreadable", pinInput({ binaryDigest: null }), "binarySha256 differs from its pin"],
    ["plan runner", session({ runnerSha256: "0" }), "runnerSha256 differs from its pin"],
    ["runner on disk", pinInput({ runnerDigest: "0" }), "runnerSha256 differs from its pin"],
    ["runner unreadable", pinInput({ runnerDigest: null }), "runnerSha256 differs from its pin"],
    ["portctl", pinInput({ portctlSha256: "0" }), "portctlSha256 differs from its pin"],
    ["harness", pinInput({ version: "0" }), "harnessVersion differs from its pin"],
    [
      "fixture",
      session({ input: { ...INPUT, schedule: "every 6 minutes" } }),
      "fixtureSha256 differs from its pin",
    ],
    [
      "unreadable fixture",
      session({ input: { ...INPUT, schedule: 5 } }),
      "fixtureSha256 differs from its pin",
    ],
    ["config", session({ anchor: "2026-10-02T00:00:01Z" }), "configSha256 differs from its pin"],
    [
      "refusal line",
      pinInput({ refusalCheck: { ok: false, problems: [] } }),
      "the pinned refusal line is not explained by the pinned source",
    ],
  ])
    assert.deepEqual(pinProblems(input), [problem], name);
  // The fixture and the refusal line are the certificate's alone.
  const control = session({ input: { ...INPUT, timeZone: "Asia/Tokyo" }, anchor: "x" });
  control.certificate = false;
  control.refusalCheck = { ok: false };
  assert.deepEqual(pinProblems(control), []);
});

test("a certificate never launches a refusal fixture that names a process API", () => {
  for (const timeZone of ["child_process", "x spawn y", "execFile", "fork", "./controls.cjs"]) {
    const input = pinInput();
    input.plan.session.input = { ...INPUT, timeZone };
    input.plan.pins.fixtureSha256 = sha(calendarFixture(input.plan.session.input));
    assert.deepEqual(pinProblems(input), ["the refusal fixture names a process API"], timeZone);
  }
});

test("supervisionOf keeps exactly the fields the verdict reads", () => {
  assert.deepEqual(
    supervisionOf({
      timedOut: false,
      cancelled: true,
      inventoryFailures: 2,
      escalate: true,
      other: 1,
    }),
    { timedOut: false, cancelled: true, inventoryFailures: 2, escalate: true },
  );
  assert.equal(supervisionOf(undefined), undefined);
  assert.equal(supervisionOf(null), undefined);
});

test("recorded identities come from identity rows and both trackers, never the measuring entry", () => {
  const files = {
    "measure.jsonl": [
      { type: "header", pid: 100 },
      { type: "identity", handle: "measure:1", pid: 200, started: "s200" },
      { type: "birth", handle: "measure:2", pid: 999 },
    ],
    "outer.jsonl": [{ type: "identity", handle: "outer:2", pid: 300, started: "s300" }],
  };
  const inner = { ownedProcesses: [{ pid: 400, uid: 7, started: "s400" }] };
  const outerSupervision = {
    ownedProcesses: [
      { pid: 100, uid: 501, started: "self" },
      { pid: 500, started: "s500" },
    ],
  };
  assert.deepEqual(
    recordedIdentities({ files, inner, outerSupervision, selfPid: 100, selfUid: 501 }),
    [
      { pid: 200, uid: 501, started: "s200" },
      { pid: 300, uid: 501, started: "s300" },
      { pid: 400, uid: 7, started: "s400" },
      { pid: 500, uid: 501, started: "s500" },
    ],
  );
  assert.deepEqual(
    recordedIdentities({ files: {}, inner: null, outerSupervision: null, selfPid: 1, selfUid: 0 }),
    [],
  );
});

test("the helper's identity comes from its first sighting", () => {
  assert.deepEqual(
    helperIdentity({
      injected: { pid: 777, acquired: true, firstSighting: { started: "s", pgid: 777, ppid: 1 } },
    }),
    { pid: 777, started: "s", acquired: true, pgid: 777 },
  );
  assert.deepEqual(
    helperIdentity({
      injected: { pid: 777, acquired: false, firstSighting: { started: "s", pgid: 5 } },
    }),
    {
      pid: 777,
      started: "s",
      acquired: false,
      pgid: 5,
    },
  );
  for (const inner of [null, {}, { injected: { pid: 777, firstSighting: null } }])
    assert.equal(helperIdentity(inner), null);
});

test("a bind counts as before the inventory only when it strictly preceded it", () => {
  assert.deepEqual(boundBefore({ port: 1, boundAt: 10 }, 10001), {
    port: 1,
    boundAt: 10,
    beforeInventory: true,
  });
  assert.equal(boundBefore({ boundAt: 10 }, 10000).beforeInventory, false);
  assert.equal(boundBefore({ boundAt: "10" }, 99999).beforeInventory, false);
  assert.equal(boundBefore(null, 1), null);
});

test("the helper's first sighting is kept, and it is acquired only as itself", async () => {
  const { noteSighting, calendarDiagnostics } = await import("./calendar-run-local.mjs");
  const helper = { pid: 777, ppid: 300, pgid: 777, started: "s1" };
  const injected = { pid: 777 };
  noteSighting(injected, [], [], 10);
  assert.deepEqual(injected, { pid: 777, acquired: false });
  noteSighting(injected, [helper], [], 20);
  assert.deepEqual(injected.firstSighting, { afterMs: 20, ppid: 300, pgid: 777, started: "s1" });
  assert.equal(injected.acquired, false);
  // A later sighting changes nothing, and a recycled PID is not the helper.
  noteSighting(injected, [{ ...helper, ppid: 1 }], [{ pid: 777, started: "s2" }], 30);
  assert.deepEqual(injected.firstSighting, { afterMs: 20, ppid: 300, pgid: 777, started: "s1" });
  assert.equal(injected.acquired, false);
  noteSighting(injected, [helper], [{ pid: 777, started: "s1" }], 40);
  assert.equal(injected.acquired, true);
  noteSighting(injected, [], [], 50);
  assert.equal(injected.acquired, true, "acquisition is never lost");
  // Without a PID yet, nothing is noted.
  const unknown = { pid: null };
  noteSighting(unknown, [helper], [helper], 60);
  assert.deepEqual(unknown, { pid: null });
  // The diagnostics kept from the daemon: startup and refusal lines only, at most 20.
  assert.deepEqual(
    calendarDiagnostics(
      'x\nfunctions loaded: a\nAuthorization: Bearer y\nerror: unknown time zone "Z"\ncalendarProbe ok\ninvalid timezone\ninvalid schedule\n',
    ),
    [
      "functions loaded: a",
      'error: unknown time zone "Z"',
      "calendarProbe ok",
      "invalid timezone",
      "invalid schedule",
    ],
  );
  assert.equal(calendarDiagnostics("calendarReceipt\n".repeat(30)).length, 20);
});

test("the final inventory takes passes until two clean ones, a definite answer or five", async () => {
  const { finalInventory } = await import("./calendar-measure.mjs");
  const ctx = { sessionId: 300, recorded: [], privateDirs: [], launchTime: 0, rootPid: 100 };
  const base = [
    {
      pid: 1,
      ppid: 0,
      uid: 0,
      started: "Thu Jan 1 00:00:00 1970",
      stat: "S",
      args: "launchd",
      sid: 1,
    },
    {
      pid: 100,
      ppid: 1,
      uid: 501,
      started: "Thu Jan 1 00:00:00 1970",
      stat: "S",
      args: "measure",
      sid: 50,
    },
  ];
  const churn = {
    pid: 5000,
    ppid: 1,
    uid: 501,
    started: "Fri Oct 2 06:00:05 2026",
    stat: "S",
    args: "x",
    sid: "ESRCH",
  };
  const run = async (sequence) => {
    let taken = 0;
    const result = await finalInventory(
      async () => sequence[Math.min(taken++, sequence.length - 1)],
      ctx,
    );
    return [result.outcome, taken];
  };
  assert.deepEqual(await run([base]), ["clean", 2]);
  assert.deepEqual(await run([base, [...base, churn], base, base]), ["clean", 4]);
  assert.deepEqual(await run([[...base, churn]]), ["inconclusive", 5]);
  assert.deepEqual(await run([[...base, { ...churn, sid: 300 }]]), ["survivors", 1]);
  assert.deepEqual(await run([[...base, { ...churn, sid: "EPERM" }]]), ["inconclusive", 1]);
});

// assembleRun: every input reaches the verdict and the report where it should.
function runInput() {
  const supervision = (escalate = true) => ({
    timedOut: false,
    cancelled: false,
    inventoryFailures: 0,
    escalate,
    settledWithoutEscalation: true,
    cleanupVerified: true,
    selfEnded: [{ pid: 9 }],
  });
  return {
    plan: { pins: { ...PINS } },
    kind: { kind: "certificate", escalation: "on", certificate: true },
    version: PINS.harnessVersion,
    outerResult: {
      identity: {
        sourceCommit: PINS.sourceCommit,
        binarySha256: PINS.binarySha256,
        runnerSha256: PINS.runnerSha256,
        fixtureSha256: PINS.fixtureSha256,
        configSha256: PINS.configSha256,
      },
      inner: {
        ...supervision(),
        exitCode: 1,
        diagnostics: ["functions loaded: none", PINS.refusalLine],
        diagnosticsDrained: true,
        observationHandshake: false,
        stderrTailPath: "/private/run/daemon-stderr-tail.txt",
        selfEnded: [{ pid: 8 }],
      },
      supervision: supervision(),
      callback: null,
      releaseCode: 0,
      claimsAfter: [],
    },
    chain: { rootSid: 50, outerPid: 300, outerSid: 300 },
    records: {
      ok: true,
      problems: [],
      signals: [],
      births: { measure: ["outer"], outer: ["claim", "inner"], inner: ["daemon"] },
    },
    validator: { ok: true, controls: [] },
    inventory: {
      outcome: "clean",
      reason: undefined,
      survivors: [],
      passes: [
        { survivors: [], repass: [1], unrelatedZombies: [2], ignored: [3], inconclusive: [4] },
      ],
    },
    claims: [],
    lsof: [{ result: "none" }],
    alive: [],
    bound: null,
    extra: { portctlSha256: PINS.portctlSha256, refusalCheck: { ok: true, problems: [] } },
  };
}

test("a complete refusal run assembles to a passing verdict and a full report", () => {
  const report = assembleRun(runInput());
  assert.equal(report.verdict.verdict, "pass", JSON.stringify(report.verdict.conditions));
  assert.deepEqual(report.identity, {
    ...runInput().outerResult.identity,
    portctlSha256: PINS.portctlSha256,
    harnessVersion: PINS.harnessVersion,
  });
  assert.deepEqual(report.refusal, { exitCode: 1, line: PINS.refusalLine });
  assert.equal(report.control, null);
  assert.equal(report.daemonStderrTail, null);
  assert.equal(report.lsofByPid, "skipped: no recorded identity alive");
  assert.deepEqual(report.selfEnded, { inner: [{ pid: 8 }], outer: [{ pid: 9 }] });
  assert.deepEqual(report.records, { ok: true, problems: [], signals: 0 });
  assert.deepEqual(report.inventory.passes, [
    { repass: [1], unrelatedZombies: [2], ignored: [3], inconclusive: [4] },
  ]);
  assert.deepEqual(report.supervision.inner, {
    timedOut: false,
    cancelled: false,
    inventoryFailures: 0,
    escalate: true,
  });
  assert.equal(assembleRun({ ...runInput(), alive: [7] }).lsofByPid, "ran");
});

test("each collected input reaches its condition", () => {
  const change = (apply) => {
    const input = runInput();
    apply(input);
    return assembleRun(input);
  };
  for (const [name, apply, letter] of [
    ["exit code", (i) => (i.outerResult.inner.exitCode = 0), "A"],
    ["refusal line", (i) => (i.outerResult.inner.diagnostics = ["functions loaded: none"]), "A"],
    ["identity", (i) => (i.outerResult.identity.binarySha256 = "0"), "A"],
    ["portctl", (i) => (i.extra.portctlSha256 = "0"), "A"],
    ["harness", (i) => (i.version = "0"), "A"],
    ["refusal check", (i) => (i.extra.refusalCheck = { ok: false, problems: ["p"] }), "A"],
    ["chain", (i) => (i.chain.outerSid = 50), "B"],
    ["records", (i) => (i.records = { ...i.records, ok: false, problems: ["r"] }), "C"],
    ["drain", (i) => (i.outerResult.inner.diagnosticsDrained = false), "D"],
    ["daemon timeout", (i) => (i.outerResult.inner.timedOut = true), "D"],
    ["daemon cancelled", (i) => (i.outerResult.inner.cancelled = true), "D"],
    ["inner settle", (i) => (i.outerResult.inner.settledWithoutEscalation = false), "D"],
    ["outer settle", (i) => (i.outerResult.supervision.settledWithoutEscalation = false), "D"],
    ["outer timeout", (i) => (i.outerResult.supervision.timedOut = true), "D"],
    ["inner polls", (i) => (i.outerResult.inner.inventoryFailures = 1), "D"],
    [
      "inventory",
      (i) =>
        (i.inventory = {
          ...i.inventory,
          outcome: "survivors",
          survivors: [{ rules: ["session"] }],
        }),
      "E",
    ],
    ["claims", (i) => (i.claims = [{ port: 1 }]), "F"],
    ["no claims read", (i) => (i.claims = null), "F"],
    ["lsof", (i) => (i.lsof = [{ result: "listener", pids: [1] }]), "F"],
    ["escalation", (i) => (i.outerResult.supervision.escalate = false), "G"],
    ["validator", (i) => (i.validator = { ok: false }), "G"],
    [
      "kind",
      (i) => {
        i.kind = { kind: "control", escalation: "off", certificate: false };
        i.plan.control = { mode: "orphan" };
      },
      "G",
    ],
  ]) {
    const report = change(apply);
    assert.notEqual(report.verdict.conditions[letter].outcome, "pass", name);
    for (const other of "ABCDEFG")
      if (other !== letter && !(name === "kind" && other === "G"))
        assert.equal(report.verdict.conditions[other].outcome, "pass", `${name} touched ${other}`);
  }
  // No inner supervisor result: (A) and (D) cannot pass.
  const noInner = change((i) => (i.outerResult.inner = null));
  assert.equal(noInner.verdict.conditions.A.outcome, "inconclusive");
  assert.equal(noInner.verdict.conditions.D.outcome, "inconclusive");
  assert.deepEqual(noInner.refusal, { exitCode: null, line: null });
  // An (A) failure names the private stderr tail; another failure does not.
  assert.equal(
    change((i) => (i.outerResult.inner.exitCode = 0)).daemonStderrTail,
    "/private/run/daemon-stderr-tail.txt",
  );
  assert.equal(change((i) => (i.claims = [{ port: 1 }])).daemonStderrTail, null);
  // The observed refusal: the pinned line when printed, else the first zone line, else none.
  const observed = (diagnostics) =>
    change((i) => (i.outerResult.inner.diagnostics = diagnostics)).refusal.line;
  assert.equal(observed(["unknown time zone x", PINS.refusalLine]), PINS.refusalLine);
  assert.equal(
    observed(["a", 'error: unknown time zone "Q"', "unknown time zone R"]),
    'error: unknown time zone "Q"',
  );
  assert.equal(observed(["a"]), null);
  assert.equal(observed(undefined), null);
  // Without an identity there is none to report.
  assert.equal(change((i) => (i.outerResult.identity = undefined)).identity, null);
});

test("a control's report carries its helper's identity, binding and observation", () => {
  const positive = (apply = () => {}) => {
    const input = runInput();
    input.kind = { kind: "positive", escalation: "on", certificate: false };
    input.outerResult.inner.observationHandshake = true;
    input.outerResult.callback = { matched: true };
    apply(input);
    return assembleRun(input).control;
  };
  assert.deepEqual(positive(), {
    mode: "positive",
    injected: null,
    bound: null,
    counts: true,
    rulesFired: [],
  });
  for (const [name, apply] of [
    ["no handshake", (i) => (i.outerResult.inner.observationHandshake = false)],
    ["no match", (i) => (i.outerResult.callback = { matched: false })],
    ["inner cleanup", (i) => (i.outerResult.inner.cleanupVerified = false)],
    ["outer cleanup", (i) => (i.outerResult.supervision.cleanupVerified = false)],
    ["release", (i) => (i.outerResult.releaseCode = 1)],
    ["claims kept", (i) => (i.outerResult.claimsAfter = [{}])],
    ["claims unread", (i) => (i.outerResult.claimsAfter = undefined)],
  ])
    assert.equal(positive(apply).counts, false, name);
  const orphan = runInput();
  orphan.kind = { kind: "control", escalation: "off", certificate: false };
  orphan.plan.control = { mode: "orphan" };
  orphan.outerResult.inner.injected = {
    pid: 777,
    acquired: false,
    firstSighting: { started: "s777", pgid: 700, ppid: 1 },
  };
  orphan.inventory.survivors = [
    { row: { pid: 777, ppid: 1, started: "s777" }, rules: ["session"] },
  ];
  orphan.bound = { beforeInventory: true };
  const control = assembleRun(orphan).control;
  assert.deepEqual(control, {
    mode: "orphan",
    injected: { pid: 777, started: "s777", acquired: false, pgid: 700 },
    bound: { beforeInventory: true },
    counts: true,
    rulesFired: ["session"],
  });
});
