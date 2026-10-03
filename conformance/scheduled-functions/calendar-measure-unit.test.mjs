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

test("certify reads every report and attempt, digests each file and applies the explanations", async (t) => {
  const { certify } = await import("./calendar-measure.mjs");
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = await mkdtemp(join(tmpdir(), "calendar-certify-unit-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const write = async (name, value) => {
    const path = join(directory, name);
    await writeFile(path, JSON.stringify(value));
    return path;
  };
  const refusal = await write("refusal.json", { kind: "certificate", launchTime: 2000 });
  const failed = await write("failed.json", {
    kind: "certificate",
    launchTime: 1000,
    verdict: { verdict: "fail" },
  });
  const list = await write("list.json", { refusal, controls: [], attempts: [failed] });
  const result = await certify(list);
  assert.ok(
    result.problems.includes(`an earlier attempt failed without an explanation: ${failed}`),
    String(result.problems),
  );
  const failedSha = sha(
    JSON.stringify({ kind: "certificate", launchTime: 1000, verdict: { verdict: "fail" } }),
  );
  const explained = await write("list2.json", {
    refusal,
    controls: [],
    attempts: [failed],
    explanations: { [failedSha]: "port collision" },
  });
  assert.ok(
    !(await certify(explained)).problems.some((problem) =>
      problem.startsWith("an earlier attempt"),
    ),
  );
  // A missing report file is no report.
  const missing = await write("list3.json", {
    refusal: join(directory, "absent.json"),
    controls: [],
  });
  assert.ok(
    (await certify(missing)).problems.includes("the refusal report is not a certificate run"),
  );
});

import { claimArguments, complete, planKind } from "./calendar-measure.mjs";
import { CONTROL_VARIANTS } from "./calendar-controls.mjs";

test("planKind selects the exact fixture and escalation for every control mode", () => {
  const plan = (timeZone, extra = {}) => ({ session: { input: { timeZone } }, ...extra });
  const certificate = { kind: "certificate", escalation: "on", certificate: true };
  const positive = { kind: "positive", escalation: "on", certificate: false };
  assert.deepEqual(planKind(plan("Invalid/CalendarZone")), certificate);
  assert.deepEqual(planKind(plan("UTC", { positive: true })), positive);
  assert.throws(() => planKind(plan("UTC")), /the certificate run needs the refusal fixture/);
  assert.throws(
    () => planKind(plan("Invalid/CalendarZone", { positive: true })),
    /the positive control needs a valid time zone/,
  );
  for (const [mode, variant] of Object.entries(CONTROL_VARIANTS)) {
    const correct = variant.fixture === "valid" ? "UTC" : "Invalid/CalendarZone";
    const wrong = variant.fixture === "valid" ? "Invalid/CalendarZone" : "UTC";
    assert.deepEqual(
      planKind(plan(correct, { control: { mode } })),
      { kind: "control", escalation: variant.escalation, certificate: false },
      mode,
    );
    assert.throws(
      () => planKind(plan(wrong, { control: { mode } })),
      /control fixture variant differs/,
      mode,
    );
    assert.throws(
      () => planKind(plan(correct, { control: { mode }, positive: true })),
      /a run is one control at most/,
      mode,
    );
  }
  for (const mode of [undefined, "", "missing", "toString"])
    assert.throws(() => planKind(plan("UTC", { control: { mode } })), /unknown control mode/);
});

test("complete requires each independent query condition in the full truth table", () => {
  for (const code of [0, 1])
    for (const stderr of ["", "unreadable"])
      for (const truncated of [false, true, undefined])
        for (const timedOut of [false, true]) {
          const answer = { code, stderr, truncated, timedOut };
          const expected = code === 0 && stderr === "" && truncated === false && timedOut === false;
          assert.equal(complete(answer), expected, JSON.stringify(answer));
        }
});

test("claimArguments preserves every private registry argument in order", () => {
  for (let index = 0; index < 64; index++) {
    const input = {
      script: `/tools/${index}/portctl.py`,
      database: `/runs/${index}/registry.sqlite`,
      cwd: `/work/${index}`,
      service: `calendar-${index}`,
    };
    assert.deepEqual(claimArguments(input), [
      input.script,
      "--db",
      input.database,
      "--cwd",
      input.cwd,
      "claim",
      "--service",
      input.service,
      "--range",
      "10000-19999",
      "--ttl",
      "5m",
      "--format",
      "json",
      "--random",
    ]);
    for (const key of ["script", "database", "cwd"])
      for (const value of ["relative", undefined, null, 42])
        assert.throws(
          () => claimArguments({ ...input, [key]: value }),
          /portctl claim paths must be absolute/,
        );
  }
});

const loaderReport = (kind, overrides = {}) => ({
  kind,
  harnessVersion: PINS.harnessVersion,
  launchTime: Date.parse("2026-10-02T03:00:00Z"),
  verdict: { verdict: kind === "certificate" ? "pass" : "fail" },
  validatorControls: { ok: true },
  identity: { ...PINS },
  pins: { ...PINS },
  refusal: {
    exitCode: kind === "certificate" ? 1 : 0,
    line: kind === "certificate" ? PINS.refusalLine : null,
  },
  root: { pid: 100, started: "Fri Oct 2 03:00:00 2026", sid: 50 },
  control: kind === "certificate" ? null : { mode: kind, counts: true },
  ...overrides,
});

test("certify binds a complete certificate to each exact loaded byte sequence", async (t) => {
  const { certify } = await import("./calendar-measure.mjs");
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = await mkdtemp(join(tmpdir(), "calendar-loader-binding-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const write = async (name, report) => {
    const path = join(directory, name);
    const bytes = `  ${JSON.stringify(report, null, 2)}\n\n`;
    await writeFile(path, bytes);
    return { path, sha256: sha(bytes) };
  };
  const files = [await write("refusal.json", loaderReport("certificate"))];
  for (const kind of ["positive", "orphan", "escaper", "listener", "leftover"])
    files.push(await write(`${kind}.json`, loaderReport(kind)));
  const earlier = await write(
    "earlier.json",
    loaderReport("certificate", {
      launchTime: Date.parse("2026-10-02T02:00:00Z"),
      verdict: { verdict: "fail" },
    }),
  );
  const listPath = join(directory, "list.json");
  const list = {
    refusal: files[0].path,
    controls: files.slice(1).map((file) => file.path),
    attempts: [earlier.path],
    explanations: { [earlier.sha256]: "observed port collision" },
  };
  await writeFile(listPath, JSON.stringify(list));
  const valid = await certify(listPath);
  assert.equal(valid.verdict, "pass", JSON.stringify(valid.problems));
  assert.deepEqual(
    valid.certificate.reports.map(({ path, sha256 }) => ({ path, sha256 })),
    files,
  );
  assert.deepEqual(valid.certificate.attempts, [
    { ...earlier, verdict: "fail", explanation: "observed port collision" },
  ]);
  // Equal parsed data with different bytes invalidates the earlier hash-keyed explanation.
  await writeFile(
    earlier.path,
    JSON.stringify(
      loaderReport("certificate", {
        launchTime: Date.parse("2026-10-02T02:00:00Z"),
        verdict: { verdict: "fail" },
      }),
    ),
  );
  const changed = await certify(listPath);
  assert.equal(changed.verdict, "fail");
  assert.ok(
    changed.problems.includes(`an earlier attempt failed without an explanation: ${earlier.path}`),
  );
  const absent = join(directory, "absent.json");
  await writeFile(
    listPath,
    JSON.stringify({ ...list, attempts: [absent], explanations: { null: "lost bytes" } }),
  );
  assert.equal((await certify(listPath)).verdict, "fail");
  await writeFile(earlier.path, "{unreadable");
  await writeFile(
    listPath,
    JSON.stringify({ ...list, explanations: { [sha("{unreadable")]: "lost parse" } }),
  );
  assert.equal((await certify(listPath)).verdict, "fail");
  await writeFile(listPath, JSON.stringify({ ...list, attempts: [null] }));
  assert.equal((await certify(listPath)).verdict, "fail");
  // These are synthetic unit records, never an actual pinned-build measurement.
  const { readFile } = await import("node:fs/promises");
  const standInSha = sha(await readFile(new URL("./testdata/fake-runner.cjs", import.meta.url)));
  for (const [index, kind] of [
    "certificate",
    "positive",
    "orphan",
    "escaper",
    "listener",
    "leftover",
  ].entries()) {
    const record = loaderReport(kind);
    record.identity.runnerSha256 = standInSha;
    record.pins.runnerSha256 = standInSha;
    await writeFile(files[index].path, JSON.stringify(record));
  }
  await writeFile(listPath, JSON.stringify({ ...list, attempts: [] }));
  const standIn = await certify(listPath);
  assert.equal(standIn.verdict, "fail");
  assert.ok(standIn.problems.includes("the refusal run used the stand-in runner"));
});

test("certify rejects explicit malformed attempt lists while omitted and empty remain optional", async (t) => {
  const { certify } = await import("./calendar-measure.mjs");
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = await mkdtemp(join(tmpdir(), "calendar-attempt-list-schema-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const write = async (name, value) => {
    const path = join(directory, name);
    await writeFile(path, JSON.stringify(value));
    return path;
  };
  const refusal = await write("refusal.json", loaderReport("certificate"));
  const controls = [];
  for (const mode of ["positive", "orphan", "escaper", "listener", "leftover"])
    controls.push(await write(`${mode}.json`, loaderReport(mode)));
  const listPath = join(directory, "list.json");
  for (const attempts of [null, {}, "unknown", false, 1]) {
    await writeFile(listPath, JSON.stringify({ refusal, controls, attempts }));
    const result = await certify(listPath);
    assert.equal(result.verdict, "fail", JSON.stringify(attempts));
    assert.equal(result.certificate, null);
    assert.deepEqual(result.problems, ["the attempt list is unreadable"]);
  }
  for (const list of [
    { refusal, controls },
    { refusal, controls, attempts: [] },
  ]) {
    await writeFile(listPath, JSON.stringify(list));
    const result = await certify(listPath);
    assert.equal(result.verdict, "pass", JSON.stringify(result.problems));
    assert.deepEqual(result.certificate.attempts, []);
  }
});

test("the CLI certificate boundary refuses synthetic summaries and omitted failures", async (t) => {
  const { certify } = await import("./calendar-measure.mjs");
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = await mkdtemp(join(tmpdir(), "calendar-campaign-boundary-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const reports = ["certificate", "positive", "orphan", "escaper", "listener", "leftover"].map(
    (kind) => loaderReport(kind),
  );
  const paths = reports.map((_, i) => join(directory, `report-${i}.json`));
  const earlier = join(directory, "earlier-failed.json");
  await writeFile(
    earlier,
    JSON.stringify(
      loaderReport("certificate", { launchTime: launchTime - 1000, verdict: { verdict: "fail" } }),
    ),
  );
  const listPath = join(directory, "list.json");
  for (const contradiction of [false, true]) {
    if (contradiction) {
      reports[0].verdict.conditions = {
        A: { ok: false, outcome: "fail" },
        E: { ok: false, outcome: "inconclusive" },
      };
      reports[0].records = { ok: false, signals: 1 };
      reports[0].inventory = { outcome: "inconclusive", passes: [] };
      reports[1].inventory = { outcome: "survivors", survivors: [{ row: { pid: 999 } }] };
      reports[1].cleanup = { outcome: "unknown" };
    }
    for (let i = 0; i < paths.length; i++) await writeFile(paths[i], JSON.stringify(reports[i]));
    for (const attempts of [undefined, []]) {
      await writeFile(
        listPath,
        JSON.stringify({ refusal: paths[0], controls: paths.slice(1), attempts }),
      );
      assert.equal(
        (await certify(listPath)).verdict,
        "pass",
        "synthetic pure helper compatibility",
      );
      const result = await certify(listPath, { requireCampaign: true });
      assert.equal(result.verdict, "fail", "CLI requires native sealed campaign evidence");
      assert.equal(result.certificate, null);
      const { spawnSync } = await import("node:child_process");
      const { fileURLToPath } = await import("node:url");
      const cli = fileURLToPath(new URL("./calendar-run-local.mjs", import.meta.url));
      const child = spawnSync(process.execPath, [cli, "--certify", listPath], {
        encoding: "utf8",
        timeout: 10000,
      });
      assert.equal(child.status, 1, child.stdout + child.stderr);
      assert.equal(JSON.parse(child.stdout).nativeCertificateIssued, false);
    }
  }
});

test("a campaign awaits durable birth before effects and retains exactly one raw plan read", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  const events = [];
  const bytes = Buffer.from('{"plan":"retained"}');
  const retained = Buffer.from(bytes);
  let release;
  const ack = new Promise((resolve) => {
    release = resolve;
  });
  const scope = { campaign: "unit", utcDay: "2026-10-02" };
  const handles = {
    registerBirth: async ({ planBytes }) => {
      events.push("birth");
      assert.deepEqual(planBytes, bytes);
      await ack;
      events.push("birth-ack");
      return { durable: true };
    },
    recordTerminal: async ({ reportBytes }) => {
      events.push("terminal");
      const envelope = JSON.parse(reportBytes);
      assert.equal(envelope.outcome, "fail");
      assert.equal(envelope.rawReportSha256, sha(Buffer.from(envelope.rawReport, "base64")));
      return { durable: true };
    },
    seal: async () => {
      events.push("seal");
      return { state: "complete", durabilityAcknowledged: true };
    },
    close: async () => {
      events.push("close");
    },
  };
  const pending = produceCampaign({
    classifyReport: (report) => report?.verdict?.verdict,
    scope,
    authorityId: "unit",
    attempts: [{ attemptId: "a", planPath: "/plan", planSha256: sha(bytes) }],
    bootstrap: async () => {
      events.push("bootstrap");
      return { scope, receipt: { phase: "infrastructure" } };
    },
    readPlan: async () => {
      events.push("read-plan");
      return bytes;
    },
    createLedger: async () => {
      events.push("ledger");
      return handles;
    },
    measureAttempt: async (raw) => {
      events.push("effects");
      assert.deepEqual(raw, retained);
      return Buffer.from('{"verdict":{"verdict":"fail"}}');
    },
    readSnapshot: async () => {
      events.push("readback");
      return {};
    },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(events, ["bootstrap", "ledger", "read-plan", "birth"]);
  bytes[0] = 32;
  release();
  const result = await pending;
  assert.deepEqual(events, [
    "bootstrap",
    "ledger",
    "read-plan",
    "birth",
    "birth-ack",
    "effects",
    "terminal",
    "seal",
    "readback",
    "close",
  ]);
  assert.equal(result.state, "complete");
  assert.equal(result.externalApprovalVerified, false);
  assert.equal(result.allDayCertified, false);
});

test("campaign early exceptions remain unknown terminals and never seal as complete failures", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  for (const outcome of ["pass", "fail", "inconclusive", "throw", "bad-json"]) {
    const events = [];
    let envelope;
    const raw = Buffer.from("{}");
    const result = await produceCampaign({
      classifyReport: (report) => report?.verdict?.verdict,
      authorityId: "unit",
      attempts: [{ attemptId: "one", planPath: "/one", planSha256: sha(raw) }],
      bootstrap: async () => ({
        scope: { utcDay: "2026-10-02" },
        receipt: { phase: "infrastructure" },
      }),
      readPlan: async () => raw,
      createLedger: async () => ({
        registerBirth: async () => {
          events.push("birth-ack");
          return { durable: true };
        },
        recordTerminal: async ({ reportBytes }) => {
          envelope = JSON.parse(reportBytes);
          events.push("terminal");
          return { durable: true };
        },
        seal: async () => {
          events.push("seal");
          if (envelope.outcome === "unknown") throw new Error("unknown terminal");
          return { state: "complete", durabilityAcknowledged: true };
        },
        close: async () => {
          events.push("close");
        },
      }),
      measureAttempt: async () => {
        events.push("effects");
        if (outcome === "throw") throw new Error("prelaunch");
        return Buffer.from(
          outcome === "bad-json" ? "{" : JSON.stringify({ verdict: { verdict: outcome } }),
        );
      },
      readSnapshot: async () => ({}),
    });
    const known = ["pass", "fail"].includes(outcome);
    assert.equal(envelope.outcome, known ? outcome : "unknown");
    assert.equal(result.state, known ? "complete" : "unknown");
    assert.deepEqual(events, ["birth-ack", "effects", "terminal", "seal", "close"]);
    assert.equal(result.externalApprovalVerified, false);
  }
});

test("post-verdict cleanup saves an independent after inventory and refuses unknown signals", async () => {
  const { cleanupOwned } = await import("./calendar-measure.mjs");
  for (const [signalOk, remains, expected] of [
    [true, false, "clean"],
    [false, false, "unknown"],
    [true, true, "unknown"],
  ]) {
    let calls = 0;
    const target = row({ pid: 201, sid: 300 });
    const result = await cleanupOwned({
      inventory: async () => (++calls === 1 || remains ? [target] : []),
      signal: async () => signalOk,
      context: { chain, launchTime, recorded: [], injected: null, selfPid: 100 },
    });
    assert.equal(calls, 2);
    assert.deepEqual(result.after, remains ? [target] : []);
    assert.equal(result.outcome, expected);
  }
});

function nativeFixture() {
  const input = runInput();
  input.plan = { ...pinInput().plan, positive: false };
  const h = PINS.harnessVersion;
  const start = "Fri Oct 2 06:00:00 2026";
  const header = (role, pid) => ({ type: "header", role, pid, started: start, harnessVersion: h });
  let tick = 0;
  const birth = (role, n, pid, purpose) => ({
    type: "birth",
    handle: `${role}:${n}`,
    pid,
    uid: 501,
    purpose,
    file: "node",
    argvSha256: "a".repeat(64),
    spawnMonoNs: String(++tick),
  });
  const exit = (role, n, code = 0) => ({
    type: "exit",
    handle: `${role}:${n}`,
    code,
    signal: null,
    exitMonoNs: String(++tick),
  });
  const identity = (role, n, pid) => ({
    type: "identity",
    handle: `${role}:${n}`,
    pid,
    started: start,
  });
  const files = {
    "measure.jsonl": [
      header("measure", 100),
      birth("measure", 1, 300, "outer"),
      identity("measure", 1, 300),
      exit("measure", 1),
    ],
    "outer.jsonl": [
      header("outer", 300),
      birth("outer", 1, 301, "claim"),
      exit("outer", 1),
      birth("outer", 2, 400, "inner"),
      identity("outer", 2, 400),
      exit("outer", 2),
    ],
    "inner.jsonl": [header("inner", 400), birth("inner", 1, 500, "daemon"), exit("inner", 1)],
  };
  const queries = [];
  const answer = (stdout, code = 0) => ({
    stdout,
    code,
    stderr: "",
    timedOut: false,
    truncated: false,
  });
  const query = (purpose, file, args, stdout, code = 0) => {
    const n = files["measure.jsonl"].filter((r) => r.type === "birth").length + 1;
    const b = birth("measure", n, 600 + n, purpose);
    b.file = file;
    b.argvSha256 = sha(JSON.stringify([file, ...args]));
    files["measure.jsonl"].push(b, exit("measure", n, code));
    queries.push({
      purpose,
      file,
      args,
      answer: { ...answer(stdout, code), handle: b.handle, pid: b.pid },
    });
  };
  const sources = {};
  for (const { path, text } of Object.values(REFUSAL_FORMATS))
    sources[path] = (sources[path] ?? "") + text + "\n";
  for (const [path, text] of Object.entries(sources))
    query("pinned-source", "git", ["-C", "/source", "show", `${PINS.sourceCommit}:${path}`], text);
  for (let i = 0; i < 2; i++) {
    query(
      "inventory",
      "ps",
      [],
      "1 0 1 0 Thu Jan 1 00:00:00 1970 S launchd\n100 1 50 501 Fri Oct 2 06:00:00 2026 S node measure\n",
    );
    query("getsid", "python3", [], '{"1":1,"100":50}');
  }
  query("claims-read", "python3", [], '{"claims":[]}');
  query("lsof", "lsof", [], "", 1);
  input.records = validateRecords(files);
  input.validator = validatorControls(files);
  input.inventory = judgeInventory(
    [
      [
        {
          pid: 1,
          ppid: 0,
          pgid: 1,
          uid: 0,
          started: "Thu Jan 1 00:00:00 1970",
          stat: "S",
          args: "launchd",
          sid: 1,
        },
        {
          pid: 100,
          ppid: 1,
          pgid: 50,
          uid: 501,
          started: start,
          stat: "S",
          args: "node measure",
          sid: 50,
        },
      ],
      [
        {
          pid: 1,
          ppid: 0,
          pgid: 1,
          uid: 0,
          started: "Thu Jan 1 00:00:00 1970",
          stat: "S",
          args: "launchd",
          sid: 1,
        },
        {
          pid: 100,
          ppid: 1,
          pgid: 50,
          uid: 501,
          started: start,
          stat: "S",
          args: "node measure",
          sid: 50,
        },
      ],
    ],
    { sessionId: 300, recorded: [], privateDir: "/run", launchTime, rootPid: 100 },
  );
  const report = {
    ...assembleRun(input),
    launchTime,
    chain: input.chain,
    kind: "certificate",
    escalation: "on",
    harnessVersion: h,
    pins: input.plan.pins,
    root: { pid: 100, uid: 501, started: start, sid: 50 },
    rootSid: 50,
    accountingDirectory: "/run",
    cleanup: { outcome: "clean", before: [], signals: [], after: [] },
  };
  report.native = {
    schema: "calendar-native-proof/v1",
    rawPlan: Buffer.from(JSON.stringify(input.plan)).toString("base64"),
    rawOuterResult: Buffer.from(JSON.stringify(input.outerResult)).toString("base64"),
    rawRecords: Object.fromEntries(
      Object.entries(files).map(([name, rows]) => [
        name,
        Buffer.from(rows.map((r) => JSON.stringify(r) + "\n").join("")).toString("base64"),
      ]),
    ),
    queries,
    inventoryStartedAt: launchTime,
    rawBound: null,
    portctlSha256: PINS.portctlSha256,
  };
  const cleanupQueries = queries.filter((q) => ["inventory", "getsid"].includes(q.purpose));
  const handles = new Set(cleanupQueries.map((q) => q.answer.handle));
  report.cleanup = {
    outcome: "clean",
    before: input.inventory.passes[0].rows,
    after: input.inventory.passes[0].rows,
    signals: [],
    queries: cleanupQueries,
    rawRecords: Buffer.from(
      [files["measure.jsonl"][0], ...files["measure.jsonl"].filter((r) => handles.has(r.handle))]
        .map((r) => JSON.stringify(r) + "\n")
        .join(""),
    ).toString("base64"),
  };
  report.cleanup.before = parseInventory(
    queries.find((q) => q.purpose === "inventory").answer.stdout,
  ).map((r) => ({ ...r, sid: r.pid === 1 ? 1 : 50 }));
  report.cleanup.after = structuredClone(report.cleanup.before);
  return JSON.parse(JSON.stringify(report));
}

import {
  validateRecords,
  validatorControls,
  judgeInventory,
  REFUSAL_FORMATS,
  parseInventory,
} from "./calendar-accounting.mjs";

test("native certificate facts are recomputed from raw records rather than contradictory summaries", async () => {
  const { recomputeNativeReport } = await import("./calendar-measure.mjs");
  const base = nativeFixture();
  assert.equal(recomputeNativeReport(base).ok, true);
  for (const change of [
    (r) => {
      r.records.ok = false;
    },
    (r) => {
      r.records.signals = 1;
    },
    (r) => {
      r.verdict.conditions.A.outcome = "fail";
    },
    (r) => {
      r.inventory.outcome = "inconclusive";
    },
    (r) => {
      r.cleanup.outcome = "unknown";
    },
    (r) => {
      delete r.cleanup.rawRecords;
    },
    (r) => {
      r.cleanup.queries = r.cleanup.queries.slice(0, 2);
    },
    (r) => {
      r.cleanup.after = [];
    },
    (r) => {
      delete r.native.rawRecords["inner.jsonl"];
    },
    (r) => {
      r.native.queries.find((q) => q.purpose === "inventory").answer.timedOut = true;
    },
  ]) {
    const report = structuredClone(base);
    change(report);
    assert.equal(recomputeNativeReport(report).ok, false);
  }
});

test("campaign packets bind the current day, whole H file set and fixed real build", async () => {
  const { validateCampaignPacket, FIXED_BUILD_PINS, HARNESS_FILES } =
    await import("./calendar-measure.mjs");
  const filePins = Object.fromEntries(HARNESS_FILES.map((name) => [name, "a".repeat(64)]));
  const context = { utcDay: "2026-10-02", harnessH: "b".repeat(64), filePins };
  const packet = {
    schema: "calendar-campaign/v1",
    campaign: "unit",
    authorityId: "root-unit",
    utcDay: context.utcDay,
    runRoot: "/run",
    harnessH: context.harnessH,
    harnessFiles: filePins,
    buildPins: { ...FIXED_BUILD_PINS },
    bootstrap: "ordinary-user-own-ps",
    attempts: [{ attemptId: "a", planPath: "/plan", planSha256: "c".repeat(64) }],
    refusalAttemptId: "a",
    controlAttemptIds: ["b", "c", "d", "e", "f"],
  };
  packet.attempts.push(
    ...packet.controlAttemptIds.map((attemptId) => ({
      attemptId,
      planPath: `/plan-${attemptId}`,
      planSha256: "c".repeat(64),
    })),
  );
  assert.deepEqual(validateCampaignPacket(packet, context), []);
  for (const change of [
    (p) => {
      p.utcDay = "2026-10-03";
    },
    (p) => {
      p.harnessH = "d".repeat(64);
    },
    (p) => {
      delete p.harnessFiles["calendar-attempt-ledger.mjs"];
    },
    (p) => {
      p.buildPins.sourceCommit = "e".repeat(40);
    },
    (p) => {
      p.attempts.push(p.attempts[0]);
    },
    (p) => {
      p.attempts.push({ ...p.attempts[0], planPath: "/plan-duplicate-id" });
    },
    (p) => {
      p.controlAttemptIds[0] = "missing";
    },
    (p) => {
      p.runRoot = "/alias/../run";
    },
    (p) => {
      p.externalApprovalVerified = true;
    },
  ]) {
    const changed = structuredClone(packet);
    change(changed);
    assert.notEqual(validateCampaignPacket(changed, context).length, 0);
  }
});

test("sealed campaign validation rejects omission, extras and raw nested report substitution", async () => {
  const { evaluateCampaignSnapshot } = await import("./calendar-measure.mjs");
  const scope = {
    campaign: "unit",
    utcDay: "2026-10-02",
    runRoot: "/run",
    harnessH: "a".repeat(64),
    buildPins: {
      sourceCommit: "a".repeat(40),
      binarySha256: "b".repeat(64),
      runnerSha256: "c".repeat(64),
    },
    nativeRoot: { pid: 100, start: "Fri Oct 2 06:00:00 2026", sid: 50 },
  };
  const authorityBytes = Buffer.from(
    JSON.stringify({ schema: "scoped-attempt-authority/v1", authorityId: "root-unit", scope }),
  );
  const rawPlan = Buffer.from("{}");
  const rawReport = Buffer.from(JSON.stringify(loaderReport("certificate")));
  const envelope = Buffer.from(
    JSON.stringify({
      schema: "attempt-report/v1",
      scope,
      attemptId: "one",
      outcome: "pass",
      rawPlan: rawPlan.toString("base64"),
      rawPlanSha256: sha(rawPlan),
      rawReport: rawReport.toString("base64"),
      rawReportSha256: sha(rawReport),
    }),
  );
  const rows = [
    { type: "header", seq: 0, scope, authoritySha256: sha(authorityBytes) },
    { type: "birth", seq: 1, scope, attemptId: "one", planSha256: sha(rawPlan) },
    {
      type: "terminal",
      seq: 2,
      scope,
      attemptId: "one",
      reportFile: "report-1.json",
      reportSha256: sha(envelope),
      reportBytes: envelope.length,
    },
    { type: "seal", seq: 3, scope, tail: 2, births: 1 },
  ];
  const snapshot = {
    authorityBytes,
    ledgerBytes: Buffer.from(rows.map((r) => JSON.stringify(r) + "\n").join("")),
    reports: new Map([["report-1.json", envelope]]),
  };
  const packet = {
    authorityId: "root-unit",
    ...scope,
    attempts: [{ attemptId: "one", planPath: "/plan", planSha256: sha(rawPlan) }],
    refusalAttemptId: "one",
    controlAttemptIds: [],
  };
  assert.equal(
    evaluateCampaignSnapshot(packet, snapshot).verdict,
    "fail",
    "summary-only data is not native proof",
  );
  for (const change of [
    (s) => {
      s.reports.clear();
    },
    (s) => {
      s.reports.set("extra.json", envelope);
    },
    (s) => {
      s.reports.set("report-1.json", Buffer.from("{}"));
    },
  ]) {
    const changed = { ...snapshot, reports: new Map(snapshot.reports) };
    change(changed);
    const result = evaluateCampaignSnapshot(packet, changed);
    assert.equal(result.verdict, "fail");
    assert.equal(result.certificate, null);
  }
  for (const change of [
    (p) => {
      p.attempts = [];
    },
    (p) => {
      p.attempts.push(p.attempts[0]);
    },
    (p) => {
      p.utcDay = "2026-10-03";
    },
  ]) {
    const changed = structuredClone(packet);
    change(changed);
    assert.equal(evaluateCampaignSnapshot(changed, snapshot).verdict, "fail");
  }
});

test("campaign traces agree with an independent model for generated terminal sequences", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  const outcomes = ["pass", "fail", "inconclusive", "throw"];
  for (let seed = 0; seed < 64; seed++) {
    const expected = [];
    const actual = [];
    const terminals = [];
    const attempts = Array.from({ length: 3 }, (_, i) => ({
      attemptId: `a${i}`,
      planPath: `/a${i}`,
      planSha256: sha(Buffer.from(JSON.stringify({ i }))),
    }));
    const sequence = Array.from({ length: 3 }, (_, i) => outcomes[Math.floor(seed / 4 ** i) % 4]);
    for (let i = 0; i < sequence.length; i++)
      expected.push(
        `birth:${i}`,
        `effects:${i}`,
        `terminal:${i}:${["pass", "fail"].includes(sequence[i]) ? sequence[i] : "unknown"}`,
      );
    expected.push("seal", "close");
    const result = await produceCampaign({
      classifyReport: (report) => report?.verdict?.verdict,
      authorityId: "unit",
      attempts,
      bootstrap: async () => ({
        scope: { utcDay: "2026-10-02" },
        receipt: { phase: "infrastructure" },
      }),
      readPlan: async (path) => Buffer.from(JSON.stringify({ i: Number(path.at(-1)) })),
      createLedger: async () => ({
        registerBirth: async ({ attemptId }) => {
          await Promise.resolve();
          actual.push(`birth:${attemptId.at(-1)}`);
          return { durable: true };
        },
        recordTerminal: async ({ attemptId, reportBytes }) => {
          const envelope = JSON.parse(reportBytes);
          terminals.push(envelope);
          actual.push(`terminal:${attemptId.at(-1)}:${envelope.outcome}`);
          return { durable: true };
        },
        seal: async () => {
          actual.push("seal");
          if (terminals.some((e) => e.outcome === "unknown")) throw new Error("unknown");
          return { state: "complete", durabilityAcknowledged: true };
        },
        close: async () => {
          actual.push("close");
        },
      }),
      measureAttempt: async (raw) => {
        const { i } = JSON.parse(raw);
        actual.push(`effects:${i}`);
        if (sequence[i] === "throw") throw new Error("prelaunch exception");
        return Buffer.from(JSON.stringify({ verdict: { verdict: sequence[i] } }));
      },
      readSnapshot: async () => ({}),
    });
    assert.deepEqual(actual, expected, `seed ${seed}`);
    assert.equal(
      result.state,
      sequence.every((o) => ["pass", "fail"].includes(o)) ? "complete" : "unknown",
    );
  }
});

test("campaign failures in birth, terminal or seal cannot start later effects or issue approval", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  for (const boundary of ["birth", "terminal", "seal", "snapshot", "day-rollover"]) {
    const events = [];
    const raw = Buffer.from("{}");
    const result = await produceCampaign({
      classifyReport: (report) => report?.verdict?.verdict,
      authorityId: "unit",
      attempts: [{ attemptId: "a", planPath: "/a", planSha256: sha(raw) }],
      bootstrap: async () => ({
        scope: { utcDay: "2026-10-02" },
        receipt: { phase: "infrastructure" },
      }),
      readPlan: async () => raw,
      createLedger: async () => ({
        registerBirth: async () => {
          events.push("birth");
          if (["birth", "day-rollover"].includes(boundary)) throw new Error(boundary);
          return { durable: true };
        },
        recordTerminal: async () => {
          events.push("terminal");
          if (boundary === "terminal") throw new Error(boundary);
          return { durable: true };
        },
        seal: async () => {
          events.push("seal");
          if (boundary === "seal") throw new Error(boundary);
          return { state: "complete", durabilityAcknowledged: true };
        },
        close: async () => {
          events.push("close");
        },
      }),
      measureAttempt: async () => {
        events.push("effects");
        return Buffer.from('{"verdict":{"verdict":"pass"}}');
      },
      readSnapshot: async () => {
        throw new Error("snapshot");
      },
    });
    assert.equal(result.state, "unknown");
    assert.equal(result.externalApprovalVerified, false);
    assert.equal(events.at(-1), "close");
    if (["birth", "day-rollover"].includes(boundary)) assert.deepEqual(events, ["birth", "close"]);
  }
});

function nativeControlFixture(mode, inconclusive = false) {
  const report = nativeFixture();
  const proof = report.native;
  const plan = JSON.parse(Buffer.from(proof.rawPlan, "base64"));
  const outerResult = JSON.parse(Buffer.from(proof.rawOuterResult, "base64"));
  if (mode === "positive") plan.positive = true;
  else {
    plan.control = { mode };
    delete plan.positive;
  }
  plan.session.input.timeZone =
    mode === "positive" || CONTROL_VARIANTS[mode].fixture === "valid"
      ? "UTC"
      : "Invalid/CalendarZone";
  const files = Object.fromEntries(
    Object.entries(proof.rawRecords).map(([name, raw]) => [
      name,
      Buffer.from(raw, "base64")
        .toString()
        .trimEnd()
        .split("\n")
        .map((line) => JSON.parse(line)),
    ]),
  );
  const helperStart = "Fri Oct 2 06:00:05 2026";
  const helper = { pid: 900, uid: 501, started: helperStart, pgid: mode === "orphan" ? 300 : 900 };
  if (mode === "positive") {
    outerResult.inner.observationHandshake = true;
    outerResult.callback = { matched: true };
  } else {
    outerResult.identity.controlMode = mode;
    outerResult.inner.injected = { pid: 900, acquired: mode !== "orphan", firstSighting: helper };
    if (mode !== "orphan") outerResult.inner.ownedProcesses = [helper];
  }
  if (mode === "leftover")
    files["measure.jsonl"].push({
      type: "signal",
      target: { pid: 900, uid: 501, started: helperStart },
      kind: "SIGTERM",
      monoNs: "9999",
    });
  for (let i = 0; i < proof.queries.length; i++) {
    const q = proof.queries[i];
    if (inconclusive && q.purpose === "getsid") {
      const sessions = JSON.parse(q.answer.stdout);
      sessions["100"] = "EPERM";
      q.answer.stdout = JSON.stringify(sessions);
    }
    if (q.purpose === "inventory" && ["orphan", "escaper", "listener"].includes(mode)) {
      q.answer.stdout += `900 1 ${helper.pgid} 501 ${helperStart} S helper\n`;
      const sessions = JSON.parse(proof.queries[i + 1].answer.stdout);
      sessions["900"] = mode === "orphan" ? 300 : 900;
      proof.queries[i + 1].answer.stdout = JSON.stringify(sessions);
    }
    if (q.purpose === "lsof" && mode === "listener") {
      q.answer.stdout = "p900\ncunit-helper\nnTCP *:12345 (LISTEN)\n";
      q.answer.code = 0;
      files["measure.jsonl"].find((r) => r.type === "exit" && r.handle === q.answer.handle).code =
        0;
    }
  }
  const records = validateRecords(files);
  const identities = recordedIdentities({
    files,
    inner: outerResult.inner,
    outerSupervision: outerResult.supervision,
    selfPid: 100,
    selfUid: 501,
  });
  const passes = [];
  for (let i = 0; i < proof.queries.length; i++)
    if (proof.queries[i].purpose === "inventory") {
      const sessions = JSON.parse(proof.queries[i + 1].answer.stdout);
      passes.push(
        parseInventory(proof.queries[i].answer.stdout).map((r) => ({
          ...r,
          sid: sessions[String(r.pid)],
        })),
      );
    }
  const inventory = judgeInventory(passes, {
    sessionId: 300,
    recorded: identities,
    privateDir: "/run",
    launchTime,
    rootPid: 100,
  });
  const bound = mode === "listener" ? { boundAt: launchTime / 1000 - 1, pid: 900 } : null;
  const assembled = assembleRun({
    plan,
    kind: planKind(plan),
    version: PINS.harnessVersion,
    outerResult,
    chain: report.chain,
    records,
    validator: validatorControls(files),
    inventory,
    claims: [],
    lsof: proof.queries.filter((q) => q.purpose === "lsof").map((q) => interpretLsof(q.answer)),
    alive: inventory.passes.at(-1).survivors.map((e) => e.row.pid),
    bound: bound === null ? null : boundBefore(bound, launchTime),
    extra: {
      portctlSha256: PINS.portctlSha256,
      refusalCheck: {
        ok: mode === "orphan" || mode === "listener",
        problems:
          mode === "orphan" || mode === "listener"
            ? []
            : ["the pinned refusal line is not explained by the pinned format strings"],
      },
    },
  });
  Object.assign(report, assembled, {
    kind: mode === "positive" ? "positive" : "control",
    escalation: planKind(plan).escalation,
  });
  proof.rawPlan = Buffer.from(JSON.stringify(plan)).toString("base64");
  proof.rawOuterResult = Buffer.from(JSON.stringify(outerResult)).toString("base64");
  proof.rawRecords = Object.fromEntries(
    Object.entries(files).map(([name, rows]) => [
      name,
      Buffer.from(rows.map((r) => JSON.stringify(r) + "\n").join("")).toString("base64"),
    ]),
  );
  proof.rawBound = bound === null ? null : Buffer.from(JSON.stringify(bound)).toString("base64");
  return JSON.parse(JSON.stringify(report));
}

import { interpretLsof } from "./calendar-accounting.mjs";

test("raw native positive and all four negative controls reproduce their named facts", async () => {
  const { recomputeNativeReport } = await import("./calendar-measure.mjs");
  for (const mode of ["positive", "orphan", "escaper", "listener", "leftover"]) {
    const report = nativeControlFixture(mode);
    assert.equal(report.control.counts, true, mode);
    assert.equal(
      recomputeNativeReport(report).ok,
      true,
      `${mode}: ${JSON.stringify(recomputeNativeReport(report))}`,
    );
    const fake = structuredClone(report);
    fake.control.counts = false;
    assert.equal(recomputeNativeReport(fake).ok, false, mode);
  }
});

function completeCampaignFixture() {
  const h = "a".repeat(64);
  const reports = [
    nativeFixture(),
    ...["positive", "orphan", "escaper", "listener", "leftover"].map((mode) =>
      nativeControlFixture(mode),
    ),
  ];
  for (const report of reports) {
    report.harnessVersion = h;
    report.identity.harnessVersion = h;
    report.pins.harnessVersion = h;
    const plan = JSON.parse(Buffer.from(report.native.rawPlan, "base64"));
    plan.pins.harnessVersion = h;
    report.native.rawPlan = Buffer.from(JSON.stringify(plan)).toString("base64");
    const replaceHeader = (raw) => {
      const rows = Buffer.from(raw, "base64")
        .toString()
        .trimEnd()
        .split("\n")
        .map((line) => JSON.parse(line));
      rows[0].harnessVersion = h;
      return Buffer.from(rows.map((r) => JSON.stringify(r) + "\n").join("")).toString("base64");
    };
    report.native.rawRecords = Object.fromEntries(
      Object.entries(report.native.rawRecords).map(([name, raw]) => [name, replaceHeader(raw)]),
    );
    report.cleanup.rawRecords = replaceHeader(report.cleanup.rawRecords);
  }
  const scope = {
    campaign: "unit",
    utcDay: "2026-10-02",
    runRoot: "/run",
    harnessH: h,
    buildPins: {
      sourceCommit: PINS.sourceCommit,
      binarySha256: PINS.binarySha256,
      runnerSha256: PINS.runnerSha256,
    },
    nativeRoot: { pid: 100, start: reports[0].root.started, sid: 50 },
  };
  const authorityBytes = Buffer.from(
    JSON.stringify({ schema: "scoped-attempt-authority/v1", authorityId: "root-unit", scope }),
  );
  const records = [{ type: "header", seq: 0, scope, authoritySha256: sha(authorityBytes) }];
  const rawReports = new Map();
  const attempts = [];
  for (const [i, report] of reports.entries()) {
    const attemptId = `a${i}`;
    const rawPlan = Buffer.from(report.native.rawPlan, "base64");
    const rawReport = Buffer.from(JSON.stringify(report));
    const birth = {
      type: "birth",
      seq: records.length,
      scope,
      attemptId,
      planSha256: sha(rawPlan),
    };
    records.push(birth);
    const raw = Buffer.from(
      JSON.stringify({
        schema: "attempt-report/v1",
        scope,
        attemptId,
        outcome: report.verdict.verdict,
        rawPlan: rawPlan.toString("base64"),
        rawPlanSha256: sha(rawPlan),
        rawReport: rawReport.toString("base64"),
        rawReportSha256: sha(rawReport),
        error: null,
      }),
    );
    const name = `report-${birth.seq}.json`;
    rawReports.set(name, raw);
    records.push({
      type: "terminal",
      seq: records.length,
      scope,
      attemptId,
      reportFile: name,
      reportSha256: sha(raw),
      reportBytes: raw.length,
    });
    attempts.push({ attemptId, planPath: `/plan-${i}`, planSha256: sha(rawPlan) });
  }
  records.push({
    type: "seal",
    seq: records.length,
    scope,
    tail: records.length - 1,
    births: reports.length,
  });
  return {
    packet: {
      ...scope,
      authorityId: "root-unit",
      attempts,
      refusalAttemptId: "a0",
      controlAttemptIds: ["a1", "a2", "a3", "a4", "a5"],
    },
    snapshot: {
      authorityBytes,
      ledgerBytes: Buffer.from(records.map((r) => JSON.stringify(r) + "\n").join("")),
      reports: rawReports,
    },
    records,
  };
}

test("a complete raw sealed fixture passes only as a scoped predicate and retains every birth", async () => {
  const { evaluateCampaignSnapshot } = await import("./calendar-measure.mjs");
  const { packet, snapshot } = completeCampaignFixture();
  const result = evaluateCampaignSnapshot(packet, snapshot);
  assert.equal(result.verdict, "pass", JSON.stringify(result.problems));
  assert.equal(result.predicateOnly, true);
  assert.equal(result.nativeCertificateIssued, false);
  assert.equal(result.externalApprovalVerified, false);
  assert.equal(result.allDayCertified, false);
  assert.equal(result.historicalCompleteness, "UNKNOWN");
  assert.equal(result.allBirths.length, 6);
  for (const change of [
    (p) => {
      p.attempts.pop();
    },
    (p) => {
      p.attempts.reverse();
    },
    (p) => {
      p.attempts.push(p.attempts[0]);
    },
    (p) => {
      p.controlAttemptIds[0] = p.refusalAttemptId;
    },
    (p) => {
      p.buildPins.binarySha256 = "0".repeat(64);
    },
  ]) {
    const changed = structuredClone(packet);
    change(changed);
    assert.equal(evaluateCampaignSnapshot(changed, snapshot).verdict, "fail");
  }
});

test("file campaign entry points require an external host verifier rather than self approval", async () => {
  const { campaign, certify } = await import("./calendar-measure.mjs");
  for (const trustedPacketVerifier of [undefined, true, {}, "ROOT-approved", { closed: true }]) {
    const result = await campaign("/missing-unit-packet", { trustedPacketVerifier });
    assert.equal(result.verdict, "fail");
    assert.equal(result.nativeCertificateIssued, false);
    assert.equal(result.externalApprovalVerified, false);
  }
  const result = await certify("/missing-unit-manifest", { requireCampaign: true });
  assert.equal(result.nativeCertificateIssued, false);
});

test("host binding requires a closed exact raw packet, H, build, root and lifetime receipt", async () => {
  const { verifyTrustedBinding } = await import("./calendar-measure.mjs");
  const request = {
    schema: "calendar-trusted-binding/v1",
    phase: "sealed-certificate",
    packetSha256: sha(Buffer.from("raw packet")),
    harnessH: "b".repeat(64),
    harnessFiles: { file: "c".repeat(64) },
    utcDay: "2026-10-02",
    buildPins: { sourceCommit: "d".repeat(40) },
    nativeRoot: { pid: 100, start: "native", sid: 50 },
    campaign: "unit",
    runRoot: "/run",
    lifetime: { id: "unit-lifetime", pid: 100 },
    authoritySha256: "e".repeat(64),
    ledgerSha256: "f".repeat(64),
  };
  const good = async (input) => ({ ...input.binding, closed: true });
  assert.deepEqual(
    await verifyTrustedBinding(good, request, Buffer.from("raw packet"), {
      now: () => Date.parse("2026-10-02T06:00:00Z"),
    }),
    {
      ...request,
      closed: true,
    },
  );
  for (const provider of [
    undefined,
    true,
    async () => true,
    async () => ({ closed: true }),
    async () => ({ ...request, closed: false }),
    async () => ({ ...request, closed: true, ledgerSha256: "0".repeat(64) }),
    async () => ({ ...request, closed: true, lifetime: { id: "other", pid: 100 } }),
  ]) {
    await assert.rejects(
      verifyTrustedBinding(provider, request, Buffer.from("raw packet"), {
        now: () => Date.parse("2026-10-02T06:00:00Z"),
      }),
    );
  }
});

test("nested raw report hashes and outcomes survive independent envelope rehash attacks", async () => {
  const { evaluateCampaignSnapshot } = await import("./calendar-measure.mjs");
  for (const change of [
    (e) => {
      e.rawReportSha256 = "0".repeat(64);
    },
    (e) => {
      e.rawPlanSha256 = "0".repeat(64);
    },
    (e) => {
      e.outcome = "fail";
    },
    (e) => {
      e.error = "late unknown";
    },
    (e) => {
      const r = JSON.parse(Buffer.from(e.rawReport, "base64"));
      r.records.signals = 1;
      const raw = Buffer.from(JSON.stringify(r));
      e.rawReport = raw.toString("base64");
      e.rawReportSha256 = sha(raw);
    },
    (e) => {
      const r = JSON.parse(Buffer.from(e.rawReport, "base64"));
      r.root.pid = 101;
      const raw = Buffer.from(JSON.stringify(r));
      e.rawReport = raw.toString("base64");
      e.rawReportSha256 = sha(raw);
    },
  ]) {
    const { packet, snapshot, records } = completeCampaignFixture();
    const name = "report-1.json";
    const envelope = JSON.parse(snapshot.reports.get(name));
    change(envelope);
    const raw = Buffer.from(JSON.stringify(envelope));
    snapshot.reports.set(name, raw);
    const terminal = records.find((r) => r.type === "terminal" && r.reportFile === name);
    terminal.reportSha256 = sha(raw);
    terminal.reportBytes = raw.length;
    snapshot.ledgerBytes = Buffer.from(records.map((r) => JSON.stringify(r) + "\n").join(""));
    assert.equal(evaluateCampaignSnapshot(packet, snapshot).verdict, "fail");
  }
});

test("a changed raw plan is registered but stops before measurement effects", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  let effects = 0;
  let envelope;
  const result = await produceCampaign({
    classifyReport: (report) => report?.verdict?.verdict,
    authorityId: "unit",
    attempts: [{ attemptId: "a", planPath: "/a", planSha256: "0".repeat(64) }],
    bootstrap: async () => ({
      scope: { utcDay: "2026-10-02" },
      receipt: { phase: "infrastructure" },
    }),
    readPlan: async () => Buffer.from("{}"),
    createLedger: async () => ({
      registerBirth: async () => ({ durable: true }),
      recordTerminal: async ({ reportBytes }) => {
        envelope = JSON.parse(reportBytes);
        return { durable: true };
      },
      seal: async () => {
        if (envelope.outcome === "unknown") throw new Error("unknown");
        return { state: "complete", durabilityAcknowledged: true };
      },
      close: async () => {},
    }),
    measureAttempt: async () => {
      effects++;
      return Buffer.from('{"verdict":{"verdict":"pass"}}');
    },
    readSnapshot: async () => ({}),
  });
  assert.equal(effects, 0);
  assert.equal(envelope.outcome, "unknown");
  assert.equal(result.state, "unknown");
});

test("native own-wait, root and kind bindings reject independent single-field contradictions", async () => {
  const { recomputeNativeReport } = await import("./calendar-measure.mjs");
  for (const change of [
    (r) => {
      r.native.queries.find((q) => q.purpose === "pinned-source").answer.pid += 1;
    },
    (r) => {
      r.rootSid += 1;
    },
    (r) => {
      r.escalation = "off";
    },
  ]) {
    const report = nativeFixture();
    change(report);
    assert.equal(recomputeNativeReport(report).ok, false);
  }
});

test("a complete sealed predicate rejects extra publications and an extra selected refusal", async () => {
  const { evaluateCampaignSnapshot } = await import("./calendar-measure.mjs");
  for (const extraReport of [true, false]) {
    const { packet, snapshot } = completeCampaignFixture();
    if (extraReport) snapshot.reports.set("extra.json", Buffer.from("{}"));
    else packet.controlAttemptIds.push(packet.refusalAttemptId);
    assert.equal(evaluateCampaignSnapshot(packet, snapshot).verdict, "fail");
  }
});

test("a coherently rebound authority cannot substitute another SID for the native report root", async () => {
  const { evaluateCampaignSnapshot } = await import("./calendar-measure.mjs");
  const { packet, snapshot, records } = completeCampaignFixture();
  const authority = JSON.parse(snapshot.authorityBytes);
  authority.scope.nativeRoot.sid = 51;
  packet.nativeRoot.sid = 51;
  snapshot.authorityBytes = Buffer.from(JSON.stringify(authority));
  for (const row of records) row.scope = structuredClone(authority.scope);
  records[0].authoritySha256 = sha(snapshot.authorityBytes);
  for (const [name, raw] of snapshot.reports) {
    const envelope = JSON.parse(raw);
    envelope.scope = structuredClone(authority.scope);
    const replaced = Buffer.from(JSON.stringify(envelope));
    snapshot.reports.set(name, replaced);
    const terminal = records.find((r) => r.type === "terminal" && r.reportFile === name);
    terminal.reportSha256 = sha(replaced);
    terminal.reportBytes = replaced.length;
  }
  snapshot.ledgerBytes = Buffer.from(records.map((r) => JSON.stringify(r) + "\n").join(""));
  const result = evaluateCampaignSnapshot(packet, snapshot);
  assert.equal(result.verdict, "fail");
  assert.ok(result.problems.includes("foreign native root, day or H"));
});

test("a host verifier cannot close a certificate after the frozen UTC day rolls over", async () => {
  const { verifyTrustedBinding } = await import("./calendar-measure.mjs");
  let now = Date.parse("2026-10-02T23:59:59Z");
  const bytes = Buffer.from("unit packet");
  const binding = {
    utcDay: "2026-10-02",
    packetSha256: sha(bytes),
    lifetime: { id: "unit", pid: 100 },
  };
  await assert.rejects(
    verifyTrustedBinding(
      async (request) => {
        now += 2000;
        return { ...request.binding, closed: true };
      },
      binding,
      bytes,
      { now: () => now },
    ),
  );
});

test("default producer classification retains incomplete failures as unknown and complete controls as fail", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  const cases = [
    [{ verdict: { verdict: "fail" } }, "unknown"],
    [nativeFixture(), "pass"],
    [nativeControlFixture("orphan"), "fail"],
    [nativeControlFixture("positive", true), "unknown"],
  ];
  const incomplete = nativeFixture();
  incomplete.verdict.verdict = "fail";
  incomplete.verdict.conditions.E = { ok: false, outcome: "inconclusive", reasons: ["unknown"] };
  cases.push([incomplete, "unknown"]);
  assert.equal(cases[3][0].verdict.verdict, "fail");
  assert.equal(cases[3][0].verdict.conditions.E.outcome, "inconclusive");
  const { recomputeNativeReport } = await import("./calendar-measure.mjs");
  assert.equal(recomputeNativeReport(cases[3][0]).ok, true);
  for (const [report, expected] of cases) {
    const raw = Buffer.from(JSON.stringify(report));
    const plan = Buffer.from(report.native?.rawPlan ?? "e30=", "base64");
    let envelope;
    const result = await produceCampaign({
      authorityId: "unit",
      attempts: [{ attemptId: "a", planPath: "/a", planSha256: sha(plan) }],
      bootstrap: async () => ({
        scope: { utcDay: "2026-10-02" },
        receipt: { phase: "infrastructure" },
      }),
      readPlan: async () => plan,
      createLedger: async () => ({
        registerBirth: async () => ({ durable: true }),
        recordTerminal: async ({ reportBytes }) => {
          envelope = JSON.parse(reportBytes);
          return { durable: true };
        },
        seal: async () => {
          if (envelope.outcome === "unknown") throw new Error("unknown");
          return { state: "complete", durabilityAcknowledged: true };
        },
        close: async () => {},
      }),
      measureAttempt: async () => raw,
      readSnapshot: async () => ({}),
    });
    assert.equal(envelope.outcome, expected);
    assert.equal(result.state, expected === "unknown" ? "unknown" : "complete");
    assert.deepEqual(Buffer.from(envelope.rawReport, "base64"), raw);
  }
});

async function fixedSourceBytes() {
  const { execFileSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const repository = fileURLToPath(new URL("../../", import.meta.url));
  const commit = "33970bf501ac85e62fd8aee488d16a9405a8a019";
  return new Map(
    Object.values(REFUSAL_FORMATS).map(({ path }) => [
      path,
      execFileSync("git", ["-C", repository, "show", `${commit}:${path}`], { maxBuffer: 1048576 }),
    ]),
  );
}

test("all 537475 immutable source bytes reach durable ledger terminal and seal through bounded native references", async () => {
  const fs = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const m = await import("./calendar-measure.mjs");
  const sources = await fixedSourceBytes();
  assert.deepEqual(
    [...sources.values()].map((b) => b.length),
    [1946, 26838, 364353, 144338],
  );
  assert.equal(
    [...sources.values()].reduce((sum, b) => sum + b.length, 0),
    537475,
  );
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-source-bound-")));
  try {
    const directory = join(root, "accounting-unit");
    await fs.mkdir(directory);
    const scope = {
      campaign: "unit-source-bound",
      utcDay: new Date().toISOString().slice(0, 10),
      runRoot: root,
      harnessH: "a".repeat(64),
      buildPins: { ...m.FIXED_BUILD_PINS },
      nativeRoot: { pid: 100, start: "unit-only", sid: 50 },
    };
    const plan = Buffer.from("{}");
    const report = {
      accountingDirectory: directory,
      pins: { ...m.FIXED_BUILD_PINS },
      verdict: { verdict: "fail" },
      native: {
        schema: "calendar-native-proof/v1",
        queries: [...sources].map(([path, raw], i) => ({
          file: "git",
          args: ["-C", "/source", "show", `${m.FIXED_BUILD_PINS.sourceCommit}:${path}`],
          purpose: "pinned-source",
          answer: {
            stdout: raw.toString("utf8"),
            stderr: "",
            code: 0,
            timedOut: false,
            truncated: false,
            handle: `measure:${i + 1}`,
            pid: 600 + i,
          },
        })),
      },
    };
    const raw = Buffer.from(JSON.stringify(report));
    assert.ok(raw.length > 537475);
    const result = await m.produceCampaign({
      authorityId: "unit",
      attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(plan) }],
      bootstrap: async () => ({ scope, receipt: { phase: "infrastructure", unitOnly: true } }),
      readPlan: async () => plan,
      measureAttempt: async () => raw,
      retainReport: async (bytes, attempt, currentScope) => {
        const bounded = await m.publishNativeSources(
          JSON.parse(bytes),
          attempt.attemptId,
          currentScope,
        );
        return Buffer.from(JSON.stringify(bounded));
      },
      classifyReport: () => "fail",
      readSnapshot: async () => ({}),
    });
    assert.equal(result.state, "complete", JSON.stringify(result));
    assert.equal(result.durabilityAcknowledged, true);
    const rows = (await fs.readFile(join(root, "attempt-ledger/ledger.jsonl"), "utf8"))
      .trimEnd()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      rows.map((r) => r.type),
      ["header", "birth", "terminal", "seal"],
    );
    const terminal = rows[2];
    assert.ok(terminal.reportBytes <= 262144);
    const envelope = JSON.parse(
      await fs.readFile(join(root, "attempt-ledger", terminal.reportFile)),
    );
    const compact = JSON.parse(Buffer.from(envelope.rawReport, "base64"));
    assert.equal(compact.native.schema, "calendar-native-proof/v2");
    const restored = await m.resolveNativeSources(compact, "one", scope);
    for (const [path, raw] of sources) assert.deepEqual(restored.get(path), raw);
    assert.equal(result.nativeCertificateIssued, undefined);
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

async function fullNativeSourceFixture(root, initialReport = nativeFixture()) {
  const fs = await import("node:fs/promises");
  const { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const report = JSON.parse(
    JSON.stringify(initialReport).replaceAll(PINS.harnessVersion, "a".repeat(64)),
  );
  const rebindRawH = (raw) =>
    Buffer.from(
      Buffer.from(raw, "base64").toString("utf8").replaceAll(PINS.harnessVersion, "a".repeat(64)),
    ).toString("base64");
  report.native.rawPlan = rebindRawH(report.native.rawPlan);
  report.native.rawOuterResult = rebindRawH(report.native.rawOuterResult);
  report.native.rawRecords = Object.fromEntries(
    Object.entries(report.native.rawRecords).map(([name, raw]) => [name, rebindRawH(raw)]),
  );
  report.cleanup.rawRecords = rebindRawH(report.cleanup.rawRecords);

  const directory = await fs.mkdtemp(join(root, "accounting-"));
  report.accountingDirectory = directory;
  report.pins.sourceCommit = m.FIXED_BUILD_PINS.sourceCommit;
  const plan = JSON.parse(Buffer.from(report.native.rawPlan, "base64"));
  plan.pins.sourceCommit = m.FIXED_BUILD_PINS.sourceCommit;
  plan.session.sourceCommit = m.FIXED_BUILD_PINS.sourceCommit;
  report.native.rawPlan = Buffer.from(JSON.stringify(plan)).toString("base64");
  const rows = Buffer.from(report.native.rawRecords["measure.jsonl"], "base64")
    .toString()
    .trimEnd()
    .split("\n")
    .map(JSON.parse);
  for (const [path, raw] of await fixedSourceBytes()) {
    const q = report.native.queries.find(
      (q) => q.purpose === "pinned-source" && q.args.at(-1).endsWith(":" + path),
    );
    q.args[3] = `${m.FIXED_BUILD_PINS.sourceCommit}:${path}`;
    q.answer.stdout = raw.toString();
    rows.find((r) => r.type === "birth" && r.handle === q.answer.handle).argvSha256 = sha(
      JSON.stringify([q.file, ...q.args]),
    );
  }
  report.native.rawRecords["measure.jsonl"] = Buffer.from(
    rows.map((r) => JSON.stringify(r) + "\n").join(""),
  ).toString("base64");
  // The report is reconstructed with the unchanged fixture pins except the pinned source commit.
  report.identity.sourceCommit = m.FIXED_BUILD_PINS.sourceCommit;
  const outer = JSON.parse(Buffer.from(report.native.rawOuterResult, "base64"));
  outer.identity.sourceCommit = m.FIXED_BUILD_PINS.sourceCommit;
  report.native.rawOuterResult = Buffer.from(JSON.stringify(outer)).toString("base64");
  const scope = {
    campaign: "source-unit",
    utcDay: "2026-10-02",
    runRoot: root,
    harnessH: report.harnessVersion,
    buildPins: { ...m.FIXED_BUILD_PINS },
    nativeRoot: { pid: 100, start: report.root.started, sid: 50 },
  };
  return { report, scope };
}

test("native v2 recomputes A-G from every resolved full source byte and rejects absent or changed raw authority", async () => {
  const fs = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-native-source-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    assert.equal(
      m.recomputeNativeReport(report).ok,
      true,
      JSON.stringify(m.recomputeNativeReport(report)),
    );
    const compact = await m.publishNativeSources(report, "one", scope);
    const sourceBlobs = await m.resolveNativeSources(compact, "one", scope);
    for (let i = 0; i < 4; i++) {
      const expected = m.FIXED_NATIVE_SOURCES[i],
        q = compact.native.queries.find(
          (q) => q.purpose === "pinned-source" && q.args.at(-1).endsWith(":" + expected.path),
        );
      assert.equal("stdout" in q.answer, false);
      assert.deepEqual(q.answer.sourceRef, {
        schema: "calendar-native-source/v1",
        sourceCommit: "33970bf501ac85e62fd8aee488d16a9405a8a019",
        sourcePath: expected.path,
        blobFile: `source-${i}.raw`,
        rawSha256: sha(sourceBlobs.get(expected.path)),
        rawBytes: sourceBlobs.get(expected.path).length,
        scopeSha256: sha(Buffer.from(JSON.stringify(scope))),
        attemptId: "one",
        queryArgvSha256: sha(Buffer.from(JSON.stringify([q.file, ...q.args]))),
        ownHandle: q.answer.handle,
        ownPid: q.answer.pid,
      });
    }

    const options = { sourceBlobs, attemptId: "one", scope };
    assert.equal(m.recomputeNativeReport(compact, options).ok, true);
    assert.equal(m.recomputeNativeReport(compact).ok, false);
    assert.equal(m.recomputeNativeReport(compact, { ...options, attemptId: "foreign" }).ok, false);
    assert.equal(
      m.recomputeNativeReport(compact, { ...options, scope: { ...scope, campaign: "foreign" } }).ok,
      false,
    );
    const missing = new Map(sourceBlobs);
    missing.delete(m.FIXED_NATIVE_SOURCES[0].path);
    assert.equal(m.recomputeNativeReport(compact, { ...options, sourceBlobs: missing }).ok, false);
    const changed = new Map(sourceBlobs);
    const raw = Buffer.from(changed.get(m.FIXED_NATIVE_SOURCES[0].path));
    raw[0] ^= 1;
    changed.set(m.FIXED_NATIVE_SOURCES[0].path, raw);
    assert.equal(m.recomputeNativeReport(compact, { ...options, sourceBlobs: changed }).ok, false);
    const extra = new Map(sourceBlobs);
    extra.set("foreign", Buffer.from("raw"));
    assert.equal(m.recomputeNativeReport(compact, { ...options, sourceBlobs: extra }).ok, false);
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("explicit raw report plan and serialized overhead budgets keep every admitted envelope under the unchanged ledger ceiling", async () => {
  const { encodeAttemptEnvelope, NATIVE_ENVELOPE_BUDGET: b } =
    await import("./calendar-measure.mjs");
  assert.deepEqual(b, {
    reportBytes: 180000,
    planBytes: 8192,
    overheadBytes: 8192,
    envelopeBytes: 262144,
  });
  const fields = { scope: { label: 'é雪😀\u0000"' }, attemptId: "a", outcome: "fail", error: null };
  const oracle = (n) => 4 * Math.floor((n + 2) / 3);
  for (const r of [0, 1, 2, 3, 179998, 179999, 180000])
    for (const p of [0, 1, 2, 3, 8190, 8191, 8192]) {
      const rawReport = Buffer.alloc(r, 0x78),
        planBytes = Buffer.alloc(p, 0x79);
      const envelope = encodeAttemptEnvelope({ ...fields, rawReport, planBytes });
      const parsed = JSON.parse(envelope);
      const empty = { ...parsed, rawPlan: "", rawReport: "" };
      const overhead = Buffer.byteLength(JSON.stringify(empty), "utf8");
      assert.equal(envelope.length, oracle(r) + oracle(p) + overhead);
      assert.ok(envelope.length <= 259116);
      assert.ok(envelope.length <= 262144);
    }
  assert.throws(() =>
    encodeAttemptEnvelope({
      ...fields,
      rawReport: Buffer.alloc(180001),
      planBytes: Buffer.alloc(1),
    }),
  );
  assert.throws(() =>
    encodeAttemptEnvelope({ ...fields, rawReport: Buffer.alloc(1), planBytes: Buffer.alloc(8193) }),
  );
  assert.throws(() =>
    encodeAttemptEnvelope({
      ...fields,
      scope: { label: "雪".repeat(3000) },
      rawReport: Buffer.alloc(1),
      planBytes: Buffer.alloc(1),
    }),
  );
  const blank = encodeAttemptEnvelope({
    ...fields,
    scope: { label: "" },
    rawReport: Buffer.alloc(0),
    planBytes: Buffer.alloc(0),
  });
  const padding = "x".repeat(8192 - blank.length);
  assert.equal(
    encodeAttemptEnvelope({
      ...fields,
      scope: { label: padding },
      rawReport: Buffer.alloc(0),
      planBytes: Buffer.alloc(0),
    }).length,
    8192,
  );
  assert.throws(() =>
    encodeAttemptEnvelope({
      ...fields,
      scope: { label: padding + "x" },
      rawReport: Buffer.alloc(0),
      planBytes: Buffer.alloc(0),
    }),
  );
});

test("a late classifier exception retains an unknown terminal after the accepted birth", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  let envelope;
  const result = await produceCampaign({
    authorityId: "unit",
    attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(Buffer.from("{}")) }],
    bootstrap: async () => ({ scope: { utcDay: "2026-10-02" }, receipt: { unitOnly: true } }),
    readPlan: async () => Buffer.from("{}"),
    measureAttempt: async () => Buffer.from("{}"),
    classifyReport: async () => {
      throw new Error("source resolution changed");
    },
    createLedger: async () => ({
      registerBirth: async () => ({ durable: true }),
      recordTerminal: async ({ reportBytes }) => {
        envelope = JSON.parse(reportBytes);
        return { durable: true };
      },
      seal: async () => {
        throw new Error("unknown terminal");
      },
      close: async () => {},
    }),
    readSnapshot: async () => ({}),
  });
  assert.equal(result.state, "unknown");
  assert.equal(envelope?.outcome, "unknown");
  assert.match(envelope.error, /source resolution changed/);
});

test("full native source publications handle short writes and refuse failed durable readback", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-source-write-")));
  try {
    let writes = 0,
      fileSync = 0,
      dirSync = 0;
    const { report, scope } = await fullNativeSourceFixture(root);
    const publicationOpen = async (path, flags, mode) => {
      const h = await fs.open(path, flags, mode);
      return {
        write: async (raw, offset, length, position) => {
          writes++;
          return h.write(raw, offset, Math.min(length, 2048), position);
        },
        sync: async () => {
          if (flags === "wx") fileSync++;
          else dirSync++;
          return h.sync();
        },
        close: () => h.close(),
      };
    };
    const compact = await m.publishNativeSources(report, "one", scope, { publicationOpen });
    assert.ok(writes > 4);
    assert.equal(fileSync, 4);
    assert.equal(dirSync, 6);
    assert.equal((await m.resolveNativeSources(compact, "one", scope)).size, 4);
    const bad = await fullNativeSourceFixture(root);
    const corruptedOpen = async (path, flags, mode) => {
      const h = await fs.open(path, flags, mode);
      return {
        write: (...args) => h.write(...args),
        sync: async () => {
          if (flags === "wx") await h.write(Buffer.from("!"), 0, 1, 0);
          return h.sync();
        },
        close: () => h.close(),
      };
    };
    await assert.rejects(
      m.publishNativeSources(bad.report, "two", bad.scope, { publicationOpen: corruptedOpen }),
      /readback/,
    );
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("native source references and publication sets refuse independent substitution and filesystem alias attacks", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-source-alias-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    const compact = await m.publishNativeSources(report, "one", scope);
    const directory = join(report.accountingDirectory, "native-sources"),
      path = join(directory, "source-0.raw"),
      original = await fs.readFile(path);
    for (const [field, value] of Object.entries({
      schema: "foreign",
      sourceCommit: "a".repeat(40),
      sourcePath: "foreign",
      blobFile: "../source-0.raw",
      rawSha256: "0".repeat(64),
      rawBytes: 1945,
      scopeSha256: "0".repeat(64),
      attemptId: "foreign",
      queryArgvSha256: "0".repeat(64),
      ownHandle: "measure:foreign",
      ownPid: 999,
    })) {
      const changed = structuredClone(compact);
      changed.native.queries.find((q) => q.purpose === "pinned-source").answer.sourceRef[field] =
        value;
      await assert.rejects(m.resolveNativeSources(changed, "one", scope), undefined, field);
    }
    for (const change of [
      (r) => r.native.queries.push(r.native.queries[0]),
      (r) => (r.native.queries[0].answer.stdout = "summary"),
      (r) => (r.native.queries[0].args[1] = "/foreign"),
      (r) => (r.native.sourceBinding.attemptId = "foreign"),
      (r) => (r.accountingDirectory = join(root, "accounting-unit/../foreign")),
      (r) => (r.native.schema = "calendar-native-proof/v1"),
    ]) {
      const changed = structuredClone(compact);
      change(changed);
      await assert.rejects(m.resolveNativeSources(changed, "one", scope));
    }
    await assert.rejects(m.resolveNativeSources(compact, "foreign", scope));
    await assert.rejects(
      m.resolveNativeSources(compact, "one", { ...scope, utcDay: "2026-10-01" }),
    );
    await fs.writeFile(join(directory, "extra.raw"), "extra");
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.unlink(join(directory, "extra.raw"));
    await fs.unlink(path);
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.writeFile(path, original);
    await fs.writeFile(path, original.subarray(0, -1));
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.writeFile(path, original);
    await fs.writeFile(path, Buffer.concat([original, Buffer.from("x")]));
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.writeFile(path, original);
    const changed = Buffer.from(original);
    changed[0] ^= 1;
    await fs.writeFile(path, changed);
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.writeFile(path, original);
    await fs.link(path, join(root, "hardlink"));
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.unlink(join(root, "hardlink"));
    await fs.rename(path, join(root, "foreign-source"));
    await fs.symlink(join(root, "foreign-source"), path);
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.unlink(path);
    await fs.rename(join(root, "foreign-source"), path);
    await fs.rename(directory, join(root, "foreign-directory"));
    await fs.symlink(join(root, "foreign-directory"), directory);
    await assert.rejects(m.resolveNativeSources(compact, "one", scope));
    await fs.unlink(directory);
    await fs.rename(join(root, "foreign-directory"), directory);
    const foreignDirectory = join(root, "foreign-accounting");
    await fs.rename(report.accountingDirectory, foreignDirectory);
    const foreign = structuredClone(compact);
    foreign.accountingDirectory = foreignDirectory;
    await assert.rejects(m.resolveNativeSources(foreign, "one", scope));
    await fs.rename(foreignDirectory, report.accountingDirectory);
    await assert.rejects(m.publishNativeSources(report, "one", scope));
    assert.equal((await m.resolveNativeSources(compact, "one", scope)).size, 4);
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("full raw sources and default A-G classification reach actual terminal seal I/O without a native certificate", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-native-ledger-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    scope.utcDay = new Date().toISOString().slice(0, 10);
    const plan = Buffer.from(report.native.rawPlan, "base64");
    let compact;
    const result = await m.produceCampaign({
      authorityId: "unit",
      attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(plan) }],
      bootstrap: async () => ({ scope, receipt: { phase: "infrastructure", unitOnly: true } }),
      readPlan: async () => plan,
      measureAttempt: async () => Buffer.from(JSON.stringify(report)),
      retainReport: async (bytes) => {
        compact = await m.publishNativeSources(JSON.parse(bytes), "one", scope);
        return Buffer.from(JSON.stringify(compact));
      },
      classifyReport: async (r) =>
        m.classifyTerminalReport(r, {
          sourceBlobs: await m.resolveNativeSources(r, "one", scope),
          attemptId: "one",
          scope,
        }),
      readSnapshot: async () => m.readCampaignSnapshot({ runRoot: scope.runRoot }),
    });
    assert.equal(result.state, "complete", JSON.stringify(result));
    assert.equal(result.durabilityAcknowledged, true);
    assert.equal(result.snapshot.nativeSources.get("one").size, 4);
    const rows = (await fs.readFile(join(root, "attempt-ledger/ledger.jsonl"), "utf8"))
      .trimEnd()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      rows.map((r) => r.type),
      ["header", "birth", "terminal", "seal"],
    );
    const envelope = JSON.parse(
      await fs.readFile(join(root, "attempt-ledger", rows[2].reportFile)),
    );
    assert.equal(envelope.outcome, "pass");
    assert.equal(
      JSON.parse(Buffer.from(envelope.rawReport, "base64")).native.schema,
      "calendar-native-proof/v2",
    );
    assert.equal(result.externalApprovalVerified, false);
    assert.equal(result.allDayCertified, false);
    assert.equal(result.historicalCompleteness, "UNKNOWN");
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("a failed report publication retains the measured raw bytes in an unknown terminal", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  const raw = Buffer.from('{"error":"unit unknown"}');
  let envelope;
  const result = await produceCampaign({
    authorityId: "unit",
    attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(Buffer.from("{}")) }],
    bootstrap: async () => ({ scope: { utcDay: "2026-10-02" }, receipt: { unitOnly: true } }),
    readPlan: async () => Buffer.from("{}"),
    measureAttempt: async () => raw,
    retainReport: async () => {
      throw new Error("durable readback unknown");
    },
    classifyReport: () => "pass",
    createLedger: async () => ({
      registerBirth: async () => ({ durable: true }),
      recordTerminal: async ({ reportBytes }) => {
        envelope = JSON.parse(reportBytes);
        return { durable: true };
      },
      seal: async () => {
        throw new Error("unknown terminal");
      },
      close: async () => {},
    }),
    readSnapshot: async () => ({}),
  });
  assert.equal(result.state, "unknown");
  assert.equal(envelope.outcome, "unknown");
  assert.match(envelope.error, /readback unknown/);
  assert.deepEqual(Buffer.from(envelope.rawReport, "base64"), raw);
  assert.equal(envelope.rawReportSha256, sha(raw));
});

test("over-budget plan bytes stop before effects and over-budget reports cannot acknowledge a complete terminal", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  for (const oversizedPlan of [true, false]) {
    const plan = Buffer.alloc(oversizedPlan ? 8193 : 2, 0x78);
    let effects = 0,
      terminals = 0,
      seals = 0;
    const result = await produceCampaign({
      authorityId: "unit",
      attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(plan) }],
      bootstrap: async () => ({ scope: { utcDay: "2026-10-02" }, receipt: { unitOnly: true } }),
      readPlan: async () => plan,
      measureAttempt: async () => {
        effects++;
        return Buffer.alloc(180001, 0x78);
      },
      classifyReport: () => "pass",
      createLedger: async () => ({
        registerBirth: async () => ({ durable: true }),
        recordTerminal: async () => {
          terminals++;
          return { durable: true };
        },
        seal: async () => {
          seals++;
          return { state: "complete", durabilityAcknowledged: true };
        },
        close: async () => {},
      }),
      readSnapshot: async () => ({}),
    });
    assert.equal(result.state, "unknown");
    assert.equal(effects, oversizedPlan ? 0 : 1);
    assert.equal(terminals, 0);
    assert.equal(seals, 0);
  }
});

test("an aliased accounting ancestor is refused before any source bytes are published into the foreign directory", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(
    await fs.mkdtemp(join(tmpdir(), "calendar-source-prepublication-")),
  );
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    const foreign = join(root, "foreign-directory");
    await fs.rename(report.accountingDirectory, foreign);
    await fs.symlink(foreign, report.accountingDirectory);
    await assert.rejects(m.publishNativeSources(report, "one", scope));
    assert.deepEqual(await fs.readdir(foreign), []);
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

function bindFixedUnitCampaign(report, scope, fixed) {
  Object.assign(report.pins, fixed);
  Object.assign(report.identity, fixed);
  const plan = JSON.parse(Buffer.from(report.native.rawPlan, "base64"));
  Object.assign(plan.pins, fixed);
  Object.assign(plan.session, fixed);
  report.native.rawPlan = Buffer.from(JSON.stringify(plan)).toString("base64");
  const outer = JSON.parse(Buffer.from(report.native.rawOuterResult, "base64"));
  Object.assign(outer.identity, fixed);
  report.native.rawOuterResult = Buffer.from(JSON.stringify(outer)).toString("base64");
  scope.utcDay = new Date().toISOString().slice(0, 10);
  report.launchTime = Date.parse(scope.utcDay + "T06:00:00Z");
}

async function hugeNativeReportFixture(root) {
  const { report, scope } = await fullNativeSourceFixture(root);
  const listing = Array.from(
    { length: 450 },
    (_, i) => `${20000 + i} 1 1 0 Thu Jan 1 00:00:00 1970 S foreign-process-${"x".repeat(700)}\n`,
  ).join("");
  for (const queries of [report.native.queries, report.cleanup.queries]) {
    for (let i = 0; i < queries.length; i++) {
      if (queries[i].purpose !== "inventory") continue;
      queries[i].answer.stdout += listing;
      const sessions = JSON.parse(queries[i + 1].answer.stdout);
      for (let n = 0; n < 450; n++) sessions[String(20000 + n)] = 1;
      queries[i + 1].answer.stdout = JSON.stringify(sessions);
    }
  }
  const inventories = (queries) =>
    queries.flatMap((q, i) =>
      q.purpose !== "inventory"
        ? []
        : [
            parseInventory(q.answer.stdout)
              .filter((r) => r.pid !== q.answer.pid)
              .map((r) => ({ ...r, sid: JSON.parse(queries[i + 1].answer.stdout)[String(r.pid)] })),
          ],
    );
  const outer = JSON.parse(Buffer.from(report.native.rawOuterResult, "base64"));
  const files = Object.fromEntries(
    Object.entries(report.native.rawRecords).map(([name, raw]) => [
      name,
      Buffer.from(raw, "base64").toString().trimEnd().split("\n").map(JSON.parse),
    ]),
  );
  const identities = recordedIdentities({
    files,
    inner: outer.inner,
    outerSupervision: outer.supervision,
    selfPid: report.root.pid,
    selfUid: report.root.uid,
  });
  const state = judgeInventory(inventories(report.native.queries), {
    sessionId: report.chain.outerSid,
    recorded: identities,
    privateDir: outer.directory ?? report.accountingDirectory,
    privateDirs: [outer.directory, report.accountingDirectory].filter((d) => typeof d === "string"),
    launchTime: report.launchTime,
    rootPid: report.root.pid,
  });
  report.inventory = {
    outcome: state.outcome,
    reason: state.reason,
    survivors: state.survivors,
    passes: state.passes.map(({ repass, unrelatedZombies, ignored, inconclusive }) => ({
      repass,
      unrelatedZombies,
      ignored,
      inconclusive,
    })),
  };
  [report.cleanup.before, report.cleanup.after] = inventories(report.cleanup.queries);
  bindFixedUnitCampaign(report, scope, (await import("./calendar-measure.mjs")).FIXED_BUILD_PINS);
  return { report: JSON.parse(JSON.stringify(report)), scope };
}

test("whole native report archive reaches the real ledger seal and default full raw snapshot", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-full-report-")));
  try {
    const { report, scope } = await hugeNativeReportFixture(root);
    const raw = Buffer.from(JSON.stringify(report) + "\n");
    assert.ok(raw.length > 2495176);
    assert.equal(
      m.recomputeNativeReport(report).ok,
      true,
      JSON.stringify(m.recomputeNativeReport(report)),
    );
    const plan = Buffer.from(report.native.rawPlan, "base64");
    const produced = await m.produceCampaign({
      authorityId: "unit",
      attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(plan) }],
      bootstrap: async () => ({ scope, receipt: { phase: "infrastructure", unitOnly: true } }),
      readPlan: async () => plan,
      measureAttempt: async () => raw,
      retainReport: m.publishNativeReport,
    });
    assert.equal(produced.state, "complete", JSON.stringify(produced));
    assert.equal(produced.durabilityAcknowledged, true);
    const journal = (await fs.readFile(join(root, "attempt-ledger/ledger.jsonl"), "utf8"))
      .trimEnd()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      journal.map((r) => r.type),
      ["header", "birth", "terminal", "seal"],
    );
    const envelopeRaw = produced.snapshot.reports.get(journal[2].reportFile);
    assert.ok(envelopeRaw.length <= m.NATIVE_ENVELOPE_BUDGET.envelopeBytes);
    const envelope = JSON.parse(envelopeRaw);
    assert.equal(envelope.outcome, "pass");
    const descriptor = JSON.parse(Buffer.from(envelope.rawReport, "base64"));
    assert.equal(descriptor.schema, "calendar-native-report-ref/v1");
    const hydrated = await m.resolveNativeReport(descriptor, "one", scope);
    assert.deepEqual(hydrated.originalBytes, raw);
    assert.equal(hydrated.report.native.schema, "calendar-native-proof/v2");
    const actual = m.recomputeNativeReport(hydrated.report, {
      sourceBlobs: hydrated.sourceBlobs,
      attemptId: "one",
      scope,
    });
    assert.equal(actual.ok, true, JSON.stringify(actual));
    assert.deepEqual(hydrated.report.cleanup, report.cleanup);
    assert.deepEqual(hydrated.report.inventory, report.inventory);
    assert.deepEqual(hydrated.report.verdict, report.verdict);
    assert.equal(produced.externalApprovalVerified, false);
    assert.equal(produced.allDayCertified, false);
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("an oversized retention failure preserves the original cause alongside encoder failure", async () => {
  const { produceCampaign } = await import("./calendar-measure.mjs");
  const plan = Buffer.from("{}");
  let closed = 0,
    terminals = 0;
  const result = await produceCampaign({
    authorityId: "unit",
    attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(plan) }],
    bootstrap: async () => ({ scope: {}, receipt: {} }),
    readPlan: async () => plan,
    measureAttempt: async () => Buffer.alloc(180001, 0x78),
    retainReport: async () => {
      throw new Error("original retention sync failure");
    },
    createLedger: async () => ({
      registerBirth: async () => ({ durable: true }),
      recordTerminal: async () => {
        terminals++;
      },
      close: async () => {
        closed++;
      },
    }),
    classifyReport: () => "pass",
    readSnapshot: async () => ({}),
  });
  assert.equal(result.state, "unknown");
  assert.match(result.reasons.join("; "), /original retention sync failure/);
  assert.match(result.reasons.join("; "), /native raw acceptance budget exceeded/);
  assert.equal(terminals, 0);
  assert.equal(closed, 1);
});

test("whole report archive has a separate finite admission policy and a one-byte oversize refusal", async () => {
  const m = await import("./calendar-measure.mjs");
  assert.deepEqual(m.NATIVE_ENVELOPE_BUDGET, {
    reportBytes: 180000,
    planBytes: 8192,
    overheadBytes: 8192,
    envelopeBytes: 262144,
  });
  assert.equal(m.NATIVE_ARCHIVE_BUDGET.reportBytes, 32 * 1024 * 1024);
  assert.equal(m.NATIVE_ARCHIVE_BUDGET.manifestBytes, 8192);
  assert.equal(m.NATIVE_ARCHIVE_BUDGET.sourceBytes, 537475);
  assert.equal(m.NATIVE_ARCHIVE_BUDGET.fileCount, 6);
  assert.equal(m.NATIVE_ARCHIVE_BUDGET.currentAttemptCount, 6);
  assert.equal(6 * (32 * 1024 * 1024 + 8192 + 537475), 204600594);
  await assert.rejects(
    m.publishNativeReport(Buffer.alloc(32 * 1024 * 1024 + 1), { attemptId: "one" }, {}),
    /acceptance budget/,
  );
  for (const field of ["rawBytes", "manifestBytes"])
    await assert.rejects(
      m.resolveNativeReport(
        {
          schema: "calendar-native-report-ref/v1",
          attemptId: "one",
          scopeSha256: sha(JSON.stringify({ harnessH: "a".repeat(64) })),
          harnessH: "a".repeat(64),
          ownerUid: process.getuid(),
          rawBytes: 1,
          manifestBytes: 1,
          [field]: (field === "rawBytes" ? 32 * 1024 * 1024 : 8192) + 1,
        },
        "one",
        { harnessH: "a".repeat(64) },
      ),
      /acceptance budget/,
    );
});

test("whole report archive readback preserves exact original bytes and rejects independent binding changes", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-bind-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    const originalBytes = Buffer.from(JSON.stringify(report) + "\n");
    const attempt = {
      attemptId: "one",
      planSha256: sha(Buffer.from(report.native.rawPlan, "base64")),
    };
    const descriptor = JSON.parse(await m.publishNativeReport(originalBytes, attempt, scope));
    const restored = await m.resolveNativeReport(descriptor, "one", scope);
    assert.deepEqual(restored.originalBytes, originalBytes);
    assert.equal(
      m.recomputeNativeReport(restored.report, {
        sourceBlobs: restored.sourceBlobs,
        attemptId: "one",
        scope,
      }).ok,
      true,
    );
    assert.deepEqual(await fs.readdir(join(report.accountingDirectory, "native-report")), [
      "manifest.json",
      "report.raw",
    ]);
    for (const [key, value] of Object.entries({
      attemptId: "foreign",
      scopeSha256: "f".repeat(64),
      planSha256: "f".repeat(64),
      harnessH: "f".repeat(64),
      ownerUid: process.getuid() + 1,
      rawFile: "foreign.raw",
      rawBytes: originalBytes.length - 1,
      rawSha256: "f".repeat(64),
      manifestFile: "foreign.json",
      manifestBytes: descriptor.manifestBytes + 1,
      manifestSha256: "f".repeat(64),
      extra: true,
    }))
      await assert.rejects(
        m.resolveNativeReport({ ...descriptor, [key]: value }, "one", scope),
        undefined,
        key,
      );
    await assert.rejects(m.publishNativeReport(originalBytes, attempt, scope));
    const path = join(report.accountingDirectory, "native-report/report.raw");
    await fs.writeFile(path, originalBytes.subarray(0, -1));
    await assert.rejects(m.resolveNativeReport(descriptor, "one", scope), /byte count/);
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("whole report archive rejects alias missing extra and hardlinked publications", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  for (const attack of ["extra", "missing", "symlink", "hardlink", "directory-alias"]) {
    const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-alias-")));
    try {
      const { report, scope } = await fullNativeSourceFixture(root);
      const descriptor = JSON.parse(
        await m.publishNativeReport(
          Buffer.from(JSON.stringify(report)),
          { attemptId: "one", planSha256: sha(Buffer.from(report.native.rawPlan, "base64")) },
          scope,
        ),
      );
      const directory = join(report.accountingDirectory, "native-report"),
        rawPath = join(directory, "report.raw");
      if (attack === "extra") await fs.writeFile(join(directory, "extra"), "!");
      if (attack === "missing") await fs.unlink(rawPath);
      if (attack === "hardlink") await fs.link(rawPath, join(root, "linked"));
      if (attack === "symlink") {
        await fs.rename(rawPath, join(root, "foreign.raw"));
        await fs.symlink(join(root, "foreign.raw"), rawPath);
      }
      if (attack === "directory-alias") {
        await fs.rename(directory, join(root, "foreign-directory"));
        await fs.symlink(join(root, "foreign-directory"), directory);
      }
      await assert.rejects(m.resolveNativeReport(descriptor, "one", scope), undefined, attack);
    } finally {
      await fs.rm(root, { recursive: true });
    }
  }
});

test("whole report archive short writes and independent durability faults retain fail closed authority", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  for (const fault of ["none", "zero-write", "file-sync", "directory-sync", "corrupt-readback"]) {
    const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-write-")));
    try {
      const { report, scope } = await fullNativeSourceFixture(root);
      const raw = Buffer.from(JSON.stringify(report));
      let writes = 0,
        fileSyncs = 0,
        directorySyncs = 0;
      const publicationOpen = async (path, flags, mode) => {
        const handle = await fs.open(path, flags, mode);
        const archiveFile = path.endsWith("native-report/report.raw");
        const archiveDirectory = path.endsWith("native-report");
        return {
          write: async (bytes, offset, length, position) => {
            writes++;
            if (fault === "zero-write" && archiveFile) return { bytesWritten: 0 };
            return handle.write(bytes, offset, Math.min(length, 2048), position);
          },
          sync: async () => {
            if (flags === "wx") fileSyncs++;
            else directorySyncs++;
            if (fault === "file-sync" && archiveFile) throw new Error("archive file sync unknown");
            if (fault === "directory-sync" && archiveDirectory)
              throw new Error("archive directory sync unknown");
            if (fault === "corrupt-readback" && archiveFile)
              await handle.write(Buffer.from("!"), 0, 1, 0);
            return handle.sync();
          },
          close: () => handle.close(),
        };
      };
      const publication = m.publishNativeReport(
        raw,
        { attemptId: "one", planSha256: sha(Buffer.from(report.native.rawPlan, "base64")) },
        scope,
        { publicationOpen },
      );
      if (fault !== "none") {
        await assert.rejects(publication, /progress|sync unknown|readback/, fault);
        await assert.rejects(fs.stat(join(report.accountingDirectory, "durable-verdict.json")), {
          code: "ENOENT",
        });
      } else {
        const descriptor = JSON.parse(await publication);
        assert.ok(writes > 7);
        assert.equal(fileSyncs, 7);
        assert.equal(directorySyncs, 10);
        assert.deepEqual(
          (await m.resolveNativeReport(descriptor, "one", scope)).originalBytes,
          raw,
        );
      }
    } finally {
      await fs.rm(root, { recursive: true });
    }
  }
});

test("a caller map or cloned snapshot cannot provide whole native archive authority", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-authority-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    bindFixedUnitCampaign(report, scope, m.FIXED_BUILD_PINS);
    const plan = Buffer.from(report.native.rawPlan, "base64"),
      attempt = { attemptId: "one", planPath: "/unit", planSha256: sha(plan) };
    const produced = await m.produceCampaign({
      authorityId: "unit",
      attempts: [attempt],
      bootstrap: async () => ({ scope, receipt: { unitOnly: true } }),
      readPlan: async () => plan,
      measureAttempt: async () => Buffer.from(JSON.stringify(report)),
      retainReport: m.publishNativeReport,
    });
    assert.equal(produced.state, "complete", JSON.stringify(produced));
    const packet = {
      ...scope,
      authorityId: "unit",
      attempts: [attempt],
      refusalAttemptId: "one",
      controlAttemptIds: [],
    };
    const actual = m.evaluateCampaignSnapshot(packet, produced.snapshot, "f".repeat(64));
    assert.match(actual.problems.join(";"), /selected report partition/);
    assert.equal(actual.nativeCertificateIssued, false);
    const cloned = {
      ...produced.snapshot,
      nativeArchives: new Map([["one", report]]),
      nativeReports: new Map([["one", report]]),
    };
    const rejected = m.evaluateCampaignSnapshot(packet, cloned, "f".repeat(64));
    assert.match(rejected.problems.join(";"), /missing default native archive authority/);
    assert.equal(rejected.nativeCertificateIssued, false);
    const name = [...produced.snapshot.reports.keys()][0];
    const envelope = JSON.parse(produced.snapshot.reports.get(name));
    envelope.outcome = "fail";
    const altered = Buffer.from(JSON.stringify(envelope));
    produced.snapshot.reports.set(name, altered);
    const rows = produced.snapshot.ledgerBytes.toString().trimEnd().split("\n").map(JSON.parse);
    rows[2].reportSha256 = sha(altered);
    rows[2].reportBytes = altered.length;
    // The ledger parser rejects a changed sealed journal before archive authority is considered.
    assert.equal(
      m.evaluateCampaignSnapshot(packet, produced.snapshot, "f".repeat(64)).nativeCertificateIssued,
      false,
    );
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("the current archive campaign admission rejects a seventh attempt before infrastructure or effects", async () => {
  const m = await import("./calendar-measure.mjs");
  let bootstrap = 0,
    effects = 0;
  const result = await m.produceCampaign({
    attempts: Array.from({ length: 7 }, (_, i) => ({ attemptId: `a${i}` })),
    bootstrap: async () => {
      bootstrap++;
      throw new Error("unexpected infrastructure");
    },
    measureAttempt: async () => {
      effects++;
    },
    retainReport: m.publishNativeReport,
  });
  assert.equal(result.state, "unknown");
  assert.match(result.reasons.join(";"), /archive campaign acceptance budget/);
  assert.equal(bootstrap, 0);
  assert.equal(effects, 0);
});

test("archive manifest bindings reject rehashed projected summaries or changed full source references", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-manifest-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    const descriptor = JSON.parse(
      await m.publishNativeReport(
        Buffer.from(JSON.stringify(report)),
        { attemptId: "one", planSha256: sha(Buffer.from(report.native.rawPlan, "base64")) },
        scope,
      ),
    );
    const path = join(report.accountingDirectory, "native-report/manifest.json");
    const original = await fs.readFile(path),
      manifest = JSON.parse(original);
    for (const change of [
      (m) => {
        m.projectionSha256 = "f".repeat(64);
      },
      (m) => {
        m.projectionBytes--;
      },
      (m) => {
        m.sources[0].ownPid++;
      },
      (m) => {
        m.sources[0].queryArgvSha256 = "f".repeat(64);
      },
      (m) => {
        m.sources[0].rawSha256 = "f".repeat(64);
      },
      (m) => {
        m.sources[0].sourcePath = "foreign/path";
      },
      (m) => {
        m.sources.push(m.sources[0]);
      },
      (m) => {
        m.sources.pop();
      },
      (m) => {
        m.originalSchema = "summary/v1";
      },
    ]) {
      const forged = structuredClone(manifest);
      change(forged);
      const raw = Buffer.from(JSON.stringify(forged) + "\n");
      await fs.writeFile(path, raw);
      await assert.rejects(
        m.resolveNativeReport(
          { ...descriptor, manifestBytes: raw.length, manifestSha256: sha(raw) },
          "one",
          scope,
        ),
        /manifest binding/,
      );
    }
    await fs.writeFile(path, original);
    assert.deepEqual(
      (await m.resolveNativeReport(descriptor, "one", scope)).report.cleanup,
      report.cleanup,
    );
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("archive descriptor admission property model preserves bindings for independent malformed shapes", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-model-")));
  try {
    const { report, scope } = await fullNativeSourceFixture(root);
    const descriptor = JSON.parse(
      await m.publishNativeReport(
        Buffer.from(JSON.stringify(report)),
        { attemptId: "one", planSha256: sha(Buffer.from(report.native.rawPlan, "base64")) },
        scope,
      ),
    );
    const values = [
      null,
      false,
      [],
      {},
      -1,
      0,
      0.5,
      Number.MAX_SAFE_INTEGER + 1,
      "",
      "../foreign",
      "f".repeat(64),
      "é".repeat(63),
    ];
    const fields = [
      "attemptId",
      "scopeSha256",
      "planSha256",
      "harnessH",
      "rawBytes",
      "rawSha256",
      "manifestBytes",
      "manifestSha256",
      "ownerUid",
      "rawFile",
      "manifestFile",
    ];
    let state = 0x786;
    for (let i = 0; i < 64; i++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const field = fields[state % fields.length],
        value = values[(state >>> 8) % values.length];
      await assert.rejects(
        m.resolveNativeReport({ ...descriptor, [field]: value }, "one", scope),
        undefined,
        `case ${i}: ${field}`,
      );
    }
    assert.deepEqual(
      (await m.resolveNativeReport(descriptor, "one", scope)).report.inventory,
      report.inventory,
    );
  } finally {
    await fs.rm(root, { recursive: true });
  }
});

test("default whole archive classification cannot promote contradictory records control or unknown cleanup", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  for (const field of ["records", "cleanup", "control"]) {
    const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-unknown-")));
    try {
      const { report, scope } = await fullNativeSourceFixture(
        root,
        field === "control" ? nativeControlFixture("orphan") : nativeFixture(),
      );
      bindFixedUnitCampaign(report, scope, m.FIXED_BUILD_PINS);
      assert.equal(m.recomputeNativeReport(report).ok, true);
      if (field === "records") report.records.ok = false;
      if (field === "cleanup") report.cleanup.outcome = "unknown";
      if (field === "control") report.control.counts = false;
      const plan = Buffer.from(report.native.rawPlan, "base64");
      const result = await m.produceCampaign({
        authorityId: "unit",
        attempts: [{ attemptId: "one", planPath: "/unit", planSha256: sha(plan) }],
        bootstrap: async () => ({ scope, receipt: { unitOnly: true } }),
        readPlan: async () => plan,
        measureAttempt: async () => Buffer.from(JSON.stringify(report)),
        retainReport: m.publishNativeReport,
      });
      assert.equal(result.state, "unknown", field);
      const journal = (await fs.readFile(join(root, "attempt-ledger/ledger.jsonl"), "utf8"))
        .trimEnd()
        .split("\n")
        .map(JSON.parse);
      const terminal = JSON.parse(
        await fs.readFile(
          join(root, "attempt-ledger", journal.find((r) => r.type === "terminal").reportFile),
        ),
      );
      assert.equal(terminal.outcome, "unknown", field);
      assert.equal(result.externalApprovalVerified, false);
      assert.equal(result.allDayCertified, false);
    } finally {
      await fs.rm(root, { recursive: true });
    }
  }
});

test("a sealed source-only archive campaign reaches the production certifier and rejects invented host authority", async () => {
  const fs = await import("node:fs/promises"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  const m = await import("./calendar-measure.mjs");
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), "calendar-archive-certifier-")));
  try {
    const currentH = await m.harnessVersion(),
      reports = new Map(),
      attempts = [];
    let scope;
    for (const [i, mode] of [
      "refusal",
      "orphan",
      "escaper",
      "listener",
      "leftover",
      "positive",
    ].entries()) {
      const fixture = await fullNativeSourceFixture(
        root,
        mode === "refusal" ? nativeFixture() : nativeControlFixture(mode),
      );
      bindFixedUnitCampaign(fixture.report, fixture.scope, m.FIXED_BUILD_PINS);
      const oldH = fixture.report.harnessVersion;
      const report = JSON.parse(JSON.stringify(fixture.report).replaceAll(oldH, currentH));
      const rebind = (raw) =>
        Buffer.from(Buffer.from(raw, "base64").toString().replaceAll(oldH, currentH)).toString(
          "base64",
        );
      report.native.rawPlan = rebind(report.native.rawPlan);
      report.native.rawOuterResult = rebind(report.native.rawOuterResult);
      report.native.rawRecords = Object.fromEntries(
        Object.entries(report.native.rawRecords).map(([name, raw]) => [name, rebind(raw)]),
      );
      report.cleanup.rawRecords = rebind(report.cleanup.rawRecords);
      fixture.scope.harnessH = currentH;
      scope ??= fixture.scope;
      assert.equal(m.recomputeNativeReport(report).ok, true, mode);
      const plan = Buffer.from(report.native.rawPlan, "base64"),
        attemptId = `unit-${mode}`,
        planPath = join(root, `plan-${i}.json`);
      await fs.writeFile(planPath, plan);
      attempts.push({ attemptId, planPath, planSha256: sha(plan) });
      reports.set(attemptId, report);
    }
    const produced = await m.produceCampaign({
      authorityId: "unit-source-only",
      attempts,
      bootstrap: async () => ({ scope, receipt: { unitOnly: true } }),
      measureAttempt: async (bytes, attempt) =>
        Buffer.from(JSON.stringify(reports.get(attempt.attemptId))),
      retainReport: m.publishNativeReport,
    });
    assert.equal(produced.state, "complete", JSON.stringify(produced));
    const harnessFiles = Object.fromEntries(
      await Promise.all(
        m.HARNESS_FILES.map(async (name) => [
          name,
          sha(await fs.readFile(new URL(name, import.meta.url))),
        ]),
      ),
    );
    const packet = {
      schema: "calendar-campaign/v1",
      ...scope,
      authorityId: "unit-source-only",
      harnessFiles,
      bootstrap: "ordinary-user-own-ps",
      attempts,
      refusalAttemptId: attempts[0].attemptId,
      controlAttemptIds: attempts.slice(1).map((a) => a.attemptId),
    };
    const predicate = m.evaluateCampaignSnapshot(packet, produced.snapshot, "f".repeat(64));
    assert.equal(predicate.verdict, "pass", JSON.stringify(predicate));
    assert.equal(predicate.predicateOnly, true);
    assert.equal(predicate.nativeCertificateIssued, false);
    assert.equal(predicate.externalApprovalVerified, false);
    assert.equal(predicate.allDayCertified, false);
    const packetPath = join(root, "packet.json"),
      packetRaw = Buffer.from(JSON.stringify(packet));
    await fs.writeFile(packetPath, packetRaw);
    await fs.mkdir(join(root, "campaign-bootstrap"));
    await fs.writeFile(
      join(root, "campaign-bootstrap/receipt.json"),
      JSON.stringify({
        phase: "infrastructure",
        operation: "ordinary-user-own-ps",
        packetSha256: sha(packetRaw),
        nativeRoot: scope.nativeRoot,
        lifetime: { id: "unit-only", pid: 100, openedAt: Date.now() },
        unitOnly: true,
      }),
    );
    const manifestPath = join(root, "snapshot.json");
    await fs.writeFile(
      manifestPath,
      JSON.stringify({
        schema: "calendar-campaign-snapshot/v1",
        packetPath,
        packetSha256: sha(packetRaw),
        runRoot: root,
      }),
    );
    let providerCalls = 0;
    const refused = await m.certify(manifestPath, {
      requireCampaign: true,
      trustedPacketVerifier: async () => {
        providerCalls++;
        return true;
      },
    });
    assert.equal(providerCalls, 1);
    assert.equal(refused.nativeCertificateIssued, false);
    assert.match(refused.problems.join(";"), /external verifier did not close this exact binding/);
    for (const row of predicate.allBirths)
      assert.equal(
        row.rawReportSha256,
        sha(Buffer.from(JSON.stringify(reports.get(row.attemptId)))),
      );
  } finally {
    await fs.rm(root, { recursive: true });
  }
});
