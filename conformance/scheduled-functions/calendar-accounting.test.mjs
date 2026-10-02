import assert from "node:assert/strict";
import { test } from "node:test";
import {
  validateRecords,
  judgeInventory,
  interpretLsof,
  refusalVerdict,
  parseInventory,
  controlOutcome,
  REFUSAL_FORMATS,
  rustDebugString,
  refusalLineCheck,
  validatorControls,
  certificateVerdict,
  CERTIFICATE_LIMITS,
} from "./calendar-accounting.mjs";

function generated(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

// A complete record set for the chain measuring entry -> outer -> inner -> daemon, with
// `extra` short helper children (ps, getsid, lsof) per lane-owned process.
function recordSet(random = () => 0) {
  let mono = 1000n;
  const tick = () => String((mono += 1n + BigInt(random() % 5)));
  const shortChildren = (role, next, count) => {
    const rows = [];
    for (let i = 0; i < count; i++) {
      const handle = `${role}:${next + i}`;
      rows.push({
        type: "birth",
        handle,
        pid: 1000 + next + i,
        uid: 501,
        purpose: "ps",
        file: "ps",
        argvSha256: "a".repeat(64),
        spawnMonoNs: tick(),
      });
      rows.push({ type: "exit", handle, code: 0, signal: null, exitMonoNs: tick() });
    }
    return rows;
  };
  const measure = [
    {
      type: "header",
      role: "measure",
      pid: 100,
      started: "Fri Oct  2 06:00:00 2026",
      harnessVersion: "h",
    },
    {
      type: "birth",
      handle: "measure:1",
      pid: 200,
      uid: 501,
      purpose: "outer",
      file: "node",
      argvSha256: "b".repeat(64),
      spawnMonoNs: tick(),
    },
    { type: "identity", handle: "measure:1", pid: 200, started: "Fri Oct  2 06:00:01 2026" },
    ...shortChildren("measure", 2, random() % 3),
    { type: "exit", handle: "measure:1", code: 0, signal: null, exitMonoNs: tick() },
    ...shortChildren("measure", 10, random() % 3),
  ];
  const outer = [
    {
      type: "header",
      role: "outer",
      pid: 200,
      started: "Fri Oct  2 06:00:01 2026",
      harnessVersion: "h",
    },
    {
      type: "birth",
      handle: "outer:1",
      pid: 201,
      uid: 501,
      purpose: "claim",
      file: "python3",
      argvSha256: "c".repeat(64),
      spawnMonoNs: tick(),
    },
    { type: "exit", handle: "outer:1", code: 0, signal: null, exitMonoNs: tick() },
    {
      type: "birth",
      handle: "outer:2",
      pid: 300,
      uid: 501,
      purpose: "inner",
      file: "node",
      argvSha256: "d".repeat(64),
      spawnMonoNs: tick(),
    },
    { type: "identity", handle: "outer:2", pid: 300, started: "Fri Oct  2 06:00:02 2026" },
    ...shortChildren("outer", 3, random() % 3),
    { type: "exit", handle: "outer:2", code: 1, signal: null, exitMonoNs: tick() },
    ...shortChildren("outer", 20, random() % 3),
  ];
  const inner = [
    {
      type: "header",
      role: "inner",
      pid: 300,
      started: "Fri Oct  2 06:00:02 2026",
      harnessVersion: "h",
    },
    {
      type: "birth",
      handle: "inner:1",
      pid: 400,
      uid: 501,
      purpose: "daemon",
      file: "fireemu",
      argvSha256: "e".repeat(64),
      spawnMonoNs: tick(),
    },
    ...shortChildren("inner", 2, random() % 4),
    { type: "exit", handle: "inner:1", code: 1, signal: null, exitMonoNs: tick() },
  ];
  return { "measure.jsonl": measure, "outer.jsonl": outer, "inner.jsonl": inner };
}

const corruptions = {
  "drop an exit": (set) => {
    const rows = set["inner.jsonl"];
    rows.splice(
      rows.findIndex((row) => row.type === "exit"),
      1,
    );
  },
  "duplicate an exit": (set) => {
    const rows = set["outer.jsonl"];
    rows.push({ ...rows.find((row) => row.type === "exit") });
  },
  "drop a whole file": (set) => {
    delete set["inner.jsonl"];
  },
  "add an extra file": (set) => {
    set["stray.jsonl"] = [
      { type: "header", role: "inner", pid: 999, started: "x", harnessVersion: "h" },
    ];
  },
  "header PID differs": (set) => {
    set["outer.jsonl"][0] = { ...set["outer.jsonl"][0], pid: 201 };
  },
  "header start differs": (set) => {
    set["inner.jsonl"][0] = { ...set["inner.jsonl"][0], started: "Fri Oct  2 06:59:59 2026" };
  },
  "spawn-failed with a PID": (set) => {
    set["measure.jsonl"].push({
      type: "spawn-failed",
      handle: "measure:99",
      pid: 5,
      purpose: "ps",
      file: "ps",
      argvSha256: "f".repeat(64),
      spawnMonoNs: "1",
    });
  },
  "exit before birth": (set) => {
    const rows = set["inner.jsonl"];
    const exit = rows.find((row) => row.type === "exit" && row.handle === "inner:1");
    exit.exitMonoNs = "1";
  },
  "exit without birth": (set) => {
    set["outer.jsonl"].push({
      type: "exit",
      handle: "outer:77",
      code: 0,
      signal: null,
      exitMonoNs: "99999",
    });
  },
  "unknown row type": (set) => {
    set["inner.jsonl"].push({ type: "note", text: "x" });
  },
  "missing header": (set) => {
    set["inner.jsonl"].shift();
  },
  "lane-owned child without identity": (set) => {
    const rows = set["outer.jsonl"];
    rows.splice(
      rows.findIndex((row) => row.type === "identity"),
      1,
    );
  },
  "duplicate birth handle": (set) => {
    const rows = set["measure.jsonl"];
    rows.push({ ...rows.find((row) => row.type === "birth"), pid: 4242 });
  },
};

test("a complete chain of record files validates and reports its harness signals", () => {
  const set = recordSet();
  set["inner.jsonl"].push({
    type: "signal",
    target: { pid: 400, uid: 501, started: "s" },
    kind: "SIGTERM",
    monoNs: "99999",
  });
  const result = validateRecords(set);
  assert.deepEqual(result.problems, []);
  assert.equal(result.ok, true);
  assert.equal(result.signals.length, 1);
  assert.deepEqual(result.roles, ["measure", "outer", "inner"]);
});

test("each record corruption is refused for its own reason", () => {
  for (const [name, corrupt] of Object.entries(corruptions)) {
    const set = recordSet();
    corrupt(set);
    const result = validateRecords(set);
    assert.equal(result.ok, false, name);
    assert.ok(result.problems.length > 0, name);
  }
});

test("PID reuse across two short children is paired by handle, not by PID", () => {
  const set = recordSet();
  const rows = set["measure.jsonl"];
  rows.push(
    {
      type: "birth",
      handle: "measure:50",
      pid: 7000,
      uid: 501,
      purpose: "ps",
      file: "ps",
      argvSha256: "a".repeat(64),
      spawnMonoNs: "50000",
    },
    { type: "exit", handle: "measure:50", code: 0, signal: null, exitMonoNs: "50001" },
    {
      type: "birth",
      handle: "measure:51",
      pid: 7000,
      uid: 501,
      purpose: "ps",
      file: "ps",
      argvSha256: "a".repeat(64),
      spawnMonoNs: "50002",
    },
    { type: "exit", handle: "measure:51", code: 0, signal: null, exitMonoNs: "50003" },
  );
  assert.equal(validateRecords(set).ok, true);
});

test("generated record sets validate exactly when no corruption was applied", () => {
  const random = generated(0x5eed742);
  const names = Object.keys(corruptions);
  for (let i = 0; i < 200; i++) {
    const set = recordSet(random);
    const corrupted = random() % 3 === 0;
    const name = names[random() % names.length];
    if (corrupted) corruptions[name](set);
    const result = validateRecords(set);
    assert.equal(
      result.ok,
      !corrupted,
      `seed5eed742/${i}/${corrupted ? name : "clean"}: ${result.problems}`,
    );
  }
});

// Inventory rows are built from a named category whose expected judgement is fixed by
// construction, so the generated test checks the classifier against an independent model.
const ctx = {
  sessionId: 300,
  recorded: [{ pid: 400, uid: 501, started: "Fri Oct  2 06:00:03 2026" }],
  privateDir: "/private/run-1",
  launchTime: Date.parse("2026-10-02T06:00:00Z"),
  rootPid: 100,
};
const row = (overrides) => ({
  pid: 5000,
  ppid: 1,
  pgid: 5000,
  uid: 501,
  started: "Fri Oct  2 05:00:00 2026",
  stat: "S",
  args: "/usr/bin/other",
  sid: 77,
  ...overrides,
});
// Every real pass lists launchd and the measuring entry (review round 2, M3); the tests add
// them to each pass they build, unless the pass names those PIDs itself.
const baseRows = [
  row({ pid: 1, ppid: 0, sid: 1, args: "/sbin/launchd" }),
  row({ pid: 100, ppid: 1, sid: 50, args: "node calendar-run-local.mjs --measure plan.json" }),
];
const judgeComplete = (passes, context) =>
  judgeInventory(
    Array.isArray(passes)
      ? passes.map((pass) => [
          ...baseRows.filter((base) => !pass.some((other) => other.pid === base.pid)),
          ...pass,
        ])
      : passes,
    context,
  );
const categories = {
  unrelated: { make: (pid) => row({ pid }), expect: "clean" },
  "session member": { make: (pid) => row({ pid, sid: 300 }), expect: "survivor" },
  "recorded identity": {
    make: () => row({ pid: 400, started: "Fri Oct  2 06:00:03 2026", sid: 9 }),
    expect: "survivor",
  },
  "recorded PID, other start": {
    make: () => row({ pid: 400, started: "Fri Oct  2 07:00:00 2026" }),
    expect: "clean",
  },
  "private path after launch": {
    make: (pid) =>
      row({
        pid,
        started: "Fri Oct  2 06:00:05 2026",
        args: "node x --source /private/run-1/fixture",
      }),
    expect: "survivor",
  },
  "private path before launch": {
    make: (pid) => row({ pid, args: "node x --source /private/run-1/fixture" }),
    expect: "clean",
  },
  "zombie of a recorded parent": {
    make: (pid) => row({ pid, ppid: 400, stat: "Z", sid: "ESRCH" }),
    expect: "survivor",
  },
  "unrelated zombie, live parent outside": {
    make: (pid) => row({ pid, ppid: 6000, stat: "Z", sid: "ESRCH" }),
    expect: "clean",
    parent: true,
  },
  "unrelated zombie, parent gone": {
    make: (pid) => row({ pid, ppid: 6001, stat: "Z", sid: "ESRCH" }),
    expect: "inconclusive",
  },
  "ESRCH, unrelated parent": {
    make: (pid) => row({ pid, ppid: 6000, sid: "ESRCH" }),
    expect: "clean",
    parent: true,
  },
  "ESRCH, parent 1, started after the launch": {
    make: (pid) => row({ pid, ppid: 1, sid: "ESRCH", started: "Fri Oct  2 06:00:05 2026" }),
    expect: "repass",
  },
  "ESRCH, parent 1, started before the launch": {
    make: (pid) => row({ pid, ppid: 1, sid: "ESRCH" }),
    expect: "clean",
  },
  "getsid error": { make: (pid) => row({ pid, sid: "EPERM" }), expect: "inconclusive" },
};
const parentRow = row({ pid: 6000, ppid: 1, sid: 88 });

test("each inventory category is judged as the model says", () => {
  for (const [name, category] of Object.entries(categories)) {
    const pass = [category.make(5000), ...(category.parent ? [parentRow] : [])];
    const result = judgeComplete([pass, pass], ctx);
    const outcome =
      category.expect === "survivor"
        ? "survivors"
        : category.expect === "inconclusive" || category.expect === "repass"
          ? "inconclusive"
          : "clean";
    assert.equal(result.outcome, outcome, name);
  }
});

test("a re-pass trigger in the second pass needs a later clean pair; the bound is five passes", () => {
  const esrch = row({ pid: 5000, ppid: 1, sid: "ESRCH", started: "Fri Oct 2 06:00:05 2026" });
  const clean = [row({ pid: 5001 })];
  assert.equal(judgeComplete([clean, [esrch], clean, clean], ctx).outcome, "clean");
  assert.equal(
    judgeComplete([clean, [esrch], [esrch], [esrch], [esrch]], ctx).outcome,
    "inconclusive",
  );
  assert.equal(judgeComplete([clean], ctx).outcome, "inconclusive", "one pass is never enough");
  assert.equal(
    judgeComplete([clean, clean, clean, clean, clean, clean], ctx).outcome,
    "inconclusive",
    "more than five passes",
  );
});

test("generated inventories are judged as the category model says", () => {
  const random = generated(0x1e7e742);
  const names = Object.keys(categories);
  for (let i = 0; i < 300; i++) {
    const chosen = Array.from({ length: 1 + (random() % 4) }, () => names[random() % names.length]);
    const pass = [parentRow],
      inserted = [];
    chosen.forEach((name, index) => {
      const made = categories[name].make(5000 + index * 10);
      // Two categories can share a PID (the recorded one); only the inserted row counts.
      if (!pass.some((existing) => existing.pid === made.pid)) {
        pass.push(made);
        inserted.push(name);
      }
    });
    const expects = inserted.map((name) => categories[name].expect);
    const model = expects.includes("survivor")
      ? "survivors"
      : expects.some((e) => e === "inconclusive" || e === "repass")
        ? "inconclusive"
        : "clean";
    const result = judgeComplete([pass, pass], ctx);
    assert.equal(result.outcome, model, `seed1e7e742/${i}/${inserted}`);
    if (model === "survivors") assert.ok(result.survivors.length > 0);
  }
});

test("the survivor report names every rule that fired", () => {
  const member = row({
    pid: 400,
    started: "Fri Oct  2 06:00:03 2026",
    sid: 300,
    args: "fireemu --config /private/run-1/fireemu.json",
  });
  const result = judgeComplete([[member], [member]], {
    ...ctx,
    launchTime: Date.parse("2026-10-02T06:00:00Z"),
  });
  assert.deepEqual(result.survivors[0].rules, ["session", "identity", "path"]);
});

test("lsof answers are none only for a silent exit 1", () => {
  assert.deepEqual(
    interpretLsof({ code: 1, stdout: "", stderr: "", timedOut: false, truncated: false }),
    {
      result: "none",
    },
  );
  assert.deepEqual(
    interpretLsof({
      code: 0,
      stdout: "p4242\ncnode\nn*:12345\n",
      stderr: "",
      timedOut: false,
      truncated: false,
    }),
    { result: "listener", pids: [4242] },
  );
  for (const answer of [
    { code: 1, stdout: "", stderr: "lsof: illegal option", timedOut: false, truncated: false },
    { code: 1, stdout: "p1\n", stderr: "", timedOut: false, truncated: false },
    { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false },
    { code: 0, stdout: "garbage\n", stderr: "", timedOut: false, truncated: false },
    { code: 2, stdout: "", stderr: "", timedOut: false, truncated: false },
    { code: null, stdout: "", stderr: "", timedOut: true, truncated: false },
  ])
    assert.equal(interpretLsof(answer).result, "inconclusive", JSON.stringify(answer));
});

// refusalVerdict combines the conditions (A)-(G) of owner ledger 786.
function verdictInput() {
  const pins = {
    sourceCommit: "a".repeat(40),
    harnessVersion: "h",
    binarySha256: "b".repeat(64),
    runnerSha256: "c".repeat(64),
    fixtureSha256: "d".repeat(64),
    configSha256: "e".repeat(64),
    portctlSha256: "f".repeat(64),
    exitCode: 1,
    refusalLine:
      'error: manifest: function "calendarProbe": time zone: unknown time zone "Invalid/CalendarZone"',
  };
  return {
    certificate: true,
    escalation: "on",
    pins,
    identity: { ...pins, exitCode: undefined, refusalLine: undefined },
    refusalCheck: { ok: true, problems: [] },
    supervision: {
      inner: { timedOut: false, cancelled: false, inventoryFailures: 0, escalate: true },
      outer: { timedOut: false, cancelled: false, inventoryFailures: 0, escalate: true },
    },
    validatorControls: { ok: true, controls: [] },
    daemon: {
      exitCode: 1,
      diagnostics: ["functions loaded: none", pins.refusalLine],
      diagnosticsDrained: true,
      timedOut: false,
      cancelled: false,
    },
    chain: { rootSid: 50, outerPid: 200, outerSid: 200 },
    records: validateRecords(recordSet()),
    settle: { inner: true, outer: true },
    inventory: { outcome: "clean", survivors: [] },
    ports: { claims: [], lsof: [{ result: "none" }, { result: "none" }] },
  };
}

const breaks = {
  "binary hash differs": [(v) => (v.identity.binarySha256 = "0".repeat(64)), "fail", "A"],
  "fixture hash differs": [(v) => (v.identity.fixtureSha256 = "0".repeat(64)), "fail", "A"],
  "portctl hash differs": [(v) => (v.identity.portctlSha256 = "0".repeat(64)), "fail", "A"],
  "exit status differs": [(v) => (v.daemon.exitCode = 0), "fail", "A"],
  "refusal line differs": [(v) => (v.daemon.diagnostics = ["unknown time zone"]), "fail", "A"],
  "pinned line unexplained by the pinned source": [
    (v) => (v.refusalCheck = { ok: false, problems: ["x"] }),
    "fail",
    "A",
  ],
  "outer not a session leader": [(v) => (v.chain.outerSid = 50), "fail", "B"],
  "no daemon birth": [(v) => (v.records.births.inner = ["ps"]), "fail", "B"],
  "records incomplete": [
    (v) => (v.records = { ...v.records, ok: false, problems: ["x"] }),
    "fail",
    "C",
  ],
  "harness signal": [(v) => (v.records.signals = [{ kind: "SIGTERM" }]), "fail", "D"],
  "daemon timed out": [(v) => (v.daemon.timedOut = true), "fail", "D"],
  "settle escalated": [(v) => (v.settle.inner = false), "fail", "D"],
  survivor: [
    (v) => (v.inventory = { outcome: "survivors", survivors: [{ rules: ["session"] }] }),
    "fail",
    "E",
  ],
  // Breaks compose: one that touches a field another may have broken keeps that break.
  "inventory inconclusive": [
    (v) => {
      if (v.inventory.outcome === "clean") v.inventory = { outcome: "inconclusive", survivors: [] };
    },
    "inconclusive",
    "E",
  ],
  "claim kept": [(v) => (v.ports.claims = [{ port: 12345 }]), "fail", "F"],
  listener: [(v) => v.ports.lsof.push({ result: "listener", pids: [9] }), "fail", "F"],
  "lsof inconclusive": [(v) => v.ports.lsof.push({ result: "inconclusive" }), "inconclusive", "F"],
  "escalation off in a certificate": [(v) => (v.escalation = "off"), "fail", "G"],
};

test("a complete refusal run passes every condition", () => {
  const verdict = refusalVerdict(verdictInput());
  assert.equal(verdict.verdict, "pass", JSON.stringify(verdict.conditions));
  assert.deepEqual(Object.keys(verdict.conditions), ["A", "B", "C", "D", "E", "F", "G"]);
});

test("each broken condition is reported under its letter", () => {
  for (const [name, [apply, expected, letter]] of Object.entries(breaks)) {
    const input = verdictInput();
    apply(input);
    const verdict = refusalVerdict(input);
    assert.equal(verdict.verdict, expected, name);
    assert.equal(verdict.conditions[letter].ok, false, name);
  }
});

test("a control run may turn escalation off but never passes, and a missing input is never a pass", () => {
  const control = verdictInput();
  control.certificate = false;
  control.escalation = "off";
  const G = refusalVerdict(control).conditions.G;
  assert.equal(G.ok, false);
  assert.deepEqual(G.reasons, ["not a certificate run"]);
  for (const key of [
    "pins",
    "identity",
    "refusalCheck",
    "supervision",
    "validatorControls",
    "daemon",
    "chain",
    "records",
    "settle",
    "inventory",
    "ports",
  ]) {
    const input = verdictInput();
    delete input[key];
    assert.notEqual(refusalVerdict(input).verdict, "pass", key);
  }
});

test("generated combinations of breaks: any failure fails, else any unknown is inconclusive", () => {
  const random = generated(0xd786);
  const names = Object.keys(breaks);
  for (let i = 0; i < 300; i++) {
    const input = verdictInput();
    const chosen = names.filter(() => random() % 6 === 0);
    for (const name of chosen) breaks[name][0](input);
    const outcomes = chosen.map((name) => breaks[name][1]);
    const model = outcomes.includes("fail")
      ? "fail"
      : outcomes.includes("inconclusive")
        ? "inconclusive"
        : "pass";
    assert.equal(refusalVerdict(input).verdict, model, `seedd786/${i}/${chosen}`);
  }
});

test("inventory rows keep the state column and refuse an unreadable row", () => {
  const rows = parseInventory(
    "  100     1   100   501 Fri Oct  2 06:00:00 2026     Ss   /bin/zsh -l\n  4242   100  4242   501 Fri Oct  2 06:00:01 2026     Z    (sleep)\n",
  );
  assert.deepEqual(rows[1], {
    pid: 4242,
    ppid: 100,
    pgid: 4242,
    uid: 501,
    started: "Fri Oct 2 06:00:01 2026",
    stat: "Z",
    args: "(sleep)",
  });
  assert.throws(() => parseInventory("garbage\n"));
  assert.throws(() => parseInventory(""));
});

test("the positive control passes B-F, including D, and observes the runner and the child", () => {
  const conditions = Object.fromEntries(
    ["A", "B", "C", "D", "E", "F", "G"].map((letter) => [letter, { ok: true }]),
  );
  const passing = {
    verdict: "pass",
    conditions,
    observation: { runner: true, child: true, matched: true, cleanupVerified: true },
  };
  assert.equal(controlOutcome({ mode: "positive" }, passing).counts, true);
  for (const letter of ["B", "C", "D", "E", "F"]) {
    const broken = structuredClone(passing);
    broken.conditions[letter].ok = false;
    assert.equal(controlOutcome({ mode: "positive" }, broken).counts, false, letter);
  }
  assert.equal(
    controlOutcome(
      { mode: "positive" },
      {
        ...passing,
        observation: { runner: false, child: true, matched: true, cleanupVerified: true },
      },
    ).counts,
    false,
  );
});

// Condition (A): the pinned refusal line is explained by the format strings at the pinned source,
// so its expected value is not taken only from the harness's own output (review S-d).
const pinnedSources = () =>
  Object.fromEntries(
    Object.values(REFUSAL_FORMATS).map(({ path, text }) => [path, `fn x() {\n    ${text}\n}\n`]),
  );
const fixture = { functionName: "calendarProbe", timeZone: "Invalid/CalendarZone" };
const core =
  'manifest: function "calendarProbe": time zone: unknown time zone "Invalid/CalendarZone"';

test("rustDebugString quotes as Rust's Debug for str does, and refuses what it does not model", () => {
  assert.equal(rustDebugString("Invalid/CalendarZone"), '"Invalid/CalendarZone"');
  assert.equal(rustDebugString('a"b\\c'), '"a\\"b\\\\c"');
  assert.equal(rustDebugString("a'b"), '"a\'b"');
  assert.equal(rustDebugString("\n\r\t\0"), '"\\n\\r\\t\\0"');
  assert.equal(rustDebugString("\x01\x1f\x7f"), '"\\u{1}\\u{1f}\\u{7f}"');
  assert.equal(rustDebugString(" ~"), '" ~"');
  for (const value of ["\u00e9", "\u200d", 7, null]) assert.equal(rustDebugString(value), null);
});

test("the pinned refusal line is explained by the format strings at the pinned source", () => {
  assert.deepEqual(refusalLineCheck("error: " + core, { ...fixture, sources: pinnedSources() }), {
    ok: true,
    problems: [],
  });
  const wrapped = 'error: the Functions codebase "default": ' + core;
  assert.equal(refusalLineCheck(wrapped, { ...fixture, sources: pinnedSources() }).ok, true);
  for (const [name, line] of [
    ["no error prefix", core],
    ["unexplained wrapper", "error: functions[default]: " + core],
    ["another zone", "error: " + core.replace("Invalid/CalendarZone", "Invalid/Other")],
    ["another function", "error: " + core.replace("calendarProbe", "calendarReceipt")],
    ["trailing text", "error: " + core + " "],
    ["not a string", undefined],
  ])
    assert.equal(refusalLineCheck(line, { ...fixture, sources: pinnedSources() }).ok, false, name);
  for (const { path } of Object.values(REFUSAL_FORMATS)) {
    const sources = pinnedSources();
    sources[path] = sources[path].replace("format!", "format !").replace("eprintln!", "println!");
    const result = refusalLineCheck("error: " + core, { ...fixture, sources });
    assert.equal(result.ok, false, path);
    assert.ok(
      result.problems.some((problem) => problem.includes(path)),
      path,
    );
  }
  const unmodelled = refusalLineCheck("error: " + core, {
    ...fixture,
    timeZone: "Zone\u00e9",
    sources: pinnedSources(),
  });
  assert.equal(unmodelled.ok, false);
});

// Review round 1 of harness H (2026-10-02): M1-M3, S1-S3, S7, S8 and the validator controls.
test("record files must agree on the harness version, and the version is pinned", () => {
  const set = recordSet();
  set["inner.jsonl"][0] = { ...set["inner.jsonl"][0], harnessVersion: "other" };
  const result = validateRecords(set);
  assert.equal(result.ok, false);
  assert.ok(result.problems.some((problem) => problem.includes("harness version")));
  const input = verdictInput();
  input.identity.harnessVersion = "edited";
  assert.equal(refusalVerdict(input).conditions.A.ok, false);
});

test("only a certificate run with escalation on and a clean identity can pass", () => {
  for (const [name, apply] of [
    ["a control run", (v) => (v.certificate = false)],
    ["certificate missing", (v) => delete v.certificate],
    ["escalation off", (v) => (v.escalation = "off")],
    ["a control identity", (v) => (v.identity.controlMode = "orphan")],
    ["a control preamble hash", (v) => (v.identity.controlsSha256 = "0".repeat(64))],
  ]) {
    const input = verdictInput();
    apply(input);
    assert.notEqual(refusalVerdict(input).verdict, "pass", name);
  }
});

test("(D) judges both supervisions: a timeout fails, a failed tracker poll is inconclusive", () => {
  for (const [name, apply, outcome] of [
    ["outer timed out", (v) => (v.supervision.outer.timedOut = true), "fail"],
    ["outer cancelled", (v) => (v.supervision.outer.cancelled = true), "fail"],
    ["inner timed out", (v) => (v.supervision.inner.timedOut = true), "fail"],
    ["inner poll failed", (v) => (v.supervision.inner.inventoryFailures = 1), "inconclusive"],
    ["outer poll failed", (v) => (v.supervision.outer.inventoryFailures = 2), "inconclusive"],
    ["poll count missing", (v) => delete v.supervision.outer.inventoryFailures, "inconclusive"],
    ["no supervision", (v) => delete v.supervision, "inconclusive"],
  ]) {
    const input = verdictInput();
    apply(input);
    const verdict = refusalVerdict(input);
    assert.equal(verdict.conditions.D.outcome, outcome, name);
    assert.equal(verdict.verdict, outcome, name);
  }
});

test("(G) in one run needs the validator controls on that run's own records", () => {
  const missing = verdictInput();
  delete missing.validatorControls;
  assert.equal(refusalVerdict(missing).conditions.G.outcome, "inconclusive");
  const failed = verdictInput();
  failed.validatorControls = { ok: false, controls: [] };
  assert.equal(refusalVerdict(failed).conditions.G.outcome, "fail");
});

test("the validator controls refuse a removed file, a dropped exit and a failed spawn with a PID, and pair PID reuse", () => {
  const result = validatorControls(recordSet());
  assert.equal(result.ok, true, JSON.stringify(result.controls));
  assert.deepEqual(
    result.controls.map((control) => [control.name, control.expected, control.observed]),
    [
      ["outer.jsonl removed", "refused", "refused"],
      ["inner.jsonl removed", "refused", "refused"],
      ["dropped exit row", "refused", "refused"],
      ["spawn-failed with a PID", "refused", "refused"],
      ["PID reuse across two short children", "accepted", "accepted"],
    ],
  );
  const broken = recordSet();
  broken["inner.jsonl"].push({ type: "note" });
  assert.equal(validatorControls(broken).ok, false, "controls need valid base records");
  assert.equal(validatorControls(undefined).ok, false);
});

test("an uncovered zombie is unrelated only when its parent is alive outside the session", () => {
  const zombie = (sid, ppid) => row({ pid: 5000, ppid, stat: "Z", sid });
  assert.equal(
    judgeComplete([[zombie(77, 6001)], [zombie(77, 6001)]], ctx).outcome,
    "inconclusive",
  );
  const withParent = [zombie(77, 6000), parentRow];
  const result = judgeComplete([withParent, withParent], ctx);
  assert.equal(result.outcome, "clean");
  assert.equal(result.passes[0].unrelatedZombies.length, 1, "logged");
  const insideParent = [zombie(77, 6000), { ...parentRow, sid: "ESRCH" }];
  assert.equal(judgeComplete([insideParent, insideParent], ctx).outcome, "inconclusive");
});

test("start times are read in UTC, and an unreadable one is inconclusive", () => {
  const late = row({ started: "Fri Oct 2 06:00:01 2026", args: "x /private/run-1/y" });
  assert.equal(judgeComplete([[late], [late]], ctx).outcome, "survivors");
  const early = row({ started: "Fri Oct 2 05:59:59 2026", args: "x /private/run-1/y" });
  assert.equal(judgeComplete([[early], [early]], ctx).outcome, "clean");
  const unreadable = row({ started: "Fri Foo 2 05:59:59 2026" });
  assert.equal(judgeComplete([[unreadable], [unreadable]], ctx).outcome, "inconclusive");
});

test("an ESRCH row asks for another pass when its parent could have been in the session", () => {
  const member = row({ pid: 6100, sid: 300, args: "member" });
  for (const [name, rows] of [
    [
      "parent a recorded identity",
      [row({ pid: 5000, ppid: 400, sid: "ESRCH", started: "Fri Oct 2 06:00:05 2026" })],
    ],
    [
      "parent an ESRCH row under launchd",
      [
        row({ pid: 5000, ppid: 6200, sid: "ESRCH", started: "Fri Oct 2 06:00:05 2026" }),
        row({ pid: 6200, ppid: 1, sid: "ESRCH", started: "Fri Oct 2 06:00:04 2026" }),
      ],
    ],
  ]) {
    const clean = [row({ pid: 5001 })];
    assert.equal(judgeComplete([clean, rows, clean], ctx).outcome, "inconclusive", name);
    assert.equal(judgeComplete([clean, rows, clean, clean], ctx).outcome, "clean", name);
  }
  // A session member parent makes the member itself a survivor, so the run fails either way.
  assert.equal(
    judgeComplete([[member, row({ pid: 5000, ppid: 6100, sid: "ESRCH" })]], ctx).outcome,
    "survivors",
  );
});

test("the positive control needs verified cleanup and a released claim", () => {
  const conditions = Object.fromEntries(
    ["B", "C", "D", "E", "F"].map((letter) => [letter, { ok: true }]),
  );
  const observation = { runner: true, child: true, matched: true, cleanupVerified: true };
  assert.equal(controlOutcome({ mode: "positive" }, { conditions, observation }).counts, true);
  assert.equal(
    controlOutcome(
      { mode: "positive" },
      { conditions, observation: { ...observation, cleanupVerified: false } },
    ).counts,
    false,
  );
});

// The certificate (condition (G)): the refusal run and every control under the same H, same day.
const IDENTITY = {
  sourceCommit: "a".repeat(40),
  binarySha256: "b".repeat(64),
  runnerSha256: "c".repeat(64),
  portctlSha256: "f".repeat(64),
  harnessVersion: "h1",
  fixtureSha256: "d".repeat(64),
  configSha256: "e".repeat(64),
};
const REFUSAL_LINE =
  'error: manifest: function "calendarProbe": time zone: unknown time zone "Invalid/CalendarZone"';
function report(kind, overrides = {}) {
  return {
    kind,
    harnessVersion: "h1",
    launchTime: Date.parse("2026-10-02T03:00:00Z"),
    verdict: { verdict: kind === "certificate" ? "pass" : "fail" },
    validatorControls: { ok: true },
    identity: { ...IDENTITY },
    pins: { ...IDENTITY, exitCode: 1, refusalLine: REFUSAL_LINE },
    refusal: {
      exitCode: kind === "certificate" ? 1 : 0,
      line: kind === "certificate" ? REFUSAL_LINE : null,
    },
    root: { pid: 100, started: "Fri Oct 2 03:00:00 2026", sid: 50 },
    control:
      kind === "certificate"
        ? null
        : { mode: kind === "positive" ? "positive" : kind, counts: true },
    ...overrides,
  };
}
const pick = ({ verdict, problems }) => ({ verdict, problems });
const allControls = () =>
  ["positive", "orphan", "escaper", "listener", "leftover"].map((kind) => report(kind));

test("a certificate needs the refusal run and every control, same harness version, same UTC day", () => {
  assert.deepEqual(
    pick(certificateVerdict({ refusal: report("certificate"), controls: allControls() })),
    { verdict: "pass", problems: [] },
  );
  for (const [name, refusal, controls] of [
    [
      "the refusal run failed",
      report("certificate", { verdict: { verdict: "inconclusive" } }),
      allControls(),
    ],
    ["not a certificate run", report("positive"), allControls()],
    ["a control is missing", report("certificate"), allControls().slice(1)],
    [
      "a control did not count",
      report("certificate"),
      allControls().map((r) =>
        r.kind === "escaper" ? { ...r, control: { ...r.control, counts: false } } : r,
      ),
    ],
    [
      "another harness version",
      report("certificate"),
      allControls().map((r) => (r.kind === "orphan" ? { ...r, harnessVersion: "h2" } : r)),
    ],
    [
      "another day",
      report("certificate"),
      allControls().map((r) =>
        r.kind === "leftover" ? { ...r, launchTime: Date.parse("2026-10-03T00:00:01Z") } : r,
      ),
    ],
    [
      "validator controls failed in a control run",
      report("certificate"),
      allControls().map((r) =>
        r.kind === "listener" ? { ...r, validatorControls: { ok: false } } : r,
      ),
    ],
    [
      "validator controls failed in the refusal run",
      report("certificate", { validatorControls: { ok: false } }),
      allControls(),
    ],
    ["no controls", report("certificate"), undefined],
  ]) {
    const result = certificateVerdict({ refusal, controls });
    assert.equal(result.verdict, "fail", name);
    assert.ok(result.problems.length > 0, name);
  }
});

// Mutation round 1 (validator mutation of harness H): each judge's exact answer, so a mutant that
// only changes which reason refuses a record set, or drops one of two redundant reasons, is
// still seen.
const birthRow = (overrides) => ({
  type: "birth",
  handle: "measure:9",
  pid: 9000,
  uid: 501,
  purpose: "ps",
  file: "ps",
  argvSha256: "a".repeat(64),
  spawnMonoNs: "5000",
  ...overrides,
});
const exactCorruptions = {
  "inner rows are not a list": [
    (set) => (set["inner.jsonl"] = {}),
    ["inner.jsonl: the first row is not a header", "missing inner record file"],
  ],
  ...Object.fromEntries(
    [
      ["role", "x"],
      ["pid", 1],
      ["pid", 2.5],
      ["started", ""],
      ["harnessVersion", ""],
    ].map(([key, value]) => [
      `header ${key} ${JSON.stringify(value)}`,
      [
        (set) => (set["inner.jsonl"][0] = { ...set["inner.jsonl"][0], [key]: value }),
        ["inner.jsonl: malformed header", "missing inner record file"],
      ],
    ]),
  ),
  "a second inner file": [
    (set) =>
      (set["stray.jsonl"] = [
        { type: "header", role: "inner", pid: 999, started: "x", harnessVersion: "h" },
      ]),
    ["stray.jsonl: a second inner record file"],
  ],
  ...Object.fromEntries(
    [
      ["handle", ""],
      ["pid", 1],
      ["pid", "9000"],
      ["uid", "501"],
      ["purpose", ""],
      ["file", ""],
      ["argvSha256", "abc"],
      ["spawnMonoNs", "1.5"],
    ].map(([key, value]) => [
      `birth ${key} ${JSON.stringify(value)}`,
      [
        (set) => set["measure.jsonl"].push(birthRow({ [key]: value })),
        ["measure.jsonl: malformed birth row"],
      ],
    ]),
  ),
  "a birth with PID 2 is well formed (it only lacks its exit)": [
    (set) => set["measure.jsonl"].push(birthRow({ pid: 2 })),
    ["measure.jsonl: measure:9 has no exit"],
  ],
  ...Object.fromEntries(
    [
      ["handle", ""],
      ["pid", 0],
      ["started", ""],
    ].map(([key, value]) => [
      `identity ${key} ${JSON.stringify(value)}`,
      [
        (set) =>
          set["outer.jsonl"].push({
            type: "identity",
            handle: "outer:1",
            pid: 201,
            started: "s",
            [key]: value,
          }),
        ["outer.jsonl: malformed identity row"],
      ],
    ]),
  ),
  "exit without a handle": [
    (set) => set["outer.jsonl"].push({ type: "exit", handle: "", exitMonoNs: "5" }),
    ["outer.jsonl: malformed exit row"],
  ],
  "exit with an unreadable time": [
    (set) => set["outer.jsonl"].push({ type: "exit", handle: "outer:77", exitMonoNs: "x" }),
    ["outer.jsonl: malformed exit row"],
  ],
  ...Object.fromEntries(
    [
      ["target", { pid: 1, started: "s" }],
      ["target", { pid: 400, started: "" }],
      ["kind", "SIGINT"],
    ].map(([key, value]) => [
      `signal ${key} ${JSON.stringify(value)}`,
      [
        (set) =>
          set["inner.jsonl"].push({
            type: "signal",
            target: { pid: 400, started: "s" },
            kind: "SIGTERM",
            [key]: value,
          }),
        ["inner.jsonl: malformed signal row"],
      ],
    ]),
  ),
  "a failed spawn reuses a born handle": [
    (set) => set["measure.jsonl"].push({ type: "spawn-failed", handle: "measure:1", pid: null }),
    ["measure.jsonl: handle measure:1 is born twice"],
  ],
  "a failed spawn without a handle": [
    (set) => set["measure.jsonl"].push({ type: "spawn-failed", handle: "", pid: null }),
    ["measure.jsonl: a failed spawn carries a PID or no handle"],
  ],
  "a failed spawn with an exit": [
    (set) =>
      set["measure.jsonl"].push(
        { type: "spawn-failed", handle: "measure:8", pid: null },
        { type: "exit", handle: "measure:8", code: 0, signal: null, exitMonoNs: "9999" },
      ),
    ["measure.jsonl: failed spawn measure:8 has an exit"],
  ],
  "an exit at its birth's own time is accepted": [
    (set) => {
      const rows = set["outer.jsonl"];
      rows.find((row) => row.handle === "outer:1" && row.type === "exit").exitMonoNs = rows.find(
        (row) => row.handle === "outer:1" && row.type === "birth",
      ).spawnMonoNs;
    },
    [],
  ],
  "exit before birth": [
    (set) =>
      (set["inner.jsonl"].find(
        (row) => row.type === "exit" && row.handle === "inner:1",
      ).exitMonoNs = "1"),
    ["inner.jsonl: inner:1 exits before it was born"],
  ],
  "an identity row names another PID": [
    (set) => (set["outer.jsonl"].find((row) => row.type === "identity").pid = 301),
    ["outer.jsonl: identity row outer:2 names no matching birth"],
  ],
  "a lane-owned child without identity": [
    (set) => {
      const rows = set["outer.jsonl"];
      rows.splice(
        rows.findIndex((row) => row.type === "identity"),
        1,
      );
    },
    [
      "outer.jsonl: lane-owned child outer:2 has no identity row",
      "inner.jsonl: header identity differs from its parent's birth record",
      "inner.jsonl: record file no parent accounts for",
    ],
  ],
  "two outer children": [
    (set) =>
      set["measure.jsonl"].push(
        birthRow({ handle: "measure:5", pid: 250, purpose: "outer" }),
        { type: "identity", handle: "measure:5", pid: 250, started: "s" },
        { type: "exit", handle: "measure:5", code: 0, signal: null, exitMonoNs: "6000" },
      ),
    [
      "measure.jsonl: more than one outer child",
      "measure.jsonl: more than one outer child",
      "outer.jsonl: record file no parent accounts for",
      "inner.jsonl: record file no parent accounts for",
    ],
  ],
  "no measuring-entry file": [
    (set) => delete set["measure.jsonl"],
    [
      "no measuring-entry record file",
      "outer.jsonl: record file no parent accounts for",
      "inner.jsonl: record file no parent accounts for",
    ],
  ],
  "an outer header with another PID": [
    (set) => (set["outer.jsonl"][0] = { ...set["outer.jsonl"][0], pid: 201 }),
    [
      "outer.jsonl: header identity differs from its parent's birth record",
      "outer.jsonl: record file no parent accounts for",
      "inner.jsonl: record file no parent accounts for",
    ],
  ],
  "an unexpected row type": [
    (set) => set["inner.jsonl"].push({ type: "note", text: "x" }),
    ['inner.jsonl: unexpected row "note"'],
  ],
};

test("each record corruption gives exactly its expected problems", () => {
  for (const [name, [corrupt, expected]] of Object.entries(exactCorruptions)) {
    const set = recordSet();
    corrupt(set);
    const result = validateRecords(set);
    assert.deepEqual(result.problems, expected, name);
    assert.equal(result.ok, expected.length === 0, name);
  }
  for (const files of [undefined, null, "records"])
    assert.deepEqual(validateRecords(files), {
      ok: false,
      problems: ["no record files"],
      signals: [],
      roles: [],
      births: {},
    });
});

test("a harness signal row is reported with the file it came from", () => {
  const set = recordSet();
  const signal = {
    type: "signal",
    target: { pid: 400, started: "s" },
    kind: "SIGKILL",
    monoNs: "7",
  };
  set["inner.jsonl"].push(signal);
  assert.deepEqual(validateRecords(set).signals, [{ file: "inner.jsonl", ...signal }]);
  assert.deepEqual(validateRecords(recordSet()).births, {
    measure: ["outer"],
    outer: ["claim", "inner"],
    inner: ["daemon"],
  });
});

test("inventory reasons, the launch-time boundary, ignored rows and the pass bound are exact", () => {
  const judge = (rows) => judgeComplete([rows, rows], ctx);
  assert.equal(judge([row({ sid: "EPERM" })]).reason, "session query failed");
  assert.equal(
    judge([row({ started: "Fri Foo 2 05:59:59 2026" })]).reason,
    "unreadable start time",
  );
  assert.equal(
    judge([row({ ppid: 6001, stat: "Z", sid: "ESRCH" })]).reason,
    "zombie with an unknown parent",
  );
  const atLaunch = row({ started: "Fri Oct 2 06:00:00 2026", args: "x /private/run-1/y" });
  assert.deepEqual(judge([atLaunch]).survivors[0].rules, ["path"]);
  const zombie = row({ pid: 5000, ppid: 400, stat: "Z", sid: "ESRCH" });
  assert.deepEqual(judge([zombie]).survivors[0].rules, ["zombie"]);
  const unrelated = row({ pid: 5000, ppid: 6000, sid: "ESRCH" });
  const result = judge([unrelated, parentRow]);
  assert.equal(result.outcome, "clean");
  assert.deepEqual(result.passes[0].ignored, [unrelated]);
  const clean = [row({ pid: 5001 })];
  assert.deepEqual(judgeComplete([], ctx), {
    passes: [],
    outcome: "inconclusive",
    reason: "an inventory has one to five passes",
    survivors: [],
  });
  const esrch = [row({ pid: 5000, ppid: 1, sid: "ESRCH", started: "Fri Oct 2 06:00:05 2026" })];
  assert.equal(judgeComplete([clean, esrch, esrch, clean, clean], ctx).outcome, "clean");
  assert.equal(
    judgeComplete([clean, esrch, esrch, esrch, clean], ctx).reason,
    "no two consecutive clean passes",
  );
});

test("lsof answers: every shape other than a silent exit 1 or a readable listener is inconclusive", () => {
  const inconclusive = { result: "inconclusive" };
  for (const answer of [
    { code: 1, stdout: "", stderr: "", timedOut: true, truncated: false },
    { code: 0, stdout: "p12\n", stderr: "warning", timedOut: false, truncated: false },
    { code: 2, stdout: "", stderr: "", timedOut: false, truncated: false },
    { code: 0, stdout: "", stderr: "", timedOut: false, truncated: false },
    { code: 0, stdout: "p12\nx\n", stderr: "", timedOut: false, truncated: false },
    { code: 0, stdout: "f3\nn*:1\n", stderr: "", timedOut: false, truncated: false },
  ])
    assert.deepEqual(interpretLsof(answer), inconclusive, JSON.stringify(answer));
  assert.deepEqual(
    interpretLsof({
      code: 0,
      stdout: "p12\ncnode\nf3\nn*:1\np13\n",
      stderr: "",
      timedOut: false,
      truncated: false,
    }),
    { result: "listener", pids: [12, 13] },
  );
});

test("the refusal format strings are the ones at the pinned source", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(REFUSAL_FORMATS)), {
    zone: {
      path: "crates/fireemu-adapter-functions/src/zone.rs",
      text: 'format!("unknown time zone {name:?}")',
    },
    manifest: {
      path: "crates/fireemu-adapter-functions/src/manifest_json.rs",
      text: 'format!("manifest: function {name:?}: time zone: {e}")',
    },
    label: {
      path: "crates/fireemu/src/functions.rs",
      text: 'format!("the Functions codebase {label:?}: {e}")',
    },
    fail: { path: "crates/fireemu/src/main.rs", text: 'eprintln!("error: {}", e.message)' },
  });
});

test("refusal line problems are exact", () => {
  const sources = pinnedSources();
  assert.deepEqual(
    refusalLineCheck("error: " + core, { ...fixture, timeZone: "Zoneé", sources }).problems,
    ["the fixture's names are not modelled"],
  );
  assert.deepEqual(
    refusalLineCheck("error: " + core, { ...fixture, functionName: "fé", sources }).problems,
    ["the fixture's names are not modelled"],
  );
  assert.deepEqual(refusalLineCheck(undefined, { ...fixture, sources }).problems, [
    "no pinned refusal line",
  ]);
  assert.deepEqual(refusalLineCheck("error: x", { ...fixture, sources }).problems, [
    "the pinned refusal line is not explained by the pinned format strings",
  ]);
});

test("each condition's reasons are exact", () => {
  const reasons = (apply, letter) => {
    const input = verdictInput();
    apply(input);
    return refusalVerdict(input).conditions[letter].reasons;
  };
  const complete = refusalVerdict(verdictInput());
  for (const condition of Object.values(complete.conditions))
    assert.deepEqual(condition, { ok: true, outcome: "pass", reasons: [] });
  for (const key of [
    "sourceCommit",
    "harnessVersion",
    "binarySha256",
    "runnerSha256",
    "fixtureSha256",
    "configSha256",
    "portctlSha256",
  ])
    assert.deepEqual(
      reasons((v) => (v.identity[key] = "0"), "A"),
      [`${key} differs from its pin`],
    );
  for (const [apply, letter, expected] of [
    [
      (v) => (v.identity.controlMode = "orphan"),
      "A",
      ["the run's identity names a control fixture"],
    ],
    [(v) => (v.refusalCheck = { ok: false, problems: [] }), "A", ["unchecked"]],
    [(v) => (v.refusalCheck = { ok: false }), "A", ["unchecked"]],
    [(v) => (v.refusalCheck = { ok: false, problems: ["p"] }), "A", ["p"]],
    [(v) => (v.daemon.exitCode = 0), "A", ["the daemon's exit status differs from its pin"]],
    [(v) => (v.daemon.diagnostics = []), "A", ["the pinned refusal line was not printed"]],
    [
      (v) => (v.chain = { rootSid: 200, outerPid: 200, outerSid: 200 }),
      "B",
      ["the outer launcher is not the leader of its own session"],
    ],
    [
      (v) => (v.records.births.measure = []),
      "B",
      ["the measuring entry did not start the outer launcher"],
    ],
    [(v) => (v.records.births.outer = ["inner"]), "B", ["the outer launcher has no claim child"]],
    [(v) => (v.records.births.inner = []), "B", ["the inner supervisor did not start the daemon"]],
    [(v) => (v.records = { ...v.records, ok: false, problems: [] }), "C", ["records invalid"]],
    [(v) => (v.records = { ...v.records, ok: false }), "C", ["records invalid"]],
    [(v) => (v.records = { ...v.records, ok: false, problems: ["q"] }), "C", ["q"]],
    [(v) => (v.daemon.cancelled = true), "D", ["the daemon did not exit by itself"]],
    [(v) => (v.settle.outer = false), "D", ["a settle phase did not empty without escalation"]],
    [(v) => (v.ports.claims = [{}]), "F", ["the private registry still holds a claim"]],
    [(v) => (v.ports.lsof = "none"), "F", ["no lsof answer"]],
    [(v) => (v.ports.lsof = []), "F", ["no lsof answer"]],
    [(v) => v.ports.lsof.push({ result: "listener", pids: [1] }), "F", ["a TCP listener is held"]],
    [(v) => v.ports.lsof.push({ result: "?" }), "F", ["an lsof answer is inconclusive"]],
    [(v) => (v.escalation = "off"), "G", ["escalation off is for control runs only"]],
    [(v) => (v.validatorControls = { ok: false }), "G", ["a validator control did not hold"]],
  ])
    assert.deepEqual(reasons(apply, letter), expected, String(apply));
  const missing = verdictInput();
  delete missing.inventory;
  assert.deepEqual(refusalVerdict(missing).conditions.E, {
    ok: false,
    outcome: "inconclusive",
    reasons: ["missing inventory"],
  });
});

test("an unreadable inventory row names itself", () => {
  assert.throws(() => parseInventory("garbage\n"), /^Error: unreadable inventory row$/);
});

test("the validator controls report what each one changed and why it was refused", () => {
  const result = validatorControls(recordSet());
  assert.deepEqual(
    result.controls.map(({ name, rowsChanged, problems }) => [name, rowsChanged, problems]),
    [
      [
        "outer.jsonl removed",
        -recordSet()["outer.jsonl"].length,
        ["missing outer record file", "inner.jsonl: record file no parent accounts for"],
      ],
      ["inner.jsonl removed", -recordSet()["inner.jsonl"].length, ["missing inner record file"]],
      ["dropped exit row", -1, ["measure.jsonl: measure:1 has no exit"]],
      ["spawn-failed with a PID", 1, ["measure.jsonl: a failed spawn carries a PID or no handle"]],
      ["PID reuse across two short children", 4, []],
    ],
  );
  assert.deepEqual(validatorControls("records"), {
    ok: false,
    controls: [],
    reason: "the base records do not validate",
  });
  // One control that does not hold fails the set, whatever the others did.
  let calls = 0;
  const lenient = (files) => (calls++ === 0 ? validateRecords(files) : { ok: true, problems: [] });
  assert.equal(validatorControls(recordSet(), lenient).ok, false);
});

test("certificate problems are exact, and a missing day never throws", () => {
  const controls = () =>
    ["positive", "orphan", "escaper", "listener", "leftover"].map((mode) =>
      report(mode === "positive" ? "positive" : "control", {
        control: { mode, counts: true },
      }),
    );
  assert.deepEqual(
    pick(certificateVerdict({ refusal: report("certificate"), controls: controls() })),
    { verdict: "pass", problems: [] },
  );
  assert.deepEqual(
    certificateVerdict({
      refusal: report("certificate", { launchTime: undefined }),
      controls: [],
    }).problems.slice(0, 1),
    ["the refusal run names no harness version or day"],
  );
  assert.deepEqual(
    certificateVerdict({
      refusal: report("certificate", { harnessVersion: undefined }),
      controls: controls(),
    }).problems[0],
    "the refusal run names no harness version or day",
  );
  assert.deepEqual(
    certificateVerdict({
      refusal: report("positive", {
        verdict: { verdict: "fail" },
        validatorControls: { ok: false },
      }),
      controls: controls(),
    }).problems.slice(0, 3),
    [
      "the refusal report is not a certificate run",
      "the refusal run did not pass",
      "the refusal run's validator controls did not hold",
    ],
  );
  // The day is the full UTC date: a year a millennium apart is another day.
  const later = controls().map((r) =>
    r.control.mode === "orphan" ? { ...r, launchTime: Date.parse("3026-10-02T03:00:00Z") } : r,
  );
  assert.deepEqual(
    certificateVerdict({ refusal: report("certificate"), controls: later }).problems,
    ["control orphan ran on another day"],
  );
});

// Mutation round 2 survivors that a test can tell apart.
test("an array-like record file is refused, and a born handle is born only once", () => {
  const set = recordSet();
  set["inner.jsonl"] = { 0: set["inner.jsonl"][0], length: 1 };
  assert.deepEqual(validateRecords(set).problems, [
    "inner.jsonl: the first row is not a header",
    "missing inner record file",
  ]);
  const twice = recordSet();
  twice["measure.jsonl"].push({ ...twice["measure.jsonl"][1], pid: 4242 });
  assert.deepEqual(validateRecords(twice).problems, [
    "measure.jsonl: handle measure:1 is born twice",
  ]);
});

test("a listener on another PID never counts, even when the helper bound in time", () => {
  assert.equal(
    controlOutcome(
      { mode: "listener", injected: { pid: 777 }, bound: { beforeInventory: true } },
      { ports: { lsof: [{ result: "listener", pids: [9] }] } },
    ).counts,
    false,
  );
});

test("validator controls run only on valid base records, and drop the first exit row", () => {
  const broken = recordSet();
  broken["inner.jsonl"].push({ type: "note" });
  assert.deepEqual(validatorControls(broken), {
    ok: false,
    controls: [],
    reason: "the base records do not validate",
  });
  // With short children after the outer launcher's exit, the first exit is not the last row.
  const set = recordSet(() => 1);
  const dropped = validatorControls(set).controls.find((c) => c.name === "dropped exit row");
  assert.deepEqual(
    [dropped.rowsChanged, dropped.problems],
    [
      -1,
      [
        `measure.jsonl: ${set["measure.jsonl"].find((row) => row.type === "exit").handle} has no exit`,
      ],
    ],
  );
});

// Review round 2, M6: an exit row carries exactly one of an exit code and a signal, and (B) needs
// numeric session ids.
test("an exit row needs exactly one of a numeric code and a signal", () => {
  const exitOf = (set) => set["inner.jsonl"].find((row) => row.type === "exit");
  for (const [name, change, ok] of [
    ["code 0", (row) => Object.assign(row, { code: 0, signal: null }), true],
    ["signal only", (row) => Object.assign(row, { code: null, signal: "SIGKILL" }), true],
    ["neither", (row) => Object.assign(row, { code: null, signal: null }), false],
    ["both", (row) => Object.assign(row, { code: 1, signal: "SIGTERM" }), false],
    ["fields absent", (row) => (delete row.code, delete row.signal), false],
    ["code a string", (row) => Object.assign(row, { code: "0", signal: null }), false],
    ["code a fraction", (row) => Object.assign(row, { code: 0.5, signal: null }), false],
    ["signal empty", (row) => Object.assign(row, { code: null, signal: "" }), false],
  ]) {
    const set = recordSet();
    change(exitOf(set));
    const result = validateRecords(set);
    assert.equal(result.ok, ok, name);
    if (!ok)
      assert.deepEqual(
        result.problems,
        ["inner.jsonl: malformed exit row", "inner.jsonl: inner:1 has no exit"],
        name,
      );
  }
});

test("(B) needs positive numeric session ids for the root and the outer launcher", () => {
  for (const [name, chain] of [
    ["root undefined", { rootSid: undefined, outerPid: 200, outerSid: 200 }],
    ["root an error", { rootSid: "E1", outerPid: 200, outerSid: 200 }],
    ["root ESRCH", { rootSid: "ESRCH", outerPid: 200, outerSid: 200 }],
    ["root zero", { rootSid: 0, outerPid: 200, outerSid: 200 }],
    ["root a string number", { rootSid: "50", outerPid: 200, outerSid: 200 }],
    ["outer missing", { rootSid: 50, outerPid: undefined, outerSid: undefined }],
    ["outer an error", { rootSid: 50, outerPid: "E1", outerSid: "E1" }],
  ]) {
    const input = verdictInput();
    input.chain = chain;
    assert.deepEqual(
      refusalVerdict(input).conditions.B,
      {
        ok: false,
        outcome: "fail",
        reasons: ["the outer launcher is not the leader of its own session"],
      },
      name,
    );
  }
});

// Review round 2, D4 and S2: zombies and re-passes, judged by start time. The run's session did
// not exist before the launch, so nothing that started earlier can have been in it.
const launchd = row({ pid: 1, ppid: 0, sid: 1, args: "/sbin/launchd" });
const afterLaunch = "Fri Oct 2 06:00:05 2026";

test("a launchd-adopted zombie that started after the launch asks for another pass", () => {
  const zombie = row({
    pid: 7001,
    ppid: 1,
    stat: "Z",
    sid: "ESRCH",
    started: afterLaunch,
    args: "<defunct>",
  });
  const clean = [launchd];
  // Reaped by the next passes: clean.
  assert.equal(
    judgeComplete([[launchd, zombie], [launchd, zombie], clean, clean], ctx).outcome,
    "clean",
  );
  // Persisting to the bound: inconclusive, never clean.
  const persisting = [launchd, zombie];
  const result = judgeComplete([persisting, persisting, persisting, persisting, persisting], ctx);
  assert.deepEqual(
    [result.outcome, result.reason],
    ["inconclusive", "no two consecutive clean passes"],
  );
  // Started before the launch: unrelated (its live parent launchd is outside the session).
  const older = { ...zombie, started: "Fri Oct 2 05:59:59 2026" };
  const unrelated = judgeComplete(
    [
      [launchd, older],
      [launchd, older],
    ],
    ctx,
  );
  assert.equal(unrelated.outcome, "clean");
  assert.deepEqual(unrelated.passes[0].unrelatedZombies, [older]);
});

test("an uncovered zombie is unrelated only under a live, non-zombie parent outside the session", () => {
  const zombie = row({ pid: 7001, ppid: 6000, stat: "Z", sid: "ESRCH" });
  // launchd is in every pass, so the parent row itself is judged only for what it is.
  const judge = (parent) =>
    judgeComplete(
      [
        [launchd, zombie, parent],
        [launchd, zombie, parent],
      ],
      ctx,
    );
  assert.equal(judge(parentRow).outcome, "clean");
  for (const [name, parent] of [
    ["a zombie parent", { ...parentRow, stat: "Z" }],
    ["a zombie parent with a session answer", { ...parentRow, stat: "Z+", sid: 88 }],
    ["a parent with no session answer", { ...parentRow, sid: "ESRCH" }],
  ])
    assert.equal(judge(parent).outcome, "inconclusive", name);
});

test("an ESRCH row that started before the launch is ignored, even under launchd", () => {
  const old = row({ pid: 5000, ppid: 1, sid: "ESRCH" });
  const result = judgeComplete(
    [
      [launchd, old],
      [launchd, old],
    ],
    ctx,
  );
  assert.equal(result.outcome, "clean");
  assert.deepEqual(result.passes[1].ignored, [old]);
  const young = { ...old, started: afterLaunch };
  assert.equal(
    judgeComplete(
      [
        [launchd, young],
        [launchd, young],
      ],
      ctx,
    ).outcome,
    "inconclusive",
  );
});

// Review round 2, M3: a pass without launchd or the measuring entry is not a complete inventory.
test("a pass that misses launchd or the measuring entry is inconclusive", () => {
  const other = row({ pid: 5000 });
  for (const [name, pass] of [
    ["empty", []],
    ["no launchd", [baseRows[1], other]],
    ["no measuring entry", [baseRows[0], other]],
  ]) {
    const result = judgeInventory([pass, [...baseRows, other]], ctx);
    assert.deepEqual(
      [result.outcome, result.reason],
      ["inconclusive", "incomplete inventory pass"],
      name,
    );
  }
  assert.equal(judgeInventory([[...baseRows], [...baseRows]], ctx).outcome, "clean");
  const { rootPid, ...noRoot } = ctx;
  assert.equal(rootPid, 100);
  assert.equal(judgeInventory([[...baseRows], [...baseRows]], noRoot).outcome, "inconclusive");
});

test("(D) fails when the daemon's output pipes stayed open after it exited", () => {
  for (const drained of [false, undefined]) {
    const input = verdictInput();
    input.daemon.diagnosticsDrained = drained;
    assert.deepEqual(refusalVerdict(input).conditions.D.reasons, [
      "the daemon's output pipes stayed open after it exited",
    ]);
  }
});

test("an lsof answer cut at maxBuffer, or not saying, is inconclusive", () => {
  const listener = { code: 0, stdout: "p12\n", stderr: "", timedOut: false };
  assert.equal(interpretLsof({ ...listener, truncated: false }).result, "listener");
  for (const truncated of [true, undefined])
    assert.deepEqual(interpretLsof({ ...listener, truncated }), { result: "inconclusive" });
  assert.deepEqual(
    interpretLsof({ code: 1, stdout: "", stderr: "", timedOut: false, truncated: true }),
    {
      result: "inconclusive",
    },
  );
});

// Review round 2, M1: the certificate names what it certifies, quotes the limits every time and
// binds every control to the refusal run's build and harness.
test("the certificate limits are the condition's text, word for word", () => {
  assert.deepEqual(CERTIFICATE_LIMITS, [
    "Without privilege the run cannot prove that no short-lived grandchild was born, nor count, pair, read the exit status of, or confirm the reaping of such a process. Examples: the daemon's Node `--version` and `-p` probes, `/bin/kill` in the probe timeout path, a Functions runner or `--calendar-child` that lives shorter than the polling interval, children of portctl, `ps`, `lsof` or `python3`.",
    "A descendant that leaves the session (`setsid`) and is still alive at the end is missed by (E) unless its identity was recorded or its arguments name a run path.",
    "Survivors are judged at the time of the final inventory.",
    "(F) covers TCP listeners only, not UDP or Unix-domain sockets.",
    "The certificate proves that nothing survived and no TCP port was held. It does not prove that nothing else started.",
  ]);
  assert.ok(Object.isFrozen(CERTIFICATE_LIMITS));
});

test("a passing certificate names its pins, root, refusal, reports and limits", () => {
  const files = [
    { path: "/runs/refusal/verdict.json", sha256: "1".repeat(64) },
    ...["positive", "orphan", "escaper", "listener", "leftover"].map((kind, index) => ({
      path: `/runs/${kind}/verdict.json`,
      sha256: String(index + 2).repeat(64),
    })),
  ];
  const result = certificateVerdict({
    refusal: report("certificate"),
    controls: allControls(),
    files,
  });
  assert.equal(result.verdict, "pass", JSON.stringify(result.problems));
  assert.deepEqual(result.certificate, {
    pins: { ...IDENTITY, exitCode: 1, refusalLine: REFUSAL_LINE },
    root: { pid: 100, started: "Fri Oct 2 03:00:00 2026", sid: 50 },
    refusal: { exitCode: 1, line: REFUSAL_LINE },
    reports: [
      {
        kind: "certificate",
        mode: null,
        path: "/runs/refusal/verdict.json",
        sha256: "1".repeat(64),
      },
      ...["positive", "orphan", "escaper", "listener", "leftover"].map((kind, index) => ({
        kind,
        mode: kind,
        path: `/runs/${kind}/verdict.json`,
        sha256: String(index + 2).repeat(64),
      })),
    ],
    attempts: [],
    limits: CERTIFICATE_LIMITS,
  });
  // A failing certificate is still a record of what was judged, without a certificate body.
  const failed = certificateVerdict({ refusal: report("certificate"), controls: [], files });
  assert.equal(failed.verdict, "fail");
  assert.equal(failed.certificate, null);
});

test("every control must have run the refusal run's build, portctl and harness", () => {
  for (const key of [
    "sourceCommit",
    "binarySha256",
    "runnerSha256",
    "portctlSha256",
    "harnessVersion",
  ]) {
    const controls = allControls().map((r) =>
      r.control.mode === "escaper" ? { ...r, identity: { ...r.identity, [key]: "0" } } : r,
    );
    assert.deepEqual(
      certificateVerdict({ refusal: report("certificate"), controls }).problems,
      [`control escaper ran another ${key}`],
      key,
    );
  }
  const unnamed = allControls().map((r) =>
    r.control.mode === "orphan" ? { ...r, identity: undefined } : r,
  );
  assert.deepEqual(
    certificateVerdict({ refusal: report("certificate"), controls: unnamed }).problems,
    ["control orphan names no build"],
  );
});

test("the refusal run must name its build, quote its refusal exactly and match its pins", () => {
  for (const [name, overrides, problem] of [
    ["no identity", { identity: undefined }, "the refusal run names no build"],
    ["no pins", { pins: undefined }, "the refusal run names no pins"],
    [
      "a build other than its pins",
      { identity: { ...IDENTITY, binarySha256: "0" } },
      "the refusal run's binarySha256 differs from its pin",
    ],
    [
      "another exit status",
      { refusal: { exitCode: 2, line: REFUSAL_LINE } },
      "the refusal run's exit status differs from its pin",
    ],
    [
      "another line",
      { refusal: { exitCode: 1, line: "error: x" } },
      "the refusal run's refusal line differs from its pin",
    ],
    ["no root", { root: undefined }, "the refusal run names no root"],
    [
      "a root without a session",
      { root: { pid: 100, started: "x", sid: "ESRCH" } },
      "the refusal run names no root",
    ],
  ]) {
    const result = certificateVerdict({
      refusal: report("certificate", overrides),
      controls: allControls(),
    });
    assert.ok(result.problems.includes(problem), `${name}: ${result.problems}`);
    assert.equal(result.verdict, "fail", name);
  }
});

test("reports of the stand-in daemon are never certified", () => {
  const standIn = "9".repeat(64);
  const withRunner = (r) => ({ ...r, identity: { ...r.identity, runnerSha256: standIn } });
  const refusal = report("certificate", {
    identity: { ...IDENTITY, runnerSha256: standIn },
    pins: { ...IDENTITY, runnerSha256: standIn, exitCode: 1, refusalLine: REFUSAL_LINE },
  });
  const result = certificateVerdict({
    refusal,
    controls: allControls().map(withRunner),
    standInRunnerSha256: standIn,
  });
  assert.equal(result.verdict, "fail");
  assert.ok(
    result.problems.includes("the refusal run used the stand-in runner"),
    String(result.problems),
  );
});

// Review S7: the rows that asked for another pass are kept, so an inconclusive inventory names
// its cause.
test("each pass names the rows that asked for another pass", () => {
  const young = row({ pid: 5000, ppid: 1, sid: "ESRCH", started: "Fri Oct 2 06:00:05 2026" });
  const zombie = row({
    pid: 7001,
    ppid: 1,
    stat: "Z",
    sid: "ESRCH",
    started: "Fri Oct 2 06:00:06 2026",
  });
  const result = judgeComplete([[young], [young, zombie]], ctx);
  assert.deepEqual(result.passes[0].repass, [young]);
  assert.deepEqual(result.passes[1].repass, [young, zombie]);
  assert.deepEqual(judgeComplete([[], []], ctx).passes[0].repass, []);
});

// Load reproduction (review round 2, M4): under churn, ESRCH chains of unrelated processes asked
// for passes until the bound. A process in S has every ancestor up to S's leader in S (setsid
// makes a new session, never S), so an ESRCH chain that reaches a live ancestor in another
// session, other than launchd, cannot have been in S.
test("an ESRCH chain is followed to its first ancestor with a session answer", () => {
  const t = "Fri Oct 2 06:00:05 2026";
  const other = row({ pid: 8000, ppid: 1, sid: 88, started: "Fri Oct 2 05:00:00 2026" });
  const member = row({ pid: 8100, ppid: 1, sid: 300, started: t });
  const chain = (top) => [
    row({ pid: 8201, ppid: top, sid: "ESRCH", started: t }),
    row({ pid: 8202, ppid: 8201, sid: "ESRCH", started: t }),
  ];
  const judge = (rows) => judgeComplete([rows, rows], ctx);
  // Under a live ancestor in another session: ignored, clean.
  const unrelated = judge([other, ...chain(8000)]);
  assert.equal(unrelated.outcome, "clean");
  assert.deepEqual(unrelated.passes[0].repass, []);
  // Under launchd: another pass.
  assert.equal(judge(chain(1)).reason, "no two consecutive clean passes");
  // Under an ancestor that left no row (the condition's "other ESRCH rows"): ignored.
  assert.equal(judge(chain(8999)).outcome, "clean");
  // Under a member of S or a recorded identity: the member is a survivor, or another pass.
  assert.equal(judge([member, ...chain(8100)]).outcome, "survivors");
  const recordedTop = row({ pid: 400, ppid: 1, sid: "ESRCH", started: "Fri Oct  2 06:00:03 2026" });
  assert.equal(judge([recordedTop, ...chain(400)]).outcome, "survivors");
  // A cycle in the parent links is not followed forever.
  const cyclic = [
    row({ pid: 8301, ppid: 8302, sid: "ESRCH", started: t }),
    row({ pid: 8302, ppid: 8301, sid: "ESRCH", started: t }),
  ];
  assert.equal(judge(cyclic).reason, "no two consecutive clean passes");
});

// Review round 2, S5 (and the earlier PID-only tests it replaces): a negative control counts only
// when its named rule fired on the injected helper's identity (PID and start time) and the helper
// had the topology the control is for.
const HELPER = { pid: 777, started: "Fri Oct 2 06:00:06 2026", acquired: true, pgid: 777 };
const helperRow = (overrides) => ({ pid: 777, ppid: 1, started: HELPER.started, ...overrides });
const outcomeOf = (mode, result, injected = HELPER, bound = { beforeInventory: true }) =>
  controlOutcome({ mode, injected, bound }, result);
const survivorsOf = (...entries) => ({ inventory: { survivors: entries } });

test("each negative control counts on its helper's identity and topology", () => {
  // (i) orphan: in S, reparented to launchd.
  assert.deepEqual(
    outcomeOf("orphan", survivorsOf({ row: helperRow(), rules: ["session", "path"] })),
    {
      counts: true,
      rulesFired: ["session", "path"],
    },
  );
  assert.equal(
    outcomeOf("orphan", survivorsOf({ row: helperRow({ ppid: 900 }), rules: ["session"] })).counts,
    false,
    "not reparented to launchd",
  );
  // (ii) escaper: recorded, outside S.
  assert.equal(
    outcomeOf("escaper", survivorsOf({ row: helperRow({ ppid: 5 }), rules: ["identity"] })).counts,
    true,
  );
  assert.equal(
    outcomeOf("escaper", survivorsOf({ row: helperRow(), rules: ["identity", "session"] })).counts,
    false,
    "still in S",
  );
  // (iii) listener: bound before the inventory, holds the port, alive as itself, outside S.
  const listening = (rules) => ({
    ...survivorsOf({ row: helperRow({ ppid: 5 }), rules }),
    ports: { lsof: [{ result: "listener", pids: [777] }] },
  });
  assert.deepEqual(outcomeOf("listener", listening(["path"])), {
    counts: true,
    rulesFired: ["path", "port"],
  });
  assert.equal(outcomeOf("listener", listening(["path", "session"])).counts, false, "in S");
  assert.equal(
    outcomeOf("listener", listening(["path"]), HELPER, { beforeInventory: false }).counts,
    false,
  );
  assert.equal(outcomeOf("listener", listening(["path"]), HELPER, null).counts, false);
  assert.equal(
    outcomeOf("listener", { ports: { lsof: [{ result: "listener", pids: [777] }] } }).counts,
    false,
    "no row of the helper itself",
  );
  assert.equal(
    outcomeOf("listener", {
      ...listening(["path"]),
      ports: { lsof: [{ result: "listener", pids: [9] }] },
    }).counts,
    false,
    "another PID listens",
  );
  // (iv) leftover: acquired, in its own group, removed by a signal to its identity.
  const signalled = (started) => ({ records: { signals: [{ target: { pid: 777, started } }] } });
  assert.deepEqual(outcomeOf("leftover", signalled(HELPER.started)), {
    counts: true,
    rulesFired: ["harness-signal"],
  });
  assert.equal(
    outcomeOf("leftover", signalled("Fri Oct 2 06:00:09 2026")).counts,
    false,
    "a recycled PID",
  );
  assert.equal(
    outcomeOf("leftover", signalled(HELPER.started), { ...HELPER, acquired: false }).counts,
    false,
  );
  assert.equal(
    outcomeOf("leftover", signalled(HELPER.started), { ...HELPER, pgid: 700 }).counts,
    false,
  );
});

test("a row or signal of a recycled PID never counts for the helper", () => {
  const recycled = helperRow({ started: "Fri Oct 2 06:00:09 2026" });
  for (const mode of ["orphan", "escaper"])
    assert.deepEqual(
      outcomeOf(mode, survivorsOf({ row: recycled, rules: ["session", "identity"] })),
      {
        counts: false,
        rulesFired: [],
      },
    );
  for (const injected of [null, { pid: 777 }, { started: HELPER.started }])
    assert.equal(
      outcomeOf("orphan", survivorsOf({ row: helperRow(), rules: ["session"] }), injected).counts,
      false,
    );
  // No port rule without a listener of the helper.
  assert.deepEqual(
    outcomeOf("orphan", {
      ...survivorsOf({ row: helperRow(), rules: ["session"] }),
      ports: { lsof: [] },
    }).rulesFired,
    ["session"],
  );
});

// Review S4: (G) checks the escalation each supervisor actually ran with, not only the plan's.
test("(G) fails a certificate run whose supervisors did not escalate", () => {
  for (const role of ["inner", "outer"])
    for (const escalate of [false, undefined]) {
      const input = verdictInput();
      input.supervision[role].escalate = escalate;
      assert.deepEqual(refusalVerdict(input).conditions.G.reasons, [
        `the ${role} supervisor did not run with escalation on`,
      ]);
    }
});

// Review S6: clause 3 names either private directory of the run.
test("clause 3 matches the arguments of either private directory", () => {
  const dirs = { ...ctx, privateDirs: ["/private/run-1", "/private/acc-1"] };
  const late = (args) => row({ started: "Fri Oct 2 06:00:01 2026", args });
  for (const args of ["x /private/run-1/y", "node outer /private/acc-1/plan.json"])
    assert.deepEqual(
      judgeComplete([[late(args)], [late(args)]], dirs).survivors[0].rules,
      ["path"],
      args,
    );
  assert.equal(
    judgeComplete([[late("x /private/run-10/y")], [late("x /private/run-10/y")]], dirs).outcome,
    "clean",
  );
  const { privateDir, ...none } = dirs;
  assert.equal(privateDir, "/private/run-1");
  assert.equal(
    judgeComplete([[late("x /private/acc-1/y")], [late("x /private/acc-1/y")]], {
      ...none,
      privateDirs: [],
    }).outcome,
    "clean",
  );
});

// Coordinator policy (review round 2 addendum): every attempt is kept, and a pass never counts
// after a failed attempt whose cause has not been explained.
test("a certificate refuses a pass that follows an unexplained failed attempt", () => {
  const attempt = (verdict, launchTime, sha256) => ({
    report: report("certificate", { verdict: { verdict }, launchTime }),
    file: { path: `/runs/${sha256.slice(0, 2)}/verdict.json`, sha256 },
  });
  const earlier = attempt("fail", Date.parse("2026-10-02T02:00:00Z"), "a1".repeat(32));
  const later = attempt("fail", Date.parse("2026-10-02T04:00:00Z"), "b2".repeat(32));
  const judge = (attempts, explanations) =>
    certificateVerdict({
      refusal: report("certificate"),
      controls: allControls(),
      attempts,
      explanations,
    });
  assert.deepEqual(judge([earlier], {}).problems, [
    `an earlier attempt failed without an explanation: /runs/a1/verdict.json`,
  ]);
  const explained = judge([earlier], {
    ["a1".repeat(32)]: "port collision, Errno 48 (stderr tail)",
  });
  assert.equal(explained.verdict, "pass");
  assert.deepEqual(explained.certificate.attempts, [
    {
      path: "/runs/a1/verdict.json",
      sha256: "a1".repeat(32),
      verdict: "fail",
      explanation: "port collision, Errno 48 (stderr tail)",
    },
  ]);
  // A blank explanation explains nothing; a failure after the pass does not undo it.
  assert.equal(judge([earlier], { ["a1".repeat(32)]: "  " }).verdict, "fail");
  assert.equal(judge([later], {}).verdict, "pass");
  assert.deepEqual(judge(undefined, undefined).certificate.attempts, []);
});
