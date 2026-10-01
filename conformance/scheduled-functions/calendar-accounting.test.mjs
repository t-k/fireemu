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
  "ESRCH, parent 1": { make: (pid) => row({ pid, ppid: 1, sid: "ESRCH" }), expect: "repass" },
  "getsid error": { make: (pid) => row({ pid, sid: "EPERM" }), expect: "inconclusive" },
};
const parentRow = row({ pid: 6000, ppid: 1, sid: 88 });

test("each inventory category is judged as the model says", () => {
  for (const [name, category] of Object.entries(categories)) {
    const pass = [category.make(5000), ...(category.parent ? [parentRow] : [])];
    const result = judgeInventory([pass, pass], ctx);
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
  const esrch = row({ pid: 5000, ppid: 1, sid: "ESRCH" });
  const clean = [row({ pid: 5001 })];
  assert.equal(judgeInventory([clean, [esrch], clean, clean], ctx).outcome, "clean");
  assert.equal(
    judgeInventory([clean, [esrch], [esrch], [esrch], [esrch]], ctx).outcome,
    "inconclusive",
  );
  assert.equal(judgeInventory([clean], ctx).outcome, "inconclusive", "one pass is never enough");
  assert.equal(
    judgeInventory([clean, clean, clean, clean, clean, clean], ctx).outcome,
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
    const result = judgeInventory([pass, pass], ctx);
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
  const result = judgeInventory([[member], [member]], {
    ...ctx,
    launchTime: Date.parse("2026-10-02T06:00:00Z"),
  });
  assert.deepEqual(result.survivors[0].rules, ["session", "identity", "path"]);
});

test("lsof answers are none only for a silent exit 1", () => {
  assert.deepEqual(interpretLsof({ code: 1, stdout: "", stderr: "", timedOut: false }), {
    result: "none",
  });
  assert.deepEqual(
    interpretLsof({ code: 0, stdout: "p4242\ncnode\nn*:12345\n", stderr: "", timedOut: false }),
    { result: "listener", pids: [4242] },
  );
  for (const answer of [
    { code: 1, stdout: "", stderr: "lsof: illegal option", timedOut: false },
    { code: 1, stdout: "p1\n", stderr: "", timedOut: false },
    { code: 0, stdout: "", stderr: "", timedOut: false },
    { code: 0, stdout: "garbage\n", stderr: "", timedOut: false },
    { code: 2, stdout: "", stderr: "", timedOut: false },
    { code: null, stdout: "", stderr: "", timedOut: true },
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
      inner: { timedOut: false, cancelled: false, inventoryFailures: 0 },
      outer: { timedOut: false, cancelled: false, inventoryFailures: 0 },
    },
    validatorControls: { ok: true, controls: [] },
    daemon: {
      exitCode: 1,
      diagnostics: ["functions loaded: none", pins.refusalLine],
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

test("a negative control counts only when its named rule fired on the injected row", () => {
  const base = {
    verdict: "fail",
    conditions: { D: { ok: true }, E: { ok: true }, F: { ok: true } },
  };
  const injected = { pid: 777, uid: 501, started: "s" };
  const withSurvivor = (rules) => ({
    ...base,
    inventory: { survivors: [{ row: { pid: 777 }, rules }] },
  });
  assert.equal(
    controlOutcome({ mode: "orphan", injected }, withSurvivor(["session", "path"])).counts,
    true,
  );
  assert.equal(
    controlOutcome({ mode: "orphan", injected }, withSurvivor(["identity"])).counts,
    false,
  );
  assert.equal(
    controlOutcome({ mode: "escaper", injected }, withSurvivor(["identity"])).counts,
    true,
  );
  assert.equal(
    controlOutcome({ mode: "orphan", injected: { pid: 1 } }, withSurvivor(["session"])).counts,
    false,
    "another row's survival does not count",
  );
  assert.equal(
    controlOutcome(
      { mode: "listener", injected, bound: { beforeInventory: true } },
      { ...base, ports: { lsof: [{ result: "listener", pids: [777] }] } },
    ).counts,
    true,
  );
  assert.equal(
    controlOutcome(
      { mode: "listener", injected },
      { ...base, ports: { lsof: [{ result: "listener", pids: [9] }] } },
    ).counts,
    false,
  );
  assert.equal(
    controlOutcome(
      { mode: "leftover", injected },
      { ...base, records: { signals: [{ target: { pid: 777 } }] } },
    ).counts,
    true,
  );
  assert.equal(
    controlOutcome(
      { mode: "leftover", injected },
      { ...base, records: { signals: [{ target: { pid: 9 } }] } },
    ).counts,
    false,
  );
  const fired = controlOutcome(
    { mode: "orphan", injected },
    withSurvivor(["session", "path"]),
  ).rulesFired;
  assert.deepEqual(fired, ["session", "path"]);
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
    judgeInventory([[zombie(77, 6001)], [zombie(77, 6001)]], ctx).outcome,
    "inconclusive",
  );
  const withParent = [zombie(77, 6000), parentRow];
  const result = judgeInventory([withParent, withParent], ctx);
  assert.equal(result.outcome, "clean");
  assert.equal(result.passes[0].unrelatedZombies.length, 1, "logged");
  const insideParent = [zombie(77, 6000), { ...parentRow, sid: "ESRCH" }];
  assert.equal(judgeInventory([insideParent, insideParent], ctx).outcome, "inconclusive");
});

test("start times are read in UTC, and an unreadable one is inconclusive", () => {
  const late = row({ started: "Fri Oct 2 06:00:01 2026", args: "x /private/run-1/y" });
  assert.equal(judgeInventory([[late], [late]], ctx).outcome, "survivors");
  const early = row({ started: "Fri Oct 2 05:59:59 2026", args: "x /private/run-1/y" });
  assert.equal(judgeInventory([[early], [early]], ctx).outcome, "clean");
  const unreadable = row({ started: "Fri Foo 2 05:59:59 2026" });
  assert.equal(judgeInventory([[unreadable], [unreadable]], ctx).outcome, "inconclusive");
});

test("an ESRCH row asks for another pass when its parent could have been in the session", () => {
  const member = row({ pid: 6100, sid: 300, args: "member" });
  for (const [name, rows] of [
    ["parent a recorded identity", [row({ pid: 5000, ppid: 400, sid: "ESRCH" })]],
    [
      "parent an ESRCH row",
      [row({ pid: 5000, ppid: 6200, sid: "ESRCH" }), row({ pid: 6200, ppid: 6300, sid: "ESRCH" })],
    ],
  ]) {
    const clean = [row({ pid: 5001 })];
    assert.equal(judgeInventory([clean, rows, clean], ctx).outcome, "inconclusive", name);
    assert.equal(judgeInventory([clean, rows, clean, clean], ctx).outcome, "clean", name);
  }
  // A session member parent makes the member itself a survivor, so the run fails either way.
  assert.equal(
    judgeInventory([[member, row({ pid: 5000, ppid: 6100, sid: "ESRCH" })]], ctx).outcome,
    "survivors",
  );
});

test("the listener control counts only when its helper bound before the final inventory", () => {
  const injected = { pid: 777 };
  const listening = {
    ports: { lsof: [{ result: "listener", pids: [777] }] },
  };
  assert.equal(
    controlOutcome({ mode: "listener", injected, bound: { beforeInventory: true } }, listening)
      .counts,
    true,
  );
  for (const bound of [undefined, { beforeInventory: false }])
    assert.equal(controlOutcome({ mode: "listener", injected, bound }, listening).counts, false);
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
function report(kind, overrides = {}) {
  return {
    kind,
    harnessVersion: "h1",
    launchTime: Date.parse("2026-10-02T03:00:00Z"),
    verdict: { verdict: kind === "certificate" ? "pass" : "fail" },
    validatorControls: { ok: true },
    control:
      kind === "certificate"
        ? null
        : { mode: kind === "positive" ? "positive" : kind, counts: true },
    ...overrides,
  };
}
const allControls = () =>
  ["positive", "orphan", "escaper", "listener", "leftover"].map((kind) => report(kind));

test("a certificate needs the refusal run and every control, same harness version, same UTC day", () => {
  assert.deepEqual(
    certificateVerdict({ refusal: report("certificate"), controls: allControls() }),
    {
      verdict: "pass",
      problems: [],
    },
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
