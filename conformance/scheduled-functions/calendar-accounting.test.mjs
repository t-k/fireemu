import assert from "node:assert/strict";
import { test } from "node:test";
import {
  validateRecords,
  judgeInventory,
  interpretLsof,
  refusalVerdict,
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
  launchTime: Date.parse("Fri Oct  2 06:00:00 2026"),
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
    launchTime: Date.parse("Fri Oct  2 06:00:00 2026"),
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
    binarySha256: "b".repeat(64),
    runnerSha256: "c".repeat(64),
    fixtureSha256: "d".repeat(64),
    configSha256: "e".repeat(64),
    portctlSha256: "f".repeat(64),
    exitCode: 1,
    refusalLine:
      'manifest: function "calendarProbe": time zone: unknown time zone "Invalid/CalendarZone"',
  };
  return {
    certificate: true,
    escalation: "on",
    pins,
    identity: { ...pins, exitCode: undefined, refusalLine: undefined },
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
  "inventory inconclusive": [
    (v) => (v.inventory = { outcome: "inconclusive", survivors: [] }),
    "inconclusive",
    "E",
  ],
  "claim kept": [(v) => (v.ports.claims = [{ port: 12345 }]), "fail", "F"],
  listener: [(v) => (v.ports.lsof = [{ result: "listener", pids: [9] }]), "fail", "F"],
  "lsof inconclusive": [(v) => (v.ports.lsof = [{ result: "inconclusive" }]), "inconclusive", "F"],
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

test("a control run may turn escalation off, and a missing input is never a pass", () => {
  const control = verdictInput();
  control.certificate = false;
  control.escalation = "off";
  assert.equal(refusalVerdict(control).conditions.G.ok, true);
  for (const key of [
    "pins",
    "identity",
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
