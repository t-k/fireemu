import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import * as sandbox from "./functions-events/record/sandbox.mjs";

const row = (over) =>
  JSON.stringify({
    ts: "2026-10-01T08:00:00Z",
    project: sandbox.PROJECT,
    taskId: sandbox.TASK_ID,
    ...over,
  });
const now = Date.parse("2026-10-04T12:00:00Z");
const clean = [
  row({ event: "started", runDir: "r1", estimatedUsd: 2 }),
  row({
    ts: "2026-10-01T08:30:00Z",
    event: "finished",
    outcome: "prepared",
    lockRetained: false,
    runDir: "r1",
    estimatedUsd: 2,
  }),
].join("\n");

test("a project whose last run ended prepared and kept no lock admits a new run", () => {
  assert.deepEqual(sandbox.ledgerProblems(clean, now), []);
});

test("an open run, a recent line, an unreadable time or a kept lock each refuse the start", () => {
  const open = `${clean}\n${row({ ts: "2026-10-02T00:00:00Z", event: "started", taskId: "OTHER-TASK" })}`;
  assert.ok(sandbox.ledgerProblems(open, now).some((p) => p.includes("OTHER-TASK")));
  // a run left open before the latest clean closing line is history, not a blocker
  const history = `${row({ ts: "2026-09-01T00:00:00Z", event: "started", taskId: "OLD-TASK" })}\n${clean}`;
  assert.deepEqual(sandbox.ledgerProblems(history, now), []);
  assert.ok(
    sandbox
      .ledgerProblems(row({ event: "started" }), now)
      .some((p) => p.includes("no clean closing line")),
  );
  assert.ok(
    sandbox
      .ledgerProblems(`${clean}\n${row({ ts: "2026-10-04T11:45:00Z", event: "note" })}`, now)
      .some((p) => p.includes("30 minutes")),
  );
  assert.ok(
    sandbox
      .ledgerProblems(`${clean}\n${row({ ts: "not a time", event: "note" })}`, now)
      .some((p) => p.includes("unreadable")),
  );
  const kept = [
    row({ event: "started" }),
    row({ event: "finished", outcome: "needs-recovery", lockRetained: true }),
  ].join("\n");
  assert.ok(sandbox.ledgerProblems(kept, now).some((p) => p.includes("did not end cleanly")));
  assert.deepEqual(
    sandbox.ledgerProblems(
      `${kept}\n${row({ ts: "2026-10-02T00:00:00Z", event: "cleanup-verified", sandboxAtBaseline: true })}`,
      now,
    ),
    [],
  );
});

test("lines of other projects do not matter", () => {
  const other = JSON.stringify({
    ts: "2026-10-04T11:59:00Z",
    project: "fireemu-oracle-idp",
    taskId: "X",
    event: "started",
  });
  assert.deepEqual(sandbox.ledgerProblems(`${clean}\n${other}`, now), []);
});

test("the budget counts each run once and refuses a reserve that passes the cap", () => {
  const spent = (usd) =>
    [
      row({ event: "started", runDir: "a", estimatedUsd: 2 }),
      row({ event: "finished", runDir: "a", estimatedUsd: 2 }),
      row({ event: "started", runDir: "b", estimatedUsd: usd }),
    ].join("\n");
  assert.deepEqual(sandbox.budgetProblems(spent(26)), []);
  assert.equal(sandbox.budgetProblems(spent(28.5)).length, 1);
  assert.equal(sandbox.budgetProblems(row({ event: "started", estimatedUsd: -1 })).length, 1);
  assert.equal(sandbox.budgetProblems(row({ event: "started", estimatedUsd: "2" })).length, 1);
});

const pins = {
  packetSha256: "a".repeat(64),
  harnessSha256: "b".repeat(64),
  sourceCommit: "c".repeat(40),
};
const E = `- 2026-10-04 | ${sandbox.ENVELOPE_TOPIC} | envelopeId=FE-FORMAL-1; project=fireemu-oracle-events; maxRequests=520; cliMax=2; reserveUsd=4.00; retries=none; writes=declared resources only; onStop=needs-recovery keeps the lock | オーナー | ledger 812`;
const V = `- 2026-10-04 | ${sandbox.TOPIC} | decision=APPROVE; envelopeId=FE-FORMAL-1; packetSha256=${pins.packetSha256}; harnessSha256=${pins.harnessSha256}; sourceCommit=${pins.sourceCommit} | Claude（委任。枠の内） | review`;

test("an envelope line and a version line that name the same pins approve the run", () => {
  assert.deepEqual(sandbox.approval(`${E}\n${V}`, pins).problems, []);
});

test("the approval is refused for another pin, a missing or smaller envelope, a revocation or an unknown decider", () => {
  const refused = (text, p = pins) => sandbox.approval(text, p).problems.length > 0;
  assert.ok(refused(V));
  assert.ok(refused(E));
  for (const key of Object.keys(pins))
    assert.ok(
      refused(`${E}\n${V}`, { ...pins, [key]: "d".repeat(key === "sourceCommit" ? 40 : 64) }),
      key,
    );
  for (const [from, to] of [
    ["maxRequests=520", "maxRequests=519"],
    ["cliMax=2", "cliMax=1"],
    ["reserveUsd=4.00", "reserveUsd=3.99"],
    ["retries=none", "retries=twice"],
    ["project=fireemu-oracle-events", "project=other"],
  ])
    assert.ok(refused(`${E.replace(from, to)}\n${V}`), to);
  assert.ok(
    refused(
      `${E}\n${V}\n- 2026-10-05 | ${sandbox.TOPIC} | REVOKED packetSha256=${pins.packetSha256} | Claude（委任 | x`,
    ),
  );
  assert.ok(
    refused(
      `${E}\n${V}\n- 2026-10-05 | ${sandbox.ENVELOPE_TOPIC} | REVOKED envelopeId=FE-FORMAL-1 | Claude（委任 | x`,
    ),
  );
  assert.ok(refused(`${E}\n${V.replace("Claude（委任。枠の内）", "Codex")}`));
  assert.ok(refused(`${E.replace("オーナー", "Codex")}\n${V}`));
});

test("a packet whose run already started cannot start again", () => {
  assert.equal(
    sandbox.packetUsed(
      row({ event: "started", packetSha256: pins.packetSha256 }),
      pins.packetSha256,
    ),
    true,
  );
  assert.equal(sandbox.packetUsed(clean, pins.packetSha256), false);
});

test("the lock is exclusive, private, refused beside the legacy lock, and released only by its owner", () => {
  const dir = mkdtempSync(join(tmpdir(), "fe-lock-"));
  const lockDir = join(dir, "locks");
  const legacyLock = join(dir, "ledger.lock");
  const lock = sandbox.acquireLock({ lockDir, legacyLock, body: { pid: process.pid } });
  assert.throws(() => sandbox.acquireLock({ lockDir, legacyLock, body: {} }), /is held/);
  writeFileSync(lock.path, "tampered");
  assert.throws(() => sandbox.releaseLock(lock), /rewritten/);
  writeFileSync(lock.path, JSON.stringify({ pid: process.pid }));
  sandbox.releaseLock(lock);
  assert.equal(existsSync(lock.path), false);
  writeFileSync(legacyLock, "x");
  assert.throws(() => sandbox.acquireLock({ lockDir, legacyLock, body: {} }), /legacy/);
});

test("the ledger lines carry the packet, the envelope and the reserve; a kept lock is said", () => {
  const started = sandbox.startedLine({
    ts: "t",
    runDir: "r",
    packetSha256: pins.packetSha256,
    harnessSha256: pins.harnessSha256,
    gitSha: pins.sourceCommit,
    approval: { envelopeId: "FE-FORMAL-1" },
    lock: { sha256: "s" },
  });
  assert.deepEqual(
    [started.event, started.estimatedUsd, started.maxRequests, started.cliMax],
    ["started", 4, 520, 2],
  );
  const finished = sandbox.finishedLine({
    ts: "t",
    runDir: "r",
    packetSha256: pins.packetSha256,
    gitSha: pins.sourceCommit,
    outcome: "needs-recovery",
    requests: 400,
    cliAttempts: { deploy: 1, delete: 1 },
    lockRetained: true,
  });
  assert.equal(finished.lockRetained, true);
  const path = join(mkdtempSync(join(tmpdir(), "fe-led-")), "ledger.jsonl");
  sandbox.appendLedger(path, started);
  sandbox.appendLedger(path, finished);
  assert.equal(readFileSync(path, "utf8").trim().split("\n").length, 2);
});

// ---- the spacing after a run that wrote nothing -------------------------------------------------

const RUN = "/runs/functions-events-formal-20261004T145510Z-3827f1195f825ed4";
// rows 579-581 of the shared ledger (the 14:55Z run of envelope 001), with the run directory shortened
const realStarted = {
  ts: "2026-10-04T14:55:11.429Z",
  event: "started",
  taskId: "FUNCTIONS-EVENTS-SANDBOX",
  project: "fireemu-oracle-events",
  database: "(default)",
  phase: "formal-record",
  runDir: RUN,
  envelopeId: "FUNCTIONS-EVENTS-FORMAL-001",
  maxRequests: 520,
  cliMax: 2,
  estimatedUsd: 4,
};
const realFinished = {
  ts: "2026-10-04T14:55:26.646Z",
  event: "finished",
  taskId: "FUNCTIONS-EVENTS-SANDBOX",
  project: "fireemu-oracle-events",
  database: "(default)",
  phase: "formal-record",
  runDir: RUN,
  outcome: "stopped-clean",
  requests: 22,
  cliAttempts: { deploy: 0, delete: 0 },
  estimatedUsd: 4,
  lockRetained: false,
};
const realClosed = {
  ts: "2026-10-04T14:56:22.709811Z",
  event: "cleanup-verified",
  taskId: "FUNCTIONS-EVENTS-SANDBOX",
  project: "fireemu-oracle-events",
  database: "(default)",
  phase: "formal-record",
  runDir: RUN,
  sandboxAtBaseline: true,
  requests: 22,
  readbackRequests: 0,
  unknownAnswers: 0,
  estimatedUsd: 0,
  lockReleased: "by the recorder",
};
/** The journal layout of the transport: a before-send line and a response-persisted line per request. */
const journal = (n = 22, { mutation = false, kind = "success", skip } = {}) =>
  Array.from({ length: n }, (_, i) => i + 1)
    .flatMap((seq) => [
      { ts: "t", seq, id: `s${seq}`, state: "before-send", method: "GET", url: "u", mutation },
      ...(seq === skip
        ? []
        : [{ ts: "t", seq, id: `s${seq}`, state: "response-persisted", status: 200, kind }]),
    ])
    .map((entry) => JSON.stringify(entry))
    .join("\n");
const ledgerOf = (...rows) => [clean, ...rows.map((r) => JSON.stringify(r))].join("\n");
const after = Date.parse("2026-10-04T15:00:00Z");
const journalOf = (text) => ({ readJournal: () => text });
const spaced = (problems) => problems.some((p) => p.includes("30 minutes"));

test("the run of 14:55Z that wrote nothing no longer holds the spacing; without its journal it does", () => {
  const text = ledgerOf(realStarted, realFinished, realClosed);
  assert.deepEqual(sandbox.ledgerProblems(text, after, journalOf(journal())), []);
  assert.ok(spaced(sandbox.ledgerProblems(text, after)));
  assert.ok(spaced(sandbox.ledgerProblems(text, after, {})));
  // the journal is asked for the run directory of the lines
  const asked = [];
  sandbox.ledgerProblems(text, after, { readJournal: (dir) => (asked.push(dir), journal()) });
  assert.deepEqual(asked, [RUN]);
});

const nearMisses = [
  ["one mutating send", { journal: journal(22).replace('"mutation":false', '"mutation":true') }],
  ["a send without a mutation flag", { journal: journal(22).replace('"mutation":false', '"x":1') }],
  [
    "a mutation flag that is not a boolean",
    { journal: journal(22).replace('"mutation":false', '"mutation":"no"') },
  ],
  ["a send with no answer", { journal: journal(22, { skip: 7 }) }],
  ["an answer of the unknown kind", { journal: journal(22, { kind: "unknown" }) }],
  ["an answer of a kind we do not know", { journal: journal(22, { kind: "ok" }) }],
  ["a journal of fewer sends than the line says", { journal: journal(21) }],
  ["a journal of more sends than the line says", { journal: journal(23) }],
  ["a journal line that does not parse", { journal: `${journal()}\n{nope` }],
  ["a repeated sequence number", { journal: `${journal(1)}\n${journal(1)}` }],
  ["a state we do not know", { journal: `${journal()}\n{"seq":1,"state":"response-headers"}` }],
  [
    "an answer with no send",
    { journal: `{"seq":9,"state":"response-persisted","kind":"success"}` },
  ],
  [
    "a journal that cannot be read",
    {
      reader: () => {
        throw new Error("ENOENT");
      },
    },
  ],
  ["a journal that is not text", { reader: () => undefined }],
  ["a CLI deploy attempt", { finished: { cliAttempts: { deploy: 1, delete: 0 } } }],
  ["a CLI delete attempt", { finished: { cliAttempts: { deploy: 0, delete: 1 } } }],
  ["CLI attempts that are not known", { finished: { cliAttempts: null } }],
  ["CLI attempts that are missing", { finished: { cliAttempts: undefined } }],
  ["a CLI count that is not a number", { finished: { cliAttempts: { deploy: "0", delete: 0 } } }],
  ["a kept lock", { finished: { lockRetained: true } }],
  ["a lock flag that is missing", { finished: { lockRetained: undefined } }],
  ["an outcome of needs-recovery", { finished: { outcome: "needs-recovery", lockRetained: true } }],
  ["an outcome of recorded", { finished: { outcome: "recorded" } }],
  ["an outcome that is missing", { finished: { outcome: undefined } }],
  [
    "a request count that is not a number",
    { finished: { requests: "22" }, closed: { requests: "22" } },
  ],
  ["a request count that is missing", { finished: { requests: null }, closed: { requests: null } }],
  ["a close line with another request count", { closed: { requests: 21 } }],
  ["unknown answers on the close line", { closed: { unknownAnswers: 1 } }],
  ["unknown answers missing on the close line", { closed: { unknownAnswers: undefined } }],
  ["unknown answers as a string", { closed: { unknownAnswers: "0" } }],
  ["a sandbox not at its baseline", { closed: { sandboxAtBaseline: false } }],
  ["a baseline that is not stated", { closed: { sandboxAtBaseline: undefined } }],
  ["an unreadable time on the closing line", { finished: { ts: "later" } }],
  ["a closing line before the start", { finished: { ts: "2026-10-04T14:00:00Z" } }],
  ["a close line before the closing line", { closed: { ts: "2026-10-04T14:55:20Z" } }],
  ["a start line of another task", { started: { taskId: "OTHER-TASK" } }],
  ["no close line", { drop: "closed" }],
  ["no closing line", { drop: "finished" }],
  ["no start line", { drop: "started" }],
  [
    "a recovery line of the same run directory",
    { extra: { event: "needs-recovery", ts: "2026-10-04T14:57:00Z" } },
  ],
  ["a note of the same run directory", { extra: { event: "note", ts: "2026-10-04T14:57:00Z" } }],
  [
    "a foreign line of the same run directory",
    { extra: { event: "note", taskId: "OTHER-TASK", ts: "2026-10-04T14:57:00Z" } },
  ],
  ["a second close line", { extra: { ...realClosed, ts: "2026-10-04T14:58:00Z" } }],
];
for (const [label, change] of nearMisses) {
  test(`the spacing holds for ${label}`, () => {
    const rows = {
      started: { ...realStarted, ...change.started },
      finished: { ...realFinished, ...change.finished },
      closed: { ...realClosed, ...change.closed },
    };
    const lines = Object.entries(rows)
      .filter(([name]) => name !== change.drop)
      .map(([, entry]) => entry);
    if (change.extra) lines.push({ ...realClosed, ...change.extra });
    const reader = change.reader ?? (() => change.journal ?? journal());
    const problems = sandbox.ledgerProblems(ledgerOf(...lines), after, { readJournal: reader });
    assert.ok(spaced(problems), JSON.stringify(problems));
  });
}

test("a journal that hides a change behind a repeated sequence number or a second answer is refused", () => {
  const first = JSON.parse(journal(1).split("\n")[0]);
  const tampered = {
    "a repeated send that overwrites a mutating one": `${JSON.stringify({ ...first, mutation: true })}\n${journal(22)}`,
    "a second answer that replaces an unknown one": `${journal(22, { kind: "unknown" })}\n${JSON.stringify({ seq: 1, state: "response-persisted", kind: "success" })}`,
    "an answer with no kind": `${journal(22)}`.replace('"kind":"success"', '"x":1'),
  };
  for (const [label, text] of Object.entries(tampered)) {
    const problems = sandbox.ledgerProblems(
      ledgerOf(realStarted, realFinished, realClosed),
      after,
      journalOf(text),
    );
    assert.ok(spaced(problems), label);
  }
  assert.equal(sandbox.journalFacts(`${journal(1)}\n${journal(1)}`), undefined);
  assert.equal(
    sandbox.journalFacts(`${journal(2)}\n{"seq":1,"state":"response-persisted","kind":"success"}`),
    undefined,
  );
  // a reader that hands back bytes, not text, is not trusted
  assert.ok(
    spaced(
      sandbox.ledgerProblems(ledgerOf(realStarted, realFinished, realClosed), after, {
        readJournal: () => Buffer.from(journal()),
      }),
    ),
  );
});

test("lines with no run directory are never taken for a run that wrote nothing", () => {
  const bare = [realStarted, realFinished, realClosed].map(({ runDir: _runDir, ...rest }) => rest);
  let asked = 0;
  const problems = sandbox.ledgerProblems(ledgerOf(...bare), after, {
    readJournal: () => (asked++, journal()),
  });
  assert.ok(spaced(problems), JSON.stringify(problems));
  assert.equal(asked, 0);
  const empty = [realStarted, realFinished, realClosed].map((r) => ({ ...r, runDir: "" }));
  assert.ok(spaced(sandbox.ledgerProblems(ledgerOf(...empty), after, journalOf(journal()))));
});

test("the run the exemption is built from still passes with the same inputs (guards the table above)", () => {
  assert.deepEqual(
    sandbox.ledgerProblems(
      ledgerOf(realStarted, realFinished, realClosed),
      after,
      journalOf(journal()),
    ),
    [],
  );
});

test("a line that is not part of the run still holds the spacing from its own time", () => {
  const exempt = [realStarted, realFinished, realClosed];
  const note = (ts, extra) => ({
    ts,
    event: "note",
    taskId: "SANDBOX-CONFIG",
    project: "fireemu-oracle-events",
    ...extra,
  });
  const recent = ledgerOf(...exempt, note("2026-10-04T15:20:00Z"));
  const at = Date.parse("2026-10-04T15:40:00Z");
  assert.ok(spaced(sandbox.ledgerProblems(recent, at, journalOf(journal()))));
  const later = Date.parse("2026-10-04T15:51:00Z");
  assert.deepEqual(sandbox.ledgerProblems(recent, later, journalOf(journal())), []);
  // a different run directory is a different run, even one with the same shape
  const other = { ...realFinished, runDir: `${RUN}-2`, ts: "2026-10-04T15:25:00Z" };
  assert.ok(spaced(sandbox.ledgerProblems(ledgerOf(...exempt, other), at, journalOf(journal()))));
  // a run left open after the exempt one is still reported
  const open = ledgerOf(...exempt, {
    ...realStarted,
    taskId: "OTHER-TASK",
    runDir: "x",
    ts: "2026-10-04T15:01:00Z",
  });
  assert.ok(
    sandbox.ledgerProblems(open, later, journalOf(journal())).some((p) => p.includes("OTHER-TASK")),
  );
});

test("the journal facts count what was sent, what could be a change and what has no usable answer", () => {
  assert.deepEqual(sandbox.journalFacts(journal(3)), { sent: 3, mutating: 0, unknown: 0 });
  assert.deepEqual(sandbox.journalFacts(""), { sent: 0, mutating: 0, unknown: 0 });
  assert.deepEqual(sandbox.journalFacts(journal(3, { mutation: true })), {
    sent: 3,
    mutating: 3,
    unknown: 0,
  });
  assert.deepEqual(sandbox.journalFacts(journal(3, { kind: "refusal" })), {
    sent: 3,
    mutating: 0,
    unknown: 0,
  });
  assert.deepEqual(sandbox.journalFacts(journal(3, { skip: 2 })), {
    sent: 3,
    mutating: 0,
    unknown: 1,
  });
  assert.equal(sandbox.journalFacts("[]"), undefined);
  assert.equal(sandbox.journalFacts('{"seq":"1","state":"before-send"}'), undefined);
});

test("the journal is read only from a plain file under the runs directory", () => {
  const runs = mkdtempSync(join(tmpdir(), "fe-spacing-"));
  const dir = join(runs, "run-1");
  mkdirSync(join(dir, "transport"), { recursive: true });
  writeFileSync(join(dir, "transport", "journal.jsonl"), journal(2));
  assert.equal(sandbox.readRunJournal(runs, dir), journal(2));
  assert.throws(() => sandbox.readRunJournal(runs, runs), /outside/);
  assert.throws(() => sandbox.readRunJournal(runs, tmpdir()), /outside/);
  assert.throws(() => sandbox.readRunJournal(runs, join(runs, "missing")));
  const linked = join(runs, "run-2");
  mkdirSync(join(linked, "transport"), { recursive: true });
  symlinkSync(join(dir, "transport", "journal.jsonl"), join(linked, "transport", "journal.jsonl"));
  assert.throws(() => sandbox.readRunJournal(runs, linked), /plain file/);
  const away = mkdtempSync(join(tmpdir(), "fe-away-"));
  symlinkSync(away, join(runs, "run-3"));
  assert.throws(() => sandbox.readRunJournal(runs, join(runs, "run-3")), /outside/);
});

// The shared ledger itself (untracked): the real rows, when this checkout can see them.
const realRuns =
  process.env.FE_SANDBOX_RUNS ?? join(import.meta.dirname, "../../../../docs.local/runs");
const realLedger = join(realRuns, "sandbox-ledger.jsonl");
const realRun = join(realRuns, "functions-events-formal-20261004T145510Z-3827f1195f825ed4");
const haveReal = existsSync(realLedger) && existsSync(join(realRun, "transport", "journal.jsonl"));
const realRows = (from, to) =>
  readFileSync(realLedger, "utf8")
    .split("\n")
    .slice(from - 1, to)
    .join("\n");

test(
  "real ledger: rows 579-581 (the 14:55Z run) are exempt, the FE 012 stage 2 run is not",
  { skip: !haveReal },
  () => {
    const readJournal = (dir) => sandbox.readRunJournal(realRuns, dir);
    const today = realRows(1, 581);
    assert.deepEqual(
      sandbox.ledgerProblems(today, Date.parse("2026-10-04T15:00:00Z"), { readJournal }),
      [],
    );
    assert.ok(spaced(sandbox.ledgerProblems(today, Date.parse("2026-10-04T15:00:00Z"))));
    const fe012 = realRows(1, 566);
    const when = Date.parse("2026-10-01T08:55:00Z");
    assert.ok(spaced(sandbox.ledgerProblems(fe012, when, { readJournal })));
    assert.ok(spaced(sandbox.ledgerProblems(fe012, when, journalOf(journal(84)))));
  },
);

test(
  "real ledger: the same rows with one mutation or one CLI attempt are not exempt",
  { skip: !haveReal },
  () => {
    const at = Date.parse("2026-10-04T15:00:00Z");
    const readJournal = (dir) => sandbox.readRunJournal(realRuns, dir);
    const mutated = (text) => ({ readJournal: (dir) => text(readJournal(dir)) });
    const rows = realRows(1, 581);
    assert.ok(
      spaced(
        sandbox.ledgerProblems(
          rows,
          at,
          mutated((t) => t.replace('"mutation":false', '"mutation":true')),
        ),
      ),
    );
    const cli = rows.replace(
      '"cliAttempts":{"deploy":0,"delete":0}',
      '"cliAttempts":{"deploy":1,"delete":0}',
    );
    assert.notEqual(cli, rows);
    assert.ok(spaced(sandbox.ledgerProblems(cli, at, { readJournal })));
  },
);

test("model: with a run that wrote nothing in the ledger, only the other lines of the project hold the spacing (seeded, 300 ledgers)", () => {
  let seed = 20261005;
  const next = (n) => {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
    return seed % n;
  };
  const start = Date.parse("2026-10-04T14:00:00Z");
  const at = (minutes) => new Date(start + minutes * 60_000).toISOString();
  const nowMs = start + 90 * 60_000;
  for (let i = 0; i < 300; i += 1) {
    const extras = Array.from({ length: next(4) }, () => ({
      ts: at(next(100)),
      event: ["note", "started", "finished", "change"][next(4)],
      taskId: ["SANDBOX-CONFIG", "OTHER-TASK", sandbox.TASK_ID][next(3)],
      project: [sandbox.PROJECT, sandbox.PROJECT, "fireemu-oracle-idp"][next(3)],
      ...(next(3) === 0 ? { runDir: RUN } : {}),
    }));
    const trio = [realStarted, realFinished, realClosed].map((r, k) => ({
      ...r,
      ts: at(60 + k),
    }));
    const lines = [...trio, ...extras];
    const text = [clean, ...lines.map((r) => JSON.stringify(r))].join("\n");
    const sharesRun = extras.some((r) => r.runDir === RUN && r.project === sandbox.PROJECT);
    const holders = extras
      .filter((r) => r.project === sandbox.PROJECT)
      .map((r) => Date.parse(r.ts))
      .concat(sharesRun ? trio.map((r) => Date.parse(r.ts)) : []);
    const expected = holders.some((t) => nowMs - t < 30 * 60_000);
    const problems = sandbox.ledgerProblems(text, nowMs, journalOf(journal()));
    assert.equal(spaced(problems), expected, JSON.stringify({ extras, problems }));
  }
});
