import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { harnessDigest } from "./functions-events/record/main.mjs";
import { main, parseArgs } from "./functions-events/record/recover-main.mjs";
import { ORIGIN_RUN_DIR_NAME } from "./functions-events/record/recover-targets.mjs";
import * as sandbox from "./functions-events/record/sandbox.mjs";
import { createRecoverWorld } from "./functions-events-recover-world.mjs";

const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
  cwd: new URL(".", import.meta.url).pathname,
})
  .toString()
  .trim();
const head = execFileSync("git", ["-C", root, "rev-parse", "HEAD"]).toString().trim();
const NOW = Date.parse("2026-10-04T16:50:00Z");
const origin = (runs) => join(runs, ORIGIN_RUN_DIR_NAME);

/** The ledger lines of the v4 run as they were written (rows 582-584 of the v3 run before it, then the v4 started/finished). */
function ledgerFor(runs, lockText) {
  const row = (over) =>
    JSON.stringify({
      project: sandbox.PROJECT,
      taskId: sandbox.TASK_ID,
      database: "(default)",
      phase: "formal-record",
      ...over,
    });
  const v3 = join(runs, "functions-events-formal-20261004T152647Z-368f8ccdac4f441e");
  return [
    row({ ts: "2026-10-04T15:26:48.489Z", event: "started", runDir: v3, estimatedUsd: 4 }),
    row({
      ts: "2026-10-04T15:28:29.427Z",
      event: "finished",
      runDir: v3,
      outcome: "incomplete-clean",
      requests: 57,
      estimatedUsd: 4,
      lockRetained: false,
    }),
    row({
      ts: "2026-10-04T15:30:40.780Z",
      event: "cleanup-verified",
      runDir: v3,
      sandboxAtBaseline: true,
      requests: 57,
      unknownAnswers: 0,
      estimatedUsd: 0,
    }),
    row({
      ts: "2026-10-04T16:10:51.815Z",
      event: "started",
      runDir: origin(runs),
      estimatedUsd: 4,
      lockSha256: sha256(lockText),
      envelopeId: "FUNCTIONS-EVENTS-FORMAL-003",
    }),
    row({
      ts: "2026-10-04T16:37:57.703Z",
      event: "finished",
      runDir: origin(runs),
      outcome: "needs-recovery",
      requests: 153,
      cliAttempts: { dryRun: 1, deploy: 1, delete: 1 },
      estimatedUsd: 4,
      lockRetained: true,
    }),
  ].join("\n");
}

function arrange(options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "fe-recmain-"));
  const runsDir = join(dir, "runs");
  const lockDir = join(dir, "locks");
  mkdirSync(runsDir, { recursive: true });
  mkdirSync(lockDir, { recursive: true, mode: 0o700 });
  const lockText = JSON.stringify({
    pid: 999999,
    runDir: origin(runsDir),
    packetSha256: "e".repeat(64),
  });
  writeFileSync(join(lockDir, `${sandbox.PROJECT}.lock`), lockText, { mode: 0o600 });
  const ledgerPath = join(dir, "ledger.jsonl");
  writeFileSync(ledgerPath, `${ledgerFor(runsDir, lockText)}\n`);
  const packet = join(dir, "packet.md");
  writeFileSync(packet, "the recovery packet");
  const git = (args) => (args[0] === "rev-parse" ? head : "");
  const { digest } = harnessDigest(root, { git });
  const pins = {
    packetSha256: sha256("the recovery packet"),
    harnessSha256: digest,
    sourceCommit: head,
  };
  const E = `- 2026-10-05 | ${sandbox.RECOVERY_ENVELOPE_TOPIC} | envelopeId=R4-1; project=fireemu-oracle-events; maxRequests=90; cliMax=0; reserveUsd=0.10; retries=none | オーナー | x`;
  const V = `- 2026-10-05 | ${sandbox.RECOVERY_TOPIC} | decision=APPROVE; envelopeId=R4-1; packetSha256=${pins.packetSha256}; harnessSha256=${pins.harnessSha256}; sourceCommit=${pins.sourceCommit} | Claude（委任 | y`;
  const ownerPath = join(dir, "owner.md");
  writeFileSync(ownerPath, options.approve === false ? "" : `${E}\n${V}\n`);
  const world = createRecoverWorld(options.world);
  let t = NOW;
  const deps = {
    root,
    env: { PATH: "/usr/bin" },
    log: () => {},
    fetch: world.fetch,
    printAccessToken: async () => "ya29.synthetic-token-aaaaaaaaaaaaaaaaaaaa",
    sleep: async (seconds) => {
      t += seconds * 1000;
    },
    now: () => t,
    ledgerPath,
    ownerPath,
    lockDir,
    legacyLock: join(dir, "ledger.lock"),
    runsDir,
    nodeVersion: "22.22.1",
    git,
    isAlive: () => false,
  };
  const argv = (command) => [command, "--packet", packet, "--source-commit", head];
  return { dir, deps, argv, world, ledgerPath, lockDir, lockText, runsDir, pins };
}

test("the arguments are strict", () => {
  assert.equal(
    parseArgs(["recover", "--packet", "p", "--source-commit", "a".repeat(40)]).command,
    "recover",
  );
  assert.throws(() => parseArgs(["record"]), /usage/);
  assert.throws(() => parseArgs(["check", "--packet", "p"]), /source-commit/);
  assert.throws(() => parseArgs(["check", "--packet", "p", "--source-commit", "HEAD"]), /full SHA/);
});

test("check passes ten minutes after the origin run, reads locally and sends nothing", async () => {
  const { deps, argv, world } = arrange();
  const result = await main(argv("check"), deps);
  assert.deepEqual(result.problems, []);
  assert.equal(result.ok, true);
  assert.equal(world.state.requests.length, 0);
});

test("check refuses before the ten minutes have passed, and for each way the origin or its lock is not as expected", async () => {
  const cases = [
    [
      "ten minutes not yet passed",
      (a) => (a.deps.now = () => Date.parse("2026-10-04T16:47:00Z")),
      /less than 10 minutes old/,
    ],
    ["no approval line", (a) => writeFileSync(a.deps.ownerPath, ""), /no approval line/],
    [
      "the lock is another file",
      (a) => writeFileSync(join(a.lockDir, `${sandbox.PROJECT}.lock`), '{"pid":1,"runDir":"x"}'),
      /not the origin run's lock/,
    ],
    ["the lock is gone", (a) => writeFileSync(join(a.lockDir, "other"), ""), null],
    ["its holder is alive", (a) => (a.deps.isAlive = () => true), /still running/],
    ["the legacy lock is held", (a) => writeFileSync(a.deps.legacyLock, ""), /legacy shared lock/],
    [
      "a credential variable is set",
      (a) => (a.deps.env = { PATH: "/usr/bin", FIREBASE_TOKEN: "x" }),
      /FIREBASE_TOKEN/,
    ],
    ["the wrong Node", (a) => (a.deps.nodeVersion = "24.14.0"), /Node 22/],
    [
      "another HEAD",
      (a) => (a.deps.git = (args) => (args[0] === "rev-parse" ? "f".repeat(40) : "")),
      /pinned source commit/,
    ],
    [
      "a dirty tree",
      (a) => (a.deps.git = (args) => (args[0] === "rev-parse" ? head : " M x")),
      /not clean/,
    ],
  ];
  for (const [label, change, pattern] of cases) {
    const a = arrange();
    change(a);
    if (label === "the lock is gone")
      (await import("node:fs")).rmSync(join(a.lockDir, `${sandbox.PROJECT}.lock`));
    const result = await main(a.argv("check"), a.deps);
    assert.equal(result.ok, false, label);
    if (pattern)
      assert.ok(
        result.problems.some((p) => pattern.test(p)),
        `${label}: ${JSON.stringify(result.problems)}`,
      );
    else
      assert.ok(
        result.problems.some((p) => /not held/.test(p)),
        label,
      );
  }
});

test("recover runs the recovery, writes a started and a finished line, and leaves the project lock exactly as it was", async () => {
  const a = arrange();
  const result = await main(a.argv("recover"), a.deps);
  assert.equal(result.outcome, "recovered", JSON.stringify(result.problems));
  assert.equal(result.ok, true);
  const rows = readFileSync(a.ledgerPath, "utf8")
    .trim()
    .split("\n")
    .map((l) => JSON.parse(l));
  const [started, finished] = rows.slice(-2);
  assert.deepEqual(
    [started.event, started.phase, started.cliMax, started.estimatedUsd, started.maxRequests],
    ["started", "recovery", 0, 0.1, 90],
  );
  assert.equal(started.heldLockSha256, sha256(a.lockText));
  assert.equal(started.originRunDir, origin(a.runsDir));
  assert.deepEqual(
    [finished.event, finished.outcome, finished.lockRetained, finished.deletes],
    ["finished", "recovered", true, 2],
  );
  assert.deepEqual(finished.cliAttempts, { dryRun: 0, deploy: 0, delete: 0 });
  assert.equal(
    readFileSync(join(a.lockDir, `${sandbox.PROJECT}.lock`), "utf8"),
    a.lockText,
    "the lock is untouched",
  );
  assert.equal(statSync(join(result.runDir, "recovery.json")).mode & 0o077, 0);
  assert.ok(existsSync(join(result.runDir, "SHA256SUMS")));
  assert.ok(existsSync(join(result.runDir, "transport", "journal.jsonl")));
  assert.deepEqual([...new Set(a.world.state.requests.map((r) => r.method))].toSorted(), [
    "DELETE",
    "GET",
  ]);
  // the same packet cannot run twice
  const again = await main(a.argv("recover"), a.deps);
  assert.equal(again.ok, false);
  assert.ok(again.problems.some((p) => p.includes("already started")));
});

test("a refused admission writes nothing and sends nothing", async () => {
  const a = arrange({ approve: false });
  const before = readFileSync(a.ledgerPath, "utf8");
  const result = await main(a.argv("recover"), a.deps);
  assert.equal(result.ok, false);
  assert.equal(readFileSync(a.ledgerPath, "utf8"), before);
  assert.equal(a.world.state.requests.length, 0);
});

test("a recovery that does not settle ends needs-review, keeps the lock and says so in the ledger", async () => {
  const a = arrange({ world: { failOperationFor: ["storageArchivedV2"] } });
  const result = await main(a.argv("recover"), a.deps);
  assert.equal(result.outcome, "needs-review");
  const last = JSON.parse(readFileSync(a.ledgerPath, "utf8").trim().split("\n").at(-1));
  assert.deepEqual([last.outcome, last.lockRetained], ["needs-review", true]);
  assert.equal(readFileSync(join(a.lockDir, `${sandbox.PROJECT}.lock`), "utf8"), a.lockText);
});

test("an unexpected error in the run still writes the finished line and keeps the lock", async () => {
  const a = arrange();
  a.deps.fetch = async () => {
    throw new Error("boom");
  };
  const result = await main(a.argv("recover"), a.deps);
  assert.equal(result.ok, false);
  assert.equal(
    JSON.parse(readFileSync(a.ledgerPath, "utf8").trim().split("\n").at(-1)).event,
    "finished",
  );
  assert.equal(readFileSync(join(a.lockDir, `${sandbox.PROJECT}.lock`), "utf8"), a.lockText);
});

// ---- the admission rules on their own ---------------------------------------------------------------

test("recoveryProblems: each way the origin run is not a run to recover", () => {
  const runs = "/runs";
  const lockText = "{}";
  const lock = { text: JSON.stringify({ pid: 5, runDir: origin(runs) }), isAlive: () => false };
  const base = ledgerFor(runs, lock.text);
  const run = (ledger, extra = {}) =>
    sandbox.recoveryProblems(ledger, { originRunDir: origin(runs), now: NOW, lock, ...extra });
  assert.deepEqual(run(base), []);
  void lockText;
  const rows = base.split("\n");
  const without = (event) =>
    rows
      .filter((l) => JSON.parse(l).runDir !== origin(runs) || JSON.parse(l).event !== event)
      .join("\n");
  assert.match(run(without("started"))[0], /exactly one started and one finished/);
  assert.match(run(without("finished"))[0], /exactly one started and one finished/);
  assert.ok(
    run(base.replace('"outcome":"needs-recovery"', '"outcome":"incomplete-clean"')).some((p) =>
      /did not end needs-recovery/.test(p),
    ),
  );
  assert.ok(
    run(base.replace('"lockRetained":true', '"lockRetained":false')).some((p) =>
      /did not end needs-recovery/.test(p),
    ),
  );
  const closed = `${base}\n${JSON.stringify({ project: sandbox.PROJECT, taskId: sandbox.TASK_ID, event: "cleanup-verified", runDir: origin(runs), ts: "2026-10-04T16:40:00Z", estimatedUsd: 0 })}`;
  assert.ok(run(closed).some((p) => /already closed/.test(p)));
  const other = `${base}\n${JSON.stringify({ project: sandbox.PROJECT, taskId: "OTHER", event: "note", ts: "2026-10-04T16:39:00Z" })}`;
  assert.ok(run(other).some((p) => /follows the origin run/.test(p)));
  const unreadable = `${base}\n${JSON.stringify({ project: sandbox.PROJECT, taskId: sandbox.TASK_ID, event: "finished", phase: "recovery", originRunDir: origin(runs), ts: "soon" })}`;
  assert.ok(run(unreadable).some((p) => /unreadable time/.test(p)));
  const otherOrigin = `${base}\n${JSON.stringify({ project: sandbox.PROJECT, taskId: sandbox.TASK_ID, phase: "recovery", originRunDir: "/runs/another-origin", runDir: "/runs/rec-9", event: "started", ts: "2026-10-04T16:39:00Z" })}`;
  assert.ok(
    run(otherOrigin).some((p) => /follows the origin run/.test(p)),
    "a recovery of another origin is not this one's",
  );
  const namesOther = JSON.stringify({ pid: 5, runDir: "/runs/another-run" });
  assert.ok(
    sandbox
      .recoveryProblems(ledgerFor(runs, namesOther), {
        originRunDir: origin(runs),
        now: NOW,
        lock: { text: namesOther, isAlive: () => false },
      })
      .some((p) => /names another run/.test(p)),
    "a lock whose SHA matches but that names another run",
  );
  const foreignProject = `${base}\n${JSON.stringify({ project: "other-project", taskId: "X", event: "started", ts: "2026-10-04T16:49:00Z" })}`;
  assert.deepEqual(run(foreignProject), [], "lines of other projects do not matter");
  assert.ok(
    run(base, { lock: { text: undefined, isAlive: () => false } }).some((p) => /not held/.test(p)),
  );
  assert.ok(
    run(base, { lock: { text: "not json", isAlive: () => false } }).some((p) =>
      /does not parse|not the origin/.test(p),
    ),
  );
  assert.ok(
    run(base, {
      lock: { text: JSON.stringify({ pid: 5, runDir: "/elsewhere" }), isAlive: () => false },
    }).some((p) => /not the origin run's lock|names another run/.test(p)),
  );
  assert.ok(
    run(base, {
      lock: { text: JSON.stringify({ runDir: origin(runs) }), isAlive: () => false },
    }).some((p) => /pid is unknown|still running/.test(p)),
  );
  assert.ok(
    run(base, { now: Date.parse("2026-10-04T16:47:57Z") }).some((p) =>
      /less than 10 minutes/.test(p),
    ),
  );
  assert.deepEqual(run(base, { now: Date.parse("2026-10-04T16:47:58Z") }), []);
});

test("a recovery that started and did not finish blocks another; a finished one does not", () => {
  const runs = "/runs";
  const lockText = JSON.stringify({ pid: 5, runDir: origin(runs) });
  const lock = { text: lockText, isAlive: () => false };
  const base = ledgerFor(runs, lockText);
  const recovery = (event, ts) =>
    JSON.stringify({
      project: sandbox.PROJECT,
      taskId: sandbox.TASK_ID,
      phase: "recovery",
      originRunDir: origin(runs),
      runDir: "/runs/rec-1",
      event,
      ts,
    });
  const run = (ledger) =>
    sandbox.recoveryProblems(ledger, { originRunDir: origin(runs), now: NOW, lock });
  assert.ok(
    run(`${base}\n${recovery("started", "2026-10-04T16:20:00Z")}`).some((p) =>
      /did not finish/.test(p),
    ),
  );
  assert.deepEqual(
    run(
      `${base}\n${recovery("started", "2026-10-04T16:20:00Z")}\n${recovery("finished", "2026-10-04T16:25:00Z")}`,
    ).filter((p) => !/minutes/.test(p)),
    [],
  );
});

test("recovery approval: its own topics and limits, and no mixing with the formal approval", () => {
  const pins = {
    packetSha256: "a".repeat(64),
    harnessSha256: "b".repeat(64),
    sourceCommit: "c".repeat(40),
  };
  const E = (over = "") =>
    `- 2026-10-05 | ${sandbox.RECOVERY_ENVELOPE_TOPIC} | envelopeId=R; project=fireemu-oracle-events; maxRequests=90; cliMax=0; reserveUsd=0.10; retries=none${over} | オーナー | x`;
  const V = `- 2026-10-05 | ${sandbox.RECOVERY_TOPIC} | decision=APPROVE; envelopeId=R; packetSha256=${pins.packetSha256}; harnessSha256=${pins.harnessSha256}; sourceCommit=${pins.sourceCommit} | Claude（委任 | y`;
  assert.deepEqual(sandbox.recoveryApproval(`${E()}\n${V}`, pins).problems, []);
  assert.ok(
    sandbox.approval(`${E()}\n${V}`, pins).problems.length > 0,
    "the formal approval does not read recovery lines",
  );
  for (const [from, to] of [
    ["maxRequests=90", "maxRequests=89"],
    ["reserveUsd=0.10", "reserveUsd=0.09"],
    ["retries=none", "retries=twice"],
    ["project=fireemu-oracle-events", "project=other"],
  ])
    assert.ok(
      sandbox.recoveryApproval(`${E().replace(from, to)}\n${V}`, pins).problems.length > 0,
      to,
    );
  assert.ok(sandbox.recoveryApproval(`${V}`, pins).problems.length > 0);
  assert.ok(
    sandbox.recoveryApproval(
      `${E()}\n${V}\n- 2026-10-06 | ${sandbox.RECOVERY_TOPIC} | REVOKED packetSha256=${pins.packetSha256} | Claude（委任 | z`,
      pins,
    ).problems.length > 0,
  );
  const formalV = `- 2026-10-05 | ${sandbox.TOPIC} | decision=APPROVE; envelopeId=R; packetSha256=${pins.packetSha256}; harnessSha256=${pins.harnessSha256}; sourceCommit=${pins.sourceCommit} | Claude（委任 | y`;
  assert.ok(
    sandbox.recoveryApproval(`${E()}\n${formalV}`, pins).problems.length > 0,
    "a formal version line approves no recovery",
  );
});

// ---- the real run (the shared docs.local, when this checkout can see it) ------------------------------

const realRuns =
  process.env.FE_SANDBOX_RUNS ?? join(import.meta.dirname, "../../../../docs.local/runs");
const realOrigin = join(realRuns, ORIGIN_RUN_DIR_NAME);
const haveReal = existsSync(
  join(realOrigin, "transport", "responses", "0140-lists.functions-v2.json"),
);

test(
  "real run: the committed fixtures are the recorded bodies with only the project number replaced",
  { skip: !haveReal },
  () => {
    for (const name of [
      "0140-lists.functions-v2",
      "0141-lists.run-services",
      "0142-lists.eventarc-triggers",
      "0146-cleanup.topics",
      "0147-cleanup.subscriptions",
    ]) {
      const real = readFileSync(join(realOrigin, "transport", "responses", `${name}.json`), "utf8");
      const number = /(\d{12})-compute@/.exec(real)?.[1];
      const sanitized = number ? real.replaceAll(number, "123456789012") : real;
      const fixture = readFileSync(
        new URL(`./functions-events/record/recorded/v4-run/${name}.json`, import.meta.url),
        "utf8",
      );
      assert.deepEqual(JSON.parse(fixture), JSON.parse(sanitized), name);
    }
  },
);

test(
  "real run: the ledger and the lock say this origin is to be recovered, from ten minutes after 16:37:57Z",
  { skip: !haveReal || !existsSync(join(realRuns, "sandbox-locks", `${sandbox.PROJECT}.lock`)) },
  () => {
    const ledger = readFileSync(join(realRuns, "sandbox-ledger.jsonl"), "utf8")
      .split("\n")
      .filter((line) => !/"phase": ?"recovery"/.test(line))
      .join("\n");
    const lockText = readFileSync(
      join(realRuns, "sandbox-locks", `${sandbox.PROJECT}.lock`),
      "utf8",
    );
    const problems = sandbox.recoveryProblems(ledger, {
      originRunDir: realOrigin,
      now: Date.parse("2026-10-05T17:00:00Z"),
      lock: { text: lockText, isAlive: () => false },
    });
    // the lines that may follow the origin run are the coordinator's own (a close row or a REVOKED line); anything else is named
    assert.ok(
      problems.every((p) => /follows the origin run|already closed|minutes old/.test(p)),
      JSON.stringify(problems),
    );
    assert.ok(!problems.some((p) => /lock/.test(p)), "the real lock is the origin's own");
  },
);

test("the budget is checked: a ledger that has used the cap refuses the recovery's reserve", async () => {
  const a = arrange();
  const extra = JSON.stringify({
    project: sandbox.PROJECT,
    taskId: sandbox.TASK_ID,
    event: "started",
    runDir: "/runs/big",
    estimatedUsd: 29.95,
    ts: "2026-10-04T13:00:00Z",
  });
  writeFileSync(a.ledgerPath, `${extra}\n${readFileSync(a.ledgerPath, "utf8")}`);
  const result = await main(a.argv("check"), a.deps);
  assert.ok(
    result.problems.some((p) => /passes the cap/.test(p)),
    JSON.stringify(result.problems),
  );
  const fine = arrange();
  const small = JSON.stringify({
    project: sandbox.PROJECT,
    taskId: sandbox.TASK_ID,
    event: "started",
    runDir: "/runs/big",
    estimatedUsd: 29.9,
    ts: "2026-10-04T13:00:00Z",
  });
  writeFileSync(fine.ledgerPath, `${small}\n${readFileSync(fine.ledgerPath, "utf8")}`);
  assert.deepEqual((await main(fine.argv("check"), fine.deps)).problems, []);
});

test("the default test of a live holder: a pid that exists (even one we may not signal) blocks, a pid that does not exist does not", async () => {
  for (const [pid, blocked] of [
    [process.pid, true],
    [1, true],
    [999999, false],
  ]) {
    const a = arrange();
    const text = JSON.stringify({ pid, runDir: origin(a.runsDir), packetSha256: "e".repeat(64) });
    writeFileSync(join(a.lockDir, `${sandbox.PROJECT}.lock`), text);
    writeFileSync(a.ledgerPath, `${ledgerFor(a.runsDir, text)}\n`);
    delete a.deps.isAlive;
    const result = await main(a.argv("check"), a.deps);
    assert.equal(
      result.problems.some((p) => /still running/.test(p)),
      blocked,
      `pid ${pid}: ${JSON.stringify(result.problems)}`,
    );
  }
});
