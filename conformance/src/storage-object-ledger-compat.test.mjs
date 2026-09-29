// The rows a STORAGE-OBJECT run appends to the shared sandbox ledger must be accepted by every
// other runner's admission. Runners read the ledger with their own parsers, some strictly
// (a row without a recognised state stops the run), so the rows use only the events and outcomes
// that already exist and no new value. Each reader is fed the rows below; a reader that reads a
// different project must not be affected at all, and a reader of the query project must see an
// open run as open and a closed run as closed.

import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertAdmission as functionsHttpAssertAdmission } from "../functions-http/production.mjs";
import { recentAbort as authActionRecentAbort } from "./auth-action/run.mjs";
import {
  otherLaneOnSandbox as authConfigSdkOtherLaneOnSandbox,
  recentAbort as authConfigSdkRecentAbort,
} from "./auth-config-sdk/run.mjs";
import { recentAbort as authCredentialRecentAbort } from "./auth-credential/run.mjs";
import { sandboxBusy } from "./auth-federation/hosting.mjs";
import { recentAbort as authFsCrossRecentAbort } from "./auth-fs-cross/run.mjs";
import { admissionProblems } from "./auth-fs-cross/sandbox.mjs";
import {
  otherLaneOnSandbox as authMfaOtherLaneOnSandbox,
  recentAbort as authMfaRecentAbort,
} from "./auth-mfa/run.mjs";
import {
  assertLedgerAdmission as atbAssertLedgerAdmission,
  otherLaneOnSandbox as atbOtherLaneOnSandbox,
  recentAbort as atbRecentAbort,
} from "./auth-tenant-blocking/run.mjs";
import {
  openRuns as fsRulesOpenRuns,
  otherLanesRecently as fsRulesOtherLanesRecently,
  recentAbort as fsRulesRecentAbort,
} from "./fs-rules/run.mjs";
import {
  CLOSING_OUTCOMES,
  encodeRow,
  finishedRow,
  needsRecoveryRow,
  SANDBOX_PROJECT,
  startedRow,
  TASK_ID,
} from "./storage-object/ledger-rows.mjs";

const T0 = Date.parse("2026-10-01T09:00:00Z");
const at = (minutes) => new Date(T0 + minutes * 60_000).toISOString();
const RUN = {
  runId: "run-a",
  packetId: "storage-object-lean-v1",
  packetSha256: "a".repeat(64),
  gitSha: "b".repeat(40),
  corpusDigest: "c".repeat(64),
};

const started = (minutes = 0) =>
  startedRow({ ...RUN, ts: at(minutes), maxRequests: 3000, estimatedUsd: 0.5 });
const finished = (minutes, outcome = "recorded") =>
  finishedRow({ ...RUN, ts: at(minutes), outcome, requests: 2100, estimatedUsd: 0.15 });
const needsRecovery = (minutes) =>
  needsRecoveryRow({ ...RUN, ts: at(minutes), requests: 900, estimatedUsd: 0.1 });
const ledger = (...rows) => `${rows.map((row) => encodeRow(row)).join("")}`;

// Rows of other lanes, in the shapes they wrote: an old outcome-only row, a started line, a
// finished line, a note and a recovery pair, on the projects the readers below care about.
const OTHERS = [
  {
    ts: "2026-09-25T10:12:32.473Z",
    project: SANDBOX_PROJECT,
    taskId: "STORAGE-OBJECT-SANDBOX",
    requests: 19,
    estimatedUsd: 1,
    outcome: "preparation-stopped-p15-invalid-argument",
  },
  {
    ts: "2026-09-28T02:00:00Z",
    event: "started",
    taskId: "FS-RULES-SANDBOX",
    project: "fireemu-oracle-idp",
    estimatedUsd: 1,
  },
  {
    ts: "2026-09-28T02:20:00Z",
    event: "finished",
    outcome: "recorded",
    taskId: "FS-RULES-SANDBOX",
    project: "fireemu-oracle-idp",
    requests: 100,
    estimatedUsd: 0.1,
  },
  {
    ts: "2026-09-28T03:00:00Z",
    event: "note",
    taskId: "AUTH-FEDERATION",
    project: "fireemu-oracle-idp",
    note: "n",
    estimatedUsd: 0,
  },
  {
    ts: "2026-09-28T04:00:00Z",
    event: "started",
    taskId: "FS-QUERY-INDEX-SANDBOX",
    project: SANDBOX_PROJECT,
    estimatedUsd: 1,
  },
  {
    ts: "2026-09-28T04:10:00Z",
    event: "finished",
    outcome: "recorded",
    taskId: "FS-QUERY-INDEX-SANDBOX",
    project: SANDBOX_PROJECT,
    requests: 10,
    estimatedUsd: 0.1,
  },
];
const withOthers = (...rows) =>
  `${OTHERS.map((row) => `${JSON.stringify(row)}\n`).join("")}${ledger(...rows)}`;

// ---- the rows themselves ------------------------------------------------------------------------

test("the builders use only events and outcomes that other lanes already write", () => {
  assert.deepEqual([...CLOSING_OUTCOMES].toSorted(), [
    "recorded",
    "recovered-no-observation",
    "stopped-clean",
  ]);
  const rows = [started(), finished(5), needsRecovery(6)];
  assert.deepEqual(
    rows.map((row) => row.event),
    ["started", "finished", "needs-recovery"],
  );
  for (const row of rows) {
    assert.equal(row.project, SANDBOX_PROJECT);
    assert.equal(row.taskId, TASK_ID);
    assert.equal(typeof row.ts, "string");
    assert.equal(Number.isFinite(row.estimatedUsd), true);
  }
});

test("a row is one JSON line that round-trips", () => {
  for (const row of [started(), finished(5), needsRecovery(6)]) {
    const line = encodeRow(row);
    assert.equal(line.endsWith("\n"), true);
    assert.equal(line.slice(0, -1).includes("\n"), false);
    assert.deepEqual(JSON.parse(line), row);
  }
});

test("the builders refuse a row another lane's parser would refuse or misread", () => {
  const bad = [
    () => startedRow({ ...RUN, ts: "2026-10-01T09:00:00", maxRequests: 1, estimatedUsd: 0 }),
    () => startedRow({ ...RUN, ts: "2026-13-01T09:00:00Z", maxRequests: 1, estimatedUsd: 0 }),
    () => startedRow({ ...RUN, ts: at(0), maxRequests: 0, estimatedUsd: 0 }),
    () => startedRow({ ...RUN, ts: at(0), maxRequests: 1, estimatedUsd: -1 }),
    () => startedRow({ ...RUN, ts: at(0), maxRequests: 1, estimatedUsd: Number.NaN }),
    () => startedRow({ ...RUN, ts: at(0), maxRequests: 1, estimatedUsd: 0, runId: "a\nb" }),
    () =>
      finishedRow({ ...RUN, ts: at(1), outcome: "needs-recovery", requests: 1, estimatedUsd: 0 }),
    () =>
      finishedRow({
        ...RUN,
        ts: at(1),
        outcome: "preparation-complete",
        requests: 1,
        estimatedUsd: 0,
      }),
    () =>
      finishedRow({ ...RUN, ts: at(1), outcome: "invented-outcome", requests: 1, estimatedUsd: 0 }),
    () => finishedRow({ ...RUN, ts: at(1), outcome: "recorded", requests: -1, estimatedUsd: 0 }),
    () => finishedRow({ ...RUN, ts: at(1), outcome: "recorded", requests: 1.5, estimatedUsd: 0 }),
    () => needsRecoveryRow({ ...RUN, ts: "yesterday", requests: 1, estimatedUsd: 0 }),
  ];
  for (const build of bad) assert.throws(build);
});

test("a needs-recovery row is an event and an outcome, so every reader finds it open", () => {
  const row = needsRecovery(6);
  assert.equal(row.event, "needs-recovery");
  assert.equal(row.outcome, "needs-recovery");
  // `finished` with outcome `needs-recovery` is read as closed by one reader; never written.
  assert.notEqual(finished(5).outcome, "needs-recovery");
});

test("a closing row keeps its outcome and says the sandbox is at its baseline", () => {
  for (const outcome of CLOSING_OUTCOMES) {
    const row = finished(5, outcome);
    assert.equal(row.outcome, outcome);
    assert.equal(row.sandboxAtBaseline, true);
  }
});

test("each identity field and count is checked on its own, and the boundary values are accepted", () => {
  const valid = { ...RUN, ts: at(0), maxRequests: 1, estimatedUsd: 0 };
  assert.doesNotThrow(() => startedRow(valid));
  assert.doesNotThrow(() =>
    finishedRow({ ...RUN, ts: at(1), outcome: "recorded", requests: 0, estimatedUsd: 0 }),
  );
  assert.doesNotThrow(() => needsRecoveryRow({ ...RUN, ts: at(1), requests: 0, estimatedUsd: 0 }));
  for (const [field, value] of [
    ["runId", ""],
    ["runId", "-leading"],
    ["runId", "x".repeat(129)],
    ["packetId", "bad id"],
    ["packetId", 7],
    ["packetSha256", "A".repeat(64)],
    ["packetSha256", "a".repeat(63)],
    ["gitSha", "b".repeat(39)],
    ["gitSha", "B".repeat(40)],
    ["corpusDigest", "c".repeat(65)],
    ["ts", 1],
    ["ts", "2026-02-30T09:00:00Z"],
    ["ts", "2026-10-01T24:00:00Z"],
    ["ts", "2026-10-01T09:60:00Z"],
    ["ts", "2026-13-10T09:00:00Z"],
    ["ts", "2026-10-01T09:00:00"],
    ["ts", "2026-10-01T09:00:60Z"],
    ["ts", "2026-10-01T09:00:00+09:00"],
    ["ts", "2026-00-10T09:00:00Z"],
    ["ts", "2026-10-00T09:00:00Z"],
    ["maxRequests", 1.5],
    ["maxRequests", -1],
    ["maxRequests", "3"],
    ["estimatedUsd", "0"],
    ["estimatedUsd", Number.POSITIVE_INFINITY],
  ]) {
    assert.throws(
      () => startedRow({ ...valid, [field]: value }),
      field === "ts" ? /UTC timestamp/ : Error,
      `${field}=${String(value)}`,
    );
  }
  assert.doesNotThrow(() => startedRow({ ...valid, ts: "2026-10-01T09:00:00.123Z" }));
  assert.doesNotThrow(() => startedRow({ ...valid, ts: "2028-02-29T23:59:59Z" }));
  assert.throws(() => startedRow({ ...valid, ts: "2027-02-29T09:00:00Z" }), /UTC timestamp/);
  assert.throws(() => finishedRow({ ...valid, outcome: "recorded", requests: 1.5 }));
});

test("a needs-recovery row says the sandbox may be off its baseline", () => {
  assert.equal(needsRecovery(6).sandboxAtBaseline, false);
  assert.equal(finished(5).sandboxAtBaseline, true);
});

// ---- readers of another project or of another task ------------------------------------------------

const READERS_OF_OTHER_PROJECTS = [
  ["AUTH-FEDERATION sandboxBusy", (text, now) => sandboxBusy(text, now)],
  ["AUTH-CONFIG-SDK otherLaneOnSandbox", (text, now) => authConfigSdkOtherLaneOnSandbox(text, now)],
  ["AUTH-MFA otherLaneOnSandbox", (text, now) => authMfaOtherLaneOnSandbox(text, now)],
  ["AUTH-TENANT-BLOCKING otherLaneOnSandbox", (text, now) => atbOtherLaneOnSandbox(text, now)],
  [
    "AUTH-TENANT-BLOCKING assertLedgerAdmission",
    (text, now) => atbAssertLedgerAdmission(text, now),
  ],
  ["FS-RULES otherLanesRecently", (text, now) => fsRulesOtherLanesRecently(text, now)],
  ["FS-RULES openRuns", (text, now) => fsRulesOpenRuns(text, now)],
];

const RECENT_ABORT_READERS = [
  ["AUTH-ACTION", authActionRecentAbort],
  ["AUTH-CONFIG-SDK", authConfigSdkRecentAbort],
  ["AUTH-CREDENTIAL", authCredentialRecentAbort],
  ["AUTH-MFA", authMfaRecentAbort],
  ["AUTH-FS-CROSS", authFsCrossRecentAbort],
  ["AUTH-TENANT-BLOCKING", atbRecentAbort],
  ["FS-RULES", fsRulesRecentAbort],
];

const STATES = {
  open: () => [started(0)],
  closed: () => [started(0), finished(20)],
  recovering: () => [started(0), needsRecovery(20)],
  recovered: () => [started(0), needsRecovery(20), finished(60, "recovered-no-observation")],
};

for (const [name, read] of READERS_OF_OTHER_PROJECTS) {
  test(`${name} is not affected by a run on the query project`, () => {
    const now = T0 + 24 * 3_600_000;
    let baseline;
    try {
      baseline = { value: read(withOthers(), now) };
    } catch (error) {
      baseline = { error: error.message };
    }
    for (const [state, rows] of Object.entries(STATES)) {
      let observed;
      try {
        observed = { value: read(withOthers(...rows()), now) };
      } catch (error) {
        observed = { error: error.message };
      }
      assert.deepEqual(observed, baseline, `${name} changes for a ${state} run`);
    }
  });
}

for (const [name, read] of RECENT_ABORT_READERS) {
  test(`${name} recentAbort ignores this task's rows in every state`, () => {
    for (const [state, rows] of Object.entries(STATES)) {
      assert.equal(read(withOthers(...rows()), T0 + 61 * 60_000), undefined, `${name} ${state}`);
    }
  });
}

test("FUNCTIONS-HTTP admission is unchanged by this task's rows and never satisfied by them", () => {
  const lines = (text) =>
    text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  const reason = (rows) => {
    try {
      functionsHttpAssertAdmission(rows, T0);
      return "admitted";
    } catch (error) {
      return error.message;
    }
  };
  const base = reason(lines(withOthers()));
  for (const rows of Object.values(STATES)) {
    assert.equal(reason(lines(withOthers(...rows()))), base);
  }
  // Its Storage precondition is one historical row; a new row must never look like it.
  for (const outcome of CLOSING_OUTCOMES) {
    assert.notEqual(finished(5, outcome).outcome, "preparation-complete");
  }
});

test("the strict reader would refuse a row of the wrong shape, so the tests above can fail", () => {
  const now = T0 + 24 * 3_600_000;
  const noState = `${JSON.stringify({ ts: at(0), project: SANDBOX_PROJECT, taskId: TASK_ID })}\n`;
  const noOutcome = `${JSON.stringify({ ts: at(0), event: "finished", project: SANDBOX_PROJECT, taskId: TASK_ID })}\n`;
  const badTime = `${JSON.stringify({ ts: "yesterday", event: "started", project: SANDBOX_PROJECT, taskId: TASK_ID })}\n`;
  for (const text of [noState, noOutcome, badTime]) {
    assert.throws(() => atbAssertLedgerAdmission(`${text}`, now));
  }
  // An unread line is not "no rows": a task's open run is still found by the query reader.
  assert.equal(
    admissionProblems(`${ledger(started(0))}not json\n`, SANDBOX_PROJECT, T0 + 200 * 60_000).length,
    1,
  );
});

// ---- the reader of the query project ---------------------------------------------------------------

test("AUTH-FS-CROSS admission sees an open run as open and a closed run as closed", () => {
  const problems = (rows, minutes) =>
    admissionProblems(withOthers(...rows), SANDBOX_PROJECT, T0 + minutes * 60_000);

  const open = problems(STATES.open(), 200);
  assert.equal(open.length, 1);
  assert.match(open[0], /STORAGE-OBJECT-SANDBOX on fireemu-oracle-query is open since/);

  // A closed run leaves only the quiet interval, then nothing.
  const soon = problems(STATES.closed(), 21);
  assert.equal(soon.length, 1);
  assert.match(soon[0], /STORAGE-OBJECT-SANDBOX wrote a line/);
  assert.deepEqual(problems(STATES.closed(), 51), []);

  const recovering = problems(STATES.recovering(), 300);
  assert.equal(recovering.length, 1);
  assert.match(
    recovering[0],
    /STORAGE-OBJECT-SANDBOX on fireemu-oracle-query needs recovery since/,
  );

  assert.deepEqual(problems(STATES.recovered(), 91), []);
});

test("every closing outcome closes a run for the query-project reader", () => {
  for (const outcome of CLOSING_OUTCOMES) {
    const text = withOthers(started(0), finished(20, outcome));
    assert.deepEqual(admissionProblems(text, SANDBOX_PROJECT, T0 + 60 * 60_000), [], outcome);
  }
});

test("the historical STORAGE-OBJECT rows still read as closed", () => {
  assert.deepEqual(
    admissionProblems(withOthers(), SANDBOX_PROJECT, Date.parse("2026-10-02T00:00:00Z")),
    [],
  );
});

// ---- inventory of the readers ---------------------------------------------------------------------

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const READER_NAME =
  /export (?:async )?function (recentAbort|sandboxBusy|otherLane\w*|otherLanes\w*|admissionProblems|assertLedgerAdmission|assertAdmission|openRuns|runToRecover|recordingToRecover|samlRunToRecover)\b/g;

function sources(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === ".runs") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (name.endsWith(".mjs") && !name.endsWith(".test.mjs")) out.push(path);
  }
  return out;
}

// A new ledger reader must be added here and to the tests above, so this task's rows are proved
// against it before it lands.
const KNOWN_READERS = [
  "functions-http/production.mjs:assertAdmission",
  "src/auth-action/run.mjs:recentAbort",
  "src/auth-config-sdk/run.mjs:otherLaneOnSandbox",
  "src/auth-config-sdk/run.mjs:recentAbort",
  "src/auth-credential/run.mjs:recentAbort",
  "src/auth-federation/hosting.mjs:runToRecover",
  "src/auth-federation/hosting.mjs:sandboxBusy",
  "src/auth-federation/record.mjs:recordingToRecover",
  "src/auth-federation/saml-smoke.mjs:samlRunToRecover",
  "src/auth-fs-cross/run.mjs:recentAbort",
  "src/auth-fs-cross/sandbox.mjs:admissionProblems",
  "src/auth-mfa/run.mjs:otherLaneOnSandbox",
  "src/auth-mfa/run.mjs:recentAbort",
  "src/auth-tenant-blocking/run.mjs:assertLedgerAdmission",
  "src/auth-tenant-blocking/run.mjs:otherLaneOnSandbox",
  "src/auth-tenant-blocking/run.mjs:recentAbort",
  "src/fs-rules/run.mjs:openRuns",
  "src/fs-rules/run.mjs:otherLanesRecently",
  "src/fs-rules/run.mjs:recentAbort",
];

test("every exported ledger reader is one of those this task's rows were proved against", () => {
  const found = [];
  for (const path of sources(ROOT)) {
    const rel = path.slice(ROOT.length).replaceAll("\\", "/");
    if (rel.startsWith("src/storage-object/")) continue;
    for (const match of readFileSync(path, "utf8").matchAll(READER_NAME)) {
      found.push(`${rel}:${match[1]}`);
    }
  }
  assert.deepEqual(found.toSorted(), [...KNOWN_READERS].toSorted());
});
