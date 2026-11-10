import assert from "node:assert/strict";
import test from "node:test";

import {
  RECORDING_TASK_ID,
  RECOVERY_CAPS,
  RECOVERY_TASK_ID,
  admitRecovery,
  isRunsLeftover,
  nameFormat,
  recoverVersion,
} from "./recover-version.mjs";
import { PROJECT } from "./record.mjs";
import { createWorld } from "./world.mjs";

const secrets = { apiKey: "AIzaFAKEFAKEFAKEFAKEFAKEFAKE12345", projectNumber: "123456789012" };
const RUN = "abc123";
const ID = "0000000000000001";
const reply = (status, value = {}) => ({ status, text: JSON.stringify(value) });
const closed = {
  ts: "2026-11-09T00:00:00Z",
  project: PROJECT,
  taskId: "other",
  event: "finished",
  outcome: "recorded",
};
const startedRow = {
  ts: "2026-11-10T16:12:51.000Z",
  project: PROJECT,
  taskId: RECORDING_TASK_ID,
  run: RUN,
  event: "started",
};
const failedRow = {
  ts: "2026-11-10T16:13:00.000Z",
  project: PROJECT,
  taskId: RECORDING_TASK_ID,
  run: RUN,
  event: "needs-recovery",
  outcome: "needs-recovery",
};
const now = Date.parse("2026-11-10T17:00:00Z");

/** A world holding the run's leftover version (id 0000000000000001), and the deps around it. */
async function setup({
  overrides = [],
  rows = [closed, startedRow, failedRow],
  label = {},
  leftover = {},
} = {}) {
  const world = createWorld({ run: RUN, secrets, overrides });
  await world.http({
    method: "POST",
    url: "https://firebasehosting.googleapis.com/v1beta1/projects/-/sites/fireemu-oracle-idp/versions",
    body: JSON.stringify({ labels: { "fireemu-run": RUN, "fireemu-version": "v01", ...label } }),
  });
  Object.assign(world.state.versions.get(`sites/${PROJECT}/versions/${ID}`), leftover);
  world.log.length = 0; // the fixture's own create is not part of the recovery
  world.state.counters = {};
  const ledger = rows.map((row) => JSON.stringify(row));
  const files = {};
  const sleeps = [];
  const deps = {
    now: () => now,
    readLedger: async () => ledger.join("\n"),
    appendLedger: async (text) => ledger.push(text.trim()),
    ownerAdc: async () => ({}),
    webConfig: async () => ({
      projectId: PROJECT,
      ...secrets,
      messagingSenderId: secrets.projectNumber,
      appId: `1:${secrets.projectNumber}:web:deadbeef1234`,
    }),
    makeRunDir: async (name) => `/run/${name}`,
    writeRunFile: async (_dir, name, text) => (files[name] = text),
    appendRunFile: async (_dir, name, text) => (files[name] = (files[name] ?? "") + text),
    token: async () => ({ value: "t", expiresAt: now + 1e9 }),
    http: world.http,
    sleep: async (ms) => sleeps.push(ms),
  };
  return { world, deps, ledger, files, sleeps };
}
const go = (s, args = { run: RUN, versionId: ID }) => recoverVersion(args, s.deps);
const lastRow = (s) => JSON.parse(s.ledger.at(-1));
const writes = (s) => s.world.log.filter((call) => call.method !== "GET");
const fault = (match, answer, nth = 1) => ({ match, nth, answer });

test("it reads, proves the version is the run's own, deletes once and reads back; it never closes the run", async () => {
  const s = await setup();
  const result = await go(s);
  assert.equal(result.outcome, "recovery-read-clean");
  assert.equal(result.exitCode, 0);
  assert.deepEqual(
    writes(s).map((call) => [call.method, new URL(call.url).pathname]),
    [["DELETE", `/v1beta1/sites/${PROJECT}/versions/${ID}`]],
  );
  assert.equal(s.world.state.versions.get(`sites/${PROJECT}/versions/${ID}`).status, "DELETED");
  assert.deepEqual(result.polls, ["DELETED"]);
  assert.equal(result.listLeft, false);
  const row = lastRow(s);
  assert.equal(row.taskId, RECOVERY_TASK_ID);
  assert.equal(row.event, "recovery-read");
  assert.equal(row.outcome, "recovery-read-clean");
  assert.equal(row.a2ReadNotBefore, new Date(now + 600_000).toISOString());
  assert.deepEqual(result.read.labels, { "fireemu-run": RUN, "fireemu-version": "v01" });
  // The request counts stay inside the budget.
  for (const [kind, cap] of Object.entries(RECOVERY_CAPS))
    assert.ok(row.requests[kind] <= cap, kind);
  assert.equal(row.requests.delete, 1);
  assert.ok(!JSON.stringify([s.files, s.ledger]).includes(secrets.projectNumber));
});

test("a version that is not provably the run's leftover is never deleted", async () => {
  const cases = [
    ["another run's label", { label: { "fireemu-run": "ffffff" } }],
    ["another version label", { label: { "fireemu-version": "v02" } }],
    ["no label", { label: { "fireemu-run": undefined } }],
    ["created before the run", { leftover: { createTime: "2026-11-10T15:00:00.000Z" } }],
    ["created after the run", { leftover: { createTime: "2026-11-10T16:20:00.000Z" } }],
    ["no create time", { leftover: { createTime: undefined } }],
    ["already finalized", { leftover: { status: "FINALIZED" } }],
    ["already deleted", { leftover: { status: "DELETED" } }],
  ];
  for (const [what, options] of cases) {
    const s = await setup(options);
    const result = await go(s);
    assert.equal(result.outcome, "needs-recovery", what);
    assert.match(result.reason, /not the run's leftover/, what);
    assert.equal(writes(s).length, 0, what);
    assert.equal(lastRow(s).delete, "not-sent", what);
  }
});

test("a read that is unknown or 404 sends no delete and settles nothing", async () => {
  for (const injected of ["network-error", reply(500), reply(302), reply(404), reply(403)]) {
    const s = await setup({ overrides: [fault("GET /versions/[0-9]+$/", injected)] });
    const result = await go(s);
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(writes(s).length, 0);
    assert.match(result.reason, /version read/);
  }
});

test("the delete is sent once whatever it answers; only an own 2xx plus a DELETED read settles it", async () => {
  for (const injected of [reply(500), reply(404), reply(403), "network-error", reply(302)]) {
    const s = await setup({ overrides: [fault("DELETE /versions/", injected)] });
    const result = await go(s);
    assert.equal(result.outcome, "needs-recovery", JSON.stringify(injected));
    assert.equal(s.world.log.filter((call) => call.method === "DELETE").length, 1);
    assert.notEqual(result.delete, "ok");
  }
  // An unknown delete that did take effect still settles nothing in the run.
  const took = await setup({
    overrides: [
      fault("DELETE /versions/", (_call, state) => {
        state.versions.get(`sites/${PROJECT}/versions/${ID}`).status = "DELETED";
        return reply(500);
      }),
    ],
  });
  const result = await go(took);
  assert.deepEqual(result.polls, ["DELETED"]);
  assert.equal(result.listLeft, false);
  assert.equal(result.outcome, "needs-recovery");
  assert.equal(took.world.log.filter((call) => call.method === "DELETE").length, 1);
});

test("a delete that answers 2xx but never reads DELETED, or a list that still shows it, is not settled", async () => {
  const stuck = await setup({
    overrides: [
      {
        match: "GET /versions/[0-9]+$/",
        answer: (() => {
          let n = 0;
          return () =>
            ++n === 1
              ? undefined
              : reply(200, { name: `sites/${PROJECT}/versions/${ID}`, status: "CREATED" });
        })(),
      },
    ],
  });
  const result = await go(stuck);
  assert.equal(result.outcome, "needs-recovery");
  assert.deepEqual(result.polls, ["CREATED", "CREATED", "CREATED", "CREATED", "CREATED"]);
  assert.deepEqual(stuck.sleeps, [10000, 10000, 10000, 10000]);
  const listed = await setup({
    overrides: [
      {
        match: "GET /versions\\?pageSize=100/",
        answer: reply(200, {
          versions: [
            {
              name: `sites/${PROJECT}/versions/${ID}`,
              status: "CREATED",
              labels: { "fireemu-run": RUN },
            },
          ],
        }),
      },
    ],
  });
  assert.equal((await go(listed)).outcome, "needs-recovery");
  const unreadable = await setup({
    overrides: [{ match: "GET /versions\\?pageSize=100/", answer: reply(500) }],
  });
  const unknownList = await go(unreadable);
  assert.equal(unknownList.listLeft, undefined);
  assert.equal(unknownList.outcome, "needs-recovery");
});

test("a 404 poll after the run's own 2xx delete is the normal settlement", async () => {
  const s = await setup({
    overrides: [
      {
        match: "GET /versions/[0-9]+$/",
        answer: (() => {
          let n = 0;
          return () => (++n === 1 ? undefined : reply(404));
        })(),
      },
    ],
  });
  const result = await go(s);
  assert.deepEqual(result.polls, ["404"]);
  assert.equal(result.outcome, "recovery-read-clean");
});

test("admission: only the run's own needs-recovery row, no half-done recovery, two attempts at most", async () => {
  const ledgerText = (rows) => rows.map((row) => JSON.stringify(row)).join("\n");
  assert.ok(
    admitRecovery({ ledgerText: ledgerText([closed, startedRow, failedRow]), run: RUN }).startedAt,
  );
  for (const rows of [
    [closed, startedRow],
    [closed, startedRow, { ...failedRow, event: "cleanup-verified" }],
    [closed, startedRow, { ...failedRow, run: "ffffff" }],
    [closed, startedRow, { ...failedRow, taskId: "other" }],
    [closed, startedRow, failedRow, { ...closed, ts: "2026-11-10T17:00:00Z" }],
  ]) {
    assert.throws(
      () => admitRecovery({ ledgerText: ledgerText(rows), run: RUN }),
      /needs-recovery row/,
    );
  }
  const mine = (event) => ({
    ts: "2026-11-10T16:30:00Z",
    project: PROJECT,
    taskId: RECOVERY_TASK_ID,
    run: RUN,
    event,
  });
  // Recovery rows are not closing and not the last row of the recording task: a started recovery
  // with no result row refuses; a finished one leaves the failed row last only if it came before it.
  assert.throws(
    () =>
      admitRecovery({
        ledgerText: ledgerText([closed, startedRow, failedRow, mine("started")]),
        run: RUN,
      }),
    /needs-recovery row/,
  );
  assert.equal(
    admitRecovery({
      ledgerText: ledgerText([
        closed,
        mine("started"),
        mine("recovery-read"),
        startedRow,
        failedRow,
      ]),
      run: RUN,
    }).attempt,
    2,
  );
  assert.throws(
    () =>
      admitRecovery({
        ledgerText: ledgerText([
          closed,
          mine("started"),
          mine("recovery-read"),
          mine("started"),
          mine("recovery-read"),
          startedRow,
          failedRow,
        ]),
        run: RUN,
      }),
    /exceeds/,
  );
  assert.throws(
    () =>
      admitRecovery({
        ledgerText: ledgerText([closed, mine("started"), startedRow, failedRow]),
        run: RUN,
      }),
    /no result row/,
  );
});

test("arguments are validated and a project number in a returned name is never kept", async () => {
  const s = await setup();
  await assert.rejects(go(s, { run: "zz", versionId: ID }), /six hex/);
  await assert.rejects(go(s, { run: RUN, versionId: "../x" }), /version id/);
  assert.equal(nameFormat(`sites/${PROJECT}/versions/${ID}`, ID, "123456789012"), "site");
  assert.equal(
    nameFormat(`projects/123456789012/sites/${PROJECT}/versions/${ID}`, ID, "123456789012"),
    "project-number",
  );
  assert.equal(
    nameFormat(`projects/999999999999/sites/${PROJECT}/versions/${ID}`, ID, "123456789012"),
    "other",
  );
  const named = await setup({
    overrides: [
      fault(
        "GET /versions/[0-9]+$/",
        reply(200, {
          name: `projects/${secrets.projectNumber}/sites/${PROJECT}/versions/${ID}`,
          status: "CREATED",
          labels: { "fireemu-run": RUN, "fireemu-version": "v01" },
          createTime: "2026-11-10T16:12:57.000Z",
        }),
      ),
    ],
  });
  const result = await go(named);
  assert.equal(result.read.nameFormat, "project-number");
  assert.ok(!JSON.stringify([named.files, named.ledger]).includes(secrets.projectNumber));
  assert.ok(
    isRunsLeftover({
      read: { name: "x" },
      run: RUN,
      versionId: ID,
      window: { startedAt: 0, endedAt: 1 },
      number: "1",
    }).includes("name"),
  );
});
