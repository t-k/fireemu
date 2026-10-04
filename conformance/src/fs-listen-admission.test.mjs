import assert from "node:assert/strict";
import { test } from "node:test";

import { MIN_SPACING_MS, checkAdmission, lastRunEnd, lockPathOf } from "./fs-listen/admission.mjs";

const LEDGER = "/runs/sandbox-ledger.jsonl";
const NOW = Date.parse("2026-10-05T12:00:00.000Z");
const minutesAgo = (m) => new Date(NOW - m * 60_000).toISOString();
const row = (project, event, minutes, extra = {}) =>
  JSON.stringify({ ts: minutesAgo(minutes), event, project, ...extra });
const HOLDER = JSON.stringify({ taskId: "FS-LISTEN-SDK", pid: 1, acquiredAt: minutesAgo(1) });

/** Files by path; a missing path is ENOENT. */
function files(map) {
  return {
    readFile: async (path) => {
      if (!Object.hasOwn(map, path)) throw Object.assign(new Error("no file"), { code: "ENOENT" });
      return map[path];
    },
  };
}
const LOCK = lockPathOf(LEDGER, "fireemu-oracle-query");
const admit = (map, project = "fireemu-oracle-query") =>
  checkAdmission({ ledger: LEDGER, project, now: () => NOW, ...files(map) });

test("the lock of a project is a file beside the ledger, named for the project", () => {
  assert.equal(LOCK, "/runs/sandbox-locks/fireemu-oracle-query.lock");
  assert.equal(
    lockPathOf(LEDGER, "fireemu-oracle-txn"),
    "/runs/sandbox-locks/fireemu-oracle-txn.lock",
  );
  assert.throws(() => lockPathOf(LEDGER, "../x"), /is not a project ID/);
  assert.throws(() => lockPathOf(LEDGER, ""), /is not a project ID/);
});

test("a run is admitted when the coordinator holds the project's lock and the last run ended long enough ago", async () => {
  const ledger = [row("fireemu-oracle-query", "finished", 45, { outcome: "recorded" })].join("\n");
  const out = await admit({ [LOCK]: `${HOLDER}\n`, [LEDGER]: `${ledger}\n` });
  assert.equal(out.holder.taskId, "FS-LISTEN-SDK");
  assert.equal(out.lastRunEndAt, minutesAgo(45));
});

test("no lock, an unreadable lock, or an empty one refuses", async () => {
  await assert.rejects(admit({ [LEDGER]: "" }), /is not held/);
  await assert.rejects(admit({ [LOCK]: "not json", [LEDGER]: "" }), /does not name a holder/);
  await assert.rejects(admit({ [LOCK]: "{}", [LEDGER]: "" }), /does not name a holder/);
  await assert.rejects(admit({ [LOCK]: "[]", [LEDGER]: "" }), /does not name a holder/);
  await assert.rejects(
    admit({ [LOCK]: JSON.stringify({ taskId: "" }), [LEDGER]: "" }),
    /does not name a holder/,
  );
});

test("the legacy shared lock refuses too, whoever holds the project lock", async () => {
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [`${LEDGER}.lock`]: "x", [LEDGER]: "" }),
    /legacy shared lock/,
  );
});

test("the last run's end must be at least 30 minutes ago", async () => {
  assert.equal(MIN_SPACING_MS, 30 * 60_000);
  for (const [minutes, ok] of [
    [0, false],
    [29, false],
    [29.99, false],
    [30, true],
    [31, true],
  ]) {
    const ledger = row("fireemu-oracle-query", "finished", minutes, { outcome: "recorded" });
    const promise = admit({ [LOCK]: HOLDER, [LEDGER]: ledger });
    if (ok) await promise;
    else await assert.rejects(promise, /only .* minutes ago/, `${minutes}`);
  }
});

test("cleanup-verified and needs-recovery rows end a run too; another project's rows do not count", async () => {
  for (const event of ["cleanup-verified", "needs-recovery"])
    await assert.rejects(
      admit({ [LOCK]: HOLDER, [LEDGER]: row("fireemu-oracle-query", event, 5) }),
      /only 5 minutes ago/,
    );
  const others = [
    row("fireemu-oracle-txn", "finished", 1),
    row("fireemu-oracle-events", "needs-recovery", 2),
  ].join("\n");
  await admit({ [LOCK]: HOLDER, [LEDGER]: others });
  // The most recent end decides, whatever the order of the lines.
  const mixed = [
    row("fireemu-oracle-query", "finished", 5),
    row("fireemu-oracle-query", "finished", 90),
  ].join("\n");
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: mixed }), /only 5 minutes ago/);
});

test("a run that started and never ended refuses: another run may be live or need recovery", async () => {
  const started = row("fireemu-oracle-query", "started", 120);
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: started }), /started .* and has no end/);
  const ended = [started, row("fireemu-oracle-query", "finished", 100)].join("\n");
  await admit({ [LOCK]: HOLDER, [LEDGER]: ended });
});

test("a read-only stop is exempt from the spacing only when its row says so (ledger 821)", async () => {
  const stop = (extra) =>
    row("fireemu-oracle-query", "finished", 2, { outcome: "stopped-clean", ...extra });
  await admit({ [LOCK]: HOLDER, [LEDGER]: stop({ readOnlyStop: true }) });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: stop({}) }), /only 2 minutes ago/);
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: stop({ readOnlyStop: "yes" }) }),
    /only 2 minutes ago/,
  );
  await assert.rejects(
    admit({
      [LOCK]: HOLDER,
      [LEDGER]: row("fireemu-oracle-query", "finished", 2, {
        outcome: "recorded",
        readOnlyStop: true,
      }),
    }),
    /only 2 minutes ago/,
    "only a stopped-clean run can be a read-only stop",
  );
  await assert.rejects(
    admit({
      [LOCK]: HOLDER,
      [LEDGER]: row("fireemu-oracle-query", "needs-recovery", 2, { readOnlyStop: true }),
    }),
    /only 2 minutes ago/,
  );
});

test("a ledger line that cannot be read but names the project refuses; one that does not is skipped", async () => {
  await assert.rejects(
    admit({ [LOCK]: HOLDER, [LEDGER]: '{"project":"fireemu-oracle-query", broken' }),
    /cannot be read/,
  );
  await admit({ [LOCK]: HOLDER, [LEDGER]: '{"project":"fireemu-oracle-txn", broken\n\n   \n' });
  await assert.rejects(admit({ [LOCK]: HOLDER }), /ledger .* cannot be read/);
});

test("a row without a readable time refuses", async () => {
  const bad = JSON.stringify({
    event: "finished",
    project: "fireemu-oracle-query",
    ts: "yesterday",
  });
  await assert.rejects(admit({ [LOCK]: HOLDER, [LEDGER]: bad }), /no readable time/);
});

test("lastRunEnd reads the latest end and the open start of one project", () => {
  const lines = [
    row("p", "started", 100),
    row("p", "finished", 90),
    row("p", "started", 60),
    row("q", "finished", 1),
  ];
  assert.deepEqual(lastRunEnd(lines.join("\n"), "p"), {
    end: { ts: minutesAgo(90), event: "finished", project: "p" },
    openStart: { ts: minutesAgo(60), event: "started", project: "p" },
  });
  assert.deepEqual(lastRunEnd("", "p"), { end: undefined, openStart: undefined });
});
