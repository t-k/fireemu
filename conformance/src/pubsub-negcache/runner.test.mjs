import assert from "node:assert/strict";
import test from "node:test";

import { CAPS, StopRun } from "./runner.mjs";
import { CELLS } from "./program.mjs";
import { Refusal } from "./requests.mjs";
import { prng, record, RUN_ID } from "./support.mjs";

const empty = (world) => Object.values(world.state).every((m) => m.size === 0);
const requestsOf = (rows) => rows.filter((r) => r.event === "request");

test("a clean recording runs every cell, deletes everything and closes", async () => {
  const { run, world, rows } = record();
  const out = await run();
  assert.equal(out.stopped, null);
  assert.equal(out.records.length, 30);
  assert.ok(out.records.every((r) => r.aborted === null));
  assert.ok(out.closureReady);
  assert.deepEqual(out.open, []);
  assert.ok(empty(world));
  assert.ok(out.sent >= 191 && out.sent <= CAPS.requests, String(out.sent));
  assert.equal(requestsOf(rows).length, out.sent);
});

test("cleanup deletes snapshots before subscriptions before the topic, and reads absence from LISTs", async () => {
  const { run, rows } = record();
  const out = await run();
  const cleanup = requestsOf(rows).filter((r) => r.cell === "cleanup");
  const deletes = cleanup.filter((r) => r.method === "DELETE").map((r) => r.path);
  const rank = (p) => (p.includes("/snapshots/") ? 0 : p.includes("/subscriptions/") ? 1 : 2);
  assert.deepEqual(deletes.map(rank), deletes.map(rank).toSorted());
  assert.equal(out.report.lists, 3);
  assert.equal(out.report.rounds, 1);
});

test("only one request is ever in flight and every start is after the previous completion", async () => {
  let inFlight = 0;
  let maximum = 0;
  const { run, rows } = record({
    wrap: async (base, req, meta) => {
      inFlight += 1;
      maximum = Math.max(maximum, inFlight);
      try {
        return await base(req, meta);
      } finally {
        inFlight -= 1;
      }
    },
  });
  await run();
  assert.equal(maximum, 1);
  const list = requestsOf(rows);
  for (let i = 1; i < list.length; i += 1)
    assert.ok(list[i].startedAt >= list[i - 1].startedAt + list[i - 1].completedMs, String(i));
});

test("the journal rows carry measured timing, the cell and the step", async () => {
  const { run, rows } = record();
  await run();
  const first = requestsOf(rows).find((r) => r.cell === "N2a" && r.step === 0);
  assert.equal(first.method, "GET");
  assert.equal(first.status, 404);
  assert.equal(first.latency, "slow");
  assert.ok(first.headersMs >= 120 && first.completedMs >= first.headersMs);
});

test("a request that starts late is flagged, and the age is the measured one", async () => {
  const { run } = record({
    wrap: async (base, req, meta, clock) => {
      if (req.method === "GET" && req.path.includes("-nc-n2a-x")) await clock.sleep(1000);
      return base(req, meta);
    },
  });
  const out = await run();
  const n2a = out.records.find((r) => r.id === "N2a");
  assert.ok(n2a.steps.some((s) => s.late));
  assert.equal(n2a.steps[0].ageMs, 0);
  assert.ok(n2a.steps.every((s, i) => i === 0 || s.ageMs > 0));
});

test("an unknown create stops the recording, runs the cleanup, and an own positive read settles it", async () => {
  // The create executed in production but its answer was lost.
  const { run, world } = record({ faults: new Map([[4, "timeout"]]) });
  const out = await run();
  assert.equal(out.stopped, "unknown create");
  assert.equal(out.records.length, 1);
  assert.equal(out.report.confirmReads, 1);
  assert.ok(out.closureReady);
  assert.ok(empty(world));
});

test("an unknown create that never shows is not settled by a 404, and its name is reported", async () => {
  // The create never reached production: the cleanup's read answers a (slow) 404, which settles nothing.
  const { run } = record({
    wrap: async (base, req, meta, clock) => {
      if (req.method === "PUT" && req.path.includes("-nc-n2a-x")) {
        const startedAt = clock.now();
        await clock.sleep(19000);
        return { startedAt, failure: "timeout", completedAt: clock.now() };
      }
      return base(req, meta);
    },
  });
  const out = await run();
  assert.equal(out.stopped, "unknown create");
  assert.ok(!out.closureReady);
  assert.deepEqual(
    out.open.map((o) => o.status),
    ["unconfirmed-create"],
  );
  assert.ok(out.open[0].name.endsWith("-nc-n2a-x"));
});

test("a 5xx, a redirect and an unreadable body on a create are unknown too", async () => {
  for (const fault of ["status500", "status302", "garbage"]) {
    const { run } = record({ faults: new Map([[4, fault]]) });
    const out = await run();
    assert.equal(out.stopped, "unknown create", fault);
  }
});

test("an unknown DELETE in the cleanup is never re-sent and keeps the run open", async () => {
  // The first cleanup DELETE (a snapshot) times out.
  let deletes = 0;
  const { run, rows } = record({
    wrap: async (base, req, meta, clock) => {
      if (req.method === "DELETE") {
        deletes += 1;
        if (deletes === 1) {
          const startedAt = clock.now();
          await clock.sleep(13000);
          return { startedAt, failure: "timeout", completedAt: clock.now() };
        }
      }
      return base(req, meta);
    },
  });
  const out = await run();
  const unknown = out.open.filter((o) => o.status === "delete-unknown");
  assert.equal(unknown.length, 1);
  assert.ok(!out.closureReady);
  const attempts = requestsOf(rows).filter(
    (r) => r.method === "DELETE" && r.path.endsWith(unknown[0].name.split("/").pop()),
  );
  // A cell may have deleted the name itself, but the unknown one was attempted exactly once after it.
  assert.equal(attempts.filter((r) => r.kind === "unknown").length, 1);
  assert.equal(attempts.at(-1).kind, "unknown");
});

test("a DELETE answered from an armed entry (404 while the resource exists) is retried after the window", async () => {
  const { run, world, rows } = record({ params: { served: ["getSub", "getSnap", "deleteSub"] } });
  const out = await run();
  const v4 = out.records.find((r) => r.id === "V4");
  assert.equal(v4.steps[2].latency, "fast");
  assert.equal(v4.steps[2].status, 404);
  assert.ok(out.closureReady);
  assert.ok(empty(world));
  const deletes = requestsOf(rows).filter(
    (r) => r.method === "DELETE" && r.path.includes("-nc-v4-x"),
  );
  assert.deepEqual(
    deletes.map((r) => r.status),
    [404, 200],
  );
  assert.deepEqual(
    deletes.map((r) => r.cell),
    ["V4", "cleanup"],
  );
});

test("a resource that keeps answering DELETE 404 is tried three times and then stays open", async () => {
  let n = 0;
  const { run, rows } = record({
    wrap: async (base, req, meta, clock) => {
      if (req.method === "DELETE" && req.path.includes("-nc-n2a-x")) {
        n += 1;
        const startedAt = clock.now();
        await clock.sleep(30);
        return {
          startedAt,
          headersAt: clock.now(),
          completedAt: clock.now(),
          status: 404,
          bodyText: JSON.stringify({ error: { code: 404, message: "m", status: "NOT_FOUND" } }),
        };
      }
      return base(req, meta);
    },
  });
  const out = await run();
  assert.equal(n, 3);
  assert.ok(!out.closureReady);
  assert.deepEqual(
    out.open.map((o) => o.status),
    ["delete-404-present"],
  );
  assert.equal(
    requestsOf(rows).filter((r) => r.path.includes("-nc-n2a-x") && r.method === "DELETE").length,
    3,
  );
});

test("a LIST that is cut off or fails proves no absence", async () => {
  for (const mode of ["token", "error"]) {
    const { run } = record({
      wrap: async (base, req, meta, clock) => {
        if (req.list === "subscription") {
          const startedAt = clock.now();
          await clock.sleep(300);
          const headersAt = clock.now();
          return mode === "error"
            ? { startedAt, headersAt, completedAt: headersAt, status: 500, bodyText: "{}" }
            : {
                startedAt,
                headersAt,
                completedAt: headersAt,
                status: 200,
                bodyText: JSON.stringify({ subscriptions: [], nextPageToken: "more" }),
              };
        }
        return base(req, meta);
      },
    });
    const out = await run();
    assert.ok(!out.closureReady, mode);
    assert.ok(
      out.open.some((o) => o.status === "delete-unread"),
      mode,
    );
  }
});

test("a LIST that still shows a deleted resource makes the cleanup delete it again", async () => {
  let lists = 0;
  const { run, rows } = record({
    wrap: async (base, req, meta) => {
      const out = await base(req, meta);
      // The first subscription LIST belongs to cell V4; the second is the cleanup's.
      if (req.list === "subscription" && ++lists === 2) {
        const body = JSON.parse(out.bodyText);
        body.subscriptions = [
          ...(body.subscriptions ?? []),
          { name: `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${RUN_ID}-nc-n2a-x` },
        ];
        return { ...out, bodyText: JSON.stringify(body) };
      }
      return out;
    },
  });
  const out = await run();
  assert.equal(out.report.rounds, 2);
  assert.ok(
    requestsOf(rows).filter((r) => r.path.includes("-nc-n2a-x") && r.method === "DELETE").length >=
      2,
  );
});

test("the request cap stops the cells and leaves the cleanup its reserve", async () => {
  const { run, world } = record({ caps: { ...CAPS, requests: 100, cleanupRequests: 50 } });
  const out = await run();
  assert.equal(out.stopped, "request cap");
  assert.ok(out.sent <= 100);
  assert.ok(out.closureReady || out.open.length > 0);
  assert.ok(empty(world) || !out.closureReady);
});

test("the wall clock cap stops the cells but not the cleanup of what exists", async () => {
  const { run, world } = record({ caps: { ...CAPS, wallMs: 400000, cleanupReserveMs: 100000 } });
  const out = await run();
  assert.equal(out.stopped, "wall clock cap");
  assert.ok(out.records.length < 30);
  assert.ok(out.closureReady);
  assert.ok(empty(world));
});

test("a refused request (unlisted op) stops the recording and still cleans up", async () => {
  const cells = [
    CELLS[0],
    {
      id: "X9",
      question: "q",
      conn: "dedicated",
      arm: 0,
      steps: [{ op: "dropEverything", target: "X", at: 0 }],
    },
    CELLS[1],
  ];
  const { run, world } = record({ cells });
  const out = await run();
  assert.match(out.stopped, /refused/);
  assert.equal(out.records.length, 2);
  assert.ok(out.closureReady);
  assert.ok(empty(world));
});

test("exec refuses a request whose target is not owned, before anything is sent", async () => {
  const { recorder, world } = record();
  const request = {
    method: "PUT",
    path: "/v1/projects/fireemu-oracle-idp/topics/other",
    body: {},
    targets: ["projects/fireemu-oracle-idp/topics/other"],
    create: true,
  };
  await assert.rejects(() => recorder.exec(request, { cell: "x", step: 0, op: "put" }), Refusal);
  assert.equal(world.log.length, 0);
});

test("exec never re-sends a DELETE after an unknown one", async () => {
  const { recorder, world } = record({
    wrap: async (base, req, meta, clock) => {
      const startedAt = clock.now();
      await clock.sleep(13000);
      return { startedAt, failure: "timeout", completedAt: clock.now() };
    },
  });
  const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${RUN_ID}-nc-a1-x`;
  const request = {
    method: "DELETE",
    path: `/v1/${name}`,
    targets: [name],
    create: false,
    delete: true,
  };
  await recorder.exec(request, { cell: "x", step: 0, op: "delete" });
  await assert.rejects(() => recorder.exec(request, { cell: "x", step: 1, op: "delete" }), Refusal);
  assert.equal(world.log.length, 0);
  assert.ok(StopRun);
});

test("property: with random faults a recording never crashes, stays inside the caps and is honest about closure", async () => {
  const random = prng(2026);
  const kinds = ["timeout", "status500", "status302", "garbage"];
  for (let round = 0; round < 25; round += 1) {
    const faults = new Map();
    for (let i = 1; i <= 260; i += 1)
      if (random() < 0.03) faults.set(i, kinds[Math.floor(random() * 4)]);
    const { run, world, rows } = record({ faults });
    const out = await run();
    assert.ok(out.sent <= CAPS.requests, `round ${round}`);
    if (out.closureReady) assert.ok(empty(world), `round ${round}: closed with a live resource`);
    const unknownDeletes = requestsOf(rows).filter(
      (r) => r.method === "DELETE" && r.kind === "unknown",
    );
    for (const u of unknownDeletes) {
      const later = requestsOf(rows).filter(
        (r) => r.method === "DELETE" && r.path === u.path && r.startedAt > u.startedAt,
      );
      assert.equal(later.length, 0, `round ${round}: unknown delete re-sent`);
    }
  }
});
