import assert from "node:assert/strict";
import test from "node:test";

import { CAPS, StopRun, journaledBody } from "./runner.mjs";
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

test("a LIST answer is journaled with this run's names only and a count of the others", () => {
  const own = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${RUN_ID}-nc-v4-x`;
  const other = "projects/fireemu-oracle-idp/subscriptions/someone-elses";
  const body = { subscriptions: [{ name: own }, { name: other }, { name: other }] };
  assert.deepEqual(journaledBody({ list: "subscription" }, body, RUN_ID), {
    subscriptions: [{ name: own }],
    foreign: 2,
  });
  assert.deepEqual(journaledBody({ list: "subscription" }, {}, RUN_ID), {});
  assert.equal(journaledBody({ method: "GET" }, null, RUN_ID), null);
  assert.deepEqual(journaledBody({ method: "GET" }, { name: "n" }, RUN_ID), { name: "n" });
  assert.equal(journaledBody({ method: "GET" }, { name: "x".repeat(5000) }, RUN_ID), null);
});

test("the cleanup LIST rows in a recording never carry a foreign name", async () => {
  const { run, rows } = record({
    wrap: async (base, req, meta) => {
      const out = await base(req, meta);
      if (!req.list) return out;
      const body = JSON.parse(out.bodyText);
      const key = Object.keys(body)[0] ?? "subscriptions";
      body[key] = [
        ...(body[key] ?? []),
        { name: "projects/fireemu-oracle-idp/subscriptions/not-ours" },
      ];
      return { ...out, bodyText: JSON.stringify(body) };
    },
  });
  await run();
  const lists = requestsOf(rows).filter(
    (r) => r.method === "GET" && r.path.includes("pageSize=100"),
  );
  assert.ok(lists.length >= 4);
  for (const row of lists) assert.ok(!JSON.stringify(row.body).includes("not-ours"));
  assert.ok(lists.every((row) => row.body.foreign >= 1));
});

test("the caps and the per-request timeouts are the stated ones", async () => {
  const { timeoutMs } = await import("./runner.mjs");
  assert.deepEqual(
    { ...CAPS },
    {
      requests: 260,
      cleanupRequests: 50,
      wallMs: 2700000,
      cleanupReserveMs: 300000,
      lateMs: 250,
      cellOverrunMs: 60000,
    },
  );
  assert.equal(timeoutMs({ method: "PUT", path: "/v1/x" }), 19000);
  assert.equal(timeoutMs({ method: "DELETE", path: "/v1/x" }), 13000);
  assert.equal(timeoutMs({ method: "POST", path: "/v1/x:pull" }), 25000);
  assert.equal(timeoutMs({ method: "GET", path: "/v1/x" }), 10000);
  assert.equal(timeoutMs({ method: "POST", path: "/v1/x:seek" }), 10000);
  assert.equal(timeoutMs({ method: "PATCH", path: "/v1/x" }), 10000);
});

test("a body of exactly 4096 characters is journaled and one more is not", () => {
  const pad = (n) => ({ a: "x".repeat(n) });
  assert.equal(JSON.stringify(pad(4088)).length, 4096);
  assert.notEqual(journaledBody({ method: "GET" }, pad(4088), RUN_ID), null);
  assert.equal(journaledBody({ method: "GET" }, pad(4089), RUN_ID), null);
});

test("connection keys: dedicated per cell, fresh per request, pool for the cleanup", async () => {
  const seen = [];
  const { run } = record({
    wrap: async (base, req, meta) => {
      seen.push({ path: req.path, ...meta });
      return base(req, meta);
    },
  });
  await run();
  const of = (id) => seen.filter((s) => s.path.includes(`-nc-${id}-`) && s.conn !== "pool:cleanup");
  assert.ok(of("n2a").every((s) => s.conn === "dedicated:N2a" && s.connPolicy === "dedicated"));
  const fresh = of("n2b");
  assert.ok(fresh.every((s) => s.connPolicy === "fresh" && /^fresh:\d+$/.test(s.conn)));
  assert.equal(new Set(fresh.map((s) => s.conn)).size, fresh.length);
  assert.ok(seen.at(-1).conn === "pool:cleanup" && seen.at(-1).connPolicy === "pool");
  assert.ok(seen.slice(0, 2).every((s) => s.conn === "pool:setup"));
});

test("the answer decides what the ledger learns: 404, 409 and other errors of a create", async () => {
  const statusFor = { 404: "never-created", 409: "unconfirmed-create", 400: "never-created" };
  for (const [status, expected] of Object.entries(statusFor)) {
    const { recorder } = record({
      wrap: async (base, req, meta, clock) => {
        const startedAt = clock.now();
        await clock.sleep(300);
        const code = { 404: "NOT_FOUND", 409: "ALREADY_EXISTS", 400: "INVALID_ARGUMENT" }[status];
        return {
          startedAt,
          headersAt: clock.now(),
          completedAt: clock.now(),
          status: Number(status),
          bodyText: JSON.stringify({ error: { code: Number(status), message: "m", status: code } }),
        };
      },
    });
    const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${RUN_ID}-nc-a1-x`;
    await recorder.exec(
      { method: "PUT", path: `/v1/${name}`, body: { topic: "t" }, targets: [name], create: true },
      { cell: "a1", step: 0, op: "putSub" },
    );
    assert.equal(recorder.ledger.status(name), expected, status);
  }
});

test("own reads feed the ledger: a slow 404 shows absence, a fast 404 does not, a 200 shows presence", async () => {
  const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${RUN_ID}-nc-a1-x`;
  const get = { method: "GET", path: `/v1/${name}`, targets: [] };
  const reply = (status, ms, bodyText) => async (base, req, meta, clock) => {
    const startedAt = clock.now();
    await clock.sleep(ms);
    return { startedAt, headersAt: clock.now(), completedAt: clock.now(), status, bodyText };
  };
  const nf = JSON.stringify({ error: { code: 404, message: "m", status: "NOT_FOUND" } });
  const probe = async (wrap, expected) => {
    const { recorder } = record({ wrap });
    const id = recorder.ledger.intent({ name, action: "create", kind: "subscription" });
    recorder.ledger.answer(id, "ok");
    await recorder.exec(get, { cell: "a1", step: 0, op: "getSub" });
    assert.equal(recorder.ledger.status(name), expected);
  };
  await probe(reply(404, 300, nf), "live-suspect");
  await probe(reply(404, 20, nf), "live");
  await probe(reply(200, 300, "{}"), "live");
  await probe(reply(500, 300, "{}"), "live");
  await probe(
    reply(
      409,
      300,
      JSON.stringify({ error: { code: 409, message: "m", status: "ALREADY_EXISTS" } }),
    ),
    "live",
  );
  // A LIST or a verb URL is not a read of the resource.
  const { recorder } = record({ wrap: reply(404, 300, nf) });
  const id = recorder.ledger.intent({ name, action: "create", kind: "subscription" });
  recorder.ledger.answer(id, "ok");
  await recorder.exec(
    { method: "GET", path: `/v1/${name}:getIamPolicy`, targets: [] },
    { cell: "a1", step: 0, op: "getIamSub" },
  );
  await recorder.exec(
    {
      method: "GET",
      path: "/v1/projects/fireemu-oracle-idp/subscriptions?pageSize=100",
      targets: [],
      list: "subscription",
    },
    { cell: "a1", step: 1, op: "listSub" },
  );
  assert.equal(recorder.ledger.status(name), "live");
});

test("rows carry null for what was not measured", async () => {
  const { recorder, rows } = record({
    wrap: async (base, req, meta, clock) => {
      const startedAt = clock.now();
      await clock.sleep(5);
      return { startedAt, completedAt: clock.now(), failure: "timeout" };
    },
  });
  const request = {
    method: "GET",
    path: "/v1/projects/fireemu-oracle-idp/subscriptions/x",
    targets: [],
  };
  await recorder.exec(request, { cell: "z", step: 0, op: "getSub" });
  const failed = rows.at(-1);
  assert.equal(failed.headersMs, null);
  assert.equal(failed.completedMs, 5);
  assert.equal(failed.failure, "timeout");
  assert.equal(failed.status, null);
  const ok = record();
  await ok.recorder.exec(request, { cell: "z", step: 0, op: "getSub" });
  assert.equal(ok.rows.at(-1).failure, null);
  const noCompletion = record({
    wrap: async (base, req, meta, clock) => ({ startedAt: clock.now(), failure: "x" }),
  });
  await noCompletion.recorder.exec(request, { cell: "z", step: 0, op: "getSub" });
  assert.equal(noCompletion.rows.at(-1).completedMs, null);
});

test("a step starts no earlier than the previous completion plus the minimum gap, and lateness is exact at 250 ms", async () => {
  const cells = [
    {
      id: "G1",
      question: "q",
      conn: "dedicated",
      arm: 5,
      steps: [
        { op: "getSub", target: "X", at: 0 },
        { op: "getSub", target: "X", at: 0 },
        { op: "getSub", target: "X", at: 0 },
      ],
    },
  ];
  const delays = [0, 0, 250];
  let calls = 0;
  const { run, rows } = record({
    cells,
    wrap: async (base, req, meta, clock) => {
      if (req.path.includes("-nc-g1-")) await clock.sleep(delays[calls++] ?? 0);
      return base(req, meta);
    },
  });
  const out = await run();
  const g1 = out.records[0];
  const list = rows.filter((r) => r.event === "request" && r.cell === "G1");
  for (let i = 1; i < list.length; i += 1)
    assert.ok(list[i].startedAt >= list[i - 1].startedAt + list[i - 1].completedMs + 50);
  assert.deepEqual(
    g1.steps.map((s) => s.late),
    [false, false, false],
  );
  assert.equal(g1.steps[0].ageMs, null, "the arm step was never executed");
  const { run: run2 } = record({
    cells,
    wrap: async (base, req, meta, clock) => {
      if (req.path.includes("-nc-g1-")) await clock.sleep(251);
      return base(req, meta);
    },
  });
  assert.ok((await run2()).records[0].steps.slice(1).every((s) => s.late));
});

test("a cell that hits the request cap says so, with exactly the cap's worth of cell requests", async () => {
  const { run, rows } = record({ caps: { ...CAPS, requests: 60, cleanupRequests: 10 } });
  const out = await run();
  assert.equal(out.stopped, "request cap");
  assert.equal(out.records.at(-1).aborted, "request cap");
  assert.equal(rows.filter((r) => r.event === "request" && r.cell !== "cleanup").length, 50);
});

test("a stop at setup is reported, not thrown", async () => {
  const { run } = record({ caps: { ...CAPS, requests: 100, cleanupRequests: 100 } });
  const out = await run();
  assert.equal(out.stopped, "request cap");
  assert.equal(out.records.length, 0);
});

test("the cleanup waits exactly the quiet time and ends when its last LIST ends", async () => {
  const { run, rows, clock } = record();
  const out = await run();
  const requests = rows.filter((r) => r.event === "request");
  const lastCell = requests.filter((r) => r.cell !== "cleanup").at(-1);
  const firstCleanup = requests.find((r) => r.cell === "cleanup");
  assert.equal(firstCleanup.startedAt - (lastCell.startedAt + lastCell.completedMs), 12000);
  const last = requests.at(-1);
  assert.equal(clock.now(), last.startedAt + last.completedMs);
  assert.equal(out.report.rounds, 1);
});

test("a second round waits 30 s after the quiet time and keeps listing a resource whose DELETE answers 404", async () => {
  let lists = 0;
  const { run, rows } = record({
    wrap: async (base, req, meta) => {
      const out = await base(req, meta);
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
  const cleanup = rows.filter((r) => r.event === "request" && r.cell === "cleanup");
  const firstList = cleanup.find((r) => r.path.includes("/subscriptions?pageSize"));
  const secondDelete = cleanup.filter((r) => r.method === "DELETE")[0];
  assert.ok(secondDelete);
  const redo = cleanup.filter((r) => r.method === "DELETE" && r.path.includes("-nc-n2a-x"))[1];
  assert.ok(
    redo.startedAt - cleanup.filter((r) => r.path.includes("pageSize")).at(-4).startedAt >= 30000 ||
      redo.startedAt > firstList.startedAt,
  );
});

test("a LIST is followed for exactly five pages", async () => {
  const { run, rows } = record({
    wrap: async (base, req, meta, clock) => {
      if (req.list === "subscription") {
        const startedAt = clock.now();
        await clock.sleep(300);
        return {
          startedAt,
          headersAt: clock.now(),
          completedAt: clock.now(),
          status: 200,
          bodyText: JSON.stringify({ subscriptions: [], nextPageToken: "more" }),
        };
      }
      return base(req, meta);
    },
  });
  const out = await run();
  const cleanupLists = rows.filter(
    (r) =>
      r.event === "request" && r.cell === "cleanup" && r.path.includes("/subscriptions?pageSize"),
  );
  assert.equal(cleanupLists.length, 5);
  assert.equal(out.report.lists, 7);
});

test("a DELETE 404 that never clears is listed again in every round", async () => {
  const { run } = record({
    wrap: async (base, req, meta, clock) => {
      if (req.method === "DELETE" && req.path.includes("-nc-n2a-x")) {
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
  assert.equal(out.report.rounds, 3);
  assert.equal(out.report.lists, 5);
});

test("cleanup records a refused request and goes on", async () => {
  const { cleanup } = await import("./cleanup.mjs");
  const { createLedger } = await import("./ledger.mjs");
  const ledger = createLedger();
  const name = `projects/fireemu-oracle-idp/subscriptions/fireemu-observe-${RUN_ID}-nc-a1-x`;
  ledger.answer(ledger.intent({ name, action: "create", kind: "subscription" }), "ok");
  const calls = [];
  const exec = async (request) => {
    calls.push(request.method);
    throw new Refusal("not allowed");
  };
  const clock = { now: () => 1000, sleepUntil: async () => {} };
  const report = await cleanup({
    ledger,
    exec,
    clock,
    runId: RUN_ID,
    lastActivityAt: () => 0,
    journal: { write() {} },
  });
  assert.deepEqual(report.refused.slice(0, 1), ["not allowed"]);
  assert.ok(calls.length >= 1);
  assert.equal(report.rounds, 3);
});

test("the second round starts exactly 30 s after the first round's last LIST, and a persistent 404 adds no wait after round three", async () => {
  let lists = 0;
  const { run, rows, clock } = record({
    wrap: async (base, req, meta) => {
      const out = await base(req, meta);
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
  await run();
  const cleanup = rows.filter((r) => r.event === "request" && r.cell === "cleanup");
  const firstDeleteIndex = cleanup.findIndex((r) => r.method === "DELETE");
  const roundOneEnd = cleanup.findLastIndex(
    (r, i) =>
      i > firstDeleteIndex &&
      r.method === "GET" &&
      r.path.includes("pageSize") &&
      cleanup[i + 1]?.method === "DELETE",
  );
  const redo = cleanup[roundOneEnd + 1];
  assert.equal(
    redo.startedAt - (cleanup[roundOneEnd].startedAt + cleanup[roundOneEnd].completedMs),
    30000,
  );
  assert.ok(clock.now() > 0);
});

test("with a DELETE 404 that never clears the run ends when its last LIST ends", async () => {
  const { run, rows, clock } = record({
    wrap: async (base, req, meta, clk) => {
      if (req.method === "DELETE" && req.path.includes("-nc-n2a-x")) {
        const startedAt = clk.now();
        await clk.sleep(30);
        return {
          startedAt,
          headersAt: clk.now(),
          completedAt: clk.now(),
          status: 404,
          bodyText: JSON.stringify({ error: { code: 404, message: "m", status: "NOT_FOUND" } }),
        };
      }
      return base(req, meta);
    },
  });
  await run();
  const last = rows.filter((r) => r.event === "request").at(-1);
  assert.equal(clock.now(), last.startedAt + last.completedMs);
});

test("a wall clock that is exactly used up stops the recording", async () => {
  const { run } = record({
    caps: { ...CAPS, wallMs: 1000, cleanupReserveMs: 0 },
    wrap: async (base, req, meta, clock) => {
      await clock.sleep(1000);
      return base(req, meta);
    },
  });
  const out = await run();
  assert.equal(out.stopped, "wall clock cap");
  assert.equal(out.sent, 1);
});
