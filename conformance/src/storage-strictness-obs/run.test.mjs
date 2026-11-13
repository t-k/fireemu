import "../storage-signed-put/test-preload.mjs";
import assert from "node:assert/strict";
import { test } from "node:test";
import { CORS, requests, targetOf } from "./guard.mjs";
import { observe, readback } from "./run.mjs";
import { createWire } from "./wire.mjs";
import { createFakeWorld } from "./world.fake.mjs";
import { settlement } from "./judge.mjs";

const target = targetOf({
  project: "fireemu-oracle-query",
  defaultBucket: "fireemu-oracle-query.firebasestorage.app",
  runId: "ss-0123abcd",
});
async function run(options = {}) {
  const entries = [];
  const world = createFakeWorld(target, options);
  const client = createWire({
    target,
    net: world.net,
    journal: { append: (entry) => entries.push(entry) },
  });
  const sleeps = [];
  const report = await observe({ target, client, sleep: async (ms) => sleeps.push(ms) });
  return { entries, world, client, report, sleeps };
}

test("happy path preserves the complete sequence and deletes every created resource", async () => {
  const { report, world, entries } = await run();
  assert.equal(report.completed, true);
  assert.equal(report.closureReady, true);
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.violations, []);
  assert.equal(world.buckets.has(target.tempBucket), false);
  assert.equal(world.buckets.has(target.missingBucket), false);
  assert.equal(world.objects.size, 0);
  assert.deepEqual(
    world.log.map((r) => r.case),
    [
      "P1",
      "P2",
      "P3",
      "P4",
      "W1",
      "W2",
      "W3",
      "W4",
      ...Array.from({ length: 14 }, (_, i) => `A${i + 1}`),
      ...Array.from({ length: 8 }, (_, i) => `C${i + 1}`),
      "R1",
      "R2",
      "R3",
      "F1",
      "F2",
      "K1",
      "K2",
      "K3",
      "K4",
      "K5",
      "K6",
    ],
  );
  assert.equal(report.requests, 41);
  assert.equal(entries.filter((entry) => entry.phase === "before").length, 41);
  for (const r of world.log.filter((request) => request.method === "OPTIONS"))
    assert.equal(r.headers.authorization, undefined);
  assert.equal(world.log.find((r) => r.case === "F1").headers.authorization, "Firebase not-a-jwt");
});

test("P2 refuses anything except 404 before a write and does not clean up another bucket", async () => {
  for (const status of [200, 403, 409, 302, 503]) {
    const { world, report } = await run({ faults: { P2: { status } } });
    assert.equal(report.completed, false);
    assert.ok(world.log.every((r) => r.method === "GET"));
  }
});

test("local rehearsal skips bucket management and closes after verifying object cleanup", async () => {
  const local = { ...target, local: "http://127.0.0.1:9199" };
  const skipped = ["W1", "R1", "R2", "R3", "R4", "R5", "K3", "K-retry", "K4"];
  for (const f2 of [undefined, { status: 403 }, "transport"]) {
    const entries = [];
    const world = createFakeWorld(local, {
      faults: {
        ...Object.fromEntries(skipped.map((id) => [id, { status: 501 }])),
        W2: {
          status: 200,
          body: Buffer.from(JSON.stringify({ name: local.tempBucket, location: "US" })),
        },
        F2: f2,
      },
    });
    world.buckets.set(local.tempBucket, { name: local.tempBucket, location: "US", cors: CORS });
    const client = createWire({
      target: local,
      net: world.net,
      journal: { append: (entry) => entries.push(entry) },
    });
    const sleeps = [];
    const report = await observe({ target: local, client, sleep: async (ms) => sleeps.push(ms) });
    assert.equal(report.completed, f2 !== "transport");
    assert.equal(report.closureReady, f2 !== "transport");
    assert.equal(report.cleanupVerified, f2 !== "transport");
    assert.deepEqual(report.violations, []);
    assert.deepEqual(report.failures, f2 === "transport" ? ["sequence stopped"] : []);
    assert.deepEqual(sleeps, []);
    assert.deepEqual(world.buckets.get(local.tempBucket).cors, CORS);
    assert.equal(world.objects.size, f2 === "transport" ? 1 : 0);
    assert.equal(
      world.log.some((request) => skipped.includes(request.case)),
      false,
    );
    assert.deepEqual(
      entries.filter((entry) => entry.phase === "skipped"),
      skipped.map((id) => ({
        phase: "skipped",
        case: id,
        reason: "local: fireemu has no bucket management",
      })),
    );
    assert.deepEqual(client.entries, entries);
    assert.deepEqual(
      world.log.map((request) => request.case),
      [
        "P1",
        "P2",
        "P3",
        "P4",
        "W2",
        "W3",
        "W4",
        ...Array.from({ length: 14 }, (_, i) => `A${i + 1}`),
        ...Array.from({ length: 8 }, (_, i) => `C${i + 1}`),
        "F1",
        "F2",
        "K1",
        "K2",
        "K5",
        "K6",
        ...(f2 === undefined ? [] : f2 === "transport" ? ["K8", "K9"] : ["K7", "K8", "K9"]),
      ],
    );
    assert.equal(report.requests, world.log.length);
    assert.equal(entries.filter((entry) => entry.phase === "before").length, world.log.length);
    for (const request of world.log) {
      assert.equal(new URL(request.url).origin, local.local);
      assert.equal(
        request.headers.authorization,
        request.case === "F1" ? "Firebase not-a-jwt" : undefined,
      );
    }
  }
});

test("production sequence still sends bucket management, propagation reads and the cleanup retry", async () => {
  const { world, entries, report, sleeps } = await run({
    faults: {
      R3: { status: 200, headers: { "access-control-allow-origin": "*" } },
      R4: { status: 200, headers: { "access-control-allow-origin": "*" } },
      K3: { status: 409 },
    },
  });
  assert.equal(report.completed, true);
  assert.equal(report.closureReady, true);
  assert.deepEqual(
    entries.filter((entry) => entry.phase === "skipped"),
    [],
  );
  for (const id of ["W1", "R1", "R2", "R3", "R4", "R5", "K3", "K-retry", "K4"])
    assert.equal(world.log.filter((request) => request.case === id).length, 1, id);
  assert.deepEqual(sleeps, [20_000, 20_000]);
});

test("a refused bucket create does not authorize deleting the temporary bucket", async () => {
  const { world, report } = await run({ faults: { W1: { status: 409 } } });
  assert.equal(report.completed, false);
  assert.ok(world.log.every((r) => r.method !== "DELETE"));
});

test("W1 unknown followed only by 404 remains unconfirmed", async () => {
  const { report, world } = await run({ faults: { W1: "transport" } });
  assert.equal(report.closureReady, false);
  assert.equal(report.unresolved[0].reason, "unconfirmed create");
  assert.equal(world.log.filter((r) => r.case === "W1").length, 1);
  assert.ok(world.log.some((r) => r.case === "K-read-bucket"));
});

test("each creating request retains its obligation after an unknown answer and only negative reads", async () => {
  for (const id of ["W1", "W3", "W4", "A4", "A10", "A12", "A6", "A7"]) {
    const { report, world } = await run({ faults: { [id]: { status: 503 } } });
    assert.equal(report.closureReady, false, id);
    assert.ok(
      report.unresolved.some(
        (entry) =>
          entry.resource === requests(target)[id].resource && entry.reason === "unconfirmed create",
      ),
      id,
    );
    assert.equal(world.log.filter((r) => r.case === id).length, 1, id);
  }
});

test("unknown creates can be confirmed by an own positive read before deletion", async () => {
  for (const id of ["W1", "W3", "W4"]) {
    const { report } = await run({ faults: { [id]: "transport" }, applyBeforeFault: [id] });
    assert.equal(report.completed, false, id);
    assert.equal(report.closureReady, true, id);
    assert.deepEqual(report.unresolved, [], id);
  }
});

test("an unexpected 200 at A4 is an owned creation and does not silently pass closure", async () => {
  const { report, world } = await run({ faults: { A4: { status: 200 } } });
  assert.equal(report.completed, true);
  assert.equal(report.closureReady, false);
  assert.ok(report.unresolved.some((entry) => entry.resource.endsWith("/o/x")));
  assert.equal(world.log.filter((r) => r.case === "A4").length, 1);
});

test("a bucket 409 lists only owned objects and retries bucket deletion once", async () => {
  const { report, world } = await run({ faults: { K3: { status: 409 } } });
  assert.equal(report.closureReady, true);
  assert.equal(world.log.filter((r) => r.case === "K-list").length, 1);
  assert.equal(world.log.filter((r) => r.case === "K-retry").length, 1);
});

test("a 409 cleanup list removes only the two planned temporary object names", async () => {
  const key = `/storage/v1/b/${target.tempBucket}/o/y`;
  const { report, world } = await run({
    faults: {
      K3: (_r, state) => {
        state.objects.set(key, { name: "y", bucket: target.tempBucket, size: "4" });
        return { status: 409, headers: {}, body: Buffer.alloc(0) };
      },
    },
  });
  assert.equal(report.closureReady, true);
  assert.ok(world.log.some((r) => r.case === "K-delete-t-y"));
  assert.ok(world.log.some((r) => r.case === "K-verify-t-y"));
});

test("a refused object delete is retried only as part of the single nonempty-bucket cleanup", async () => {
  const { report, world } = await run({ faults: { K1: { status: 403 } } });
  assert.equal(report.closureReady, true);
  assert.ok(world.log.some((r) => r.case === "K-delete-t-cors"));
  assert.equal(world.log.filter((r) => r.case === "K-retry").length, 1);
});

test("F2 unknown is sticky and never resent through the JSON dialect", async () => {
  for (const applyBeforeFault of [[], ["F2"]]) {
    const { report, world } = await run({ faults: { F2: "transport" }, applyBeforeFault });
    assert.equal(report.closureReady, false);
    assert.ok(report.unresolved.some((entry) => entry.reason === "unknown delete"));
    assert.equal(
      world.log.filter((r) => r.method === "DELETE" && r.resource === requests(target).F2.resource)
        .length,
      1,
    );
  }
});

test("a refused F2 is removed only after its own positive cleanup read", async () => {
  const { report, world } = await run({ faults: { F2: { status: 403 } } });
  assert.equal(report.closureReady, true);
  assert.deepEqual(
    world.log.slice(-4).map((r) => r.case),
    ["K6", "K7", "K8", "K9"],
  );
});

test("CORS removal records up to three attempts twenty seconds apart", async () => {
  const { world, sleeps } = await run({
    faults: {
      R3: { status: 200, headers: { "access-control-allow-origin": "*" } },
      R4: { status: 200, headers: { "access-control-allow-origin": "*" } },
    },
  });
  assert.deepEqual(
    world.log.filter((r) => /^R[345]$/.test(r.case)).map((r) => r.case),
    ["R3", "R4", "R5"],
  );
  assert.deepEqual(sleeps, [20_000, 20_000]);
});

test("A2 waits ten minutes, uses only reads, and closes a previously unknown delete", async () => {
  const result = await run({ faults: { F2: "transport" }, applyBeforeFault: ["F2"] });
  const endedAt = Date.now();
  const previous = [
    {
      phase: "header",
      runId: target.runId,
      project: target.project,
      defaultBucket: target.defaultBucket,
    },
    ...result.entries,
    { phase: "summary", endedAt },
  ];
  const entries = [];
  const client = createWire({
    target,
    net: result.world.net,
    journal: { append: (entry) => entries.push(entry) },
  });
  await assert.rejects(
    readback({ target, client, previous, now: () => endedAt + 599_999 }),
    /ten-minute/,
  );
  assert.equal(entries.length, 0);
  const report = await readback({ target, client, previous, now: () => endedAt + 600_000 });
  assert.equal(report.closureReady, true);
  assert.ok(entries.filter((e) => e.phase === "before").every((e) => e.method === "GET"));
  assert.deepEqual(
    entries
      .filter((e) => e.phase === "before")
      .slice(0, 3)
      .map((e) => e.case),
    ["A2-bucket", "A2-prefix", "A2-object"],
  );
});

test("settlement near misses keep unknown creates and deletes open", () => {
  const resource = "resource";
  const event = (action, status, extra = {}) => ({
    phase: "after",
    resource,
    action,
    status,
    ...extra,
  });
  const ready = (...entries) => settlement(entries).closureReady;
  for (const status of [null, 199, 302, 503]) {
    assert.equal(ready(event("create", status), event("read", 404)), false);
    assert.equal(ready(event("create", status), event("read", 404, { session: "a2" })), false);
    assert.equal(
      ready(event("create", status), event("create", 409), event("read", 404, { session: "a2" })),
      false,
    );
    assert.equal(
      ready(
        event("create", status),
        event("create", 200),
        event("delete", 204),
        event("read", 404),
      ),
      false,
    );
    assert.equal(ready(event("create", status), event("delete", 204), event("read", 404)), false);
    assert.equal(
      ready(
        event("create", status),
        event("read", 200, { showsResource: true }),
        event("delete", 204),
        event("read", 404),
      ),
      true,
    );
    assert.equal(
      ready(event("create", status), event("read", 200), event("delete", 204), event("read", 404)),
      false,
    );
    assert.equal(
      ready(
        event("create", 200),
        event("delete", status),
        event("delete", 204),
        event("read", 404),
      ),
      false,
    );
    assert.equal(
      ready(
        event("create", 200),
        event("delete", status),
        event("delete", 409),
        event("read", 404),
      ),
      false,
    );
    assert.equal(
      ready(event("create", 200), event("delete", status), event("read", 404, { session: "a2" })),
      true,
    );
  }
  assert.equal(ready(event("create", 200), event("read", 404)), false);
  assert.equal(ready(event("create", 200), event("read", 404, { session: "a2" })), true);
  assert.equal(ready(event("create", 200), event("delete", 204), event("read", 404)), true);
  assert.equal(ready(event("create", 200), event("read", 404), event("delete", 204)), false);
  assert.equal(
    ready(event("create", 200), event("delete", 204), event("read", 200, { showsResource: true })),
    false,
  );
  assert.equal(
    ready(
      event("create", 200),
      event("delete", 204),
      event("read", 200, { showsResource: true }),
      event("read", 404),
    ),
    false,
  );
  assert.equal(ready(event("create", 409)), true);
  assert.equal(ready(event("read", 200, { showsResource: true })), true);
  assert.equal(ready({ phase: "before", n: 1, resource, action: "create" }), false);
});
