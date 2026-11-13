import "../storage-signed-put/test-preload.mjs";
import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CORS, requests, targetOf, SEND_FLAG } from "./guard.mjs";
import { main, observe, readback } from "./run.mjs";
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

test("readback refuses each mismatched journal identity before sending", async () => {
  const endedAt = 1_000_000;
  const header = {
    phase: "header",
    runId: target.runId,
    project: target.project,
    defaultBucket: target.defaultBucket,
  };
  const summary = { phase: "summary", endedAt };
  const world = createFakeWorld(target);
  const client = createWire({ target, net: world.net, journal: { append() {} } });
  for (const previous of [
    [{ ...header, phase: "other" }, summary],
    [{ ...header, runId: "other" }, summary],
    [{ ...header, project: "other" }, summary],
    [{ ...header, defaultBucket: "other" }, summary],
    [header, { ...summary, phase: "other" }],
    [header, { ...summary, endedAt: null }],
  ])
    await assert.rejects(
      readback({ target, client, previous, now: () => endedAt + 600_000 }),
      /matching completed journal/,
    );
  assert.equal(client.budget.count, 0);
});

test("preflight list rejects each incomplete or unexpected layout", async () => {
  for (const body of [
    "null",
    "[]",
    "invalid",
    JSON.stringify({ kind: "other" }),
    JSON.stringify({ items: [{}] }),
    JSON.stringify({ items: {} }),
    JSON.stringify({ prefixes: ["x"] }),
    JSON.stringify({ prefixes: {} }),
    JSON.stringify({ nextPageToken: "more" }),
    JSON.stringify({ unexpected: true }),
  ]) {
    const { report, world } = await run({
      faults: { P4: { status: 200, body: Buffer.from(body) } },
    });
    assert.equal(report.completed, false, body);
    assert.equal(report.cleanupVerified, false, body);
    assert.ok(
      world.log.every((request) => request.method === "GET"),
      body,
    );
  }
});

test("cleanup verification fails for each missing or unknown final read", async () => {
  for (const id of ["K2", "K4", "K5", "K6"]) {
    for (const fault of [{ status: 503 }, { status: 403 }]) {
      const { report } = await run({ faults: { [id]: fault } });
      assert.equal(report.cleanupVerified, false, id);
      assert.equal(report.closureReady, false, id);
    }
  }
});

test("main selects fake mode and rejects invalid mode arguments and credential overrides", async () => {
  const directory = mkdtempSync(join(tmpdir(), "strictness-main-"));
  const args = [
    "--project",
    target.project,
    "--default-bucket",
    target.defaultBucket,
    "--out",
    join(directory, "fake"),
  ];
  const oldFlag = process.env[SEND_FLAG];
  const oldCredentials = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const originalLog = console.log;
  try {
    delete process.env[SEND_FLAG];
    console.log = () => {};
    assert.equal(await main(args), 0);
    const header = JSON.parse(
      readFileSync(join(directory, "fake", "journal.jsonl"), "utf8").split("\n")[0],
    );
    assert.equal(header.mode, "fake");
    await assert.rejects(
      main([...args, "--local", "http://localhost:9199", "--send"]),
      /invalid arguments/,
    );
    await assert.rejects(main([...args, "--run-id", target.runId]), /invalid arguments/);
    await assert.rejects(main(["readback", ...args]), /invalid arguments/);
    await assert.rejects(main(["unexpected", ...args]), /invalid arguments/);
    process.env[SEND_FLAG] = "launch-script";
    process.env.GOOGLE_APPLICATION_CREDENTIALS = "synthetic";
    const productionArgs = [
      "--project",
      target.project,
      "--default-bucket",
      target.defaultBucket,
      "--out",
      join(directory, "refused"),
      "--send",
    ];
    await assert.rejects(main(productionArgs), /credential overrides refused/);
  } finally {
    console.log = originalLog;
    if (oldFlag === undefined) delete process.env[SEND_FLAG];
    else process.env[SEND_FLAG] = oldFlag;
    if (oldCredentials === undefined) delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    else process.env.GOOGLE_APPLICATION_CREDENTIALS = oldCredentials;
    rmSync(directory, { recursive: true, force: true });
  }
});

test("bucket cleanup refuses incomplete and unplanned listings", async () => {
  for (const [body, failure] of [
    [JSON.stringify({ nextPageToken: "more", items: [] }), "temporary bucket list not complete"],
    [JSON.stringify({ items: {} }), "temporary bucket list not complete"],
    [JSON.stringify({ items: [{ name: "outside" }] }), "unplanned object in temporary bucket"],
  ]) {
    const { report, world } = await run({
      faults: { K3: { status: 409 }, "K-list": { status: 200, body: Buffer.from(body) } },
    });
    assert.ok(report.failures.includes(failure), body);
    assert.equal(
      world.log.some(
        (request) => request.method === "DELETE" && request.resource?.endsWith("/o/outside"),
      ),
      false,
    );
  }
});

test("--send without the launch-script flag is refused before any file or request, never run against the fake world", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ss-send-flag-"));
  const saved = process.env[SEND_FLAG];
  try {
    for (const value of [undefined, "", "launch", "LAUNCH-SCRIPT"]) {
      if (value === undefined) delete process.env[SEND_FLAG];
      else process.env[SEND_FLAG] = value;
      const out = join(dir, `out-${String(value)}`);
      await assert.rejects(
        main([
          "--send",
          "--project",
          "fireemu-oracle-query",
          "--default-bucket",
          "fireemu-oracle-query.firebasestorage.app",
          "--out",
          out,
        ]),
        /production send flag required/,
      );
      assert.throws(() => readFileSync(join(out, "journal.jsonl")), /ENOENT/);
    }
  } finally {
    if (saved === undefined) delete process.env[SEND_FLAG];
    else process.env[SEND_FLAG] = saved;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("preconditions reject independently invalid metadata and CORS answers", async () => {
  for (const [id, fault] of [
    ["P1", { status: 403, body: Buffer.from('{"location":"US"}') }],
    ["P1", { status: 200, body: Buffer.from("{}") }],
    ["W2", { status: 403, body: Buffer.from(JSON.stringify({ cors: CORS })) }],
    ["W2", { status: 200, body: Buffer.from("{}") }],
    ["R2", { status: 403, body: Buffer.from("{}") }],
    ["R2", { status: 200, body: Buffer.from("invalid") }],
    ["R2", { status: 200, body: Buffer.from('{"cors":[]}') }],
  ]) {
    const { report } = await run({ faults: { [id]: fault } });
    assert.equal(report.completed, false, id);
    assert.ok(report.violations.includes(id), id);
  }
});

test("readback requires every absent response and an empty prefix listing", async () => {
  const endedAt = 1_000_000;
  const previous = [
    {
      phase: "header",
      runId: target.runId,
      project: target.project,
      defaultBucket: target.defaultBucket,
    },
    { phase: "summary", endedAt },
  ];
  for (const id of [
    "A2-bucket",
    "A2-prefix",
    "A2-object",
    "A2-cors",
    "A2-t-y",
    "A2-m-x",
    "A2-m-y",
  ]) {
    for (const fault of id === "A2-prefix"
      ? [{ status: 200, body: Buffer.from('{"items":[{}]}') }, { status: 503 }]
      : [{ status: 200 }, { status: 503 }]) {
      const world = createFakeWorld(target, { faults: { [id]: fault } });
      const client = createWire({ target, net: world.net, journal: { append() {} } });
      const result = await readback({ target, client, previous, now: () => endedAt + 600_000 });
      assert.equal(result.readbackVerified, false, id);
      assert.equal(result.closureReady, false, id);
    }
  }
});

test("cleanup does not delete a bucket whose creation was refused", async () => {
  const { report, world } = await run({ faults: { W1: { status: 409 } } });
  assert.equal(report.completed, false);
  assert.equal(
    world.log.some((request) => ["K1", "K3", "K-retry"].includes(request.case)),
    false,
  );
});
