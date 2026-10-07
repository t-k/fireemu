import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, CAPS, categoryCaps, validatePlan } from "./pubsub-observation-b/plan.mjs";
import { createMeter } from "./pubsub-observation-b/meter.mjs";

test("observation B fixes G3 and separate read-only G7 ceilings", () => {
  const plan = makePlan();
  assert.deepEqual(plan.groups, ["G3", "G7"]);
  assert.deepEqual(CAPS.G3, { requests: 680, rest: 340, grpc: 340, streams: 0, cellMs: 120000 });
  assert.equal(CAPS.sourceRequests, 680);
  assert.equal(CAPS.totalRequests, 694);
  assert.equal(CAPS.sourceWallMs, 2400000);
  assert.equal(CAPS.smallPublishes, 20);
  assert.equal(CAPS.smallEncodedPayloadBytes, 1024);
  assert.equal(CAPS.largePublishes, 0);
  assert.equal(CAPS.framesIn + CAPS.framesOut, 0);
  assert.deepEqual(categoryCaps("G3"), {
    create: 6,
    get: 6,
    publish: 1,
    list: 7,
    cursorDelete: 1,
    cursorGet: 1,
    cleanupDelete: 6,
    cleanupGet: 6,
  });
  assert.equal(
    Object.values(categoryCaps("G3")).reduce((a, b) => a + b, 0),
    34,
  );
  assert.equal(plan.cells.filter((c) => !c.reserve).length, 18);
  assert.equal(plan.cells.filter((c) => c.reserve).length, 2);
  assert.equal(new Set(plan.cells.map((c) => c.id)).size, 20);
  assert.equal(plan.iam, false);
  assert.equal(plan.ackSelector, "NOT_COMPARABLE-until-observed");
  for (const kind of ["topics", "subscriptions", "snapshots"])
    for (const transport of ["rest", "grpc"])
      assert.deepEqual(
        plan.cells
          .filter((c) => !c.reserve && c.kind === kind && c.transport === transport)
          .map((c) => c.permutation),
        ["lexical", "reverse", "rotated"],
      );
  validatePlan(plan);
  const changed = structuredClone(plan);
  changed.caps.G3.requests++;
  assert.throws(() => validatePlan(changed), /fixed/);
});

test("B meter compares generated start histories with an independent vector model", () => {
  const keys = [
    "create",
    "get",
    "publish",
    "list",
    "cursorDelete",
    "cursorGet",
    "cleanupDelete",
    "cleanupGet",
  ];
  const ceilings = [6, 6, 1, 7, 1, 1, 6, 6];
  for (let seed = 1; seed <= 300; seed++) {
    const meter = createMeter({ now: () => 0 });
    const cell = makePlan().cells[seed % 18];
    meter.enter(cell);
    const reference = Object.fromEntries(keys.map((k) => [k, 0]));
    let state = seed;
    for (let step = 0; step < 100; step++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const index = state % keys.length;
      if (reference[keys[index]] === ceilings[index])
        assert.throws(() => meter.start(keys[index], cell.transport), /category/);
      else {
        meter.start(keys[index], cell.transport);
        reference[keys[index]]++;
      }
      assert.deepEqual(meter.snapshot().cell.categories, reference);
      assert.equal(
        meter.snapshot().requests,
        Object.values(reference).reduce((a, b) => a + b, 0),
      );
    }
    assert.throws(() => meter.frame("out", 0), /frame/);
    assert.throws(() => meter.start("list", cell.transport === "rest" ? "grpc" : "rest"));
  }
});

test("B cleanup reserve is inside the cell and expired cells cannot reset the source clock", () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells[0]);
  clock = 80000;
  assert.throws(() => meter.start("list", "rest"), /time/);
  meter.start("cleanupGet", "rest");
  clock = 120000;
  assert.throws(() => meter.enter(makePlan().cells[1]), /time/);
  assert.equal(meter.snapshot().requests, 1);
});

test("B payload and read-only recovery reservations never expand source budgets", () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  assert.throws(() => meter.payload(1025), /payload/);
  meter.payload(1024);
  const recovery = createMeter({ now: () => 0, a2: true });
  recovery.enter({ id: "A2", group: "G7", transport: "rest" });
  for (let i = 0; i < 6; i++) {
    recovery.start("resourceRead", "rest");
    recovery.start("unknownDeleteRead", "rest");
  }
  assert.throws(() => recovery.start("resourceRead", "rest"), /category/);
  assert.throws(() => recovery.start("create", "rest"), /category/);
  assert.equal(recovery.snapshot().requests, 12);
});

const { encodeRequest, typeOf, route } = await import("./pubsub-observation-b/wire.mjs");
test("B native resource operations carry the actual protobuf selector rather than an ignored name", () => {
  for (const kind of ["Topic", "Subscription", "Snapshot"])
    for (const action of ["Get", "Delete"]) {
      const field = kind.toLowerCase(),
        name = `projects/fixture-project/${field}s/fe123456abcdef-x`;
      const raw = encodeRequest(kind === "Topic" ? "Publisher" : "Subscriber", `${action}${kind}`, {
        name,
      });
      assert.equal(typeOf(`${action}${kind}Request`).decode(raw)[field], name);
      assert.ok(raw.length > 0);
    }
});
test("B REST list query and snapshot creation match the recorded route shape", () => {
  for (const [kind, method] of [
    ["topics", "ListTopics"],
    ["subscriptions", "ListSubscriptions"],
    ["snapshots", "ListSnapshots"],
  ]) {
    const pageToken = "opaque+/=é";
    const value = route(method, { project: "projects/fixture-project", pageSize: 1, pageToken });
    const url = new URL(value.url);
    assert.equal(url.pathname, `/v1/projects/fixture-project/${kind}`);
    assert.equal(url.searchParams.get("pageToken"), pageToken);
    assert.equal(url.searchParams.get("pageSize"), "1");
    assert.equal(value.verb, "GET");
    assert.equal(value.body, undefined);
  }
  const name = "projects/fixture-project/snapshots/fe123456abcdef-x",
    subscription = "projects/fixture-project/subscriptions/fe123456abcdef-x";
  assert.deepEqual(route("CreateSnapshot", { name, subscription }), {
    url: `https://pubsub.googleapis.com/v1/${name}`,
    verb: "PUT",
    body: { subscription },
  });
});

const { graph, owned, runCell, recoverA2 } = await import("./pubsub-observation-b/scenarios.mjs");
const { createLedger } = await import("./pubsub-production/ledger.mjs");
test("B resource manifests bind the alternate-prefix sentinel and all exact prerequisites", () => {
  for (const cell of makePlan().cells) {
    const value = graph(cell, "123456abcdef");
    assert.equal(value.members.length, 4);
    assert.equal(value.resources.length, { topics: 4, subscriptions: 5, snapshots: 6 }[cell.kind]);
    assert.equal(new Set(value.resources.map((r) => r.name)).size, value.resources.length);
    for (const name of value.resources.map((r) => r.name)) {
      assert.equal(owned(name, "123456abcdef"), true);
      assert.equal(owned(name + "-foreign", "123456abcdef"), false);
      assert.equal(owned(name, "123456abcdee"), false);
    }
    assert.ok(value.members.at(-1).split("/").at(-1).startsWith("sentinel-"));
    assert.equal(
      value.members.filter((n) => n.split("/").at(-1).startsWith("fe123456abcdef-")).length,
      3,
    );
    const indexes = { lexical: [0, 1, 2], reverse: [2, 1, 0], rotated: [1, 2, 0] }[
      cell.permutation
    ];
    assert.deepEqual(
      value.resources
        .filter((r) => value.members.includes(r.name))
        .slice(0, 3)
        .map((r) => value.members.indexOf(r.name)),
      indexes,
    );
  }
  assert.throws(() => graph({ ...makePlan().cells[0], id: "foreign" }, "123456abcdef"), /declared/);
});

function pageWorld({ unknown, foreign = false, clock = { value: 0 }, slow = false } = {}) {
  const resources = new Map(),
    calls = [],
    rows = [],
    tokens = new Map();
  let tokenCounter = 0;
  return {
    resources,
    calls,
    rows,
    clock,
    async call(c) {
      calls.push(c);
      clock.value += slow
        ? c.method === "CreateTopic"
          ? 37666
          : c.method === "CreateSubscription"
            ? 13024
            : c.method.startsWith("Delete")
              ? 7665
              : 1398
        : 1;
      if (c.method === unknown) return { ok: false, code: "UNKNOWN", unknown: true, body: {} };
      const name = c.request.name;
      if (c.method.startsWith("Create")) {
        const body = { ...c.request };
        resources.set(name, body);
        return { ok: true, code: "OK", body };
      }
      if (c.method.startsWith("Get"))
        return resources.has(name)
          ? { ok: true, code: "OK", body: resources.get(name) }
          : { ok: false, code: "NOT_FOUND", status: 404, body: { error: { status: "NOT_FOUND" } } };
      if (c.method.startsWith("Delete")) {
        resources.delete(name);
        return { ok: true, code: "OK", body: {} };
      }
      if (c.method === "Publish")
        return { ok: true, code: "OK", body: { messageIds: ["own-published"] } };
      if (c.method.startsWith("List")) {
        const kind = {
          ListTopics: "topics",
          ListSubscriptions: "subscriptions",
          ListSnapshots: "snapshots",
        }[c.method];
        const all = [...resources.keys()].filter((n) => n.includes(`/${kind}/`)).sort();
        if (foreign) all.push("projects/fireemu-oracle-idp/" + kind + "/not-owned");
        const token = c.request.pageToken;
        if (token !== undefined && !tokens.has(token))
          return {
            ok: false,
            code: "INVALID_ARGUMENT",
            body: { error: { status: "INVALID_ARGUMENT", message: "bad token" } },
          };
        const after = token ? tokens.get(token) : "",
          available = all.filter((n) => n > after),
          page = available.slice(0, c.request.pageSize);
        const next = page.length < available.length ? `opaque-${++tokenCounter}+/=` : null;
        if (next) tokens.set(next, page.at(-1));
        return {
          ok: true,
          code: "OK",
          body: {
            [kind]: page.map((n) => resources.get(n) ?? { name: n }),
            ...(next ? { nextPageToken: next } : {}),
          },
        };
      }
      throw new Error("unexpected method");
    },
  };
}
async function scenario(cell = makePlan().cells[0], options = {}) {
  const world = pageWorld(options),
    ledger = createLedger(),
    meter = createMeter({ now: () => world.clock.value });
  meter.enter(cell);
  const wire = {
    call: async (c) => {
      meter.start(c.category, c.transport);
      return world.call(c);
    },
  };
  const result = await runCell({
    cell,
    runId: "123456abcdef",
    wire,
    meter,
    ledger,
    journal: { write: (r) => world.rows.push(r) },
  });
  return { ...world, result, ledger, meter };
}
test("B all eighteen baseline cells preserve genuine issued-token causality and complete bounded traversal", async () => {
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    const w = await scenario(cell);
    assert.equal(w.result.complete, true, JSON.stringify(w.result));
    assert.equal(w.result.cleanupClosed, true);
    assert.equal(w.resources.size, 0);
    assert.equal(w.calls.filter((c) => c.method.startsWith("List")).length, 7);
    const pages = w.rows.filter((r) => r.event === "page-observation");
    const first = pages.find((r) => r.stage === "first"),
      next = pages.find((r) => r.stage === "after-delete");
    assert.equal(next.requestToken, first.nextPageToken);
    assert.equal(w.result.deletedCursor, first.names[0]);
    assert.equal(pages.find((r) => r.stage === "baseline").names.length, 4);
    assert.equal(pages.find((r) => r.stage === "ownership-control").projection.length, 2);
    assert.ok(w.calls.length <= 34);
    assert.equal(w.meter.snapshot().framesIn, 0);
  }
});
test("B foreign list members are never adopted or deleted and prevent a complete witness", async () => {
  const w = await scenario(makePlan().cells[0], { foreign: true });
  assert.equal(w.result.complete, false);
  assert.equal(w.result.cleanupClosed, true);
  assert.equal(
    w.calls.some((c) => c.method.startsWith("Delete") && c.request.name.endsWith("not-owned")),
    false,
  );
});
test("B unknown creation remains open through 404 and stops later list requests", async () => {
  const w = await scenario(makePlan().cells[0], { unknown: "CreateTopic" });
  assert.equal(w.result.complete, false);
  assert.equal(w.result.cleanupClosed, false);
  assert.ok(w.ledger.outstanding().some((i) => i.action === "create"));
  assert.equal(
    w.calls.some((c) => c.method.startsWith("Delete") || c.method.startsWith("List")),
    false,
  );
});
test("B recorded maximum create latency consumes the actual cell and preserves cleanup within 120 seconds", async () => {
  const w = await scenario(makePlan().cells[0], { slow: true });
  assert.equal(w.result.complete, false);
  assert.equal(w.calls.filter((c) => c.method === "CreateTopic").length, 1);
  assert.equal(w.result.cleanupClosed, true);
  assert.ok(w.clock.value < 120000);
  assert.equal(w.calls.filter((c) => c.method.startsWith("List")).length, 0);
});
