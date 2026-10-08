import assert from "node:assert/strict";
import test from "node:test";
import {
  makePlan,
  CAPS,
  categoryCaps,
  validatePlan,
  minimumCallMs,
} from "./pubsub-observation-b/plan.mjs";
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
  assert.throws(() => meter.enter(makePlan().cells[0]), /reopen/);
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

const { graph, owned, runCell, recoverA2, parsePage } =
  await import("./pubsub-observation-b/scenarios.mjs");
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
        assert.equal(typeof c.request.name, "string");
        if (c.method === "CreateSubscription") assert.ok(resources.has(c.request.topic));
        if (c.method === "CreateSnapshot") assert.ok(resources.has(c.request.subscription));
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

const { verifyPriorPacket, scopeDigest, verifyScope, SOURCE_FILES } =
  await import("./pubsub-observation-b/admission.mjs");
const { sha256 } = await import("./pubsub-production/admission.mjs");
function priorProof() {
  const summaries = {};
  const value = {
    reviewed: true,
    suite: "pubsub-observation-a-v1",
    sourceHead: "a".repeat(40),
    envelopeId: "PUBSUB-OBSERVATION-A-FIXED",
    packetSha256: "b".repeat(64),
    runIds: ["123456abcdef", "abcdef123456"],
    summaries: [],
  };
  for (const runId of value.runIds) {
    const summary = {
      suite: value.suite,
      project: "fireemu-oracle-idp",
      runId,
      sourceHead: value.sourceHead,
      envelopeId: value.envelopeId,
      packetSha256: value.packetSha256,
      resourcesClosed: true,
      recordingComplete: true,
      a2: false,
    };
    const path = `/fixture/previous/${runId}/summary-${runId}.json`;
    const bytes = Buffer.from(JSON.stringify(summary));
    summaries[path] = bytes;
    value.summaries.push({ runId, path, sha256: sha256(bytes) });
  }
  return { value, summaries };
}
test("B prior-packet proof requires two genuine complete closed A source recordings", () => {
  const { value, summaries } = priorProof();
  verifyPriorPacket(value, (p) => summaries[p]);
  for (const change of [
    (v) => (v.reviewed = false),
    (v) => v.summaries.pop(),
    (v) => (v.runIds[1] = v.runIds[0]),
    (v) => (v.suite = "other"),
    (v) => (v.summaries[0].sha256 = "c".repeat(64)),
  ]) {
    const changed = structuredClone(value);
    change(changed);
    assert.throws(() => verifyPriorPacket(changed, (p) => summaries[p]));
  }
  for (const field of ["resourcesClosed", "recordingComplete", "a2"]) {
    const altered = { ...summaries };
    const path = value.summaries[0].path;
    const summary = JSON.parse(altered[path]);
    summary[field] = !summary[field];
    altered[path] = Buffer.from(JSON.stringify(summary));
    const proof = structuredClone(value);
    proof.summaries[0].sha256 = sha256(altered[path]);
    assert.throws(() => verifyPriorPacket(proof, (p) => altered[p]));
  }
  assert.throws(() => verifyPriorPacket(null), /prior/);
});
test("B new E/V scope binds previous packet, source pins and exact recording identities", () => {
  const { value } = priorProof();
  const scope = {
    taskId: "PUBSUB-OBSERVATION-B",
    suite: "pubsub-observation-b-v1",
    project: "fireemu-oracle-idp",
    envelopeId: "PUBSUB-OBSERVATION-B-FIXED",
    sourceHead: "d".repeat(40),
    descriptorSha256: "e".repeat(64),
    packetSha256: "f".repeat(64),
    expiresAt: "2026-10-10T00:00:00Z",
    runIds: ["012345abcdef", "abcdef012345"],
    runOutputs: { "012345abcdef": "/fixture/b-first", abcdef012345: "/fixture/b-second" },
    recoveryOutputs: {
      "012345abcdef": "/fixture/b-first-a2",
      abcdef012345: "/fixture/b-second-a2",
    },
    plan: makePlan(),
    priorPacket: value,
  };
  verifyScope(
    scope,
    { head: scope.sourceHead },
    scope.descriptorSha256,
    { runId: scope.runIds[0], out: scope.runOutputs[scope.runIds[0]] },
    Date.parse("2026-10-07T00:00:00Z"),
  );
  const changed = structuredClone(scope);
  changed.priorPacket.packetSha256 = "1".repeat(64);
  assert.notEqual(scopeDigest({ ...scope, kind: "V" }), scopeDigest({ ...changed, kind: "V" }));
  assert.ok(SOURCE_FILES.includes("conformance/src/pubsub-observation-b/wire.mjs"));
  assert.ok(SOURCE_FILES.includes("conformance/src/pubsub-observation/metadata.mjs"));
});

test("B A2 preserves unknown creates, sticky deletes and confirmed-create absence contracts", async () => {
  const name = graph(makePlan().cells[0], "123456abcdef").members[0];
  const missing = {
    ok: false,
    code: "NOT_FOUND",
    status: 404,
    body: { error: { status: "NOT_FOUND" } },
  };
  for (const shape of ["unknown-create", "confirmed-create", "unknown-delete"]) {
    const ledger = createLedger();
    const create = {
      name,
      action: "create",
      transport: "rest",
      requestId: ledger.sent({ name, action: "create", transport: "rest" }),
    };
    ledger.answered({ ...create, kind: shape === "unknown-create" ? "unknown" : "ok" });
    if (shape === "unknown-delete") {
      const del = {
        name,
        action: "delete",
        transport: "rest",
        requestId: ledger.sent({ name, action: "delete", transport: "rest" }),
      };
      ledger.answered({ ...del, kind: "unknown" });
    }
    assert.equal(ledger.settleAbsent(name, missing), false);
    const meter = createMeter({ now: () => 0, a2: true });
    meter.enter({ id: "A2", group: "G7", transport: "rest" });
    const calls = [];
    const wire = {
      call: async (c) => {
        meter.start(c.category, c.transport);
        calls.push(c);
        return missing;
      },
    };
    await assert.rejects(
      recoverA2({ wire, ledger, runId: "123456abcdef", elapsedMs: 599999, meter }),
      /age/,
    );
    const result = await recoverA2({
      wire,
      ledger,
      runId: "123456abcdef",
      elapsedMs: 600000,
      meter,
    });
    assert.equal(result.closed, shape !== "unknown-create");
    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].category,
      shape === "unknown-delete" ? "unknownDeleteRead" : "resourceRead",
    );
    assert.ok(calls.every((c) => c.method.startsWith("Get")));
  }
});
test("B recovery refuses prefix near misses and includes the exact alternate-prefix sentinel", async () => {
  const name = graph(makePlan().cells[0], "123456abcdef").members[3];
  for (const candidate of [name, name + "-other"]) {
    const ledger = createLedger();
    ledger.sent({ name: candidate, action: "create", transport: "rest" });
    let reads = 0;
    const call = () => {
      reads++;
      return { ok: true, code: "OK", body: { name: candidate } };
    };
    if (candidate === name) {
      const value = await recoverA2({
        wire: { call },
        ledger,
        runId: "123456abcdef",
        elapsedMs: 600000,
      });
      assert.equal(value.closed, false);
      assert.equal(reads, 1);
    } else {
      await assert.rejects(
        recoverA2({ wire: { call }, ledger, runId: "123456abcdef", elapsedMs: 600000 }),
        /foreign/,
      );
      assert.equal(reads, 0);
    }
  }
});

const { createWire, readResponse } = await import("./pubsub-observation-b/wire.mjs");
const { SERVICES } = await import("./pubsub-production/grpc.mjs");
const { EventEmitter } = await import("node:events");
test("B actual REST and protobuf adapters execute all resource graphs and count physical response bytes", async () => {
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    const world = pageWorld(),
      meter = createMeter({ now: () => world.clock.value });
    meter.enter(cell);
    const rows = [];
    let active;
    const native = {
      close() {},
      makeUnaryRequest(path, _enc, _dec, raw, _metadata, _options, callback) {
        const method = path.split("/").at(-1),
          service = path.includes("Publisher") ? "Publisher" : "Subscriber",
          definition = SERVICES[service].methods[method];
        const decoded = typeOf(definition[0]).toObject(typeOf(definition[0]).decode(raw), {
          longs: String,
          bytes: String,
          enums: String,
          defaults: false,
        });
        const field = {
          GetTopic: "topic",
          DeleteTopic: "topic",
          GetSubscription: "subscription",
          DeleteSubscription: "subscription",
          GetSnapshot: "snapshot",
          DeleteSnapshot: "snapshot",
        }[method];
        const request = field ? { name: decoded[field] } : decoded;
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(async () => {
          const reply = await world.call({ ...active, request });
          if (reply.ok) {
            const encoded = Buffer.from(
              typeOf(definition[1]).encode(typeOf(definition[1]).fromObject(reply.body)).finish(),
            );
            callback(null, encoded);
            rpc.emit("status", {
              code: 0,
              details: "",
              metadata: { getMap: () => ({}), get: () => [] },
            });
          } else {
            const code = reply.code === "NOT_FOUND" ? 5 : 3;
            callback({ code, details: reply.body.error.message ?? reply.code });
            rpc.emit("status", {
              code,
              details: reply.code,
              metadata: { getMap: () => ({}), get: () => [] },
            });
          }
        });
        return rpc;
      },
    };
    const fetch = async (url, options) => {
      const value = new URL(url),
        parts = value.pathname.slice(4).split("/"),
        name = parts.map(decodeURIComponent).join("/");
      let request;
      if (active.method.startsWith("List"))
        request = {
          project: parts.slice(0, 2).join("/"),
          pageSize: Number(value.searchParams.get("pageSize")),
          ...(value.searchParams.has("pageToken")
            ? { pageToken: value.searchParams.get("pageToken") }
            : {}),
        };
      else if (active.method === "Publish")
        request = { topic: name.replace(/:publish$/, ""), ...JSON.parse(options.body) };
      else request = { name, ...(options.body ? JSON.parse(options.body) : {}) };
      const reply = await world.call({ ...active, request });
      return new Response(JSON.stringify(reply.body), {
        status: reply.ok ? 200 : (reply.status ?? 400),
      });
    };
    const actual = createWire({
      meter,
      journal: { write: (r) => rows.push(r) },
      getToken: async () => "fake-only",
      client: native,
      fetch,
    });
    const wire = {
      call: (c) => {
        active = c;
        return actual.call(c);
      },
    };
    try {
      const result = await runCell({
        cell,
        runId: "123456abcdef",
        wire,
        meter,
        ledger: createLedger(),
        journal: { write: (r) => rows.push(r) },
      });
      assert.equal(result.complete, true, JSON.stringify(result));
      assert.equal(result.cleanupClosed, true);
      const responses = rows.filter((r) => r.event === "response");
      assert.ok(responses.every((r) => r.reply.bodyBytes !== undefined));
      assert.ok(
        responses.filter((r) => r.reply.ok).every((r) => typeof r.reply.bodyBytes === "number"),
      );
      assert.equal(meter.snapshot().requests, world.calls.length);
    } finally {
      actual.close();
    }
  }
});
test("B REST query bytes are included in outbound metadata before dispatch", async () => {
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells[0]);
  let sent = 0;
  const wire = createWire({
    meter,
    journal: { write() {} },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async () => {
      sent++;
      return new Response("{}");
    },
  });
  try {
    await assert.rejects(
      wire.call({
        category: "list",
        transport: "rest",
        service: "Publisher",
        method: "ListTopics",
        request: { project: "projects/fixture-project", pageSize: 1, pageToken: "é".repeat(20000) },
      }),
      /outbound/,
    );
    assert.equal(sent, 0);
    assert.equal(meter.snapshot().requests, 1);
  } finally {
    wire.close();
  }
});

test("B unreadable or oversized response bodies are unknown rather than successful ownership evidence", async () => {
  let cancelled = 0,
    reads = 0;
  await assert.rejects(
    readResponse({
      body: {
        getReader: () => ({
          read: async () =>
            ++reads === 1 ? { done: false, value: Buffer.alloc(65537) } : { done: true },
          cancel: async () => {
            cancelled++;
          },
          releaseLock() {},
        }),
      },
    }),
    /byte/,
  );
  assert.equal(cancelled, 1);
  for (const body of ["not json", "null", "[]"]) {
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells[0]);
    const wire = createWire({
      meter,
      getToken: async () => "fake",
      client: { close() {} },
      journal: { write() {} },
      fetch: async () => new Response(body, { status: 200 }),
    });
    try {
      const reply = await wire.call({
        category: "create",
        transport: "rest",
        service: "Publisher",
        method: "CreateTopic",
        request: { name: "projects/fixture-project/topics/fe123456abcdef-x" },
      });
      assert.equal(reply.unknown, true);
      assert.equal(reply.ok, false);
    } finally {
      wire.close();
    }
  }
});

test("B snapshot CREATE reserves the recorded maximum plus a timing margin", () => {
  assert.equal(minimumCallMs("CreateSnapshot"), 16000);
  assert.equal(makePlan().timeoutPolicy.minimumCreateSnapshotMs, 16000);
  assert.ok(minimumCallMs("CreateSnapshot") >= 10257 + 5000);
});

const { readFileSync } = await import("node:fs");
const recorded = JSON.parse(
  readFileSync(new URL("./pubsub-observation-b/fixtures/recorded-pages.json", import.meta.url)),
);
test("B recorded same-route snapshot and list fixtures replay actual SDK and REST request shapes", () => {
  assert.equal(recorded.rows.length, 66);
  const pairs = new Set();
  for (const row of recorded.rows) {
    const method = row.op[0].toUpperCase() + row.op.slice(1);
    pairs.add(`${row.op}/${row.transport}`);
    assert.equal(row.layoutVerdict, "NOT_COMPARABLE_LEGACY_BODY_BYTES_NOT_RECORDED");
    assert.equal(row.physicalBodyBytes, null);
    if (row.transport === "grpc") {
      const service = row.request.rpc.split("/").at(-2).includes("Publisher")
        ? "Publisher"
        : "Subscriber";
      const definition = SERVICES[service].methods[method];
      const raw = encodeRequest(service, method, row.request.body);
      const value = typeOf(definition[0]).toObject(typeOf(definition[0]).decode(raw), {
        longs: String,
        bytes: String,
        enums: String,
        defaults: false,
      });
      for (const key of Object.keys(row.request.body))
        if (["name", "snapshot", "subscription", "project", "pageToken", "pageSize"].includes(key))
          assert.equal(value[key], row.request.body[key]);
    } else {
      const url = new URL(row.request.path, "https://pubsub.googleapis.com");
      if (method.startsWith("List")) {
        const value = route(method, {
          project: url.pathname.split("/").slice(2, 4).join("/"),
          ...(url.searchParams.has("pageSize")
            ? { pageSize: Number(url.searchParams.get("pageSize")) }
            : {}),
          ...(url.searchParams.has("pageToken")
            ? { pageToken: url.searchParams.get("pageToken") }
            : {}),
        });
        assert.equal(new URL(value.url).pathname, url.pathname);
        assert.equal(
          new URL(value.url).searchParams.get("pageToken"),
          url.searchParams.get("pageToken"),
        );
      }
      if (method === "CreateSnapshot") {
        const value = route(method, { name: url.pathname.slice(4), ...row.request.body });
        assert.equal(value.verb, row.request.method);
        assert.deepEqual(value.body, row.request.body);
      }
    }
    assert.ok(
      (row.response.body && typeof row.response.body === "object") ||
        (typeof row.response.code === "string" && row.response.code !== "OK"),
    );
  }
  for (const operation of [
    "createSnapshot",
    "getSnapshot",
    "listSnapshots",
    "deleteSnapshot",
    "listTopics",
    "listSubscriptions",
  ])
    for (const transport of ["rest", "grpc"]) assert.ok(pairs.has(`${operation}/${transport}`));
});

const { main, parseArgs } = await import("./pubsub-observation-b/record.mjs");
const { verifyProof } = await import("./pubsub-observation-b/admission.mjs");
test("B default entrypoint prepares only and refuses incomplete or widening send options", async () => {
  const events = [];
  const value = await main([], {
    describe: () => ({ suite: "prepared" }),
    print: (v) => events.push(v.suite),
    createCredentials: () => {
      throw new Error("credential execution forbidden");
    },
    createWire: () => {
      throw new Error("wire execution forbidden");
    },
  });
  assert.equal(value.suite, "prepared");
  assert.deepEqual(events, ["prepared"]);
  assert.throws(() => parseArgs(["--record"]), /required/);
  assert.throws(() => parseArgs(["--max-requests", "695"]), /unknown/);
  assert.throws(() => parseArgs(["--prepare", "--out", "/fixture"]));
});
test("B proofs reject DRAFT and bind prior packet review data to the exact E/V scope SHA", () => {
  const scope = {
    taskId: "PUBSUB-OBSERVATION-B",
    suite: "pubsub-observation-b-v1",
    envelopeId: "PUBSUB-OBSERVATION-B-FIXED",
    plan: makePlan(),
    priorPacket: priorProof().value,
  };
  for (const kind of ["E", "V"]) {
    const row = { ...scope, kind, state: "APPROVED" };
    const line = `| PUBSUB-OBSERVATION-B${kind === "E" ? " envelope" : ""} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
    verifyProof(row, line, scope, kind);
    assert.throws(() => verifyProof({ ...row, state: "DRAFT" }, line, scope, kind), /scope/);
    assert.throws(
      () => verifyProof(row, line.replace("decision=APPROVE", "decision=DRAFT"), scope, kind),
      /approve/,
    );
    const changed = structuredClone(row);
    changed.priorPacket.reviewed = false;
    assert.throws(() => verifyProof(changed, line, scope, kind), /scope/);
  }
});

test("B durable dispatch rechecks authority after credentials and persistence", async () => {
  for (const changedAt of ["credential", "persistence"]) {
    let valid = true,
      sent = 0;
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells[0]);
    const wire = createWire({
      meter,
      beforeDispatch: () => {
        if (!valid) throw new Error("authority changed");
      },
      journal: {
        write: (r) => {
          if (changedAt === "persistence" && r.event === "request-dispatch") valid = false;
        },
      },
      getToken: async () => {
        if (changedAt === "credential") valid = false;
        return "fake";
      },
      client: { close() {} },
      fetch: async () => {
        sent++;
        return new Response("{}");
      },
    });
    try {
      const reply = await wire.call({
        category: "create",
        transport: "rest",
        service: "Publisher",
        method: "CreateTopic",
        request: { name: "projects/fixture-project/topics/fe123456abcdef-x" },
      });
      assert.equal(reply.unknown, true);
      assert.equal(sent, 0);
    } finally {
      wire.close();
    }
  }
});
test("B persistence expiry prevents a physical request and cannot turn settled cleanup into recording completeness", async () => {
  let clock = 0,
    sent = 0;
  const meter = createMeter({ now: () => clock });
  meter.enter(makePlan().cells[0]);
  const wire = createWire({
    meter,
    journal: {
      write: (r) => {
        if (r.event === "request-dispatch") clock = 75000;
      },
    },
    getToken: async () => "fake",
    client: { close() {} },
    fetch: async () => {
      sent++;
      return new Response("{}");
    },
  });
  try {
    const reply = await wire.call({
      category: "create",
      transport: "rest",
      service: "Publisher",
      method: "CreateTopic",
      request: { name: "projects/fixture-project/topics/fe123456abcdef-x" },
    });
    assert.equal(reply.unknown, true);
    assert.equal(sent, 0);
  } finally {
    wire.close();
  }
  const cell = makePlan().cells[0],
    world = pageWorld(),
    other = createMeter({ now: () => world.clock.value });
  other.enter(cell);
  const result = await runCell({
    cell,
    meter: other,
    wire: {
      call: async (c) => {
        other.start(c.category, c.transport);
        return world.call(c);
      },
    },
    ledger: createLedger(),
    runId: "123456abcdef",
    journal: {
      write: (r) => {
        if (r.event === "case-result") world.clock.value += 120000;
      },
    },
  });
  assert.equal(result.cleanupClosed, true);
  assert.equal(result.complete, false);
  assert.equal(result.budgetOverrun, true);
});

test("B pure page parser preserves recorded order, exact membership and token shape without adopting names", () => {
  for (const row of recorded.rows.filter(
    (r) => r.op.startsWith("list") && (r.response.code === "OK" || r.response.status === 200),
  )) {
    const kind = row.op.slice(4).toLowerCase(),
      body = row.response.body;
    const declared = (body[kind] ?? []).map((r) => r.name);
    // Explicit fixture inputs test structural parsing; source manifests never derive ownership from a list.
    const result = parsePage(body, { kind, allowed: declared, pageSize: 1000 });
    assert.deepEqual(result.names, declared);
    assert.equal(result.nextPageToken, body.nextPageToken ?? null);
    if (declared.length)
      assert.throws(() => parsePage(body, { kind, allowed: [], pageSize: 1000 }), /foreign/);
  }
  for (let seed = 1; seed <= 300; seed++) {
    const allowed = ["a", "b", "c", "d"],
      names = [...allowed]
        .sort((a, b) => ((a.charCodeAt(0) * seed) % 11) - ((b.charCodeAt(0) * seed) % 11))
        .slice(0, seed % 5);
    const body = {
      topics: names.map((name) => ({ name })),
      nextPageToken: seed % 2 ? "opaque+/=" : undefined,
    };
    const value = parsePage(body, { kind: "topics", allowed, pageSize: 4 });
    assert.deepEqual(value.names, names);
    if (names.length)
      assert.throws(
        () => parsePage(body, { kind: "topics", allowed, pageSize: names.length - 1 }),
        /cardinality/,
      );
    assert.throws(
      () =>
        parsePage(
          { ...body, topics: [{ name: "foreign" }] },
          { kind: "topics", allowed, pageSize: 4 },
        ),
      /foreign/,
    );
  }
  for (const token of [false, [], {}, "", "R".repeat(4097)])
    assert.throws(
      () =>
        parsePage(
          { topics: [], nextPageToken: token },
          { kind: "topics", allowed: [], pageSize: 1 },
        ),
      /token/,
    );
  assert.equal(
    parsePage(
      { topics: [], nextPageToken: "R".repeat(4096) },
      { kind: "topics", allowed: [], pageSize: 1 },
    ).nextPageToken.length,
    4096,
  );
});

test("B actual main connects the counted baseline to exclusive journals and preserves parent closure debt", async () => {
  const { mkdtempSync, rmSync } = await import("node:fs"),
    { tmpdir } = await import("node:os"),
    { join } = await import("node:path");
  for (const unknown of [null, "CreateTopic"]) {
    const out = mkdtempSync(join(tmpdir(), "pubsub-observation-b-main-")),
      world = pageWorld({ unknown }),
      signals = new EventEmitter();
    let exitCode = 0,
      checks = 0;
    try {
      const args = [
        "--record",
        ...Object.entries({
          authority: "fixture",
          descriptor: "fixture",
          packet: "fixture",
          E: "fixture",
          V: "fixture",
          lock: "fixture",
          "run-id": "123456abcdef",
          out,
        }).flatMap(([k, v]) => [`--${k}`, v]),
      ];
      const summary = await main(args, {
        admit: () => ({
          check: () => {
            checks++;
          },
          descriptor: { head: "a".repeat(40) },
          descriptorSha256: "b".repeat(64),
          scope: { envelopeId: "FIXTURE-B", packetSha256: "c".repeat(64) },
        }),
        signals,
        createCredentials: () => async () => "fake",
        createWire: (options) => ({
          close() {},
          call: (c) => {
            options.meter.start(c.category, c.transport);
            options.beforeDispatch();
            return world.call(c);
          },
        }),
        setExitCode: (v) => {
          exitCode = v;
        },
      });
      assert.equal(summary.recordingComplete, unknown === null);
      assert.equal(summary.resourcesClosed, unknown === null);
      assert.equal(summary.parentClosureReady, false);
      assert.equal(summary.closureReady, false);
      assert.equal(summary.results.length, unknown === null ? 18 : 1);
      assert.equal(exitCode, unknown === null ? 0 : 2);
      assert.equal(summary.meter.requests, world.calls.length);
      assert.ok(checks >= world.calls.length);
      assert.equal(
        summary.issuedSha256,
        sha256(readFileSync(join(out, "issued-123456abcdef.jsonl"))),
      );
      assert.equal(signals.listenerCount("SIGTERM"), 0);
      await assert.rejects(
        main(args, {
          admit: () => {
            throw new Error("no rerun");
          },
        }),
        /rerun/,
      );
    } finally {
      rmSync(out, { recursive: true });
    }
  }
});

test("B monotonic clock translation preserves window decisions even on an aged process", () => {
  const offset = Number(process.env.OBSERVATION_TEST_CLOCK_MS ?? 0);
  for (let seed = 0; seed < 200; seed++) {
    const begun = offset + seed * 987654321;
    let clock = begun;
    const meter = createMeter({ now: () => clock });
    meter.enter(makePlan().cells[0]);
    clock += 79999;
    assert.equal(meter.remaining(), 1);
    clock++;
    assert.throws(() => meter.remaining(), /time/);
    assert.equal(meter.remaining(true), 40000);
    clock += 40000;
    assert.throws(() => meter.remaining(true), /time/);
  }
});
test("B native uncertain statuses and aggregate trailers cannot confirm a remote CREATE", async () => {
  for (const code of [8, 15]) {
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells.find((c) => c.transport === "grpc"));
    const client = {
      close() {},
      makeUnaryRequest(_path, _e, _d, _raw, _metadata, _options, callback) {
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(() => {
          callback({ code, details: "remote answer not confirmed" });
          rpc.emit("status", {
            code,
            details: "remote answer not confirmed",
            metadata: { getMap: () => ({}), get: () => [] },
          });
        });
        return rpc;
      },
    };
    const wire = createWire({
      meter,
      client,
      journal: { write() {} },
      getToken: async () => "fake",
    });
    try {
      const reply = await wire.call({
        category: "create",
        transport: "grpc",
        service: "Publisher",
        method: "CreateTopic",
        request: { name: "projects/fixture-project/topics/fe123456abcdef-x" },
      });
      assert.equal(reply.unknown, true);
      assert.equal(reply.bodyBytes, null);
      assert.equal(reply.layoutVerdict, "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED");
    } finally {
      wire.close();
    }
  }
});

test("B callback before status still counts native body plus initial and trailing metadata", async () => {
  const { default: grpc } = await import("@grpc/grpc-js");
  const meter = createMeter({ now: () => 0 });
  meter.enter(makePlan().cells.find((c) => c.transport === "grpc"));
  let cancelled = 0;
  const bytes = Buffer.from(
    typeOf("Topic")
      .encode(
        typeOf("Topic").fromObject({
          name: "projects/fixture-project/topics/fe123456abcdef-x",
          labels: { value: "R".repeat(56000) },
        }),
      )
      .finish(),
  );
  const initial = new grpc.Metadata();
  initial.add("x-initial", "R".repeat(1000));
  const trailers = new grpc.Metadata();
  trailers.add("x-trailing", "R".repeat(7000));
  const client = {
    close() {},
    makeUnaryRequest(_p, _e, _d, _r, _m, _o, callback) {
      const rpc = new EventEmitter();
      rpc.cancel = () => {
        cancelled++;
      };
      queueMicrotask(() => {
        rpc.emit("metadata", initial);
        callback(null, bytes);
        rpc.emit("status", { code: 0, details: "", metadata: trailers });
      });
      return rpc;
    },
  };
  const wire = createWire({ meter, client, getToken: async () => "fake", journal: { write() {} } });
  try {
    const reply = await wire.call({
      category: "create",
      transport: "grpc",
      service: "Publisher",
      method: "CreateTopic",
      request: { name: "projects/fixture-project/topics/fe123456abcdef-x" },
    });
    assert.equal(reply.unknown, true);
    assert.equal(reply.ok, false);
    assert.equal(reply.bodyBytes, null);
    assert.ok(cancelled > 0);
  } finally {
    wire.close();
  }
});
test("B complete redirect, server error and sub-200 responses remain unknown", async () => {
  for (const status of [101, 302, 503]) {
    const meter = createMeter({ now: () => 0 });
    meter.enter(makePlan().cells[0]);
    const response = new Response('{"error":{"status":"UNKNOWN"}}', { status: 200 });
    const fake = { status, ok: false, headers: response.headers, body: response.body };
    const wire = createWire({
      meter,
      client: { close() {} },
      getToken: async () => "fake",
      journal: { write() {} },
      fetch: async () => fake,
    });
    try {
      const reply = await wire.call({
        category: "create",
        transport: "rest",
        service: "Publisher",
        method: "CreateTopic",
        request: { name: "projects/fixture-project/topics/fe123456abcdef-x" },
      });
      assert.equal(reply.unknown, true);
      assert.equal(reply.ok, false);
    } finally {
      wire.close();
    }
  }
});

function task28PriorPair(selection = "invalid-path-gap", omitLastCell = false) {
  const cells = ["S12", "S13", "S14", "S15", "R1", "R2"];
  if (omitLastCell) cells.pop();
  const files = new Map(), plan = {selection, cells: cells.map((id) => ({id, reserve: false}))};
  const pin = (path, value, jsonl = false) => {
    const bytes = Buffer.from(jsonl ? value.map((row) => JSON.stringify(row)).join("\n")+"\n" : JSON.stringify(value));
    files.set(path, bytes); return {path, sha256: sha256(bytes)};
  };
  const value = {reviewed: true, suite: "pubsub-observation-a-v1", sourceHead: "a".repeat(40), envelopeId: "PUBSUB-OBSERVATION-A-FIRST", packetSha256: "", runIds: ["123456abcdef", "abcdef123456"], selection, plan, summaries: []};
  for(const [index,runId] of value.runIds.entries()) {
    const base = `/fixture/pair/${runId}`, sourceHead = (index ? "b" : "a").repeat(40), envelopeId = `PUBSUB-OBSERVATION-A-${index ? "SECOND" : "FIRST"}`;
    const descriptor = pin(base+"/descriptor.json", {head: sourceHead, sources: [{path: "conformance/src/pubsub-observation/scenarios.mjs", sha256: "1".repeat(64)}]});
    const packet = pin(base+"/packet.json", {sourceHead, descriptorSha256: descriptor.sha256, taskId: "PUBSUB-OBSERVATION-A", runIds: [runId], plan});
    const context = {suite: value.suite, project: "fireemu-oracle-idp", runId, sourceHead, envelopeId, packetSha256: packet.sha256};
    const results = plan.cells.map((cell) => ({cellId: cell.id, complete: true}));
    const capture = pin(base+`/capture-${runId}.jsonl`, [{event: "run-start", at: "2026-10-08T10:00:00.000Z", ...context, descriptorSha256: descriptor.sha256}], true);
    const name = `projects/fireemu-oracle-idp/subscriptions/fe${runId}-r2-sub`;
    const issued = pin(base+`/issued-${runId}.jsonl`, [{phase: "sent", name, action: "create", transport: "rest", requestId: "create"}, {phase: "answered", name, action: "create", transport: "rest", requestId: "create", kind: "error"}], true);
    const summary = pin(base+`/summary-${runId}.json`, {...context, a2: false, resourcesClosed: true, recordingComplete: true, signalled: false, error: null, captureSha256: capture.sha256, issuedSha256: issued.sha256, results, recordingDomain: {selection: plan.selection, cellIds: plan.cells.map((cell) => cell.id)}});
    const record = {runId, sourceHead, envelopeId, packetSha256: packet.sha256, descriptor, packet, capture, issued, summary};
    value.summaries.push({runId, ...summary, record});
    if(index===0)value.packetSha256 = packet.sha256;
  }
  return {value, files, pin};
}

test("Task28 B binds two actual invalid-gap source records with independent provenance", () => {
  const f = task28PriorPair();
  assert.doesNotThrow(() => verifyPriorPacket(f.value, (path) => f.files.get(path)));
  assert.notEqual(f.value.summaries[0].record.sourceHead, f.value.summaries[1].record.sourceHead);
  for (const changed of [task28PriorPair("full"), task28PriorPair("valid-stream-gap"), task28PriorPair("invalid-path-gap", true)])
    assert.throws(() => verifyPriorPacket(changed.value, (path) => changed.files.get(path)));
  for (const edit of [
    (v) => {v.selection = "full";},
    (v) => {v.sourceHead = "0".repeat(40);},
    (v) => {v.envelopeId = "PUBSUB-OBSERVATION-A-OTHER";},
    (v) => {v.packetSha256 = "0".repeat(64);},
    (v) => {v.plan.cells.pop();},
    (v) => {v.summaries[1].record.summary.path = v.summaries[0].path;},
    (v) => {v.plan.selection = "valid-stream-gap";},
    (v) => {delete v.summaries[0].record;},
    (v) => {v.summaries[1].record.runId = v.runIds[0];},
    (v) => {v.summaries[1].sha256 = "0".repeat(64);},
    (v) => {v.summaries[1].path = `/fixture/other/summary-${v.runIds[1]}.json`;},
    (v) => {v.summaries[1].record = structuredClone(v.summaries[0].record);},
    (v) => {v.summaries[1].record.summary.sha256 = "0".repeat(64);},
    (v) => {v.summaries[1].record.descriptor.sha256 = "0".repeat(64);},
  ]) {
    const changed = structuredClone(f.value); edit(changed);
    assert.throws(() => verifyPriorPacket(changed, (path) => f.files.get(path)));
  }
});

test("Task28 B refuses A2 or incomplete semantic records even when all pins are coherent", () => {
  for(const field of ["a2", "recordingComplete", "resourcesClosed"]) {
    const f = task28PriorPair(), original = f.value.summaries[0], summary = JSON.parse(f.files.get(original.path));
    summary[field] = !summary[field];
    const changed = f.pin(original.path, summary); original.sha256 = changed.sha256; original.record.summary = changed;
    assert.throws(() => verifyPriorPacket(f.value, (path) => f.files.get(path)));
  }
});


test("Task28 actual B admission consumes the exact reviewed pair before recording", async () => {
  const { admit } = await import("./pubsub-observation-b/admission.mjs");
  const { dirname, resolve } = await import("node:path");
  const attempt = (pair) => {
    const files = new Map(pair.files);
    const descriptor = { head: "c".repeat(40), sources: [] };
    const add = (path, value) => {
      const bytes = Buffer.from(JSON.stringify(value));
      files.set(path, bytes);
      return sha256(bytes);
    };
    const options = { descriptor: "/fixture/b/descriptor.json", authority: "/fixture/b/authority.json", packet: "/fixture/b/packet.json", E: "/fixture/b/E.json", V: "/fixture/b/V.json", lock: "/fixture/b/lock", runId: "111111111111", out: "/fixture/b/run1", a2: false };
    const scope = { taskId: "PUBSUB-OBSERVATION-B", suite: "pubsub-observation-b-v1", project: "fireemu-oracle-idp", envelopeId: "PUBSUB-OBSERVATION-B-FIXED", sourceHead: descriptor.head, descriptorSha256: add(options.descriptor, descriptor), runIds: [options.runId, "222222222222"], runOutputs: {111111111111: options.out, 222222222222: "/fixture/b/run2"}, recoveryOutputs: {111111111111: "/fixture/b/a2-one", 222222222222: "/fixture/b/a2-two"}, expiresAt: "2099-01-01T00:00:00.000Z", plan: makePlan(), priorPacket: pair.value };
    scope.packetSha256 = add(options.packet, { schema: 1, taskId: scope.taskId, version: "v1", sourceHead: descriptor.head, descriptorSha256: scope.descriptorSha256, runIds: scope.runIds, runOutputs: scope.runOutputs, recoveryOutputs: scope.recoveryOutputs, plan: scope.plan });
    const lines = [];
    for (const kind of ["E", "V"]) {
      const row = { ...scope, kind, state: "APPROVED", ledgerLine: lines.length + 1 };
      const line = `| PUBSUB-OBSERVATION-B${kind === "E" ? " envelope" : ""} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
      lines.push(line); row.ledgerLineSha256 = sha256(line);
      scope[kind] = { sha256: add(options[kind], row) };
    }
    add(options.authority, scope);
    const read = (path, encoding) => path.endsWith("owner-decisions.md") ? lines.join("\n") : encoding ? files.get(path)?.toString() : files.get(path);
    const readJson = (path) => ({ value: JSON.parse(read(path)), sha256: sha256(read(path)) });
    let locks = 0;
    const entry = new Function("readJson", "verifyDescriptor", "verifyScope", "validatePlan", "git", "dirname", "resolve", "readFileSync", "sha256", "verifyProof", "PROJECT", "TASK", "verifyLiveLock", "verifyPriorPacket", "makePlan", "unusedRunPreflight", "root", `return (${admit.toString()});`)(readJson, () => {}, verifyScope, validatePlan, (...args) => args.includes("--git-common-dir") ? "/fixture/.git" : descriptor.head, dirname, resolve, read, sha256, verifyProof, scope.project, scope.taskId, () => { locks++; }, (value) => verifyPriorPacket(value, read), makePlan, () => { throw new Error("unused-run execution forbidden"); }, "/fixture");
    const result = entry(options, 0);
    assert.equal(locks, 1);
    assert.deepEqual(result.scope.priorPacket, pair.value);
    return scope;
  };
  const original = task28PriorPair();
  const scope = attempt(original);
  for (const selection of ["full", "valid-stream-gap", "invalid-path-gap"]) {
    for (const semantic of [true, false]) {
      const pair = task28PriorPair();
      pair.value.selection = selection;
      const pin = pair.value.summaries[1], summary = JSON.parse(pair.files.get(pin.path));
      summary.recordingComplete = semantic;
      const changed = pair.pin(pin.path, summary); pin.sha256 = changed.sha256; pin.record.summary = changed;
      if (selection === "invalid-path-gap" && semantic) assert.doesNotThrow(() => attempt(pair));
      else assert.throws(() => attempt(pair));
    }
  }
  const changed = structuredClone(scope);
  changed.priorPacket.selection = "full";
  assert.notEqual(scopeDigest({ ...scope, kind: "V" }), scopeDigest({ ...changed, kind: "V" }));
});
