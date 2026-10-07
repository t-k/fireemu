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
  let cancelled = 0;
  await assert.rejects(
    readResponse({
      body: {
        getReader: () => ({
          read: async () => ({ done: false, value: Buffer.alloc(65537) }),
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
