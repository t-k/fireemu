import {
  verifyPriorPacket,
  scopeDigest,
  verifyScope,
  verifyProof,
  SOURCE_FILES,
} from "./pubsub-observation-c/admission.mjs";
import { sha256 } from "./pubsub-production/admission.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, CAPS, categoryCaps } from "./pubsub-observation-c/plan.mjs";
import { createMeter } from "./pubsub-observation-c/meter.mjs";
import { route, encodeRequest, typeOf } from "./pubsub-observation-c/wire.mjs";
import { SERVICES } from "./pubsub-production/grpc.mjs";
import * as scenarios from "./pubsub-observation-c/scenarios.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createWire } from "./pubsub-observation-c/wire.mjs";
import { requestToWire } from "./pubsub-production/grpc.mjs";
import { EventEmitter } from "node:events";
import { main } from "./pubsub-observation-c/record.mjs";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { minimumCallMs } from "./pubsub-observation-c/plan.mjs";

test("C complete main requires all26baseline cells and closes each own graph", async () => {
  const out = mkdtempSync(join(tmpdir(), "pubsub-c-main-"));
  const signals = new EventEmitter(),
    worlds = [];
  try {
    const summary = await main(
      [
        "--record",
        ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap(
          (key) => [
            `--${key}`,
            key === "run-id" ? "123456abcdef" : key === "out" ? out : `/fixture/${key}`,
          ],
        ),
      ],
      {
        sleep: async () => {},
        signals,
        createCredentials: () => async () => "fake",
        print() {},
        admit: () => ({
          descriptor: { head: "a".repeat(40) },
          descriptorSha256: "b".repeat(64),
          scope: { envelopeId: "PUBSUB-OBSERVATION-C-TEST", packetSha256: "c".repeat(64) },
          check() {},
        }),
        createWire: (options) => {
          const world = referenceWorld();
          worlds.push(world);
          return referenceWire(options.meter, world, options.journal);
        },
      },
    );
    assert.equal(summary.recordingComplete, true);
    assert.equal(summary.resourcesClosed, true);
    assert.equal(summary.results.length, 26);
    assert.equal(summary.parentClosureReady, false);
    assert.equal(worlds[0].resources.size, 0);
    assert.equal(signals.listenerCount("SIGTERM") + signals.listenerCount("SIGINT"), 0);
  } finally {
    rmSync(out, { recursive: true });
  }
});

test("C Pull latency margin covers recorded19.530seconds plus5seconds", () => {
  assert.equal(minimumCallMs("Pull"), 25000);
  assert.equal(makePlan().timeoutPolicy.minimumPullMs, 25000);
});

test("C unknown CREATE DELETE and confirmed-then404 keep independent original A2 obligations", async () => {
  for (const transport of ["rest", "grpc"])
    for (const fault of ["create", "delete", "late-404"]) {
      const cell = makePlan().cells.find(
          (c) => c.transport === transport && c.variant === "multiple-subscriptions",
        ),
        meter = createMeter({ now: () => 0 }),
        ledger = createLedger(),
        world = referenceWorld({
          unknown: fault === "create" ? "CreateTopic" : fault === "delete" ? "DeleteTopic" : null,
          absentGet: fault === "late-404",
        });
      meter.enter(cell);
      const wire = referenceWire(meter, world);
      try {
        const result = await scenarios.runCell({
          cell,
          meter,
          wire,
          ledger,
          runId: "123456abcdef",
          journal: { write() {} },
          sleep: async () => {},
        });
        assert.equal(result.cleanupClosed, false, `${transport}/${fault}`);
        if (fault !== "delete") assert.equal(result.complete, false);
        if (fault === "late-404")
          assert.ok(
            [...ledger.state().values()].some((item) =>
              item.requests.some((r) => r.resolution === "confirmed"),
            ),
          );
        else assert.ok(ledger.outstanding().length);
        assert.ok(world.calls.filter((c) => c.method === "DeleteTopic").length <= 1);
        await assert.rejects(
          scenarios.recoverA2({ ledger, wire, runId: "123456abcdef", elapsedMs: 599999 }),
          /age/,
        );
        const a2meter = createMeter({ now: () => 0, a2: true });
        a2meter.enter({ id: "A2", group: "G7", transport: "rest" });
        world.resources.clear();
        const recovery = referenceWire(a2meter, world);
        try {
          const a2 = await scenarios.recoverA2({
            ledger,
            wire: recovery,
            meter: a2meter,
            runId: "123456abcdef",
            elapsedMs: 600000,
          });
          assert.equal(a2.closed, fault !== "create");
          assert.ok(a2.reads <= 12);
          assert.equal(a2.iamReads, 0);
        } finally {
          recovery.close();
        }
      } finally {
        wire.close();
      }
    }
});

test("C recorded maximum latencies consume the same180second cell before cleanup", async () => {
  for (const transport of ["rest", "grpc"]) {
    let clock = Number(process.env.OBSERVATION_TEST_CLOCK_MS ?? 0);
    const cell = makePlan().cells.find(
        (c) => c.transport === transport && c.variant === "stale-ack",
      ),
      meter = createMeter({ now: () => clock }),
      ledger = createLedger();
    const world = referenceWorld({
      clock: (method) => {
        clock +=
          method === "CreateTopic"
            ? 37666
            : method === "CreateSubscription"
              ? 13024
              : method === "CreateSnapshot"
                ? 10257
                : method.startsWith("Delete")
                  ? 7665
                  : method === "Pull"
                    ? 19530
                    : 1698;
      },
    });
    meter.enter(cell);
    const wire = referenceWire(meter, world);
    try {
      const result = await scenarios.runCell({
        cell,
        meter,
        wire,
        ledger,
        runId: "123456abcdef",
        journal: { write() {} },
        sleep: async (ms) => {
          clock += ms;
        },
      });
      assert.equal(result.complete, false);
      assert.equal(result.cleanupClosed, true);
      assert.ok(clock - Number(process.env.OBSERVATION_TEST_CLOCK_MS ?? 0) < 180000);
      assert.ok(world.calls.filter((c) => c.method === "Pull").length < 8);
    } finally {
      wire.close();
    }
  }
});

function referenceWorld({ clock = () => {}, unknown = null, absentGet = false } = {}) {
  const resources = new Map(),
    messages = new Map(),
    acknowledged = new Map(),
    leased = new Map(),
    snapshots = new Map(),
    calls = [];
  let messageSequence = 0,
    ackSequence = 0;
  const answer = (method, request) => {
    calls.push({ method, request: structuredClone(request) });
    clock(method);
    const name = request.name ?? request.topic ?? request.subscription ?? request.snapshot;
    if (method === unknown) return { ok: false, code: "UNKNOWN", status: 503, body: {} };
    const bad = (code, status) => ({
      ok: false,
      code,
      status,
      body: { error: { status: code, message: code } },
    });
    if (method.startsWith("Create")) {
      if (typeof request.name !== "string") return bad("INVALID_ARGUMENT", 400);
      if (resources.has(name)) return bad("ALREADY_EXISTS", 409);
      const body = { ...request };
      if (method === "CreateSubscription") {
        if (!resources.has(request.topic)) return bad("NOT_FOUND", 404);
        acknowledged.set(name, new Set());
        leased.set(name, new Map());
      }
      if (method === "CreateSnapshot") {
        if (!resources.has(request.subscription)) return bad("NOT_FOUND", 404);
        body.topic = resources.get(request.subscription).topic;
        snapshots.set(name, {
          topic: body.topic,
          acknowledged: new Set(acknowledged.get(request.subscription)),
        });
        delete body.subscription;
      }
      resources.set(name, body);
      return { ok: true, code: "OK", status: 200, body };
    }
    if (method.startsWith("Get"))
      return resources.has(name) && !absentGet
        ? { ok: true, code: "OK", status: 200, body: resources.get(name) }
        : bad("NOT_FOUND", 404);
    if (method.startsWith("Delete")) {
      resources.delete(name);
      return { ok: true, code: "OK", status: 200, body: {} };
    }
    if (method === "Publish") {
      if (!resources.has(request.topic)) return bad("NOT_FOUND", 404);
      const ids = request.messages.map((value) => {
        const messageId = `own-${++messageSequence}`;
        messages.set(messageId, {
          topic: request.topic,
          message: { ...value, messageId, publishTime: "2026-10-07T00:00:00.123Z" },
        });
        return messageId;
      });
      return { ok: true, code: "OK", status: 200, body: { messageIds: ids } };
    }
    const sub = resources.get(request.subscription);
    if (!sub) return bad("NOT_FOUND", 404);
    const acked = acknowledged.get(request.subscription),
      leases = leased.get(request.subscription);
    if (method === "Acknowledge" || method === "ModifyAckDeadline") {
      for (const token of request.ackIds) {
        const id = leases.get(token);
        if (!id) continue;
        leases.delete(token);
        if (method === "Acknowledge") acked.add(id);
      }
      return { ok: true, code: "OK", status: 200, body: {} };
    }
    if (method === "Seek") {
      if (request.snapshot && request.time) return bad("INVALID_ARGUMENT", 400);
      if (request.snapshot) {
        const snap = snapshots.get(request.snapshot);
        if (!snap || snap.topic !== sub.topic) return bad("INVALID_ARGUMENT", 400);
        acknowledged.set(request.subscription, new Set(snap.acknowledged));
      } else if (sub.retainAckedMessages) acked.clear();
      leases.clear();
      return { ok: true, code: "OK", status: 200, body: {} };
    }
    assert.equal(method, "Pull");
    const receivedMessages = [],
      outstanding = new Set(leases.values()),
      keys = new Set();
    for (const [id, value] of messages) {
      if (value.topic !== sub.topic || acked.has(id) || outstanding.has(id)) continue;
      const attrs = value.message.attributes ?? {};
      const pass =
        !sub.filter ||
        (sub.filter === 'attributes.env != "prod"' &&
          Object.hasOwn(attrs, "env") &&
          attrs.env !== "prod") ||
        (sub.filter.includes(" AND ") && attrs.env === "test" && attrs.region === "west") ||
        (sub.filter.includes(" OR ") && (attrs.env === "test" || attrs.region === "west")) ||
        (sub.filter === "attributes:env" && Object.hasOwn(attrs, "env"));
      if (!pass) continue;
      const key = value.message.orderingKey;
      if (
        sub.enableMessageOrdering &&
        key &&
        (keys.has(key) ||
          [...outstanding].some((other) => messages.get(other).message.orderingKey === key))
      )
        continue;
      if (key) keys.add(key);
      const ackId = `actual-${++ackSequence}`;
      leases.set(ackId, id);
      receivedMessages.push({ ackId, message: value.message });
      if (receivedMessages.length === request.maxMessages) break;
    }
    return {
      ok: true,
      code: "OK",
      status: 200,
      body: receivedMessages.length ? { receivedMessages } : {},
    };
  };
  return { resources, messages, calls, answer };
}

function referenceWire(meter, world, journal = { write() {} }) {
  const codes = { INVALID_ARGUMENT: 3, NOT_FOUND: 5, ALREADY_EXISTS: 6, UNKNOWN: 14 };
  return createWire({
    meter,
    journal,
    getToken: async () => "fake",
    fetch: async (url, options) => {
      const path = new URL(url).pathname.slice(4),
        [name, action] = path.split(":");
      const kind = name.split("/")[2],
        suffix = { topics: "Topic", subscriptions: "Subscription", snapshots: "Snapshot" }[kind];
      const method = action
        ? action[0].toUpperCase() + action.slice(1)
        : { PUT: "Create", GET: "Get", DELETE: "Delete" }[options.method] + suffix;
      const body = options.body ? JSON.parse(options.body.toString()) : {};
      const request = action
        ? { [method === "Publish" ? "topic" : "subscription"]: name, ...body }
        : { name, ...body };
      const reply = world.answer(method, request);
      return new Response(JSON.stringify(reply.body), { status: reply.status });
    },
    client: {
      close() {},
      makeUnaryRequest(path, _enc, _dec, raw, _metadata, _options, callback) {
        const method = path.split("/").at(-1),
          service = path.includes("Publisher") ? "Publisher" : "Subscriber";
        const [input, output] = SERVICES[service].methods[method];
        const request = typeOf(input).toObject(typeOf(input).decode(raw), {
          defaults: false,
          bytes: String,
          longs: String,
        });
        if (method.startsWith("Get") || method.startsWith("Delete"))
          request.name =
            request[
              method.endsWith("Topic")
                ? "topic"
                : method.endsWith("Snapshot")
                  ? "snapshot"
                  : "subscription"
            ];
        const rpc = new EventEmitter();
        rpc.cancel = () => {};
        queueMicrotask(() => {
          const reply = world.answer(method, request),
            code = reply.ok ? 0 : codes[reply.code];
          const Type = typeOf(output);
          callback(
            reply.ok ? null : { code, details: reply.code },
            reply.ok
              ? Buffer.from(Type.encode(Type.fromObject(requestToWire(reply.body))).finish())
              : undefined,
          );
          rpc.emit("status", { code, details: reply.ok ? "" : reply.code });
        });
        return rpc;
      },
    },
  });
}

test("C every declared baseline graph runs through actual REST and native request bytes", async () => {
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    const meter = createMeter({ now: () => 0 }),
      world = referenceWorld(),
      ledger = createLedger();
    meter.enter(cell);
    const wire = referenceWire(meter, world);
    try {
      const result = await scenarios.runCell({
        cell,
        meter,
        wire,
        ledger,
        runId: "123456abcdef",
        journal: { write() {} },
        sleep: async () => {},
      });
      assert.equal(result.complete, true, `${cell.id}/${cell.variant}: ${result.reason}`);
      assert.equal(result.cleanupClosed, true, cell.id);
      assert.equal(world.resources.size, 0, cell.id);
      assert.equal(ledger.outstanding().length, 0, cell.id);
      assert.ok(world.calls.length <= 37, cell.id);
      assert.equal(
        world.calls.some((c) => c.method.startsWith("List") || c.method === "StreamingPull"),
        false,
      );
      if (cell.variant === "cancel-followup")
        assert.ok(
          result.observations.some(
            (r) => r.stage === "prior-cancel-causal-debt" && r.verdict === "NOT_COMPARABLE",
          ),
        );
    } finally {
      wire.close();
    }
  }
});

test("C delivery controls retain selectors and REST Seek member order", () => {
  const subscription = "projects/fixture/subscriptions/own";
  for (const [method, body] of [
    ["Pull", { returnImmediately: false, maxMessages: 3 }],
    ["Acknowledge", { ackIds: ["observed-own-ack"] }],
    ["ModifyAckDeadline", { ackIds: ["observed-own-ack"], ackDeadlineSeconds: 0 }],
    ["Seek", { snapshot: "projects/fixture/snapshots/own", time: "2026-10-07T00:00:00Z" }],
  ]) {
    const request = { subscription, ...body };
    const address = route(method, request);
    assert.equal(address.verb, "POST");
    assert.equal(
      address.url,
      `https://pubsub.googleapis.com/v1/${subscription}:${method[0].toLowerCase() + method.slice(1)}`,
    );
    assert.deepEqual(address.body, body);
    const Type = typeOf(SERVICES.Subscriber.methods[method][0]);
    assert.equal(
      Type.decode(encodeRequest("Subscriber", method, request)).subscription,
      subscription,
    );
  }
  const a = route("Seek", { subscription, snapshot: "s", time: "t" });
  const b = route("Seek", { subscription, time: "t", snapshot: "s" });
  assert.deepEqual(Object.keys(a.body), ["snapshot", "time"]);
  assert.deepEqual(Object.keys(b.body), ["time", "snapshot"]);
});

test("C independent graph declares finite own prerequisites and never lists for ownership", () => {
  for (const cell of makePlan().cells) {
    const manifest = scenarios.graph(cell, "123456abcdef");
    assert.ok(manifest.resources.length <= 5);
    assert.equal(new Set(manifest.resources.map((r) => r.name)).size, manifest.resources.length);
    for (const resource of manifest.resources) {
      assert.equal(scenarios.owned(resource.name, "123456abcdef"), true);
      assert.equal(scenarios.owned(resource.name + "-foreign", "123456abcdef"), false);
      assert.equal(typeof resource.request.name, "string");
      if (resource.method === "CreateSubscription")
        assert.ok(manifest.resources.some((r) => r.name === resource.request.topic));
      if (resource.method === "CreateSnapshot")
        assert.ok(manifest.resources.some((r) => r.name === resource.request.subscription));
    }
    if (cell.variant === "wrong-topic-snapshot") assert.equal(manifest.resources.length, 5);
    if (cell.variant.startsWith("filter-") || cell.variant === "attribute-exists")
      assert.ok(
        manifest.resources.some((r) => r.method === "CreateSubscription" && !r.request.filter),
      );
  }
});

test("C delivery parsing requires physical own publication identity and payload before using ACK", () => {
  assert.equal(typeof scenarios.parseDelivery, "function");
  for (let seed = 0; seed < 256; seed++) {
    const id = `own-${seed}`,
      data = Buffer.from(`marker-${seed}`).toString("base64");
    const published = new Map([[id, { data, attributes: { env: "test" }, orderingKey: "key" }]]);
    const item = {
      ackId: `opaque-${seed}`,
      message: { messageId: id, data, attributes: { env: "test" }, orderingKey: "key" },
    };
    assert.deepEqual(scenarios.parseDelivery({ receivedMessages: [item] }, published), [item]);
    for (const changed of [
      { ...item, ackId: "" },
      { ...item, message: { ...item.message, messageId: "foreign" } },
      { ...item, message: { ...item.message, data: "Zm9yZWlnbg==" } },
    ])
      assert.throws(() => scenarios.parseDelivery({ receivedMessages: [changed] }, published));
    assert.deepEqual(scenarios.parseDelivery({}, published), []);
    assert.throws(() =>
      scenarios.parseDelivery({ receivedMessages: Array(4).fill(item) }, published),
    );
  }
});

test("C fixes G2 plus independent G7 reservations without streams or reassignment", () => {
  const plan = makePlan();
  assert.deepEqual(plan.groups, ["G2", "G7"]);
  assert.equal(plan.cells.filter((cell) => !cell.reserve).length, 26);
  assert.equal(plan.cells.filter((cell) => cell.reserve).length, 2);
  assert.deepEqual(CAPS.G2, { requests: 1036, rest: 518, grpc: 518, streams: 0, cellMs: 180000 });
  assert.equal(CAPS.totalRequests, 1050);
  assert.equal(CAPS.sourceWallMs, 5040000);
  assert.equal(CAPS.smallPublishes, 84);
  assert.deepEqual(categoryCaps("G2"), {
    create: 5,
    get: 5,
    publish: 3,
    pull: 8,
    ackControl: 4,
    other: 2,
    cleanupDelete: 5,
    cleanupGet: 5,
  });
  for (const transport of ["rest", "grpc"])
    assert.equal(
      plan.cells.filter((cell) => cell.transport === transport && !cell.reserve).length,
      13,
    );
});

test("C vector reference model counts every category start and clips cleanup inside180seconds", () => {
  for (let seed = 1; seed <= 256; seed++) {
    let state = seed,
      clock = 0;
    const meter = createMeter({ now: () => clock });
    meter.enter(makePlan().cells[0]);
    const reference = Object.fromEntries(Object.keys(categoryCaps("G2")).map((key) => [key, 0]));
    const categories = Object.keys(reference);
    for (let step = 0; step < 120; step++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const category = categories[state % categories.length];
      if (reference[category] === categoryCaps("G2")[category])
        assert.throws(() => meter.start(category, "rest"));
      else {
        meter.start(category, "rest");
        reference[category]++;
      }
      assert.deepEqual(meter.snapshot().cell.categories, reference);
    }
    clock = 140000;
    assert.throws(() => meter.start("pull", "rest"), /time/);
    assert.ok(meter.remaining(true) > 0);
    clock = 180000;
    assert.throws(() => meter.remaining(true), /time/);
  }
});

test("C a spent cell cannot restart or reset its category budget", () => {
  let clock = 0;
  const meter = createMeter({ now: () => clock }),
    plan = makePlan();
  meter.enter(plan.cells[0]);
  for (let i = 0; i < 5; i++) meter.start("create", "rest");
  const spent = meter.snapshot();
  assert.throws(() => meter.enter(plan.cells[0]), /reopen/);
  assert.deepEqual(meter.snapshot(), spent);
  assert.throws(() => meter.start("create", "rest"), /category/);
  clock = 180000;
  assert.throws(() => meter.enter(plan.cells[1]), /time/);
  assert.deepEqual(meter.snapshot(), spent);
});

function priorProof() {
  const summaries = {};
  const value = {
    reviewed: true,
    suite: "pubsub-observation-b-v1",
    sourceHead: "a".repeat(40),
    envelopeId: "PUBSUB-OBSERVATION-B-FIXED",
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
test("C prior-packet proof requires two genuine complete closed B source recordings", () => {
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
test("C new E/V scope binds previous packet, source pins and exact recording identities", () => {
  const { value } = priorProof();
  const scope = {
    taskId: "PUBSUB-OBSERVATION-C",
    suite: "pubsub-observation-c-v1",
    project: "fireemu-oracle-idp",
    envelopeId: "PUBSUB-OBSERVATION-C-FIXED",
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
  assert.ok(SOURCE_FILES.includes("conformance/src/pubsub-observation-c/wire.mjs"));
  assert.ok(SOURCE_FILES.includes("conformance/src/pubsub-observation/metadata.mjs"));
});
test("C proofs reject DRAFT and bind prior packet review data to the exact E/V scope SHA", () => {
  const scope = {
    taskId: "PUBSUB-OBSERVATION-C",
    suite: "pubsub-observation-c-v1",
    envelopeId: "PUBSUB-OBSERVATION-C-FIXED",
    plan: makePlan(),
    priorPacket: priorProof().value,
  };
  for (const kind of ["E", "V"]) {
    const row = { ...scope, kind, state: "APPROVED" };
    const line = `| PUBSUB-OBSERVATION-C${kind === "E" ? " envelope" : ""} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
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
