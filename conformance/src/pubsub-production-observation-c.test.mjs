import {
  admit,
  describeSource,
  verifyPriorPacket,
  verifyPreviousAttempt,
  scopeDigest,
  verifyScope,
  verifyProof,
  SOURCE_FILES,
} from "./pubsub-observation-c/admission.mjs";
import { sha256 } from "./pubsub-production/admission.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, validatePlan, CAPS, categoryCaps } from "./pubsub-observation-c/plan.mjs";
import { createMeter } from "./pubsub-observation-c/meter.mjs";
import { route, encodeRequest, typeOf } from "./pubsub-observation-c/wire.mjs";
import { SERVICES } from "./pubsub-production/grpc.mjs";
import * as scenarios from "./pubsub-observation-c/scenarios.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createWire } from "./pubsub-observation-c/wire.mjs";
import { requestToWire } from "./pubsub-production/grpc.mjs";
import { EventEmitter } from "node:events";
import { main } from "./pubsub-observation-c/record.mjs";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import fs from "node:fs";
import childProcess from "node:child_process";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { minimumCallMs } from "./pubsub-observation-c/plan.mjs";

test("C complete main requires all26baseline cells and closes each own graph", async (t) => {
  let clock = 0;
  t.mock.method(performance, "now", () => clock);
  t.mock.timers.enable({ apis: ["setTimeout"] });
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
        sleep: async (ms) => {
          clock += ms;
        },
        signals,
        createCredentials: () => async () => "fake",
        print() {},
        admit: () => ({
          plan: makePlan(),
          descriptor: { head: "a".repeat(40) },
          descriptorSha256: "b".repeat(64),
          scope: { envelopeId: "PUBSUB-OBSERVATION-C-TEST", packetSha256: "c".repeat(64) },
          check() {},
        }),
        createWire: (options) => {
          const world = referenceWorld({
            pendingCancel: true,
            now: () => clock,
            onPending: () =>
              queueMicrotask(() => {
                clock += 1000;
                t.mock.timers.tick(1000);
              }),
          });
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

function referenceWorld({
  clock = () => {},
  unknown = null,
  absentGet = false,
  now = () => 0,
  pendingCancel = false,
  onPending = () => {},
} = {}) {
  const resources = new Map(),
    messages = new Map(),
    acknowledged = new Map(),
    leased = new Map(),
    snapshots = new Map(),
    leaseExpires = new Map(),
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
      if (new Set(request.messages.map((value) => value.orderingKey ?? "")).size > 1)
        return bad("FAILED_PRECONDITION", 400);
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
    if (pendingCancel)
      for (const token of leases.keys()) if (leaseExpires.get(token) <= now()) leases.delete(token);
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
      leaseExpires.set(ackId, now() + 60000);
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
  return { resources, messages, calls, answer, pendingCancel, onPending, snapshots, acknowledged };
}

function referenceWire(meter, world, journal = { write() {} }) {
  const codes = {
    INVALID_ARGUMENT: 3,
    NOT_FOUND: 5,
    ALREADY_EXISTS: 6,
    FAILED_PRECONDITION: 9,
    UNKNOWN: 14,
  };
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
      if (
        world.pendingCancel &&
        method === "Pull" &&
        request.maxMessages === 1 &&
        request.returnImmediately === false &&
        !reply.body.receivedMessages?.length
      ) {
        world.onPending();
        return await new Promise((_resolve, reject) =>
          options.signal.addEventListener(
            "abort",
            () => reject(new Error("model client aborted")),
            { once: true },
          ),
        );
      }
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
        rpc.cancel = () => {
          callback({ code: 1, details: "model client cancellation" });
          rpc.emit("status", { code: 1, details: "model client cancellation" });
        };
        queueMicrotask(() => {
          const reply = world.answer(method, request),
            code = reply.ok ? 0 : codes[reply.code];
          if (
            world.pendingCancel &&
            method === "Pull" &&
            request.maxMessages === 1 &&
            request.returnImmediately === false &&
            !reply.body.receivedMessages?.length
          ) {
            world.onPending();
            return;
          }
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

test("C every declared baseline graph runs through actual REST and native request bytes", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    let clock = 0;
    const meter = createMeter({ now: () => clock }),
      world = referenceWorld({
        pendingCancel: cell.variant === "cancel-followup",
        now: () => clock,
        onPending: () =>
          queueMicrotask(() => {
            clock += 1000;
            t.mock.timers.tick(1000);
          }),
      }),
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
        sleep: async (ms) => {
          clock += ms;
        },
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

test("C native both-target Seek persists exact protobuf bytes for both stimuli", async () => {
  const cell = makePlan().cells.find(
    (c) => c.transport === "grpc" && c.variant === "reverse-seek-members",
  );
  const meter = createMeter({ now: () => 0 }),
    world = referenceWorld(),
    ledger = createLedger(),
    capture = [];
  const journal = {
    write(row) {
      capture.push(row);
    },
  };
  meter.enter(cell);
  const wire = referenceWire(meter, world, journal);
  try {
    const result = await scenarios.runCell({
      cell,
      meter,
      wire,
      ledger,
      runId: "123456abcdef",
      journal,
      sleep: async () => {},
    });
    assert.equal(result.complete, true);
    const rows = capture.filter((r) => r.event === "request-dispatch" && r.method === "Seek");
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.equal(typeof row.requestBodyBase64, "string");
      const raw = Buffer.from(row.requestBodyBase64, "base64");
      assert.equal(raw.length, row.requestBodyBytes);
      assert.equal(sha256(raw), row.requestSha256);
      assert.deepEqual(raw, encodeRequest("Subscriber", "Seek", row.request));
      const decoded = typeOf("SeekRequest").decode(raw);
      assert.equal(decoded.subscription, row.request.subscription);
      assert.equal(decoded.snapshot, row.request.snapshot);
      assert.ok(decoded.time);
    }
    assert.equal(
      result.observations.find((r) => r.stage === "native-member-order-scope")
        .inferredOneofSelection,
      false,
    );
  } finally {
    wire.close();
  }
});
test("C record2 rejects a different suite, project or an A2-only prior summary", () => {
  const scope = {
    runIds: ["123456abcdef", "abcdef123456"],
    sourceHead: "a".repeat(40),
    envelopeId: "PUBSUB-OBSERVATION-C-FIXED",
    packetSha256: "b".repeat(64),
    previousAttempt: { sha256: "c".repeat(64) },
  };
  const previous = {
    sha256: scope.previousAttempt.sha256,
    value: {
      runId: scope.runIds[0],
      sourceHead: scope.sourceHead,
      envelopeId: scope.envelopeId,
      packetSha256: scope.packetSha256,
      resourcesClosed: true,
      recordingComplete: true,
      suite: "pubsub-observation-c-v1",
      project: "fireemu-oracle-idp",
      a2: false,
    },
  };
  verifyPreviousAttempt(previous, scope, { head: scope.sourceHead });
  for (const [field, value] of [
    ["suite", "other"],
    ["project", "foreign"],
    ["a2", true],
  ]) {
    const changed = structuredClone(previous);
    changed.value[field] = value;
    assert.throws(() => verifyPreviousAttempt(changed, scope, { head: scope.sourceHead }), /run2/);
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

test("C delivery parser accepts masked same-route production replies from both recorded runs", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL("./pubsub-observation-c/fixtures/recorded-delivery.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(fixture.rows.length, 16);
  assert.equal(new Set(fixture.rows.map((r) => r.runId)).size, 2);
  for (const row of fixture.rows) {
    const published = new Map(
      Object.entries(row.published).map(([id, value]) => [id, value.message]),
    );
    const items = scenarios.parseDelivery(row.response.body, published);
    assert.equal(items.length, row.response.body.receivedMessages.length);
    assert.equal(row.layoutVerdict, "NOT_COMPARABLE_LEGACY_BODY_BYTES_NOT_RECORDED");
    const changed = structuredClone(row.response.body);
    changed.receivedMessages[0].message.messageId += "-foreign";
    assert.throws(() => scenarios.parseDelivery(changed, published));
    if (row.transport === "grpc") {
      const Type = typeOf(SERVICES.Subscriber.methods.Pull[0]);
      assert.equal(
        Type.decode(encodeRequest("Subscriber", "Pull", row.request.body)).subscription,
        row.request.body.subscription,
      );
    }
  }
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

const gapIds = [
  "R1",
  "R2",
  "R3",
  "R4",
  "R5",
  "R6",
  "R8",
  "R10",
  "R11",
  "N1",
  "N2",
  "N3",
  "N4",
  "N5",
  "N6",
  "N8",
  "N10",
  "N11",
];
test("C fixed remaining-gap selection preserves original cell order and closed caps", () => {
  const full = makePlan(),
    gap = makePlan({ selection: "remaining-gap" });
  assert.deepEqual(
    gap.cells.map((c) => c.id),
    gapIds,
  );
  assert.deepEqual(
    gap.cells,
    full.cells.filter((c) => gapIds.includes(c.id)),
  );
  assert.deepEqual(gap.caps.G2, {
    requests: 666,
    rest: 333,
    grpc: 333,
    streams: 0,
    cellMs: 180000,
  });
  assert.equal(gap.caps.totalRequests, 680);
  assert.equal(gap.caps.sourceRequests, 666);
  assert.equal(gap.caps.sourceWallMs, 3240000);
  assert.equal(gap.caps.smallPublishes, 54);
  assert.equal(gap.caps.largePublishes, 0);
  assert.equal(gap.caps.cleanupReserveMs, 40000);
  assert.deepEqual(validatePlan(gap), gap);
  assert.deepEqual(makePlan(), full);
  for (const change of [
    (v) => v.cells.reverse(),
    (v) => v.cells.push(v.cells[0]),
    (v) => v.cells.splice(0, 1),
    (v) => v.cells.push(full.cells.find((c) => c.id === "R7")),
    (v) => v.caps.totalRequests++,
    (v) => (v.selection = "arbitrary"),
  ]) {
    const altered = structuredClone(gap);
    change(altered);
    assert.throws(() => validatePlan(altered), /plan|selection/);
  }
});

async function withCAdmission(t, plan, packetPlan, use) {
  const root = fileURLToPath(new URL("../..", import.meta.url));
  const mainRoot = resolve(root, "../..");
  const realRead = fs.readFileSync,
    realReadDir = fs.readdirSync;
  const fixtureOut = mkdtempSync(join(tmpdir(), "pubsub-c-admit-"));
  const files = new Map();
  const put = (path, value) => {
    const bytes = Buffer.from(JSON.stringify(value));
    files.set(path, bytes);
    return sha256(bytes);
  };
  const options = {
    runId: "123456abcdef",
    out: fixtureOut,
    descriptor: "/fixture/descriptor",
    authority: "/fixture/authority",
    packet: "/fixture/packet",
    E: "/fixture/E",
    V: "/fixture/V",
    lock: resolve(mainRoot, "docs.local/runs/sandbox-locks/fireemu-oracle-idp.lock"),
    a2: false,
  };
  // Runtime identity inputs are synthetic; admission and recording predicates remain real.
  const require = createRequire(import.meta.url),
    sdkPackage = require.resolve("@google-cloud/pubsub/package.json");
  const sdkRoot = dirname(sdkPackage),
    sdkRequire = createRequire(sdkPackage);
  const runtimePackages = [
    sdkPackage,
    sdkRequire.resolve("google-gax/package.json"),
    require.resolve("@grpc/grpc-js/package.json"),
  ];
  const runtimeRoots = new Set(runtimePackages.map((path) => fs.realpathSync(dirname(path))));
  for (const path of runtimePackages) {
    const { name } = JSON.parse(realRead(path));
    put(path, { name, version: "0.0.0-fixture", dependencies: {} });
  }
  for (const path of [
    process.execPath,
    resolve(sdkRoot, "build/protos/protos.js"),
    require.resolve("@google-cloud/pubsub"),
    require.resolve("@grpc/grpc-js"),
    sdkRequire.resolve("google-gax"),
  ])
    files.set(path, Buffer.from("offline-runtime-identity-fixture"));
  const savedExecArgv = process.execArgv;
  process.execArgv = [];
  t.mock.method(childProcess, "execFileSync", (_command, args, _opts) => {
    const operation = args.slice(2);
    if (operation[0] === "show") return realRead(resolve(root, operation[1].slice(41)));
    if (operation[0] === "verify-commit") return "";
    if (operation[0] === "rev-parse")
      return operation.includes("--git-common-dir") ? resolve(mainRoot, ".git") : "a".repeat(40);
    throw new Error("unexpected fixture git operation");
  });
  t.mock.method(fs, "readFileSync", (path, options) => {
    const bytes = files.get(String(path));
    if (bytes) return options === "utf8" ? bytes.toString() : bytes;
    if (String(path).includes("docs.local/"))
      throw new Error("live admission input forbidden in fixture");
    if (String(path).includes("/node_modules/")) throw new Error("unexpected runtime fixture read");
    return realRead(path, options);
  });
  files.set(resolve(mainRoot, "docs.local/runs/sandbox-ledger.jsonl"), Buffer.alloc(0));
  t.mock.method(fs, "readdirSync", (path, options) =>
    String(path) === resolve(mainRoot, "docs.local/runs") || runtimeRoots.has(String(path))
      ? []
      : realReadDir(path, options),
  );
  syncBuiltinESMExports();
  try {
    const descriptor = describeSource(),
      descriptorSha256 = put(options.descriptor, descriptor);
    const prior = priorProof();
    for (const [path, bytes] of Object.entries(prior.summaries)) files.set(path, bytes);
    const scope = {
      taskId: "PUBSUB-OBSERVATION-C",
      suite: "pubsub-observation-c-v1",
      project: "fireemu-oracle-idp",
      envelopeId: "PUBSUB-OBSERVATION-C-GAP-TEST",
      sourceHead: descriptor.head,
      descriptorSha256,
      runIds: [options.runId, "abcdef123456"],
      runOutputs: { [options.runId]: options.out, abcdef123456: "/fixture/c-second" },
      recoveryOutputs: {
        [options.runId]: "/fixture/c-first-a2",
        abcdef123456: "/fixture/c-second-a2",
      },
      expiresAt: "2099-01-01T00:00:00Z",
      plan,
      priorPacket: prior.value,
    };
    scope.packetSha256 = put(options.packet, {
      schema: 1,
      taskId: scope.taskId,
      version: "v1",
      sourceHead: descriptor.head,
      descriptorSha256,
      runIds: scope.runIds,
      runOutputs: scope.runOutputs,
      recoveryOutputs: scope.recoveryOutputs,
      plan: packetPlan,
    });
    const lines = [];
    for (const kind of ["E", "V"]) {
      const row = { ...scope, kind, state: "APPROVED", ledgerLine: lines.length + 1 };
      const line = `| PUBSUB-OBSERVATION-C${kind === "E" ? " envelope" : ""} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
      row.ledgerLineSha256 = sha256(line);
      lines.push(line);
      scope[kind] = { sha256: put(options[kind], row) };
    }
    files.set(
      resolve(mainRoot, "docs.local/instructions/owner-decisions.md"),
      Buffer.from(lines.join("\n")),
    );
    put(options.lock, {
      pid: process.pid,
      envelopeId: scope.envelopeId,
      sourceCommit: descriptor.head,
      acquiredAt: "2026-10-08T00:00:00Z",
    });
    put(options.authority, scope);
    return await use({ admit, options });
  } finally {
    process.execArgv = savedExecArgv;
    t.mock.restoreAll();
    syncBuiltinESMExports();
    if (fs.existsSync(fixtureOut)) rmSync(fixtureOut, { recursive: true });
  }
}

test("C admitted gap reaches actual recorder and selected meter without restoring full cells", async (t) => {
  const plan = makePlan({ selection: "remaining-gap" });
  await withCAdmission(t, plan, plan, async ({ admit, options }) => {
    const admitted = admit(options);
    assert.deepEqual(admitted.plan, plan);
    const out = options.out,
      signals = new EventEmitter(),
      worlds = [];
    let clock = 0;
    t.mock.method(performance, "now", () => clock);
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let credentials = 0;
    try {
      const summary = await main(
        [
          "--record",
          ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap(
            (key) => [
              `--${key}`,
              key === "run-id" ? options.runId : key === "out" ? out : options[key],
            ],
          ),
        ],
        {
          admit: () => admitted,
          sleep: async (ms) => {
            clock += ms;
          },
          signals,
          print() {},
          setExitCode() {},
          createCredentials: () => {
            credentials++;
            return async () => "fake";
          },
          createWire: (o) => {
            const world = referenceWorld({
              pendingCancel: true,
              now: () => clock,
              onPending: () =>
                queueMicrotask(() => {
                  clock += 1000;
                  t.mock.timers.tick(1000);
                }),
            });
            worlds.push(world);
            return referenceWire(o.meter, world, o.journal);
          },
        },
      );
      assert.equal(credentials, 1);
      assert.deepEqual(
        summary.results.map((r) => r.cellId),
        gapIds,
      );
      assert.equal(summary.recordingComplete, true);
      assert.equal(summary.resourcesClosed, true);
      assert.equal(summary.parentClosureReady, false);
      assert.equal(summary.error, null);
      assert.equal(worlds[0].resources.size, 0);
      assert.equal(signals.listenerCount("SIGTERM") + signals.listenerCount("SIGINT"), 0);
      assert.ok(summary.meter.requests <= 666);
      assert.ok(summary.meter.smallPublishes <= 54);
    } finally {
      rmSync(out, { recursive: true });
    }
  });
});

test("C actual admission refuses edited or differently selected packet plans before credentials", async (t) => {
  const gap = makePlan({ selection: "remaining-gap" }),
    reordered = structuredClone(gap);
  reordered.cells.reverse();
  for (const [scopePlan, packetPlan] of [
    [gap, makePlan()],
    [makePlan(), gap],
    [gap, reordered],
  ]) {
    await withCAdmission(t, scopePlan, packetPlan, async ({ admit, options }) => {
      let credentials = 0;
      await assert.rejects(
        () =>
          main(
            [
              "--record",
              ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap(
                (key) => [`--${key}`, key === "run-id" ? options.runId : options[key]],
              ),
            ],
            {
              admit: () => admit(options),
              createCredentials: () => {
                credentials++;
                throw new Error("credentials must not start");
              },
            },
          ),
        /plan/,
      );
      assert.equal(credentials, 0);
      assert.deepEqual(fs.readdirSync(options.out), []);
    });
  }
});

test("C gap meter enforces selected starts payload and cleanup without admitting omitted cells", () => {
  const plan = makePlan({ selection: "remaining-gap" }),
    meter = createMeter({ plan, now: () => 0 });
  for (const cell of plan.cells) {
    meter.enter(cell);
    for (const [category, count] of Object.entries(categoryCaps("G2")))
      for (let i = 0; i < count; i++) meter.start(category, cell.transport);
  }
  assert.equal(meter.snapshot().requests, 666);
  assert.equal(meter.snapshot().groups.G2.rest, 333);
  assert.equal(meter.snapshot().groups.G2.grpc, 333);
  assert.throws(() => meter.enter(makePlan().cells.find((c) => c.id === "R7")), /undeclared/);
  for (let i = 0; i < 54; i++) meter.payload(1024);
  assert.throws(() => meter.payload(1), /payload cap/);
  assert.equal(meter.snapshot().smallPublishes, 54);
  assert.throws(() => meter.frame(), /frame scope/);
  const recovery = createMeter({ plan, a2: true, now: () => 0 });
  recovery.enter({ id: "A2", group: "G7", transport: "rest" });
  for (const category of ["resourceRead", "unknownDeleteRead"])
    for (let i = 0; i < 6; i++) recovery.start(category, "rest");
  assert.equal(recovery.snapshot().requests, 12);
  assert.throws(() => recovery.start("resourceRead", "rest"), /category/);
  let clock = 0;
  const timed = createMeter({ plan, now: () => clock });
  timed.enter(plan.cells[0]);
  clock = 140000;
  assert.throws(() => timed.start("pull", "rest"), /time/);
  assert.equal(timed.remaining(true), 40000);
  clock = 180000;
  assert.throws(() => timed.remaining(true), /time/);
});

test("C admitted gap retains unknown CREATE obligations and stops before the next selected cell", async (t) => {
  const plan = makePlan({ selection: "remaining-gap" });
  await withCAdmission(t, plan, plan, async ({ admit, options }) => {
    const admitted = admit(options),
      world = referenceWorld({ unknown: "CreateTopic" }),
      signals = new EventEmitter();
    const summary = await main(
      [
        "--record",
        ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap(
          (key) => [`--${key}`, key === "run-id" ? options.runId : options[key]],
        ),
      ],
      {
        admit: () => admitted,
        sleep: async () => {},
        signals,
        print() {},
        setExitCode() {},
        createCredentials: () => async () => "fake",
        createWire: (o) => referenceWire(o.meter, world, o.journal),
      },
    );
    assert.equal(summary.recordingComplete, false);
    assert.equal(summary.resourcesClosed, false);
    assert.equal(summary.parentClosureReady, false);
    assert.deepEqual(
      summary.results.map((r) => r.cellId),
      ["R1"],
    );
    const issued = readFileSync(join(options.out, "issued-123456abcdef.jsonl"), "utf8");
    assert.ok(issued.includes('"unknown"'));
    assert.equal(signals.listenerCount("SIGTERM") + signals.listenerCount("SIGINT"), 0);
    assert.throws(
      () => admit({ ...options, runId: "abcdef123456", out: "/fixture/c-second" }),
      /run2/,
    );
  });
});

const flushCancellation = () => new Promise((done) => setImmediate(done));
function cancellationWire(
  transport,
  {
    early = false,
    failCancel = false,
    writeFailure = false,
    unknown = false,
    delayedStatus = false,
    clockFailure = { value: false },
  } = {},
) {
  const rows = [],
    handles = [],
    rpcs = [],
    responseQueue = [];
  const cell = makePlan().cells.find(
    (item) => item.transport === transport && item.variant === "cancel-followup",
  );
  const clock = { value: Number(process.env.OBSERVATION_TEST_CLOCK_MS ?? 0) };
  let requests = 0;
  const meter = createMeter({
    now: () => {
      if (clockFailure.value) throw new Error("clock fixture failure");
      return clock.value;
    },
  });
  meter.enter(cell);
  const wire = createWire({
    meter,
    journal: {
      write(row) {
        if (writeFailure && row.event === "client-cancel")
          throw new Error("cancel persistence failed");
        rows.push(row);
      },
    },
    getToken: async () => "offline-fixture",
    fetch: async (_url, options) => {
      const scripted = responseQueue.shift();
      if (scripted) return new Response(JSON.stringify(scripted.body), { status: scripted.status });
      if (unknown) return new Response("{}", { status: 503 });
      if (early || ++requests > 1) return new Response("{}", { status: 200 });
      return await new Promise((_resolve, reject) => {
        options.signal.addEventListener(
          "abort",
          () => {
            handles.push("abort");
            reject(new Error("client aborted"));
          },
          { once: true },
        );
      });
    },
    client: {
      close() {},
      makeUnaryRequest(_path, _encode, _decode, _raw, _metadata, _options, callback) {
        const rpc = new EventEmitter();
        rpcs.push({ rpc, callback });
        rpc.cancel = () => {
          handles.push("cancel");
          if (failCancel) throw new Error("cancel failed");
          callback({ code: 1, details: "client cancellation" });
          rpc.emit("status", { code: 1, details: "client cancellation" });
        };
        const scripted = responseQueue.shift();
        if (scripted)
          queueMicrotask(() => {
            if (scripted.ok) {
              const service = _path.includes("Publisher") ? "Publisher" : "Subscriber";
              const type = typeOf(SERVICES[service].methods[_path.split("/").at(-1)][1]);
              callback(null, Buffer.from(type.encode(type.fromObject(scripted.body)).finish()));
              rpc.emit("status", { code: 0, details: "" });
            } else {
              const code = { UNKNOWN: 2, NOT_FOUND: 5, PERMISSION_DENIED: 7 }[scripted.code];
              callback({ code, details: scripted.code });
              rpc.emit("status", { code: scripted.statusCode ?? code, details: scripted.code });
            }
          });
        else if (unknown)
          queueMicrotask(() => {
            callback({ code: 14, details: "unavailable" });
            rpc.emit("status", { code: 14, details: "unavailable" });
          });
        else if (early || ++requests > 1) {
          callback(null, Buffer.alloc(0));
          if (!delayedStatus) queueMicrotask(() => rpc.emit("status", { code: 0, details: "" }));
        }
        return rpc;
      },
    },
  });
  const call = {
    category: "pull",
    transport,
    service: "Subscriber",
    method: "Pull",
    request: {
      subscription: `projects/fireemu-oracle-idp/subscriptions/fe123456abcdef-${cell.id.toLowerCase()}-s`,
      maxMessages: 1,
      returnImmediately: false,
    },
    cellId: cell.id,
    cancelObservation: true,
    cancelBinding: {
      outstandingMessageId: "model-A",
      outstandingAckId: "model-a-ack",
      ackedControlMessageId: "model-B",
      ackedControlAckId: "model-b-ack",
      deliveredAt: clock.value,
    },
  };
  return { wire, rows, handles, call, rpcs, clock, responseQueue };
}

for (const transport of ["rest", "grpc"]) {
  test(`C intentional ${transport} pending Pull cancellation preserves unknown and permits follow-up`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = cancellationWire(transport);
    const pending = fixture.wire.call(fixture.call);
    try {
      await flushCancellation();
      assert.equal(fixture.rows.filter((r) => r.event === "request-dispatch").length, 1);
      t.mock.timers.tick(1000);
      await flushCancellation();
      assert.equal(fixture.handles.length, 1, "actual pending transport must be cancelled");
      const reply = await pending;
      assert.equal(reply.unknown, true);
      assert.equal(reply.ok, false);
      assert.equal(reply.clientCancellation?.requestId, 1);
      const event = fixture.rows.find((r) => r.event === "client-cancel");
      assert.equal(event.subscription, fixture.call.request.subscription);
      assert.equal(event.cause, "intentional-unary-cancel");
      assert.equal(event.pending, true);
      fixture.clock.value += 61000;
      const followCall = { ...fixture.call };
      delete followCall.cancelObservation;
      delete followCall.cancelBinding;
      const follow = fixture.wire.call(followCall);
      await follow;
      assert.equal(fixture.rows.filter((r) => r.event === "request-dispatch").length, 2);
    } finally {
      fixture.wire.abortSource();
      await pending.catch(() => {});
      fixture.wire.close();
    }
  });

  test(`C intentional ${transport} Pull completed before cancel has no cancellation witness`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = cancellationWire(transport, { early: true });
    try {
      const reply = await fixture.wire.call(fixture.call);
      t.mock.timers.tick(30000);
      assert.equal(reply.ok, true);
      assert.equal(reply.clientCancellation, undefined);
      assert.equal(fixture.handles.length, 0);
      assert.equal(
        fixture.rows.some((r) => r.event === "client-cancel"),
        false,
      );
    } finally {
      fixture.wire.close();
    }
  });

  test(`C ${transport} cancellation rejects wrong request or cell before dispatch`, async () => {
    for (const edit of [
      (c) => {
        c.method = "Acknowledge";
        c.category = "ackControl";
        c.request.ackIds = ["actual"];
      },
      (c) => {
        c.cellId = transport === "rest" ? "R2" : "N2";
      },
      (c) => {
        c.request.subscription = "projects/fireemu-oracle-idp/subscriptions/foreign";
      },
      (c) => {
        c.request.returnImmediately = true;
      },
      (c) => {
        c.cancelObservation = {};
      },
    ]) {
      const fixture = cancellationWire(transport, { early: true });
      try {
        const call = structuredClone(fixture.call);
        edit(call);
        await assert.rejects(fixture.wire.call(call), /cancel observation/);
        assert.equal(fixture.rows.length, 0);
        assert.equal(fixture.handles.length, 0);
      } finally {
        fixture.wire.close();
      }
    }
  });
}

for (const transport of ["rest", "grpc"]) {
  test(`C ${transport} cancelled pending Pull leaves A outstanding until deadline and preserves ACKed control`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let clock = 0;
    const rows = [],
      cell = makePlan().cells.find(
        (c) => c.transport === transport && c.variant === "cancel-followup",
      );
    const meter = createMeter({ now: () => clock });
    meter.enter(cell);
    const world = referenceWorld({
      pendingCancel: true,
      now: () => clock,
      onPending: () =>
        queueMicrotask(() => {
          clock += 1000;
          t.mock.timers.tick(1000);
        }),
    });
    const wire = referenceWire(meter, world, { write: (r) => rows.push(r) });
    try {
      const result = await scenarios.runCell({
        cell,
        meter,
        wire,
        ledger: createLedger(),
        runId: "123456abcdef",
        journal: { write: (r) => rows.push(r) },
        sleep: async (ms) => {
          clock += ms;
        },
      });
      assert.equal(result.complete, true, result.reason);
      assert.equal(result.cleanupClosed, true);
      const cancel = rows.find((r) => r.event === "client-cancel");
      assert.ok(cancel, "must preserve actual client cancellation");
      const initial = result.observations.find((r) => r.stage === "cancel-original-delivery"),
        replay = result.observations.find((r) => r.stage === "post-deadline-cancel-followup");
      assert.equal(initial.items.length, 2);
      assert.deepEqual(
        replay.items.map((i) => i.message.messageId),
        [initial.items[0].message.messageId],
      );
      assert.ok(replay.clockMs >= initial.clockMs + 60000);
      const acks = world.calls.filter((r) => r.method === "Acknowledge");
      assert.equal(acks.length, 2);
      assert.deepEqual(acks[0].request.ackIds, [initial.items[1].ackId]);
      assert.deepEqual(acks[1].request.ackIds, [replay.items[0].ackId]);
      assert.ok(world.calls.length <= 37);
      assert.ok(world.calls.filter((r) => r.method === "Pull").length <= 8);
      assert.equal(
        world.calls.some((r) => r.method === "StreamingPull"),
        false,
      );
      assert.equal(result.parityEstablished, false);
      assert.ok(
        result.observations.some(
          (r) => r.stage === "prior-cancel-causal-debt" && r.verdict === "NOT_COMPARABLE",
        ),
      );
      t.diagnostic(
        JSON.stringify({
          transport,
          qualification:
            "No-server model; client API action is not captured RST or production semantics",
          events: rows
            .filter((r) =>
              ["request-dispatch", "response", "client-cancel", "delivery-observation"].includes(
                r.event,
              ),
            )
            .map((r) => ({
              event: r.event,
              requestId: r.requestId,
              method: r.method,
              stage: r.stage,
              clockMs: r.clockMs,
              reply: r.reply,
              requestSha256: r.requestSha256,
              requestBodyBase64: r.requestBodyBase64,
              serverOutcome: r.serverOutcome,
              possibleServerLeaseEffect: r.possibleServerLeaseEffect,
              cause: r.cause,
              transportAction: r.transportAction,
              messageIds: r.items?.map((i) => i.message.messageId),
              ackIds: r.items?.map((i) => i.ackId),
            })),
        }),
      );
    } finally {
      wire.close();
    }
  });
  test(`C ${transport} completed second Pull leaves cancellation criterion NOT_COMPARABLE`, async () => {
    const cell = makePlan().cells.find(
        (c) => c.transport === transport && c.variant === "cancel-followup",
      ),
      meter = createMeter({ now: () => 0 });
    meter.enter(cell);
    const world = referenceWorld(),
      wire = referenceWire(meter, world);
    try {
      const result = await scenarios.runCell({
        cell,
        meter,
        wire,
        ledger: createLedger(),
        runId: "123456abcdef",
        journal: { write() {} },
        sleep: async () => {},
      });
      assert.equal(result.complete, false);
      assert.match(result.reason, /cancel.*NOT_COMPARABLE/);
      assert.equal(result.cleanupClosed, true);
    } finally {
      wire.close();
    }
  });
}

for (const transport of ["rest", "grpc"]) {
  test(`C ${transport} unknown mutation still halts without cancellation allowance`, async () => {
    const fixture = cancellationWire(transport, { unknown: true });
    try {
      const mutation = {
        ...fixture.call,
        category: "create",
        method: "CreateTopic",
        service: "Publisher",
        request: { name: "projects/fireemu-oracle-idp/topics/fe123456abcdef-r3-t" },
      };
      delete mutation.cancelObservation;
      const reply = await fixture.wire.call(mutation);
      assert.equal(reply.unknown, true);
      assert.equal(reply.clientCancellation, undefined);
      await assert.rejects(fixture.wire.call(fixture.call), /source stopped/);
      assert.equal(fixture.rows.filter((r) => r.event === "request-dispatch").length, 1);
    } finally {
      fixture.wire.close();
    }
  });
  test(`C ${transport} missing durable cancel event cannot permit follow-up`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = cancellationWire(transport, { writeFailure: true });
    const pending = fixture.wire.call(fixture.call);
    try {
      await flushCancellation();
      t.mock.timers.tick(1000);
      const reply = await pending;
      assert.equal(reply.unknown, true);
      assert.equal(reply.clientCancellation, undefined);
      await assert.rejects(fixture.wire.call(fixture.call), /source stopped/);
      if (transport === "grpc") {
        const before = fixture.rows.length;
        const { rpc, callback } = fixture.rpcs[0];
        assert.equal(rpc.listenerCount("status"), 0);
        callback(null, Buffer.alloc(0));
        rpc.emit("status", { code: 0, details: "late" });
        assert.equal(fixture.rows.length, before);
      }
      const before = fixture.handles.length;
      t.mock.timers.tick(30000);
      assert.equal(fixture.handles.length, before);
    } finally {
      fixture.wire.abortSource();
      await pending.catch(() => {});
      fixture.wire.close();
    }
  });
}

for (const transport of ["rest", "grpc"]) {
  test(`C ${transport} deadline wait cannot spend cleanup reservation`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    let clock = 0;
    const cell = makePlan().cells.find(
        (c) => c.transport === transport && c.variant === "cancel-followup",
      ),
      meter = createMeter({ now: () => clock });
    meter.enter(cell);
    const rows = [],
      world = referenceWorld({
        pendingCancel: true,
        now: () => clock,
        onPending: () =>
          queueMicrotask(() => {
            clock += 1000;
            t.mock.timers.tick(1000);
          }),
      }),
      wire = referenceWire(meter, world, { write: (r) => rows.push(r) });
    try {
      const result = await scenarios.runCell({
        cell,
        meter,
        wire,
        ledger: createLedger(),
        runId: "123456abcdef",
        journal: { write: (r) => rows.push(r) },
        sleep: async (ms) => {
          clock += ms + 80000;
        },
      });
      assert.equal(result.complete, false);
      assert.equal(result.cleanupClosed, true);
      assert.match(result.reason, /time exhausted/);
      assert.equal(world.calls.filter((c) => c.method === "Pull").length, 2);
      assert.equal(
        result.observations.some((r) => r.stage === "post-deadline-cancel-followup"),
        false,
      );
    } finally {
      wire.close();
    }
  });
  test(`C ${transport} unexpected unknown Pull stops without a durable intentional cancel`, async () => {
    const fixture = cancellationWire(transport, { unknown: true });
    try {
      const reply = await fixture.wire.call(fixture.call);
      assert.equal(reply.unknown, true);
      assert.equal(reply.clientCancellation, undefined);
      await assert.rejects(fixture.wire.call(fixture.call), /source stopped/);
    } finally {
      fixture.wire.close();
    }
  });
}

test("C native failed cancel invocation has no witness and late callbacks cannot write", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fixture = cancellationWire("grpc", { failCancel: true }),
    pending = fixture.wire.call(fixture.call);
  try {
    await flushCancellation();
    t.mock.timers.tick(1000);
    const reply = await pending;
    assert.equal(reply.unknown, true);
    assert.equal(reply.clientCancellation, undefined);
    assert.equal(
      fixture.rows.some((r) => r.event === "client-cancel"),
      false,
    );
    await assert.rejects(fixture.wire.call(fixture.call), /source stopped/);
    const before = fixture.rows.length;
    fixture.rpcs[0].callback(null, Buffer.alloc(0));
    fixture.rpcs[0].rpc.emit("status", { code: 0, details: "late" });
    assert.equal(fixture.rows.length, before);
    assert.equal(fixture.rpcs[0].rpc.listenerCount("status"), 0);
    t.mock.timers.tick(30000);
    assert.equal(fixture.handles.length, 1);
  } finally {
    fixture.wire.close();
  }
});

test("C cancellation clock failure rejects finitely without signalling or late writes", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const clockFailure = { value: false };
  const fixture = cancellationWire("grpc", { clockFailure }),
    pending = fixture.wire.call(fixture.call);
  const rejection = assert.rejects(pending, /clock fixture failure/);
  await flushCancellation();
  clockFailure.value = true;
  try {
    assert.doesNotThrow(() => t.mock.timers.tick(1000));
    await rejection;
    assert.equal(fixture.handles.length, 0);
    assert.equal(
      fixture.rows.some((r) => r.event === "client-cancel"),
      false,
    );
    assert.equal(fixture.rpcs[0].rpc.listenerCount("status"), 0);
  } finally {
    fixture.wire.close();
  }
});

test("C intentional native Pull callback before cancel cannot become a witness while status is delayed", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fixture = cancellationWire("grpc", { early: true, delayedStatus: true }),
    pending = fixture.wire.call(fixture.call);
  try {
    await flushCancellation();
    t.mock.timers.tick(1000);
    assert.equal(fixture.handles.length, 0);
    assert.equal(
      fixture.rows.some((r) => r.event === "client-cancel"),
      false,
    );
    fixture.rpcs[0].rpc.emit("status", { code: 0, details: "" });
    const reply = await pending;
    assert.equal(reply.ok, true);
    assert.equal(reply.clientCancellation, undefined);
  } finally {
    fixture.wire.abortSource();
    await pending.catch(() => {});
    fixture.wire.close();
  }
});

for (const transport of ["rest", "grpc"]) {
  test(`C intentional ${transport} cancel continuation refuses early cross-cell and mutation calls`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = cancellationWire(transport),
      pending = fixture.wire.call(fixture.call);
    try {
      await flushCancellation();
      t.mock.timers.tick(1000);
      const reply = await pending;
      assert.equal(reply.unknown, true);
      const call = { ...fixture.call };
      delete call.cancelObservation;
      delete call.cancelBinding;
      await assert.rejects(fixture.wire.call(call), /declared cancel follow-up/);
      fixture.clock.value += 61000;
      for (const edit of [
        (c) => {
          c.cellId = transport === "rest" ? "R4" : "N4";
        },
        (c) => {
          c.method = "Publish";
          c.service = "Publisher";
          c.category = "publish";
          c.request = { topic: "projects/fireemu-oracle-idp/topics/foreign", messages: [] };
        },
        (c) => {
          c.request = {
            ...c.request,
            subscription: "projects/fireemu-oracle-idp/subscriptions/foreign",
          };
        },
      ]) {
        const changed = structuredClone(call);
        edit(changed);
        await assert.rejects(fixture.wire.call(changed), /declared cancel follow-up/);
      }
      assert.equal(fixture.rows.filter((r) => r.event === "request-dispatch").length, 1);
    } finally {
      fixture.wire.abortSource();
      await pending.catch(() => {});
      fixture.wire.close();
    }
  });
}

async function primeCancelFixture(t, fixture) {
  const pending = fixture.wire.call(fixture.call);
  await flushCancellation();
  t.mock.timers.tick(1000);
  const reply = await pending;
  assert.equal(reply.unknown, true);
  assert.ok(reply.clientCancellation);
  fixture.clock.value += 61000;
}
function ordinaryCancelCall(
  fixture,
  method = "Pull",
  category = "pull",
  request = fixture.call.request,
) {
  const call = {
    ...fixture.call,
    method,
    category,
    request,
    service: /Topic|Publish/.test(method) ? "Publisher" : "Subscriber",
  };
  delete call.cancelObservation;
  delete call.cancelBinding;
  return call;
}

test("C scoped REST physical dispatch rejects conflicting route identities before dispatch", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const phase of ["initial", "follow-up", "ACK", "cleanup"])
    for (const variant of ["foreign", "other-project", "encoded-sibling", "conflicting-selector"]) {
      const fixture = cancellationWire("rest", { early: phase === "initial" });
      try {
        if (phase !== "initial") await primeCancelFixture(t, fixture);
        const own = fixture.call.request.subscription;
        const call =
          phase === "initial"
            ? structuredClone(fixture.call)
            : phase === "ACK"
              ? ordinaryCancelCall(fixture, "Acknowledge", "ackControl", {
                  subscription: own,
                  ackIds: ["observed-new-A"],
                })
              : phase === "cleanup"
                ? ordinaryCancelCall(fixture, "DeleteSubscription", "cleanupDelete", { name: own })
                : ordinaryCancelCall(fixture);
        if (variant === "conflicting-selector")
          call.request = {
            ...call.request,
            name: "projects/fireemu-oracle-idp/subscriptions/foreign",
          };
        else
          call.routeName =
            variant === "foreign"
              ? "projects/fireemu-oracle-idp/subscriptions/foreign"
              : variant === "other-project"
                ? own.replace("fireemu-oracle-idp", "foreign-project")
                : `${own}%2Fsibling`;
        const before = fixture.rows.length;
        await assert.rejects(
          fixture.wire.call(call),
          /physical dispatch identity|declared cancel follow-up/,
        );
        assert.equal(fixture.rows.length, before, `${phase}/${variant} must not dispatch`);
      } finally {
        fixture.wire.abortSource();
        fixture.wire.close();
      }
    }
});

test("C scoped REST matching physical route remains accepted", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const fixture = cancellationWire("rest");
  try {
    await primeCancelFixture(t, fixture);
    const call = ordinaryCancelCall(fixture);
    call.routeName = call.request.subscription;
    const reply = await fixture.wire.call(call);
    assert.equal(reply.ok, true);
  } finally {
    fixture.wire.close();
  }
});

for (const transport of ["rest", "grpc"]) {
  test(`C ${transport} own confirmed absence retires probe without retrying unknown DELETE`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = cancellationWire(transport);
    try {
      await primeCancelFixture(t, fixture);
      const own = fixture.call.request.subscription;
      fixture.responseQueue.push({ ok: false, status: 503, code: "UNKNOWN", body: {} });
      const deleted = await fixture.wire.call(
        ordinaryCancelCall(fixture, "DeleteSubscription", "cleanupDelete", { name: own }),
      );
      assert.equal(deleted.unknown, true);
      fixture.responseQueue.push({
        ok: false,
        status: 404,
        code: "NOT_FOUND",
        body: { error: { status: "NOT_FOUND", message: "NOT_FOUND" } },
      });
      const absent = await fixture.wire.call(
        ordinaryCancelCall(fixture, "GetSubscription", "cleanupGet", { name: own }),
      );
      assert.equal(absent.unknown, false);
      assert.equal(absent.code, "NOT_FOUND");
      const next = makePlan().cells.find((c) => c.transport === transport && c.id.endsWith("4"));
      fixture.wire.meter.enter(next);
      const name = `projects/fireemu-oracle-idp/topics/fe123456abcdef-${next.id.toLowerCase()}-t`;
      fixture.responseQueue.push({ ok: true, status: 200, code: "OK", body: { name } });
      const created = await fixture.wire.call({
        category: "create",
        transport,
        service: "Publisher",
        method: "CreateTopic",
        request: { name },
        cellId: next.id,
      });
      assert.equal(created.ok, true);
      assert.equal(
        fixture.rows.filter(
          (r) => r.event === "request-dispatch" && r.method === "DeleteSubscription",
        ).length,
        1,
      );
      assert.equal(deleted.unknown, true);
      t.diagnostic(
        JSON.stringify({
          transport,
          qualification: "No-server decoded cleanup replies; unknown DELETE remains unchanged",
          replies: fixture.rows
            .filter((r) => r.event === "response")
            .map((r) => ({ method: r.method, reply: r.reply })),
        }),
      );
    } finally {
      fixture.wire.close();
    }
  });
  test(`C ${transport} ambiguous or other-resource absence cannot retire probe`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    for (const kind of [
      "ambiguous",
      "malformed404",
      "permission",
      "topic",
      "topic-as-subscription",
      "foreign",
    ]) {
      const fixture = cancellationWire(transport);
      try {
        await primeCancelFixture(t, fixture);
        const own = fixture.call.request.subscription;
        if (kind === "foreign") {
          const before = fixture.rows.length;
          await assert.rejects(
            fixture.wire.call(
              ordinaryCancelCall(fixture, "GetSubscription", "cleanupGet", {
                name: "projects/fireemu-oracle-idp/subscriptions/foreign",
              }),
            ),
            /declared cancel follow-up/,
          );
          assert.equal(fixture.rows.length, before);
        } else {
          const code =
            kind === "ambiguous"
              ? "UNKNOWN"
              : kind === "permission"
                ? "PERMISSION_DENIED"
                : "NOT_FOUND";
          fixture.responseQueue.push({
            ok: false,
            status: kind === "ambiguous" ? 503 : kind === "permission" ? 403 : 404,
            code,
            ...(kind === "malformed404" ? { statusCode: 14 } : {}),
            body: { error: { status: kind === "malformed404" ? "UNKNOWN" : code, message: code } },
          });
          const reply = await fixture.wire.call(
            ordinaryCancelCall(
              fixture,
              kind === "topic" ? "GetTopic" : "GetSubscription",
              "cleanupGet",
              {
                name: ["topic", "topic-as-subscription"].includes(kind)
                  ? own.replace("/subscriptions/", "/topics/").replace(/-s$/, "-t")
                  : own,
              },
            ),
          );
          assert.equal(reply.unknown, ["ambiguous", "malformed404"].includes(kind));
        }
        await assert.rejects(
          fixture.wire.call({
            category: "create",
            transport,
            service: "Publisher",
            method: "CreateTopic",
            request: { name: "projects/fireemu-oracle-idp/topics/fe123456abcdef-r4-t" },
            cellId: transport === "rest" ? "R4" : "N4",
          }),
          /declared cancel follow-up/,
        );
      } finally {
        fixture.wire.close();
      }
    }
  });
  test(`C ${transport} own absence never resets an existing ordinary source stop`, async (t) => {
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const fixture = cancellationWire(transport);
    try {
      await primeCancelFixture(t, fixture);
      const own = fixture.call.request.subscription;
      fixture.responseQueue.push({ ok: false, status: 503, code: "UNKNOWN", body: {} });
      assert.equal((await fixture.wire.call(ordinaryCancelCall(fixture))).unknown, true);
      fixture.responseQueue.push({
        ok: false,
        status: 404,
        code: "NOT_FOUND",
        body: { error: { status: "NOT_FOUND", message: "NOT_FOUND" } },
      });
      assert.equal(
        (
          await fixture.wire.call(
            ordinaryCancelCall(fixture, "GetSubscription", "cleanupGet", { name: own }),
          )
        ).unknown,
        false,
      );
      await assert.rejects(
        fixture.wire.call({
          category: "create",
          transport,
          service: "Publisher",
          method: "CreateTopic",
          request: { name: "projects/fireemu-oracle-idp/topics/fe123456abcdef-r4-t" },
          cellId: transport === "rest" ? "R4" : "N4",
        }),
        /source stopped/,
      );
    } finally {
      fixture.wire.close();
    }
  });
}

test("C R8 N8 ordering publications are three separately bound budgeted calls before NACK", async (t) => {
  for (const transport of ["rest", "grpc"]) {
    await t.test(transport, async () => {
      const cell = makePlan().cells.find(
        (c) => c.transport === transport && c.variant === "nack-blocked-key",
      );
      const meter = createMeter({ now: () => 0 }),
        world = referenceWorld(),
        rows = [],
        ledger = createLedger();
      meter.enter(cell);
      const wire = referenceWire(meter, world, { write: (row) => rows.push(row) });
      try {
        const result = await scenarios.runCell({
          cell,
          meter,
          wire,
          ledger,
          runId: "123456abcdef",
          journal: { write: (row) => rows.push(row) },
          sleep: async () => {},
        });
        assert.equal(result.complete, true, `${cell.id}: ${result.reason}`);
        assert.equal(result.cleanupClosed, true);
        assert.equal(result.budgetOverrun, false);
        assert.equal(ledger.outstanding().length, 0);
        assert.equal(world.resources.size, 0);
        const publications = world.calls.filter((call) => call.method === "Publish");
        assert.equal(publications.length, 3);
        assert.deepEqual(
          publications.map((call) => call.request.messages.map((m) => m.orderingKey)),
          [["key-A"], ["key-A"], ["key-B"]],
        );
        assert.deepEqual(
          publications.map((call) => call.request.messages[0].attributes.seq),
          ["0", "1", "0"],
        );
        const bindings = rows.filter(
          (row) => row.event === "delivery-observation" && row.stage === "publication-binding",
        );
        assert.equal(bindings.length, 3);
        for (let index = 0; index < 3; index++) {
          assert.equal(bindings[index].topic, publications[index].request.topic);
          assert.deepEqual(bindings[index].messages, publications[index].request.messages);
          assert.deepEqual(bindings[index].messageIds, [`own-${index + 1}`]);
          assert.equal(
            Buffer.from(bindings[index].messages[0].data, "base64").toString(),
            `123456abcdef:${cell.id}:${index}`,
          );
        }
        const predecessor = result.observations.find(
          (row) => row.stage === "outstanding-predecessor",
        ).items[0];
        const nackIndex = world.calls.findIndex((call) => call.method === "ModifyAckDeadline");
        assert.ok(publications.every((call) => world.calls.indexOf(call) < nackIndex));
        assert.deepEqual(world.calls[nackIndex].request.ackIds, [predecessor.ackId]);
        assert.equal(world.calls[nackIndex].request.ackDeadlineSeconds, 0);
        const before = result.observations.find((row) => row.stage === "before-predecessor-ACK");
        assert.ok(
          before.items.some((item) => item.message.messageId === bindings[0].messageIds[0]),
        );
        assert.ok(
          before.items.some((item) => item.message.messageId === bindings[2].messageIds[0]),
        );
        assert.equal(
          before.items.some((item) => item.message.messageId === bindings[1].messageIds[0]),
          false,
        );
        const after = result.observations.find((row) => row.stage === "after-predecessor-ACK");
        assert.deepEqual(
          after.items.map((item) => item.message.messageId),
          bindings[1].messageIds,
        );
        const acks = world.calls.filter((call) => call.method === "Acknowledge");
        assert.deepEqual(
          acks.map((call) => call.request.ackIds),
          [before.items.map((item) => item.ackId), after.items.map((item) => item.ackId)],
        );
        assert.equal(categoryCaps(cell.group).publish, 3);
        assert.ok(world.calls.length <= 37);
      } finally {
        wire.close();
      }
    });
  }
});

test("C publish ordering-key model matches homogeneous-key reference for every small key vector", () => {
  const topic = "projects/demo-app/topics/key-property";
  const keys = [undefined, "", "key-A", "key-B"];
  for (let length = 1; length <= 3; length++) {
    for (let value = 0; value < keys.length ** length; value++) {
      const world = referenceWorld();
      world.answer("CreateTopic", { name: topic });
      const messages = Array.from({ length }, (_, index) => ({
        data: "eA==",
        orderingKey: keys[Math.floor(value / keys.length ** index) % keys.length],
      }));
      const reply = world.answer("Publish", { topic, messages });
      const homogeneous = messages.every(
        (message) => (message.orderingKey ?? "") === (messages[0].orderingKey ?? ""),
      );
      assert.equal(reply.ok, homogeneous);
      assert.equal(world.messages.size, homogeneous ? length : 0);
      if (homogeneous) assert.equal(reply.body.messageIds.length, length);
      else {
        assert.equal(reply.status, 400);
        assert.equal(reply.code, "FAILED_PRECONDITION");
        assert.equal(reply.body.messageIds, undefined);
      }
    }
  }
});

test("C R8 N8 unbound follower or control stops before NACK without adopting its IDs", async () => {
  for (const transport of ["rest", "grpc"]) {
    for (const ordinal of [2, 3]) {
      for (const fault of ["refused", "missing-IDs"]) {
        const cell = makePlan().cells.find(
            (c) => c.transport === transport && c.variant === "nack-blocked-key",
          ),
          meter = createMeter({ now: () => 0 }),
          world = referenceWorld(),
          rows = [];
        const answer = world.answer;
        let publishCount = 0;
        world.answer = (method, request) => {
          if (method === "Publish" && ++publishCount === ordinal) {
            world.calls.push({ method, request: structuredClone(request) });
            return fault === "refused"
              ? {
                  ok: false,
                  code: "FAILED_PRECONDITION",
                  status: 400,
                  body: {
                    error: { status: "FAILED_PRECONDITION", message: "same ordering key required" },
                  },
                }
              : { ok: true, code: "OK", status: 200, body: { messageIds: [] } };
          }
          return answer(method, request);
        };
        meter.enter(cell);
        const wire = referenceWire(meter, world);
        try {
          const result = await scenarios.runCell({
            cell,
            meter,
            wire,
            ledger: createLedger(),
            runId: "123456abcdef",
            journal: { write: (row) => rows.push(row) },
            sleep: async () => {},
          });
          assert.equal(result.complete, false, `${transport}/${ordinal}/${fault}`);
          assert.equal(result.reason, "publication is not bound");
          assert.equal(result.cleanupClosed, true);
          assert.equal(world.resources.size, 0);
          assert.equal(
            world.calls.filter((call) => ["ModifyAckDeadline", "Acknowledge"].includes(call.method))
              .length,
            0,
          );
          assert.equal(
            rows.filter((row) => row.stage === "publication-binding").length,
            ordinal - 1,
          );
          assert.equal(world.calls.filter((call) => call.method === "Publish").length, ordinal);
        } finally {
          wire.close();
        }
      }
    }
  }
});

test("C R8 N8 predecessor search preserves unrelated batches within three attempts", async (t) => {
  for (const transport of ["rest", "grpc"]) {
    for (const mode of ["redelivery", "absent", "premature-follower", "foreign", "missing-token"]) {
      await t.test(`${transport}/${mode}`, async () => {
        const cell = makePlan().cells.find(
          (value) => value.transport === transport && value.variant === "nack-blocked-key",
        );
        const meter = createMeter({ now: () => 0 }),
          world = referenceWorld(),
          rows = [],
          ledger = createLedger(),
          waits = [];
        const answer = world.answer;
        let nacked = false,
          beforeAttempts = 0,
          predecessor,
          beforeAck = false;
        world.answer = (method, request) => {
          if (method === "ModifyAckDeadline") nacked = true;
          if (method === "Acknowledge" && nacked) beforeAck = true;
          if (method === "Pull" && nacked && !beforeAck) {
            beforeAttempts++;
            if (beforeAttempts === 1) {
              const reply = answer(method, request);
              predecessor = reply.body.receivedMessages.find(
                (item) => item.message.messageId === "own-1",
              );
              const control = reply.body.receivedMessages.find(
                (item) => item.message.messageId === "own-3",
              );
              assert.ok(predecessor);
              assert.ok(control);
              const items = [control];
              if (mode === "premature-follower")
                items.push({
                  ackId: "premature-follower-token",
                  message: world.messages.get("own-2").message,
                });
              if (mode === "foreign")
                items[0] = { ...control, message: { ...control.message, messageId: "foreign" } };
              if (mode === "missing-token") items[0] = { ...control, ackId: "" };
              return { ...reply, body: { receivedMessages: items } };
            }
            world.calls.push({ method, request: structuredClone(request) });
            return {
              ok: true,
              code: "OK",
              status: 200,
              body: mode === "absent" ? {} : { receivedMessages: [predecessor] },
            };
          }
          return answer(method, request);
        };
        meter.enter(cell);
        const wire = referenceWire(meter, world, { write: (row) => rows.push(row) });
        try {
          const result = await scenarios.runCell({
            cell,
            meter,
            wire,
            ledger,
            runId: "123456abcdef",
            journal: { write: (row) => rows.push(row) },
            sleep: async (ms) => waits.push(ms),
          });
          assert.equal(result.cleanupClosed, true);
          assert.equal(result.budgetOverrun, false);
          assert.equal(ledger.outstanding().length, 0);
          assert.equal(world.resources.size, 0);
          const before = result.observations.filter(
            (row) => row.stage === "before-predecessor-ACK",
          );
          if (["foreign", "missing-token"].includes(mode)) {
            assert.equal(result.complete, false);
            assert.match(result.reason, /foreign|unbound/);
            assert.equal(beforeAttempts, 1);
            assert.equal(beforeAck, false);
          } else if (mode === "absent") {
            assert.equal(result.complete, false);
            assert.match(
              result.reason,
              /correlated predecessor redelivery missing; NOT_COMPARABLE/,
            );
            assert.equal(beforeAttempts, 3);
            assert.deepEqual(
              before.map((row) => row.attempt),
              [0, 1, 2],
            );
            assert.deepEqual(
              before.map((row) => row.items.map((item) => item.message.messageId)),
              [["own-3"], [], []],
            );
            assert.equal(beforeAck, false);
            assert.deepEqual(waits, [1000, 1000, 1000]);
          } else {
            assert.equal(result.complete, true, result.reason);
            assert.equal(beforeAttempts, 2);
            assert.deepEqual(
              before.map((row) => row.attempt),
              [0, 1],
            );
            assert.deepEqual(
              before[0].items.map((item) => item.message.messageId),
              mode === "premature-follower" ? ["own-3", "own-2"] : ["own-3"],
            );
            assert.deepEqual(
              before[1].items.map((item) => item.message.messageId),
              ["own-1"],
            );
            const ack = world.calls.find((call) => call.method === "Acknowledge");
            assert.deepEqual(
              ack.request.ackIds,
              before.flatMap((row) => row.items.map((item) => item.ackId)),
            );
            const initial = result.observations.find(
              (row) => row.stage === "outstanding-predecessor",
            ).items[0];
            assert.notEqual(predecessor.ackId, initial.ackId);
            assert.deepEqual(waits, [1000, 1000]);
          }
          assert.ok(
            world.calls.filter((call) => call.method === "Pull").length <=
              categoryCaps(cell.group).pull,
          );
        } finally {
          wire.close();
        }
      });
    }
  }
});

const supplementalCells = () =>
  makePlan().cells.filter((c) => c.variant === "wrong-topic-snapshot");
async function originWitnessWorld(
  cell,
  {
    originAttempt = 1,
    beforeAttempt = 1,
    afterAttempt = 1,
    epoch = 0,
    fault = null,
    latency = 0,
    maxLatency = false,
  } = {},
) {
  let clock = epoch,
    originPulls = 0,
    beforePulls = 0,
    afterPulls = 0,
    sought = false;
  const manifest = scenarios.graph(cell, "123456abcdef"),
    rows = [],
    dispatches = [],
    ledger = createLedger();
  const elapsed = (method) =>
    maxLatency ? (method.startsWith("Create") ? 80000 : 30000) : latency;
  const world = referenceWorld({
    now: () => clock,
    clock: (method) => {
      clock += elapsed(method);
    },
  });
  const original = world.answer;
  world.answer = (method, request) => {
    if (method === "Seek") sought = true;
    const origin = method === "Pull" && request.subscription === manifest.origin;
    if (method === "Pull") {
      const attempt = origin ? ++originPulls : sought ? ++afterPulls : ++beforePulls;
      const required = origin ? originAttempt : sought ? afterAttempt : beforeAttempt;
      if ((origin && fault === "empty") || attempt < required) {
        world.calls.push({ method, request: structuredClone(request) });
        clock += elapsed(method);
        return { ok: true, code: "OK", status: 200, body: {} };
      }
    }
    const reply = original(method, request);
    if (
      fault === "wrong-topic" &&
      method === "CreateSubscription" &&
      request.name === manifest.origin
    )
      world.resources.set(manifest.origin, {
        ...world.resources.get(manifest.origin),
        topic: manifest.topic,
      });
    if (origin && reply.body.receivedMessages?.length) {
      const message = reply.body.receivedMessages[0].message;

      if (fault === "foreign-id") message.messageId = "foreign";
      if (fault === "foreign-payload") message.data = "Zm9yZWlnbg==";
      if (fault === "foreign-marker") message.attributes = { recorderRun: "foreign" };
    }
    return reply;
  };
  const plan = makePlan({ selection: "snapshot-origin-witness" }),
    meter = createMeter({ now: () => clock, plan });
  meter.enter(cell);
  const wire = referenceWire(meter, world, { write: (row) => rows.push(structuredClone(row)) });
  const codecCall = wire.call;
  wire.call = async (call) => {
    dispatches.push({ ...structuredClone(call), at: clock });
    const reply = await codecCall(call);
    if (
      call.method === "Pull" &&
      call.request.subscription === manifest.origin &&
      reply.body.receivedMessages?.length
    ) {
      const message = reply.body.receivedMessages[0].message;
      if (fault === "missing-time") delete message.publishTime;
      if (fault === "illegal-time") message.publishTime = "2026-02-30T00:00:00Z";
      if (fault === "bad-time") message.publishTime = "not-a-timestamp";
      if (fault === "fraction-width") message.publishTime = "2026-10-07T00:00:00.1Z";
      if (fault === "year-zero") message.publishTime = "0000-01-01T00:00:00Z";
      if (fault === "offset-time") message.publishTime = "2026-10-07T00:00:00+00:00";
    }
    return reply;
  };
  let result;
  try {
    result = await scenarios.runCell({
      cell,
      meter,
      wire,
      ledger,
      runId: "123456abcdef",
      journal: {
        write: (row) => rows.push(structuredClone(row)),
        recovery: (row) => rows.push({ event: "model-recovery", ...structuredClone(row) }),
      },
      sleep: async (ms) => {
        clock += ms;
      },
    });
  } finally {
    wire.close();
  }
  return { result, world, rows, meter, manifest, clock, originPulls, dispatches };
}

test("C supplemental fixed selection preserves both transports and exact reduced caps", () => {
  const plan = makePlan({ selection: "snapshot-origin-witness" });
  assert.deepEqual(
    plan.cells.map((c) => c.id),
    ["R11", "N11"],
  );
  assert.deepEqual(plan.cells, supplementalCells());
  assert.ok(plan.cells.every((c) => !c.reserve));
  assert.deepEqual(plan.caps.G2, { requests: 68, rest: 34, grpc: 34, streams: 0, cellMs: 180000 });
  assert.deepEqual(
    [
      plan.caps.sourceRequests,
      plan.caps.totalRequests,
      plan.caps.sourceWallMs,
      plan.caps.smallPublishes,
      plan.caps.cleanupReserveMs,
    ],
    [68, 82, 360000, 4, 40000],
  );
  assert.deepEqual(plan.caps.G7, CAPS.G7);
  assert.deepEqual(plan.timeoutPolicy, makePlan().timeoutPolicy);
  assert.deepEqual(validatePlan(plan), plan);
  for (const mutate of [
    (p) => p.cells.pop(),
    (p) => p.caps.G2.requests++,
    (p) => p.caps.sourceWallMs++,
    (p) => (p.selection = "unknown"),
  ]) {
    const changed = structuredClone(plan);
    mutate(changed);
    assert.throws(() => validatePlan(changed));
  }
});

test("C supplemental origin witness precedes Snapshot without ACK across bounded codec histories", async () => {
  for (const cell of supplementalCells())
    for (const epoch of [0, 3600000])
      for (const originAttempt of [1, 2])
        for (const beforeAttempt of [1, 2, 3])
          for (const afterAttempt of [1, 2, 3]) {
            const w = await originWitnessWorld(cell, {
              epoch,
              originAttempt,
              beforeAttempt,
              afterAttempt,
              latency: 1000,
            });
            assert.equal(w.result.complete, true, w.result.reason);
            assert.equal(w.result.cleanupClosed, true);
            assert.equal(w.world.resources.size, 0);
            assert.equal(w.originPulls, originAttempt);
            const originPublish = w.world.calls.findIndex(
              (c) => c.method === "Publish" && c.request.topic === w.manifest.otherTopic,
            );
            const originPull = w.world.calls.findIndex(
              (c) => c.method === "Pull" && c.request.subscription === w.manifest.origin,
            );
            const snapshot = w.world.calls.findIndex((c) => c.method === "CreateSnapshot");
            assert.ok(originPublish < originPull && originPull < snapshot);
            assert.equal(
              w.world.calls.filter(
                (c) =>
                  ["Acknowledge", "ModifyAckDeadline"].includes(c.method) &&
                  c.request.subscription === w.manifest.origin,
              ).length,
              0,
            );
            const witness = w.result.observations.find(
              (o) => o.stage === "snapshot-origin-saved-time",
            );
            const saved = w.world.messages.get(witness.messageId).message;
            assert.equal(witness.publishTime, saved.publishTime);
            assert.equal(witness.subscription, w.manifest.origin);
            assert.equal(witness.topic, w.manifest.otherTopic);
            assert.equal(witness.messageId, "own-1");
            assert.equal(w.world.snapshots.get(w.manifest.snapshot).acknowledged.size, 0);
            assert.equal(
              w.world.calls.filter((c) => c.method === "Pull").length,
              originAttempt + beforeAttempt + afterAttempt,
            );
            assert.equal(w.world.calls.length, 26 + originAttempt + beforeAttempt + afterAttempt);
            assert.ok(w.world.calls.length <= 34);
            assert.ok(w.rows.some((r) => r.event === "response" && r.transport === cell.transport));
            assert.ok(
              w.result.observations.some((o) => o.stage === "wrong-topic-Seek" && !o.reply.ok),
            );
            assert.ok(
              w.result.observations.some((o) => o.stage === "target-config-after-wrong-Seek"),
            );
            assert.equal(
              w.world.calls.filter(
                (c) =>
                  c.method === "Acknowledge" && c.request.subscription === w.manifest.subscription,
              ).length,
              2,
            );
            assert.equal(
              w.world.calls.filter(
                (c) =>
                  c.method === "ModifyAckDeadline" &&
                  c.request.subscription === w.manifest.subscription,
              ).length,
              1,
            );
          }
});

test("C supplemental absent malformed and foreign origin witnesses cannot complete", async () => {
  for (const cell of supplementalCells())
    for (const fault of [
      "empty",
      "missing-time",
      "illegal-time",
      "bad-time",
      "foreign-id",
      "foreign-payload",
      "foreign-marker",
      "wrong-topic",
      "fraction-width",
      "year-zero",
      "offset-time",
    ]) {
      const w = await originWitnessWorld(cell, { fault });
      assert.equal(w.result.complete, false, `${cell.id}/${fault}`);
      assert.equal(w.result.cleanupClosed, true);
      assert.equal(w.world.resources.size, 0);
      assert.equal(w.world.calls.filter((c) => c.method === "CreateSnapshot").length, 0);
      if (fault === "empty") assert.equal(w.originPulls, 2);
    }
});

test("C supplemental near-cutoff and maximum legal timing remain incomplete with durable obligations", async () => {
  for (const cell of supplementalCells())
    for (const epoch of [0, 3600000])
      for (const options of [
        { latency: 10000, originAttempt: 2 },
        { latency: 30000 },
        { maxLatency: true },
      ]) {
        const w = await originWitnessWorld(cell, { ...options, epoch });
        assert.equal(w.result.complete, false);
        assert.ok(w.clock <= epoch + 180000 + 5 * 30000);
        assert.equal(w.result.parityEstablished, false);
        assert.ok(
          w.result.cleanupClosed ||
            w.rows.some((row) => row.event === "model-recovery" && row.obligations.length > 0),
        );
        for (const call of w.dispatches) {
          const end = epoch + (call.category.startsWith("cleanup") ? 180000 : 140000);
          assert.ok(call.at + minimumCallMs(call.method) <= end, `${cell.id}/${call.method}`);
        }
      }
});

test("C supplemental real meter enforces exact transport ceilings within unused category slots", () => {
  const plan = makePlan({ selection: "snapshot-origin-witness" }),
    meter = createMeter({ now: () => 0, plan });
  const counts = {
    create: 5,
    get: 5,
    publish: 2,
    pull: 8,
    ackControl: 3,
    other: 1,
    cleanupDelete: 5,
    cleanupGet: 5,
  };
  for (const cell of plan.cells) {
    meter.enter(cell);
    for (const [category, count] of Object.entries(counts))
      for (let i = 0; i < count; i++) meter.start(category, cell.transport);
    assert.throws(() => meter.start("publish", cell.transport), /request cap/);
  }
  assert.equal(meter.snapshot().requests, 68);
  assert.deepEqual(meter.snapshot().groups.G2, { requests: 68, rest: 34, grpc: 34, streams: 0 });
});

test("C supplemental admitted recorder completes exactly both fixed cells", async (t) => {
  const plan = makePlan({ selection: "snapshot-origin-witness" });
  await withCAdmission(t, plan, plan, async ({ admit, options }) => {
    const admitted = admit(options),
      signals = new EventEmitter();
    let clock = 0;
    t.mock.method(performance, "now", () => clock);
    const world = referenceWorld({ now: () => clock });
    const summary = await main(
      [
        "--record",
        ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap(
          (key) => [`--${key}`, key === "run-id" ? options.runId : options[key]],
        ),
      ],
      {
        admit: () => admitted,
        sleep: async (ms) => {
          clock += ms;
        },
        signals,
        print() {},
        setExitCode() {},
        createCredentials: () => async () => "offline-fixture",
        createWire: (o) => referenceWire(o.meter, world, o.journal),
      },
    );
    assert.deepEqual(
      summary.results.map((r) => r.cellId),
      ["R11", "N11"],
    );
    assert.equal(summary.recordingComplete, true);
    assert.equal(summary.resourcesClosed, true);
    assert.equal(world.calls.length, 58);
    assert.equal(world.resources.size, 0);
    assert.equal(summary.parentClosureReady, false);
    assert.equal(signals.listenerCount("SIGTERM") + signals.listenerCount("SIGINT"), 0);
  });
});
