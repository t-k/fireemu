import assert from "node:assert/strict";
import test from "node:test";
import { makePlan, CAPS, categoryCaps } from "./pubsub-observation-d/plan.mjs";
import { createMeter } from "./pubsub-observation-d/meter.mjs";

test("D independent fixed approval vector and nontransferable categories", () => {
  const p = makePlan(),
    cells = p.cells.filter((c) => !c.reserve);
  assert.deepEqual(p.groups, ["G5", "G7"]);
  assert.equal(cells.length, 12);
  assert.equal(p.cells.length, 14);
  const expected = {
    create: 4,
    resourceGet: 4,
    baselineIamGet: 2,
    publish: 1,
    sourcePull: 60,
    sinkPull: 60,
    nack: 60,
    ownAck: 2,
    cleanupDelete: 4,
    cleanupGet: 4,
  };
  let rest = 0,
    grpc = 0;
  for (const c of p.cells) {
    const cats = categoryCaps(c),
      managed = c.arm === "managed-grant-readback-wait";
    for (const [key, value] of Object.entries(expected)) assert.equal(cats[key], value);
    assert.equal(
      Object.values(cats).reduce((a, b) => a + b, 0),
      managed ? 211 : 201,
    );
    const iam = managed ? 12 : 2,
      ordinary = 199;
    rest += iam + (c.transport === "rest" ? ordinary : 0);
    grpc += c.transport === "grpc" ? ordinary : 0;
  }
  assert.deepEqual(
    [rest, grpc, CAPS.sourceRequests, CAPS.totalRequests, CAPS.sourceWallMs],
    [1501, 1393, 2894, 2908, 19800000],
  );
  assert.equal(p.iam.waitAfterLastGrantMs, 900000);
  assert.equal(p.iam.convergenceClaim, false);
  assert.equal(categoryCaps({ group: "G7" }).iamRead, 2);
});

test("D generated category histories admit only native ordinary and REST IAM within201/211", () => {
  for (const cell of makePlan().cells) {
    const m = createMeter({ now: () => 0 });
    m.enter(cell);
    for (const [category, limit] of Object.entries(categoryCaps(cell))) {
      const transport =
        category.includes("Iam") || category.startsWith("iam") || category.startsWith("cleanupIam")
          ? "rest"
          : cell.transport;
      if (limit) {
        assert.throws(() => m.start(category, transport === "rest" ? "grpc" : "rest"));
      }
      for (let n = 0; n < limit; n++) m.start(category, transport);
      assert.throws(() => m.start(category, transport));
    }
    assert.equal(m.snapshot().requests, cell.arm === "managed-grant-readback-wait" ? 211 : 201);
    assert.throws(() => m.enter(cell));
  }
});

import { graph, runCell } from "./pubsub-observation-d/scenarios.mjs";
import { route, encodeRequest, typeOf } from "./pubsub-observation-d/wire.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
const clockEpoch = Number(process.env.OBSERVATION_TEST_CLOCK_MS ?? 0);
const principal = "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com";
function world(
  cell,
  {
    fault = null,
    latency = false,
    empty = false,
    tick = { value: clockEpoch },
    meterOverride = null,
    forwarding = true,
    countDispatch = true,
  } = {},
) {
  let serial = 0,
    sourceDeliveries = 0;
  const resources = new Map(),
    policies = new Map(),
    calls = [],
    rows = [];
  const meter = meterOverride ?? createMeter({ now: () => tick.value });
  if (!meterOverride) meter.enter(cell);
  const journal = { write: (r) => rows.push(structuredClone(r)) };
  const ledger = createLedger();
  let sourceId,
    data,
    attributes,
    publishedAt,
    leaseUntil = 0;
  const wire = {
    async call(call) {
      if (countDispatch) meter.start(call.category, call.transport);
      calls.push({ ...structuredClone(call), at: tick.value });
      const { method, request: r } = call;
      tick.value += latency
        ? method === "CreateTopic"
          ? 37666
          : method === "CreateSubscription"
            ? 13024
            : method === "Pull"
              ? r.returnImmediately
                ? 3500
                : 19530
              : method.startsWith("Delete")
                ? 7665
                : 1000
        : 0;
      if (fault?.(call, calls)) return { ok: false, unknown: true, code: "UNKNOWN", body: {} };
      const name = r.name ?? r.topic ?? r.subscription ?? r.resource;
      let body = {};
      let status = 200;
      if (method.startsWith("Create")) {
        assert.equal(r.name, name);
        if (method === "CreateSubscription") assert.ok(resources.has(r.topic));
        resources.set(name, r);
        policies.set(name, { etag: "AAAB" });
        body = r;
      } else if (method === "GetIamPolicy") body = structuredClone(policies.get(name));
      else if (method === "SetIamPolicy") {
        const current = policies.get(name);
        assert.equal(r.policy.etag, current.etag);
        body = { ...structuredClone(r.policy), etag: "AAAAAAAAAAC=", version: 1 };
        policies.set(name, body);
      } else if (method.startsWith("Get")) {
        if (resources.has(name)) body = resources.get(name);
        else {
          status = 404;
          body = { error: { status: "NOT_FOUND" } };
        }
      } else if (method.startsWith("Delete")) {
        resources.delete(name);
      } else if (method === "Publish") {
        publishedAt = tick.value;
        sourceId = String(++serial);
        data = r.messages[0].data;
        attributes = r.messages[0].attributes;
        body = { messageIds: [sourceId] };
      } else if (method === "Pull") {
        assert.equal(r.returnImmediately, call.category === "sinkPull");
        body = { receivedMessages: [] };
        if (
          !empty &&
          call.category === "sourcePull" &&
          sourceDeliveries < (forwarding ? 5 : 60) &&
          tick.value >= leaseUntil &&
          tick.value - publishedAt <
            Number(resources.get(name).messageRetentionDuration.slice(0, -1)) * 1000
        ) {
          leaseUntil = tick.value + 10000;
          sourceDeliveries++;
          body.receivedMessages = [
            {
              ackId: `own-ack-${sourceDeliveries}`,
              deliveryAttempt: sourceDeliveries,
              message: {
                messageId: sourceId,
                data,
                attributes,
                publishTime: "2026-01-01T00:00:00.123456789Z",
              },
            },
          ];
        }
        if (
          !empty &&
          forwarding &&
          call.category === "sinkPull" &&
          sourceDeliveries >= 5 &&
          serial === 1
        ) {
          serial++;
          body.receivedMessages = [
            {
              ackId: "sink-own",
              message: {
                messageId: "forward-2",
                data,
                attributes: {
                  ...attributes,
                  CloudPubSubDeadLetterSourceSubscription: graph(cell, "123456abcdef")
                    .subscription.split("/")
                    .at(-1),
                  CloudPubSubDeadLetterSourceSubscriptionProject: "fireemu-oracle-idp",
                  CloudPubSubDeadLetterSourceDeliveryCount: "5",
                  CloudPubSubDeadLetterSourceTopicPublishTime: "2026-01-01T00:00:00.123456789Z",
                },
              },
            },
          ];
        }
      } else if (method === "ModifyAckDeadline") {
        assert.equal(r.ackDeadlineSeconds, 0);
        leaseUntil = tick.value;
      } else assert.equal(method, "Acknowledge");
      return {
        ok: status === 200,
        unknown: false,
        status,
        code: status === 200 ? "OK" : "NOT_FOUND",
        body,
      };
    },
  };
  return {
    cell,
    meter,
    wire,
    ledger,
    runId: "123456abcdef",
    journal,
    serviceAgent: principal,
    sleep: async (ms) => {
      tick.value += ms;
    },
    calls,
    rows,
    resources,
    policies,
    clock: () => tick.value,
  };
}

test("D finite REST/native four-resource graphs, exact IAM routes and SDK selectors", () => {
  for (const c of makePlan().cells) {
    const g = graph(c, "123456abcdef");
    assert.equal(g.resources.length, 4);
    const sub = g.resources.find((r) => r.name === g.subscription);
    assert.equal(sub.request.deadLetterPolicy.deadLetterTopic, g.deadTopic);
    assert.equal(sub.request.deadLetterPolicy.maxDeliveryAttempts, 5);
    assert.equal(sub.request.ackDeadlineSeconds, 10);
    for (const r of g.resources) {
      assert.equal(route(r.method, r.request).verb, "PUT");
      const type = typeOf(r.method === "CreateTopic" ? "Topic" : "Subscription");
      assert.equal(
        type.decode(
          encodeRequest(
            r.method === "CreateTopic" ? "Publisher" : "Subscriber",
            r.method,
            r.request,
          ),
        ).name,
        r.name,
      );
    }
  }
  assert.equal(
    route("GetIamPolicy", { resource: "projects/p/topics/t", requestedPolicyVersion: 3 }).url,
    "https://pubsub.googleapis.com/v1/projects/p/topics/t:getIamPolicy?options.requestedPolicyVersion=3",
  );
  assert.deepEqual(
    route("SetIamPolicy", { resource: "projects/p/subscriptions/s", policy: { etag: "AAAB" } }),
    {
      url: "https://pubsub.googleapis.com/v1/projects/p/subscriptions/s:setIamPolicy",
      verb: "POST",
      body: { policy: { etag: "AAAB" } },
    },
  );
});

test("D independent model exercises all12cells, own ACKs, no-new-grant and preserved IAM restoration", async () => {
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    const w = world(cell);
    const result = await runCell(w);
    assert.equal(result.complete, true, JSON.stringify(result));
    assert.equal(result.cleanupClosed, true);
    assert.equal(w.resources.size, 0);
    assert.equal(result.parityEstablished, false);
    const sets = w.calls.filter((c) => c.method === "SetIamPolicy");
    assert.equal(sets.length, cell.arm === "no-new-grant" ? 0 : 4);
    for (const call of w.calls.filter((c) => c.method.includes("Iam")))
      assert.equal(call.transport, "rest");
    assert.ok(
      w.rows
        .filter((r) => r.event === "iam-evidence")
        .every((r) => r.assessment.status === "needs-review"),
    );
    if (cell.arm !== "no-new-grant") {
      const publish = w.calls.find((c) => c.method === "Publish");
      const lastGrant = w.rows.find((r) => r.stage === "iam-window");
      assert.ok(publish.at - lastGrant.grantedAt >= 900000);
    }
    if (cell.mode === "passive-deadline")
      assert.equal(w.calls.filter((c) => c.method === "ModifyAckDeadline").length, 0);
    if (cell.mode === "720-second-source-inactivity") {
      const pulls = w.calls.filter((c) => c.category === "sourcePull");
      assert.ok(pulls[9].at - pulls[8].at >= 720000);
    }
  }
});

test("D unknown grant or restore stops and protects all four resources without retry", async () => {
  for (const phase of ["iamSetupWrite", "cleanupIamRestoreWrite"]) {
    const w = world(
      makePlan().cells.find((c) => c.arm !== "no-new-grant"),
      { fault: (c) => c.category === phase },
    );
    const r = await runCell(w);
    assert.equal(r.complete, false);
    assert.equal(r.cleanupClosed, false);
    assert.equal(w.resources.size, 4);
    assert.ok(
      w.calls
        .filter((c) => c.category === phase)
        .every((c, i, a) => a.findIndex((v) => v.request.resource === c.request.resource) === i),
    );
    assert.ok(r.iam.unsettled.length > 0);
  }
});

test("D recorded maximum create/Pull/sink delays clip windows and never claim720seconds or convergence", async () => {
  for (const cell of makePlan().cells.filter(
    (c) => c.mode === "720-second-source-inactivity" && !c.reserve,
  )) {
    const w = world(cell, { latency: true, empty: true });
    const r = await runCell(w);
    assert.ok(w.clock() <= cell.cellMs + clockEpoch);
    assert.equal(r.parityEstablished, false);
    assert.ok(r.observations.every((o) => o.iamConvergenceClaim !== true));
    assert.ok(r.observations.some((o) => o.stage === "inactivity-not-completed"));
    assert.equal(
      w.calls
        .filter((c) => c.category === "sinkPull")
        .every((c) => c.request.returnImmediately === true),
      true,
    );
  }
});

import { recoverA2, parseForwarded, parseDelivery } from "./pubsub-observation-d/scenarios.mjs";
import { createIamOwnership, assessIamExchange, readPolicy } from "./pubsub-production/iam.mjs";
import { readFileSync } from "node:fs";
import {
  verifyPreviousAttempt,
  scopeDigest,
  verifyScope,
  verifyPriorPacket,
  verifyProof,
} from "./pubsub-observation-d/admission.mjs";
import { main, parseArgs } from "./pubsub-observation-d/record.mjs";

test("D recorded24same-route IAM policies remain readable while v3 requests need review", () => {
  const rows = JSON.parse(
    readFileSync(new URL("./pubsub-production/fixtures/recorded-v2-iam.json", import.meta.url)),
  );
  assert.equal(rows.length, 24);
  for (const row of rows) {
    assert.doesNotThrow(() => readPolicy(row.response.body));
    const assessment = assessIamExchange({
      ...row,
      request: { ...row.request, path: row.request.path + "?options.requestedPolicyVersion=3" },
    });
    assert.equal(assessment.status, "needs-review");
    assert.equal(row.response.status, 200);
  }
});

test("D changed and malformed source/forwarded bodies cannot authorize foreign ACKs", () => {
  const expected = { data: "YWJj", attributes: { recorderRun: "123456abcdef" } },
    source = "projects/fireemu-oracle-idp/subscriptions/own";
  const body = {
    receivedMessages: [
      {
        ackId: "owned",
        message: {
          messageId: "forward",
          data: expected.data,
          attributes: {
            ...expected.attributes,
            CloudPubSubDeadLetterSourceSubscription: "own",
            CloudPubSubDeadLetterSourceSubscriptionProject: "fireemu-oracle-idp",
            CloudPubSubDeadLetterSourceDeliveryCount: "5",
            CloudPubSubDeadLetterSourceTopicPublishTime: "2026-01-01T00:00:00.123456789Z",
          },
        },
      },
    ],
  };
  assert.equal(parseForwarded(body, expected, source).length, 1);
  for (const [field, value] of [
    ["CloudPubSubDeadLetterSourceSubscription", "foreign"],
    ["CloudPubSubDeadLetterSourceSubscriptionProject", "foreign"],
    ["CloudPubSubDeadLetterSourceDeliveryCount", "x"],
    ["CloudPubSubDeadLetterSourceTopicPublishTime", "invalid"],
    ["recorderRun", "foreign"],
  ]) {
    const copy = structuredClone(body);
    copy.receivedMessages[0].message.attributes[field] = value;
    assert.throws(() => parseForwarded(copy, expected, source));
  }
  for (const value of [null, [], { receivedMessages: {} }, { receivedMessages: [null] }])
    assert.throws(() => parseForwarded(value, expected, source));
});

test("D phase spent before last-grant wait cannot start A publish or later recording cells", async () => {
  const cell = makePlan().cells.find((c) => c.arm !== "no-new-grant"),
    w = world(cell);
  let extra = false;
  const original = w.wire.call;
  w.wire.call = async (c) => {
    const answer = await original(c);
    if (c.category === "iamSetupReadback" && !extra) {
      extra = true;
      await w.sleep(850000);
    }
    return answer;
  };
  const r = await runCell(w);
  assert.equal(r.complete, false);
  assert.equal(w.calls.filter((c) => c.method === "Publish").length, 0);
  assert.ok(w.clock() <= 1800000 + clockEpoch);
});

test("D unknown creates and deletes keep exact original aged A2 obligations without retransmission", async () => {
  for (const fault of ["create", "cleanupDelete", "resourceGet"]) {
    const cell = makePlan().cells[0],
      w = world(cell, { fault: (c) => c.category === fault });
    const r = await runCell(w);
    assert.equal(r.complete && r.cleanupClosed, false);
    const original = new Set(w.ledger.outstanding().map((r) => r.requestId));
    let reads = 0;
    const meter = createMeter({ now: () => 0, a2: true });
    meter.enter({ id: "A2", group: "G7", transport: "rest" });
    const recovery = await recoverA2({
      runId: w.runId,
      ledger: w.ledger,
      elapsedMs: 600000,
      meter,
      wire: {
        call: async (c) => {
          reads++;
          assert.ok(c.method.startsWith("Get"));
          meter.start(c.category, c.transport);
          return {
            ok: false,
            unknown: false,
            status: 404,
            code: "NOT_FOUND",
            body: { error: { status: "NOT_FOUND" } },
          };
        },
      },
    });
    if (fault === "create") assert.equal(recovery.closed, false);
    if (fault === "cleanupDelete") assert.equal(recovery.closed, true);
    assert.ok(reads <= 12);
    assert.ok(w.ledger.outstanding().every((r) => original.has(r.requestId)));
  }
});

test("D read-only IAM A2 replays original proof and never settles an ambiguous grant via404", async () => {
  const w = world(
    makePlan().cells.find((c) => c.arm !== "no-new-grant"),
    { fault: (c) => c.category === "iamSetupWrite" },
  );
  await runCell(w);
  const rows = w.rows.filter((r) => r.phase?.startsWith("grant") || r.phase?.startsWith("restore"));
  assert.ok(rows.length);
  const m = createMeter({ now: () => 0, a2: true });
  m.enter({ id: "A2", group: "G7", transport: "rest" });
  const calls = [];
  const result = await recoverA2({
    runId: w.runId,
    ledger: w.ledger,
    iamReplay: rows,
    elapsedMs: 600000,
    meter: m,
    wire: {
      call: async (c) => {
        calls.push(c);
        m.start(c.category, c.transport);
        return {
          ok: false,
          status: 404,
          unknown: false,
          code: "NOT_FOUND",
          body: { error: { status: "NOT_FOUND" } },
        };
      },
    },
  });
  assert.equal(result.closed, false);
  assert.equal(result.iamReads, 1);
  assert.equal(result.iamUnsettled.length, 1);
  assert.ok(calls.every((c) => c.method.startsWith("Get")));
  assert.throws(() =>
    createIamOwnership({
      assertOwned() {},
      replay: [{ ...rows[0], requested: { etag: "AAAB", bindings: [] } }],
    }),
  );
});

test("D run2 scope and principal are cryptographically bound; no principal argv", () => {
  assert.throws(() => parseArgs(["--service-agent", principal]));
  const descriptor = { head: "a".repeat(40) },
    scope = {
      previousAttempt: { sha256: "b".repeat(64) },
      runIds: ["123456abcdef", "abcdef123456"],
      envelopeId: "PUBSUB-OBSERVATION-D-TEST",
      packetSha256: "c".repeat(64),
    };
  const previous = {
    sha256: scope.previousAttempt.sha256,
    value: {
      runId: scope.runIds[0],
      suite: "pubsub-observation-d-v1",
      project: "fireemu-oracle-idp",
      a2: false,
      sourceHead: descriptor.head,
      envelopeId: scope.envelopeId,
      packetSha256: scope.packetSha256,
      resourcesClosed: true,
      recordingComplete: true,
    },
  };
  verifyPreviousAttempt(previous, scope, descriptor);
  for (const [key, value] of [
    ["suite", "wrong"],
    ["project", "wrong"],
    ["a2", true],
    ["resourcesClosed", false],
    ["recordingComplete", false],
  ])
    assert.throws(() =>
      verifyPreviousAttempt(
        { ...previous, value: { ...previous.value, [key]: value } },
        scope,
        descriptor,
      ),
    );
  assert.notEqual(
    scopeDigest({ ...scope, kind: "E", serviceAgent: principal }),
    scopeDigest({
      ...scope,
      kind: "E",
      serviceAgent: principal.replace("123456789012", "123456789013"),
    }),
  );
});

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { createWire } from "./pubsub-observation-d/wire.mjs";

test("D main records12 complete cells and durable IAM proofs then stops unknown before next cell", async () => {
  for (const unknown of [false, true]) {
    const out = mkdtempSync(join(tmpdir(), "pubsub-d-main-")),
      tick = { value: clockEpoch },
      worlds = new Map(),
      signals = new EventEmitter();
    try {
      const result = await main(
        [
          "--record",
          ...["authority", "descriptor", "packet", "E", "V", "lock", "run-id", "out"].flatMap(
            (key) => [
              `--${key}`,
              key === "out" ? out : key === "run-id" ? "123456abcdef" : `/fixture/${key}`,
            ],
          ),
        ],
        {
          now: () => tick.value,
          sleep: async (ms) => {
            tick.value += ms;
          },
          signals,
          createCredentials: () => async () => "fixture-token",
          setExitCode() {},
          admit: () => ({
            descriptor: { head: "a".repeat(40) },
            descriptorSha256: "b".repeat(64),
            scope: {
              envelopeId: "PUBSUB-OBSERVATION-D-TEST",
              packetSha256: "c".repeat(64),
              serviceAgent: principal,
            },
            check() {},
          }),
          createWire: ({ meter }) => ({
            close() {},
            async call(call) {
              if (!worlds.has(call.cellId)) {
                const cell = makePlan().cells.find((c) => c.id === call.cellId);
                worlds.set(
                  call.cellId,
                  world(cell, {
                    tick,
                    meterOverride: meter,
                    fault: unknown ? (c) => c.category === "iamSetupWrite" : null,
                  }),
                );
              }
              return worlds.get(call.cellId).wire.call(call);
            },
          }),
        },
      );
      assert.equal(result.recordingComplete, !unknown);
      assert.equal(result.results.length, unknown ? 2 : 12);
      assert.equal(result.resourcesClosed, !unknown);
      assert.equal(result.parentClosureReady, false);
      assert.match(result.iamSha256, /^[a-f0-9]{64}$/);
      assert.equal(signals.listenerCount("SIGTERM") + signals.listenerCount("SIGINT"), 0);
      const rows = readFileSync(join(out, "iam-123456abcdef.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map(JSON.parse);
      assert.ok(rows.some((r) => r.phase === "grant-intent"));
      if (!unknown) assert.equal(rows.filter((r) => r.phase === "restore-confirmed").length, 12);
    } finally {
      rmSync(out, { recursive: true });
    }
  }
});

test("D real recorded source and forwarded Pull bodies replay with legacy layout NOT_COMPARABLE", () => {
  const source = JSON.parse(
    readFileSync(
      new URL("./pubsub-observation-c/fixtures/recorded-delivery.json", import.meta.url),
    ),
  ).rows;
  for (const row of source) {
    const values = new Map(Object.entries(row.published).map(([id, p]) => [id, p.message]));
    if (row.response.body.receivedMessages.length <= 1)
      assert.doesNotThrow(() => parseDelivery(row.response.body, values));
    else assert.throws(() => parseDelivery(row.response.body, values));
  }
  const forwarding = JSON.parse(
    readFileSync(
      new URL("./pubsub-observation-d/fixtures/recorded-forwarding.json", import.meta.url),
    ),
  ).rows;
  assert.equal(forwarding.length, 2);
  for (const row of forwarding) {
    assert.equal(parseForwarded(row.response.body, row.expected, row.source).length, 1);
    assert.match(row.layoutVerdict, /NOT_COMPARABLE/);
  }
});

test("D actual bounded REST IAM sender captures same-route policies and always needs review", async () => {
  const rows = JSON.parse(
    readFileSync(new URL("./pubsub-production/fixtures/recorded-v2-iam.json", import.meta.url)),
  );
  for (const row of rows) {
    const cell = makePlan().cells.find((c) => c.arm !== "no-new-grant"),
      m = createMeter({ now: () => 0 });
    m.enter(cell);
    const captured = [];
    const get = row.op === "getIamPolicy",
      resource = row.request.path.slice(4).split(":")[0];
    const wire = createWire({
      meter: m,
      journal: { write: (r) => captured.push(r) },
      getToken: async () => "fixture",
      client: { close() {} },
      fetch: async (url, options) => {
        assert.ok(
          url.includes(get ? ":getIamPolicy?options.requestedPolicyVersion=3" : ":setIamPolicy"),
        );
        assert.equal(options.method, get ? "GET" : "POST");
        if (!get) assert.deepEqual(JSON.parse(options.body), { policy: row.request.body.policy });
        return new Response(JSON.stringify(row.response.body), { status: 200 });
      },
    });
    try {
      const reply = await wire.call({
        cellId: cell.id,
        category: get ? "baselineIamGet" : "iamSetupWrite",
        transport: "rest",
        service: "Publisher",
        method: get ? "GetIamPolicy" : "SetIamPolicy",
        request: get
          ? { resource, requestedPolicyVersion: 3 }
          : { resource, policy: row.request.body.policy },
      });
      assert.equal(reply.status, 200);
      readPolicy(reply.body);
      assert.equal(captured.filter((r) => r.event === "response").length, 1);
      assert.ok(reply.bodyBytes > 0);
    } finally {
      wire.close();
    }
  }
});

test("D bounded observation clock records actual elapsed duration and aggregate14cells never borrow caps", async () => {
  for (const c of makePlan().cells.filter((c) => !c.reserve)) {
    const w = world(c),
      r = await runCell(w);
    const end = r.observations.find((o) => o.stage === "bounded-window-end"),
      begin = r.observations.find((o) => o.stage === "publication-binding");
    assert.equal(end.observedWindowMs, end.clockMs - begin.clockMs);
    assert.ok(end.observedWindowMs <= 900000);
  }
  const m = createMeter({ now: () => 0 });
  for (const c of makePlan().cells) {
    m.enter(c);
    for (const [category, limit] of Object.entries(categoryCaps(c)))
      for (let i = 0; i < limit; i++)
        m.start(
          category,
          category.includes("Iam") ||
            category.startsWith("iam") ||
            category.startsWith("cleanupIam")
            ? "rest"
            : c.transport,
        );
  }
  assert.equal(m.snapshot().requests, 2894);
  assert.deepEqual(m.snapshot().groups.G5, { requests: 2894, rest: 1501, grpc: 1393, streams: 0 });
});

test("D authentic prior-C and exact APPROVE scope refuse modified SHA identity principal or decision", () => {
  const descriptor = { head: "a".repeat(40) },
    digest = "b".repeat(64),
    runIds = ["123456abcdef", "abcdef123456"],
    prior = {
      reviewed: true,
      suite: "pubsub-observation-c-v1",
      sourceHead: "c".repeat(40),
      packetSha256: "d".repeat(64),
      envelopeId: "PUBSUB-OBSERVATION-C-V1",
      runIds: ["0123456789ab", "ba9876543210"],
    };
  const bytes = prior.runIds.map((runId) =>
    Buffer.from(
      JSON.stringify({
        suite: prior.suite,
        project: "fireemu-oracle-idp",
        sourceHead: prior.sourceHead,
        packetSha256: prior.packetSha256,
        envelopeId: prior.envelopeId,
        runId,
        a2: false,
        resourcesClosed: true,
        recordingComplete: true,
      }),
    ),
  );
  prior.summaries = prior.runIds.map((runId, i) => ({
    runId,
    path: `/fixture/summary-${runId}.json`,
    sha256: sha256(bytes[i]),
  }));
  const read = (path) => bytes[prior.summaries.findIndex((s) => s.path === path)];
  verifyPriorPacket(prior, read);
  for (const value of [
    { ...prior, reviewed: false },
    { ...prior, suite: "pubsub-observation-b-v1" },
    { ...prior, summaries: prior.summaries.map((s) => ({ ...s, sha256: "f".repeat(64) })) },
  ])
    assert.throws(() => verifyPriorPacket(value, read));
  const scope = {
    taskId: "PUBSUB-OBSERVATION-D",
    suite: "pubsub-observation-d-v1",
    project: "fireemu-oracle-idp",
    envelopeId: "PUBSUB-OBSERVATION-D-TEST",
    sourceHead: descriptor.head,
    descriptorSha256: digest,
    packetSha256: "e".repeat(64),
    runIds,
    runOutputs: { [runIds[0]]: "/fixture/record1", [runIds[1]]: "/fixture/record2" },
    recoveryOutputs: { [runIds[0]]: "/fixture/a21", [runIds[1]]: "/fixture/a22" },
    expiresAt: "2030-01-01T00:00:00Z",
    plan: makePlan(),
    priorPacket: prior,
    serviceAgent: principal,
  };
  const options = { runId: runIds[0], out: scope.runOutputs[runIds[0]], a2: false };
  verifyScope(scope, descriptor, digest, options, 0);
  for (const value of [null, "", principal.replace("serviceAccount:", "")])
    assert.throws(() =>
      verifyScope({ ...scope, serviceAgent: value }, descriptor, digest, options, 0),
    );
  for (const kind of ["E", "V"]) {
    const row = { ...scope, kind, state: "APPROVED" },
      label = kind === "E" ? "PUBSUB-OBSERVATION-D envelope" : "PUBSUB-OBSERVATION-D",
      line = `| ${label} | decision=APPROVE; envelopeId=${scope.envelopeId}; scopeSha256=${scopeDigest(row)} |`;
    verifyProof(row, line, scope, kind);
    assert.throws(() =>
      verifyProof(row, line.replace("decision=APPROVE;", "decision=PENDING;"), scope, kind),
    );
    assert.throws(() => verifyProof({ ...row, state: "DRAFT" }, line, scope, kind));
    assert.throws(() =>
      verifyProof(
        { ...row, serviceAgent: principal.replace("123456789012", "123456789013") },
        line,
        scope,
        kind,
      ),
    );
  }
});
import { sha256 } from "./pubsub-production/admission.mjs";

test("D pure generated near misses keep source tokens and recovery age closed", async () => {
  const expected = { data: "YWJj", attributes: { recorderRun: "123456abcdef" } },
    values = new Map([["own", expected]]),
    body = {
      receivedMessages: [{ ackId: "observed", message: { messageId: "own", ...expected } }],
    };
  assert.equal(parseDelivery(body, values).length, 1);
  for (const field of ["messageId", "data", "attributes", "ackId"]) {
    const changed = structuredClone(body);
    if (field === "ackId") changed.receivedMessages[0].ackId = "";
    else
      changed.receivedMessages[0].message[field] =
        field === "attributes" ? { recorderRun: "foreign" } : "foreign";
    assert.throws(() => parseDelivery(changed, values));
  }
  for (const age of [0, 599999, NaN, -1])
    await assert.rejects(() => recoverA2({ elapsedMs: age }), /minimum age/);
  for (const c of makePlan().cells) {
    assert.equal(c.cellMs, c.arm === "no-new-grant" ? 900000 : 1800000);
    assert.equal(c.cleanupReserveMs, c.arm === "no-new-grant" ? 60000 : 120000);
  }
});

test("D source survives a completed720second pause in a publish-age retention model", async () => {
  for (const cell of makePlan().cells.filter(
    (c) => c.mode === "720-second-source-inactivity" && !c.reserve,
  )) {
    const w = world(cell, { forwarding: false }),
      result = await runCell(w);
    assert.equal(result.complete, true);
    const resumed = result.observations
      .filter((o) => o.stage === "source-delivery")
      .find((o) => o.attempt === 10);
    assert.equal(resumed.items.length, 1, "retention-expired absence cannot witness reset");
    assert.equal(
      resumed.items[0].message.messageId,
      result.observations.find((o) => o.stage === "publication-binding").messageIds[0],
    );
    assert.ok(
      result.observations.find((o) => o.stage === "inactivity-completed").elapsedMs >= 720000,
    );
    const source = graph(cell, w.runId).resources.find(
      (r) => r.method === "CreateSubscription" && r.name === graph(cell, w.runId).subscription,
    );
    assert.ok(Number(source.request.messageRetentionDuration.slice(0, -1)) * 1000 >= cell.cellMs);
  }
});

import grpcLib from "@grpc/grpc-js";
import { decode } from "./pubsub-observation-d/wire.mjs";
import { SERVICES, requestToWire } from "./pubsub-production/grpc.mjs";
const ordinary = () =>
  JSON.parse(
    readFileSync(
      new URL("./pubsub-observation-d/fixtures/recorded-ordinary.json", import.meta.url),
    ),
  ).rows;
const categoryFor = (method) =>
  method.startsWith("Create")
    ? "create"
    : method.startsWith("Get")
      ? "resourceGet"
      : method.startsWith("Delete")
        ? "cleanupDelete"
        : method === "Publish"
          ? "publish"
          : method === "Pull"
            ? "sourcePull"
            : method === "ModifyAckDeadline"
              ? "nack"
              : "ownAck";
const serviceFor = (method) => (/Topic|Publish/.test(method) ? "Publisher" : "Subscriber");
function recordedCall(row) {
  const method = row.op[0].toUpperCase() + row.op.slice(1);
  let request = structuredClone(row.request.body ?? {});
  if (row.transport === "rest") {
    const resource = row.request.path.replace(/^\/v1\//, "").split(":")[0];
    request = method.startsWith("Create")
      ? { name: resource, ...request }
      : method.startsWith("Get") || method.startsWith("Delete")
        ? { name: resource }
        : method === "Publish"
          ? { topic: resource, ...request }
          : { subscription: resource, ...request };
  }
  return {
    cellId: "fixture",
    category: categoryFor(method),
    transport: row.transport,
    service: serviceFor(method),
    method,
    request,
  };
}
function nativeReply(clientFunction) {
  return {
    close() {},
    makeUnaryRequest(path, _serialize, _deserialize, raw, _metadata, _options, callback) {
      const rpc = new EventEmitter();
      let done = false;
      const finish = (reply) => {
        if (done) return;
        done = true;
        rpc.emit("metadata", new grpcLib.Metadata());
        if (reply.ok) {
          const service = path.includes("Publisher") ? "Publisher" : "Subscriber",
            method = path.split("/").at(-1),
            Type = typeOf(SERVICES[service].methods[method][1]);
          callback(
            null,
            Buffer.from(Type.encode(Type.fromObject(requestToWire(reply.body))).finish()),
          );
        } else
          callback({
            code: reply.code === "NOT_FOUND" ? 5 : 1,
            details: reply.body?.error?.message ?? "recorded error",
          });
        rpc.emit("status", {
          code: reply.ok ? 0 : reply.code === "NOT_FOUND" ? 5 : 1,
          details: "",
          metadata: new grpcLib.Metadata(),
        });
      };
      rpc.cancel = () => finish({ ok: false, code: "CANCELLED", body: {} });
      queueMicrotask(async () => {
        const service = path.includes("Publisher") ? "Publisher" : "Subscriber",
          method = path.split("/").at(-1),
          request = decode(typeOf(SERVICES[service].methods[method][0]), raw);
        finish(await clientFunction(method, request));
      });
      return rpc;
    },
  };
}

test("D actual REST/native wire replays52same-route ordinary replies and required native fields", async () => {
  for (const row of ordinary()) {
    const call = recordedCall(row),
      cell = makePlan().cells.find(
        (c) => c.transport === call.transport && c.arm === "no-new-grant",
      ),
      m = createMeter({ now: () => 0 }),
      captured = [];
    m.enter(cell);
    const ok =
      row.transport === "rest"
        ? row.response.status === 200
        : [0, "OK"].includes(row.response.code);
    const wire = createWire({
      meter: m,
      journal: { write: (r) => captured.push(r) },
      getToken: async () => "fixture",
      fetch: async () =>
        new Response(JSON.stringify(row.response.body), { status: row.response.status ?? 200 }),
      client: nativeReply(async (method, request) => {
        assert.equal(method, call.method);
        if (method === "CreateSubscription") {
          assert.equal(request.name, call.request.name);
          assert.equal(request.topic, call.request.topic);
          assert.equal(request.ackDeadlineSeconds, call.request.ackDeadlineSeconds);
          assert.equal(request.messageRetentionDuration, call.request.messageRetentionDuration);
        }
        return { ok, code: ok ? "OK" : "NOT_FOUND", body: row.response.body };
      }),
    });
    try {
      const answer = await wire.call(call);
      assert.equal(answer.ok, ok);
      assert.equal(answer.unknown, false);
      if (
        ok &&
        call.method !== "Acknowledge" &&
        call.method !== "ModifyAckDeadline" &&
        !call.method.startsWith("Delete")
      ) {
        if (call.method === "Pull")
          assert.deepEqual(
            answer.body.receivedMessages ?? [],
            row.response.body.receivedMessages ?? [],
          );
        else if (call.method === "Publish")
          assert.deepEqual(answer.body.messageIds, row.response.body.messageIds);
        else assert.equal(answer.body.name, row.response.body.name);
      }
      if (!ok) assert.equal(answer.code, "NOT_FOUND");
      assert.match(row.layoutVerdict, /NOT_COMPARABLE/);
      assert.equal(captured.filter((r) => r.event === "response").length, 1);
      if (call.transport === "grpc") {
        const request = captured.find((r) => r.event === "request-dispatch"),
          raw = Buffer.from(request.requestBodyBase64, "base64");
        assert.equal(raw.length, request.requestBodyBytes);
        assert.equal(sha256(raw), request.requestSha256);
      }
    } finally {
      wire.close();
    }
  }
  for (const cell of makePlan().cells) {
    const g = graph(cell, "123456abcdef");
    for (const r of g.resources.filter((r) => r.method === "CreateSubscription")) {
      const body = decode(
        typeOf("Subscription"),
        encodeRequest("Subscriber", "CreateSubscription", r.request),
      );
      assert.equal(body.topic, r.request.topic);
      assert.equal(body.ackDeadlineSeconds, 10);
      assert.equal(body.messageRetentionDuration, "3600s");
      if (r.name === g.subscription)
        assert.deepEqual(body.deadLetterPolicy, {
          deadLetterTopic: g.deadTopic,
          maxDeliveryAttempts: 5,
        });
      assert.deepEqual(
        route(r.method, r.request).body,
        Object.fromEntries(Object.entries(r.request).filter(([key]) => key !== "name")),
      );
    }
  }
});

function modelThroughRecordedWire(w) {
  const rows = ordinary(),
    calls = [];
  const execute = async (method, request) => {
    const selectors = {
      GetTopic: "topic",
      DeleteTopic: "topic",
      GetSubscription: "subscription",
      DeleteSubscription: "subscription",
    };
    if (selectors[method] && request[selectors[method]])
      request = { name: request[selectors[method]] };
    const name = request.name ?? request.subscription ?? request.topic;
    const category =
      method === "Pull"
        ? name === graph(w.cell, w.runId).sink
          ? "sinkPull"
          : "sourcePull"
        : method.startsWith("Get") && !method.includes("Iam")
          ? w.resources.has(name)
            ? "resourceGet"
            : "cleanupGet"
          : method.includes("Iam")
            ? method === "GetIamPolicy"
              ? "baselineIamGet"
              : "iamSetupWrite"
            : categoryFor(method);
    const answer = await w.wire.call({
      category,
      method,
      request,
      transport: method.includes("Iam") ? "rest" : w.cell.transport,
    });
    calls.push({ method, request });
    if (method.includes("Iam")) return answer;
    const fixture = rows.find(
      (r) =>
        r.transport === w.cell.transport &&
        r.op === method[0].toLowerCase() + method.slice(1) &&
        (r.response.status === 200 || [0, "OK"].includes(r.response.code)) === answer.ok,
    );
    assert.ok(fixture, method);
    // Keep recorded output-only fields. Only owned identity/configuration values are parameterized for this fresh graph; this is not a production-format or byte-layout assertion.
    const body = { ...structuredClone(fixture.response.body), ...answer.body };
    return { ...answer, body };
  };
  const client = nativeReply(execute);
  const wire = createWire({
    meter: w.meter,
    journal: w.journal,
    getToken: async () => "fixture",
    client,
    fetch: async (url, options) => {
      const match = /\/v1\/(.+?)(?::(\w+))?(?:\?.*)?$/.exec(url);
      const resource = decodeURIComponent(match[1]);
      let method = match[2]
        ? match[2][0].toUpperCase() + match[2].slice(1)
        : `${options.method === "PUT" ? "Create" : options.method === "DELETE" ? "Delete" : "Get"}${resource.includes("/topics/") ? "Topic" : "Subscription"}`;
      const body = options.body ? JSON.parse(options.body) : {};
      const request = method.includes("Iam")
        ? { resource, ...body }
        : method.startsWith("Create")
          ? { name: resource, ...body }
          : method.startsWith("Get") || method.startsWith("Delete")
            ? { name: resource }
            : method === "Publish"
              ? { topic: resource, ...body }
              : { subscription: resource, ...body };
      const answer = await execute(method, request);
      return new Response(JSON.stringify(answer.body), { status: answer.status });
    },
  });
  return { wire, calls };
}

test("D real wire carries recorded ordinary structures through own lifecycle and read-only A2", async () => {
  for (const transport of ["rest", "grpc"]) {
    const cell = makePlan().cells.find(
        (c) => c.transport === transport && c.arm === "no-new-grant",
      ),
      w = world(cell, { countDispatch: false }),
      adapter = modelThroughRecordedWire(w);
    try {
      const result = await runCell({ ...w, wire: adapter.wire });
      assert.equal(result.complete, true, JSON.stringify(result));
      assert.equal(result.cleanupClosed, true);
      assert.equal(w.resources.size, 0);
      assert.ok(adapter.calls.some((c) => c.method === "ModifyAckDeadline"));
      assert.ok(adapter.calls.some((c) => c.method === "Acknowledge"));
    } finally {
      adapter.wire.close();
    }
    const name = graph(cell, w.runId).topic,
      ledger = createLedger();
    const id = ledger.sent({ name, action: "create", transport });
    ledger.answered({ name, action: "create", transport, requestId: id, kind: "ok" });
    const m = createMeter({ now: () => 0, a2: true });
    m.enter({ id: "A2", group: "G7", transport: "rest" });
    const fixture = ordinary().find(
      (r) => r.transport === "rest" && r.op === "getTopic" && r.response.status === 404,
    );
    const wire = createWire({
      meter: m,
      journal: { write() {} },
      client: { close() {} },
      getToken: async () => "fixture",
      fetch: async () => new Response(JSON.stringify(fixture.response.body), { status: 404 }),
    });
    try {
      const result = await recoverA2({ wire, meter: m, ledger, runId: w.runId, elapsedMs: 600000 });
      assert.equal(result.closed, true);
      assert.equal(result.resourceReads, 1);
    } finally {
      wire.close();
    }
  }
});

test("D native callback waits for terminal status; unknown decode,cancel and timeout cannot confirm reads", async (t) => {
  const cell = makePlan().cells.find((c) => c.transport === "grpc"),
    call = {
      cellId: cell.id,
      category: "resourceGet",
      transport: "grpc",
      service: "Publisher",
      method: "GetTopic",
      request: { name: graph(cell, "123456abcdef").topic },
    };
  for (const variant of ["delayed-status", "bad-protobuf", "cancelled", "timeout"]) {
    const m = createMeter({ now: () => 0 });
    m.enter(cell);
    let rpc,
      callback,
      cancelled = 0,
      finished = false;
    const captured = [];
    const client = {
      close() {},
      makeUnaryRequest(_path, _serializer, _decoder, _raw, _meta, _options, cb) {
        callback = cb;
        rpc = new EventEmitter();
        rpc.cancel = () => {
          cancelled++;
          callback({ code: 1, details: "cancelled" });
          rpc.emit("status", { code: 1, metadata: new grpcLib.Metadata() });
        };
        return rpc;
      },
    };
    if (variant === "timeout") t.mock.timers.enable({ apis: ["setTimeout"] });
    const wire = createWire({
      meter: m,
      journal: { write: (r) => captured.push(r) },
      client,
      getToken: async () => "fixture",
    });
    try {
      const promise = wire.call(call).then((r) => {
        finished = true;
        return r;
      });
      for (let i = 0; i < 12; i++) await Promise.resolve();
      assert.ok(rpc);
      if (variant === "timeout") t.mock.timers.tick(30001);
      else if (variant === "cancelled") wire.abortSource();
      else {
        callback(
          null,
          variant === "bad-protobuf"
            ? Buffer.from([255])
            : Buffer.from(typeOf("Topic").encode({ name: call.request.name }).finish()),
        );
        await Promise.resolve();
        assert.equal(finished, false);
        rpc.emit("status", { code: 0, metadata: new grpcLib.Metadata() });
      }
      const answer = await promise;
      assert.equal(answer.unknown, variant !== "delayed-status");
      assert.equal(answer.ok, variant === "delayed-status");
      if (["cancelled", "timeout"].includes(variant)) assert.equal(cancelled, 1);
      assert.equal(m.snapshot().requests, 1);
      assert.equal(captured.filter((r) => r.event === "response").length, 1);
    } finally {
      wire.close();
      if (variant === "timeout") t.mock.timers.reset();
    }
  }
});

test("D actual REST unreadable and3xx5xx answers remain unknown", async () => {
  for (const [status, body] of [
    [302, "{}"],
    [503, "{}"],
    [200, "not-json"],
    [200, "[]"],
  ]) {
    const cell = makePlan().cells[0],
      m = createMeter({ now: () => 0 });
    m.enter(cell);
    const wire = createWire({
      meter: m,
      journal: { write() {} },
      client: { close() {} },
      getToken: async () => "fixture",
      fetch: async () => new Response(body, { status }),
    });
    try {
      const answer = await wire.call({
        cellId: cell.id,
        category: "resourceGet",
        transport: "rest",
        service: "Publisher",
        method: "GetTopic",
        request: { name: graph(cell, "123456abcdef").topic },
      });
      assert.equal(answer.unknown, true);
      assert.equal(m.snapshot().requests, 1);
    } finally {
      wire.close();
    }
  }
});

test("Task24 D retains all graph obligations when restoration throws outside per-entry catches", async () => {
  const w = world(makePlan().cells.find((c) => c.arm !== "no-new-grant"));
  const checkpoints = [];
  w.journal.recovery = (row) => checkpoints.push(structuredClone(row));
  const r = await runCell({
    ...w,
    createIamManager(options) {
      const manager = createIamOwnership(options);
      return {
        ...manager,
        async restore() {
          throw new Error("restoration unavailable");
        },
      };
    },
  });
  assert.equal(r.complete, false);
  assert.equal(r.cleanupClosed, false);
  assert.equal(w.calls.filter((c) => c.method.startsWith("Delete")).length, 0);
  assert.equal(w.resources.size, 4);
  assert.equal(checkpoints.at(-1).obligations.length, 4);
  assert.ok(checkpoints.at(-1).iam.length >= 2);
});

test("Task24 D preserves returned unsettled entries even when the manager reports no outstanding delta", async () => {
  const w = world(makePlan().cells.find((c) => c.arm !== "no-new-grant"));
  const checkpoints = [];
  w.journal.recovery = (row) => checkpoints.push(structuredClone(row));
  let manager;
  const r = await runCell({
    ...w,
    iamJournal: {
      write(row) {
        if (row.phase === "restore-confirmed")
          throw new Error("restore confirmation persistence refused");
        w.journal.write(row);
      },
    },
    createIamManager(options) {
      manager = createIamOwnership(options);
      return manager;
    },
  });
  assert.equal(manager.outstanding().length, 0);
  assert.equal(r.iam.unsettled.length, 2);
  assert.equal(r.cleanupClosed, false);
  assert.equal(r.complete, false);
  assert.equal(w.calls.filter((c) => c.method.startsWith("Delete")).length, 0);
  assert.equal(checkpoints.at(-1).obligations.length, 4);
  assert.equal(checkpoints.at(-1).iam.length, 2);
});
