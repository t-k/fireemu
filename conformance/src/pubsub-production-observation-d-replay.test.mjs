import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";

test("D12 has a dedicated recording importer instead of accepting a C26 recording", async () => {
  const module = new URL("./pubsub-observation-d/replay-core.mjs", import.meta.url);
  assert.equal(existsSync(module), true, "D12 importer is missing");
  const { importRecording } = await import(module);
  assert.equal(typeof importRecording, "function");
  assert.throws(() => importRecording({}), /D|plan|recording/);
});

const core = () => import("./pubsub-observation-d/replay-core.mjs");
const planModule = () => import("./pubsub-observation-d/plan.mjs");
const digest = "a".repeat(64);
const reply = (body) => ({
  ok: true,
  code: "OK",
  status: 200,
  unknown: false,
  body,
  bodyBytes: Buffer.byteLength(JSON.stringify(body)),
  bodySha256: digest,
  metadataBytesIn: 20,
});
function executionInput(exchanges) {
  return {
    metadata: { runId: "012345abcdef" },
    cells: [{ id: "R1", arm: "no-new-grant", exchanges }],
  };
}
const source = (method, request, body, category = "sourcePull") => ({
  requestId: 1,
  n: 2,
  cellId: "R1",
  transport: "rest",
  category,
  method,
  request,
  reply: reply(body),
  at: "2026-01-01T00:00:00.000Z",
});
const receipt = (row) => ({
  sourceRequestId: row.requestId,
  sourceN: row.n,
  requestedInstant: row.at,
  status: 200,
  body: { clock: row.at },
});

test("D rejects mutations to the full fixed plan including unused reservations", async () => {
  const { importRecording } = await core(),
    { makePlan } = await planModule();
  for (const mutate of [
    (p) => p.cells.pop(),
    (p) => p.cells[0].cellMs--,
    (p) => p.cells[4].cleanupReserveMs--,
    (p) => p.caps.G5.rest++,
    (p) => p.caps.G7.requests++,
    (p) => p.iam.waitAfterLastGrantMs--,
    (p) => (p.selection = ["R1"]),
  ]) {
    const plan = makePlan();
    mutate(plan);
    assert.throws(() => importRecording({ packet: { plan } }), /fixed observation plan mismatch/);
  }
});

test("D dispatches actual IAM only for confirmed locally owned resources and carries local CAS", async () => {
  const { replayRecording } = await core();
  const resource = "projects/synthetic/topics/owned";
  const rows = [
    source("CreateTopic", { name: resource }, { name: resource }, "create"),
    source(
      "GetIamPolicy",
      { resource, requestedPolicyVersion: 3 },
      { etag: "AAAA" },
      "baselineIamGet",
    ),
    source(
      "SetIamPolicy",
      { resource, policy: { etag: "AAAA", version: 3, bindings: [] } },
      { etag: "AAAAAAAAAAAB", version: 1 },
      "iamSetupWrite",
    ),
    source(
      "GetIamPolicy",
      { resource, requestedPolicyVersion: 3 },
      { etag: "AAAAAAAAAAAB", version: 1 },
      "iamSetupReadback",
    ),
  ];
  const calls = [];
  const result = await replayRecording(
    executionInput(rows),
    async (call, row) => {
      calls.push(structuredClone(call));
      if (call.method === "SetIamPolicy") assert.equal(call.request.policy.etag, "BBBB");
      return reply(
        call.method === "CreateTopic"
          ? { name: resource }
          : call.method === "SetIamPolicy"
            ? { etag: "BBBBBBBBBBBC", version: 1 }
            : row.category === "baselineIamGet"
              ? { etag: "BBBB" }
              : { etag: "BBBBBBBBBBBC", version: 1 },
      );
    },
    { clockReceiptFor: receipt },
  );
  assert.deepEqual(
    calls.map((c) => c.method),
    ["CreateTopic", "GetIamPolicy", "SetIamPolicy", "GetIamPolicy"],
  );
  assert.equal(result.results[0].exchanges[2].semanticVerdict, "MATCH");
  assert.equal(result.parityEstablished, false);
  let unownedCalls = 0;
  const rejected = await replayRecording(executionInput([rows[1]]), async () => {
    unownedCalls++;
    return rows[1].reply;
  });
  assert.equal(unownedCalls, 0);
  assert.match(rejected.results[0].exchanges[0].debt, /ownership/);
});

test("D physical comparison requires clock readback associated with the exact source request", async () => {
  const { replayRecording } = await core(),
    row = source(
      "GetTopic",
      { name: "synthetic-topic" },
      { name: "synthetic-topic" },
      "resourceGet",
    );
  for (const clock of [
    undefined,
    { ...receipt(row), sourceN: row.n + 1 },
    { ...receipt(row), body: { clock: "2026-01-01T00:00:01.000Z" } },
  ]) {
    const result = await replayRecording(executionInput([row]), async () => row.reply, {
      clockReceiptFor: () => clock,
    });
    assert.equal(result.results[0].physicalVerdict, "NOT_COMPARABLE");
  }
  const result = await replayRecording(executionInput([row]), async () => row.reply, {
    clockReceiptFor: receipt,
  });
  assert.equal(result.results[0].physicalVerdict, "MATCH");
});

test("D preserves physical reply evidence while reporting actual body divergence", async () => {
  const { replayRecording } = await core(),
    row = source(
      "GetTopic",
      { name: "synthetic-topic" },
      { name: "synthetic-topic" },
      "resourceGet",
    );
  const actual = reply({ name: "foreign-topic" }),
    observed = [];
  const result = await replayRecording(executionInput([row]), async () => actual, {
    clockReceiptFor: receipt,
    observe: (entry) => observed.push(entry),
  });
  assert.equal(result.verdict, "DIVERGES");
  assert.deepEqual(observed[0].sourceReply, row.reply);
  assert.deepEqual(observed[0].localReply, actual);
});

test("D source delivery count mismatch remains a divergence without inventing a source ACK", async () => {
  const { replayRecording } = await core();
  const publish = source(
    "Publish",
    { topic: "synthetic-topic", messages: [{ data: "eA==", attributes: { test: "synthetic" } }] },
    { messageIds: ["source-id"] },
    "publish",
  );
  const pull = {
    ...source(
      "Pull",
      { subscription: "synthetic-subscription" },
      {
        receivedMessages: [
          {
            ackId: "source-ack",
            deliveryAttempt: 3,
            message: { messageId: "source-id", data: "eA==", attributes: { test: "synthetic" } },
          },
        ],
      },
    ),
    requestId: 2,
    n: 4,
  };
  for (const attempt of [3, 4]) {
    const result = await replayRecording(
      executionInput([publish, pull]),
      async (call) =>
        call.method === "Publish"
          ? reply({ messageIds: ["local-id"] })
          : reply({
              receivedMessages: [
                {
                  ackId: "local-ack",
                  deliveryAttempt: attempt,
                  message: {
                    messageId: "local-id",
                    data: "eA==",
                    attributes: { test: "synthetic" },
                  },
                },
              ],
            }),
      { clockReceiptFor: receipt },
    );
    assert.equal(result.results[0].semanticVerdict, attempt === 3 ? "MATCH" : "DIVERGES");
  }
});

test("D refuses an observed local forwarding-count mismatch without inventing an attempt threshold", async () => {
  const { replayRecording } = await core();
  const body = (count) => ({
    receivedMessages: [
      {
        ackId: "synthetic-ack",
        message: {
          messageId: "synthetic-forward",
          data: "eA==",
          attributes: {
            user: "synthetic",
            CloudPubSubDeadLetterSourceSubscription: "synthetic-source",
            CloudPubSubDeadLetterSourceSubscriptionProject: "synthetic-project",
            CloudPubSubDeadLetterSourceDeliveryCount: count,
            CloudPubSubDeadLetterSourceTopicPublishTime: "2026-01-01T00:00:00.000Z",
          },
        },
      },
    ],
  });
  const row = source("Pull", { subscription: "synthetic-sink" }, body("7"), "sinkPull");
  for (const count of ["7", "8"]) {
    const result = await replayRecording(executionInput([row]), async () => reply(body(count)), {
      clockReceiptFor: receipt,
    });
    assert.equal(result.results[0].semanticVerdict, count === "7" ? "MATCH" : "DIVERGES");
  }
});

test("D refuses own ACK translation when no physical local delivery supplied its token", async () => {
  const { replayRecording } = await core();
  let called = false;
  const row = source(
    "Acknowledge",
    { subscription: "synthetic-sink", ackIds: ["unobserved-token"] },
    {},
    "ownAck",
  );
  const result = await replayRecording(
    executionInput([row]),
    async () => {
      called = true;
      return reply({});
    },
    { clockReceiptFor: receipt },
  );
  assert.equal(called, false);
  assert.equal(result.verdict, "NOT_COMPARABLE");
  assert.match(result.results[0].exchanges[0].debt, /selector unresolved/);
});

async function syntheticRecording() {
  const { makePlan, PROJECT, SUITE } = await planModule();
  const runId = "012345abcdef",
    head = "b".repeat(40),
    packetSha256 = "c".repeat(64),
    descriptorSha256 = "d".repeat(64);
  const metadata = {
    event: "run-start",
    runId,
    suite: SUITE,
    project: PROJECT,
    sourceHead: head,
    packetSha256,
    descriptorSha256,
    envelopeId: "synthetic-envelope",
  };
  const rows = [],
    issued = [],
    iam = [],
    recovery = [],
    results = [];
  let elapsed = 0,
    n = 0,
    requestId = 0;
  const at = () => new Date(Date.parse("2026-01-01T00:00:00Z") + elapsed).toISOString();
  const write = (value) => {
    const row = { ...value, n: ++n, at: at() };
    rows.push(row);
    return row;
  };
  write(metadata);
  recovery.push({ event: "recovery-open", sequence: 1, runId, obligations: [], iam: [] });
  recovery.push({ ...metadata, event: "recovery-binding", sequence: 2, obligations: [], iam: [] });
  for (const cell of makePlan().cells.filter((c) => !c.reserve)) {
    const prefix = `projects/${PROJECT}`,
      suffix = `fe${runId}-${cell.id.toLowerCase()}`;
    const topic = `${prefix}/topics/${suffix}-t`,
      deadTopic = `${prefix}/topics/${suffix}-d`,
      sub = `${prefix}/subscriptions/${suffix}-s`,
      sink = `${prefix}/subscriptions/${suffix}-k`,
      names = [topic, deadTopic, sink, sub],
      observations = [];
    const send = (category, method, request, body = {}, status = 200) => {
      const transport =
        category.includes("Iam") || category.startsWith("iam") ? "rest" : cell.transport;
      elapsed += 2;
      const dispatch = write({
        event: "request-dispatch",
        cellId: cell.id,
        category,
        method,
        request,
        transport,
        requestId: ++requestId,
        requestBodyBytes: Buffer.byteLength(JSON.stringify(request)),
        metadataBytesOut: 20,
      });
      elapsed += 3;
      let answer = {
        ...reply(body),
        status,
        ok: status === 200,
        code: status === 200 ? "OK" : "NOT_FOUND",
      };
      if (transport === "grpc") {
        delete answer.status;
        if (status === 404)
          answer = {
            ok: false,
            unknown: false,
            code: "NOT_FOUND",
            body: { error: { status: "NOT_FOUND", message: "Synthetic missing resource" } },
            bodyBytes: null,
            layoutVerdict: "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED",
            metadataBytesIn: 20,
          };
      }
      write({ event: "response", cellId: cell.id, method, transport, requestId, reply: answer });
      return { dispatch, answer };
    };
    const observe = (stage, fields = {}) => {
      const value = {
        event: "dlq-observation",
        cellId: cell.id,
        stage,
        clockMs: elapsed,
        ...fields,
      };
      observations.push(value);
      return write(value);
    };
    for (const name of names) {
      send(
        "create",
        name.includes("/topics/") ? "CreateTopic" : "CreateSubscription",
        { name },
        { name },
      );
      issued.push(
        {
          name,
          phase: "sent",
          action: "create",
          transport: cell.transport,
          requestId: `${name}#1`,
        },
        {
          name,
          phase: "answered",
          action: "create",
          transport: cell.transport,
          requestId: `${name}#1`,
          kind: "ok",
        },
      );
    }
    const managed = cell.arm === "managed-grant-readback-wait",
      principal = "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com",
      policies = [];
    if (managed) {
      for (const [resource, role] of [
        [sub, "roles/pubsub.subscriber"],
        [deadTopic, "roles/pubsub.publisher"],
      ]) {
        const before = { etag: "AQ==" },
          requested = { etag: "AQ==", bindings: [{ role, members: [principal] }], version: 3 };
        send("baselineIamGet", "GetIamPolicy", { resource, requestedPolicyVersion: 3 }, before);
        const set = send(
            "iamSetupWrite",
            "SetIamPolicy",
            { resource, policy: requested },
            requested,
          ),
          readback = send(
            "iamSetupReadback",
            "GetIamPolicy",
            { resource, requestedPolicyVersion: 3 },
            requested,
          );
        iam.push({
          cellId: cell.id,
          phase: "grant-intent",
          resource,
          role,
          principal,
          before,
          requested,
          at: set.dispatch.at,
        });
        iam.push({
          cellId: cell.id,
          phase: "grant-confirmed",
          resource,
          role,
          principal,
          setAnswer: set.answer,
          readback: readback.answer,
          at: at(),
        });
        policies.push({ resource, role, requested });
      }
      observe("iam-window", { waitAfterLastGrantMs: 900000, iamConvergenceClaim: false });
      recovery.push({
        sequence: recovery.length + 1,
        runId,
        cellId: cell.id,
        obligations: [],
        iam: [{ resource: sub }],
      });
      elapsed += 900000;
    } else {
      for (const resource of [sub, deadTopic])
        send(
          "baselineIamGet",
          "GetIamPolicy",
          { resource, requestedPolicyVersion: 3 },
          { etag: "AQ==" },
        );
      observe("baseline-permission", {
        status: "UNAUDITED",
        newGrant: false,
        effectivePermissionClaim: false,
      });
    }
    send(
      "publish",
      "Publish",
      { topic, messages: [{ data: "eA==", attributes: { synthetic: "yes" } }] },
      { messageIds: ["synthetic-publication"] },
    );
    observe("publication-binding", {
      messageIds: ["synthetic-publication"],
      messages: [{ data: "eA==", attributes: { synthetic: "yes" } }],
    });
    const pull = (category) => {
      send(
        category,
        "Pull",
        { subscription: category === "sourcePull" ? sub : sink, maxMessages: 1 },
        {},
      );
      observe(category === "sourcePull" ? "source-delivery" : "sink-delivery", { items: [] });
    };
    if (cell.mode === "720-second-source-inactivity") {
      for (let i = 0; i < 9; i++) pull("sourcePull");
      const paused = elapsed;
      observe("inactivity-start", { sourceAttempts: 9, resumeAt: paused + 720000 });
      pull("sinkPull");
      elapsed = paused + 720000;
      observe("inactivity-completed", {
        elapsedMs: 720000,
        noSourcePullDuringWindow: true,
        resetInferred: false,
      });
    }
    pull("sourcePull");
    pull("sinkPull");
    for (const { resource, role, requested: before } of policies) {
      send(
        "cleanupIamConflictGet",
        "GetIamPolicy",
        { resource, requestedPolicyVersion: 3 },
        before,
      );
      const requested = { ...before, bindings: [] },
        set = send(
          "cleanupIamRestoreWrite",
          "SetIamPolicy",
          { resource, policy: requested },
          requested,
        ),
        readback = send(
          "cleanupIamRestoreReadback",
          "GetIamPolicy",
          { resource, requestedPolicyVersion: 3 },
          requested,
        );
      iam.push({
        cellId: cell.id,
        phase: "restore-intent",
        resource,
        role,
        principal,
        before,
        requested,
        at: set.dispatch.at,
      });
      iam.push({
        cellId: cell.id,
        phase: "restore-confirmed",
        resource,
        setAnswer: set.answer,
        readback: readback.answer,
        at: at(),
      });
    }
    for (const name of names) {
      send("cleanupDelete", name.includes("/topics/") ? "DeleteTopic" : "DeleteSubscription", {
        name,
      });
      send(
        "cleanupGet",
        name.includes("/topics/") ? "GetTopic" : "GetSubscription",
        { name },
        {},
        404,
      );
      issued.push(
        {
          name,
          phase: "sent",
          action: "delete",
          transport: cell.transport,
          requestId: `${name}#2`,
        },
        {
          name,
          phase: "answered",
          action: "delete",
          transport: cell.transport,
          requestId: `${name}#2`,
          kind: "ok",
        },
        {
          name,
          phase: "resolved",
          requestId: `${name}#1`,
          resolution: "gone",
          proof: { kind: "own-delete-404" },
        },
        {
          name,
          phase: "resolved",
          requestId: `${name}#2`,
          resolution: "gone",
          proof: { kind: "own-delete-404" },
        },
      );
    }
    const result = {
      cellId: cell.id,
      complete: true,
      cleanupClosed: true,
      budgetOverrun: false,
      outstanding: [],
      iam: { unsettled: [] },
      names,
      observations,
    };
    results.push(result);
    write({ event: "case-result", ...result });
    recovery.push({
      sequence: recovery.length + 1,
      runId,
      cellId: cell.id,
      obligations: [],
      iam: [],
    });
  }
  return {
    packet: { plan: makePlan(), sourceHead: head, runIds: [runId], descriptorSha256 },
    descriptor: { head, suite: SUITE },
    summary: {
      runId,
      suite: SUITE,
      project: PROJECT,
      sourceHead: head,
      packetSha256,
      envelopeId: "synthetic-envelope",
      recordingComplete: true,
      resourcesClosed: true,
      a2: false,
      signalled: false,
      error: null,
      results,
    },
    rows,
    issued,
    iam,
    recovery,
    packetSha256,
    descriptorSha256,
  };
}

test("D imports a complete synthetic D12 with nonzero request/setup latency and the original managed/inactivity windows", async () => {
  const { importRecording } = await core(),
    input = await syntheticRecording();
  assert.deepEqual(
    importRecording(input).cells.map((c) => c.id),
    ["R1", "R2", "R3", "R4", "R5", "R6", "N1", "N2", "N3", "N4", "N5", "N6"],
  );
});

function changeObservation(input, stage, fields) {
  for (const row of input.rows.filter((r) => r.stage === stage)) Object.assign(row, fields);
  for (const result of input.summary.results)
    for (const row of result.observations.filter((r) => r.stage === stage))
      Object.assign(row, fields);
}

test("D refuses source binding, reserve, dispatch, physical, IAM, inactivity and cleanup near misses", async (t) => {
  const { importRecording } = await core();
  const mutations = {
    "changed unused G7 reservation": (x) => x.packet.plan.caps.G7.requests++,
    "changed unused reserve cell": (x) => x.packet.plan.cells.at(-1).cellMs++,
    "wrong source head": (x) => (x.descriptor.head = "f".repeat(40)),
    "wrong packet hash": (x) => (x.packetSha256 = "f".repeat(64)),
    "wrong descriptor hash": (x) => (x.descriptorSha256 = "f".repeat(64)),
    "wrong summary run": (x) => (x.summary.runId = "fedcba012345"),
    "reserve evidence": (x) => (x.rows[1].cellId = "R2F"),
    "missing cell result": (x) => x.summary.results.pop(),
    "duplicate cell result": (x) => x.summary.results.push(x.summary.results[0]),
    "unanswered dispatch": (x) => x.rows.splice(2, 1),
    "unknown response": (x) => (x.rows[2].reply.unknown = true),
    "foreign resource": (x) => (x.rows[1].request.name = "projects/synthetic/topics/foreign"),
    "oversize request": (x) => (x.rows[1].requestBodyBytes = 65537),
    "oversize response": (x) => (x.rows[2].reply.bodyBytes = 65537),
    "missing body digest": (x) => (x.rows[2].reply.bodySha256 = null),
    "missing issued closure": (x) => (x.issued = x.issued.filter((r) => r.phase !== "resolved")),
    "missing recovery binding": (x) =>
      (x.recovery = x.recovery.filter((r) => r.event !== "recovery-binding")),
    "unclosed recovery": (x) => (x.recovery.at(-1).obligations = [{ name: "synthetic-open" }]),
    "missing IAM restore": (x) =>
      x.iam.splice(
        x.iam.findIndex((r) => r.phase === "restore-confirmed"),
        1,
      ),
    "unowned IAM delta": (x) =>
      x.iam
        .find((r) => r.phase === "grant-intent")
        .requested.bindings.push({
          role: "roles/viewer",
          members: ["user:synthetic@example.invalid"],
        }),
    "short managed window": (x) =>
      changeObservation(x, "iam-window", { waitAfterLastGrantMs: 899999 }),
    "short inactivity window": (x) =>
      changeObservation(x, "inactivity-completed", { elapsedMs: 719999 }),
    "wrong ninth boundary": (x) => changeObservation(x, "inactivity-start", { sourceAttempts: 8 }),
    "inferred reset": (x) => changeObservation(x, "inactivity-completed", { resetInferred: true }),
    "false absent permission claim": (x) =>
      changeObservation(x, "baseline-permission", { status: "ABSENT" }),
  };
  for (const [name, mutate] of Object.entries(mutations))
    await t.test(name, async () => {
      const input = await syntheticRecording();
      mutate(input);
      assert.throws(() => importRecording(input));
    });
});

test("D empty source pulls need no ACK selector and remain comparable", async () => {
  const { replayRecording } = await core(),
    row = source("Pull", { subscription: "synthetic-source" }, {});
  const result = await replayRecording(executionInput([row]), async () => row.reply, {
    clockReceiptFor: receipt,
  });
  assert.equal(result.results[0].semanticVerdict, "MATCH");
});

test("D rejects a local forwarded message missing mandatory publication-time metadata", async () => {
  const { replayRecording } = await core();
  const attrs = {
    CloudPubSubDeadLetterSourceSubscription: "synthetic-source",
    CloudPubSubDeadLetterSourceSubscriptionProject: "synthetic-project",
    CloudPubSubDeadLetterSourceDeliveryCount: "7",
    CloudPubSubDeadLetterSourceTopicPublishTime: "2026-01-01T00:00:00.000Z",
  };
  const body = (attributes) => ({
    receivedMessages: [
      {
        ackId: "synthetic-ack",
        message: { messageId: "synthetic-forward", data: "eA==", attributes },
      },
    ],
  });
  const row = source("Pull", { subscription: "synthetic-sink" }, body(attrs), "sinkPull"),
    { CloudPubSubDeadLetterSourceTopicPublishTime: _time, ...missing } = attrs;
  const result = await replayRecording(executionInput([row]), async () => reply(body(missing)), {
    clockReceiptFor: receipt,
  });
  assert.equal(result.results[0].semanticVerdict, "DIVERGES");
});

test("D imports the original bounded native absence form but refuses forged captured-byte and uncertainty claims", async (t) => {
  const { importRecording } = await core();
  assert.equal(importRecording(await syntheticRecording()).cells.length, 12);
  const mutations = {
    "wrong native transport": (r, d) => {
      r.transport = "rest";
      d.transport = "rest";
    },
    "successful absence": (r) => (r.reply.ok = true),
    "unknown absence": (r) => (r.reply.unknown = true),
    "wrong native code": (r) => (r.reply.code = "PERMISSION_DENIED"),
    "wrong error status": (r) => (r.reply.body.error.status = "PERMISSION_DENIED"),
    "non-string details": (r) => (r.reply.body.error.message = 1),
    "null error body": (r) => (r.reply.body = null),
    "array error body": (r) => (r.reply.body = []),
    "missing null byte count": (r) => delete r.reply.bodyBytes,
    "forged captured-byte count": (r) => (r.reply.bodyBytes = 0),
    "forged body digest": (r) => (r.reply.bodySha256 = "a".repeat(64)),
    "null body digest": (r) => (r.reply.bodySha256 = null),
    "missing layout marker": (r) => delete r.reply.layoutVerdict,
    "changed layout marker": (r) => (r.reply.layoutVerdict = "MATCH"),
    "missing metadata": (r) => delete r.reply.metadataBytesIn,
    "fractional metadata": (r) => (r.reply.metadataBytesIn = 1.5),
    "negative metadata": (r) => (r.reply.metadataBytesIn = -1),
    "overflow metadata": (r) => (r.reply.metadataBytesIn = 65537),
    "broken dispatch binding": (r) => (r.requestId = -1),
  };
  for (const [name, mutate] of Object.entries(mutations))
    await t.test(name, async () => {
      const x = await syntheticRecording(),
        r = x.rows.find(
          (r) => r.event === "response" && r.transport === "grpc" && r.reply.code === "NOT_FOUND",
        ),
        d = x.rows.find((d) => d.event === "request-dispatch" && d.requestId === r.requestId);
      mutate(r, d);
      assert.throws(() => importRecording(x));
    });
});

test("D local replay awaits exact clock readbacks and durably binds physical rows to source dispatches", async () => {
  const { replayLocal } = await import("./pubsub-observation-d/replay.mjs"),
    { importRecording } = await core();
  const input = importRecording(await syntheticRecording());
  input.cells = [input.cells[0]];
  const pin = {
    profile: "release",
    rustcWrapper: "",
    sha256: "a".repeat(64),
    binaryInputsSha256: "b".repeat(64),
    head: "c".repeat(40),
    command: ["cargo", "build", "--release"],
    path: "/synthetic/release/fireemu",
  };
  const environment = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:1234",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:1235/v1/",
    FIREEMU_CONTROL_TOKEN: "synthetic-test",
  };
  for (const wrong of [true, false]) {
    const persisted = [],
      sent = [];
    const report = await replayLocal(input, environment, pin, {
      fetch: async (url, options) => {
        if (url.includes(":getIamPolicy")) {
          const resource = new URL(url).pathname.slice(4).split(":")[0];
          const exchange = input.cells[0].exchanges.find(
            (e) => e.method === "GetIamPolicy" && e.request.resource === resource,
          );
          return new Response(JSON.stringify(exchange.reply.body), { status: 200 });
        }
        return new Response(
          JSON.stringify({
            clock: wrong ? "2025-01-01T00:00:00Z" : JSON.parse(options.body).instant,
          }),
          { status: 200 },
        );
      },
      persist: (kind, value) => persisted.push({ kind, value }),
      wireFactory: ({ journal, localRuntime }) => ({
        close() {},
        abortSource() {},
        call: async (call) => {
          const exchange = input.cells[0].exchanges.find((e) => e.at === call.at);
          sent.push(call);
          journal.write({ event: "request-dispatch", cellId: call.cellId, method: call.method });
          localRuntime.captureBody(
            call.transport,
            exchange.requestId,
            Buffer.from(JSON.stringify(exchange.reply.body)),
          );
          journal.write({
            event: "response",
            cellId: call.cellId,
            method: call.method,
            reply: exchange.reply,
          });
          return exchange.reply;
        },
      }),
    });
    if (wrong) {
      assert.equal(sent.length, 0);
      assert.equal(report.verdict, "NOT_COMPARABLE");
    } else {
      assert.ok(sent.length > 0);
      assert.equal(
        report.clockReceipts.length,
        sent.length + input.cells[0].exchanges.filter((e) => e.method === "GetIamPolicy").length,
      );
      assert.equal(persisted.filter((p) => p.kind === "body").length, report.clockReceipts.length);
      assert.ok(
        report.localRows.every(
          (r) => Number.isSafeInteger(r.sourceRequestId) && Number.isSafeInteger(r.sourceN),
        ),
      );
      assert.ok(persisted.some((p) => p.kind === "comparison"));
    }
  }
});

test("D failed or ambiguous local Create never authorizes cleanup of that resource", async (t) => {
  const { replayRecording } = await core();
  for (const outcome of ["already-exists", "unknown", "throw"])
    await t.test(outcome, async () => {
      const calls = [],
        entries = [],
        create = source(
          "CreateTopic",
          { name: "synthetic-topic" },
          { name: "synthetic-topic" },
          "create",
        ),
        cleanup = {
          ...source("DeleteTopic", { name: "synthetic-topic" }, {}, "cleanupDelete"),
          requestId: 2,
          n: 4,
        };
      const result = await replayRecording(
        executionInput([create, cleanup]),
        async (call) => {
          calls.push(call.method);
          if (outcome === "throw") throw new Error("synthetic ambiguous create");
          return {
            ...reply({ error: { status: "ALREADY_EXISTS", message: "Synthetic existing topic" } }),
            ok: false,
            status: outcome === "unknown" ? 503 : 409,
            code: outcome === "unknown" ? "UNAVAILABLE" : "ALREADY_EXISTS",
            unknown: outcome === "unknown",
          };
        },
        { clockReceiptFor: receipt, observe: (entry) => entries.push(entry) },
      );
      assert.deepEqual(calls, ["CreateTopic"]);
      assert.ok(
        entries.some((e) => e.method === "DeleteTopic" && /ownership.*unconfirmed/i.test(e.debt)),
      );
      assert.ok(result.results[0].ownershipDebts.some((d) => d.resource === "synthetic-topic"));
    });
});

test("D preserves cleanup of a confirmed local resource after a later incomplete call", async () => {
  const { replayRecording } = await core(),
    calls = [];
  const create = source(
      "CreateTopic",
      { name: "synthetic-topic" },
      { name: "synthetic-topic" },
      "create",
    ),
    publish = {
      ...source("Publish", { topic: "synthetic-topic", messages: [] }, {}, "publish"),
      requestId: 2,
      n: 4,
    },
    later = { ...publish, requestId: 3, n: 6 },
    cleanup = {
      ...source("DeleteTopic", { name: "synthetic-topic" }, {}, "cleanupDelete"),
      requestId: 4,
      n: 8,
    };
  const result = await replayRecording(
    executionInput([create, publish, later, cleanup]),
    async (call) => {
      calls.push(call.method);
      if (call.method === "Publish") throw new Error("synthetic incomplete publication");
      return reply(call.method === "CreateTopic" ? { name: call.request.name } : {});
    },
    { clockReceiptFor: receipt },
  );
  assert.deepEqual(calls, ["CreateTopic", "Publish", "DeleteTopic"]);
  assert.equal(result.verdict, "NOT_COMPARABLE");
});

test("D Publish renames only nonempty string IDs and preserves the remaining response shape", async (t) => {
  const { replayRecording } = await core(),
    row = source(
      "Publish",
      { topic: "synthetic-topic", messages: [{ data: "eA==" }] },
      { messageIds: ["source-id"] },
      "publish",
    );
  for (const [name, body, expected] of [
    ["valid ID rename", { messageIds: ["local-id"] }, "MATCH"],
    ["extra field", { messageIds: ["local-id"], unexpected: true }, "DIVERGES"],
    ["numeric ID", { messageIds: [123] }, "DIVERGES"],
    ["empty ID", { messageIds: [""] }, "DIVERGES"],
    ["string rather than array", { messageIds: "x" }, "DIVERGES"],
  ])
    await t.test(name, async () => {
      const result = await replayRecording(executionInput([row]), async () => reply(body), {
        clockReceiptFor: receipt,
      });
      assert.equal(result.results[0].semanticVerdict, expected);
    });
});

test("D binds the retained source terminal without promoting an unknown native returncode", async () => {
  const module = await core();
  assert.equal(typeof module.bindTerminal, "function");
  const input = {
      metadata: { runId: "012345abcdef", sourceHead: "b".repeat(40), packetSha256: "c".repeat(64) },
    },
    summarySha256 = "d".repeat(64);
  const terminal = {
    runId: input.metadata.runId,
    sourceCommit: input.metadata.sourceHead,
    packetSha256: input.metadata.packetSha256,
    summarySha256,
    recordingComplete: true,
    resourcesClosed: true,
    sandboxAtBaseline: true,
    sourceReturncode: null,
    originalSupervisorStatus: "IDENTITY_UNRESOLVED",
  };
  assert.deepEqual(module.bindTerminal(terminal, input, summarySha256), terminal);
  for (const field of [
    "runId",
    "sourceCommit",
    "packetSha256",
    "summarySha256",
    "recordingComplete",
    "resourcesClosed",
    "sandboxAtBaseline",
  ])
    assert.throws(() => module.bindTerminal({ ...terminal, [field]: false }, input, summarySha256));
});

test("D malformed successful Create does not establish local ownership or permit later ordinary calls", async (t) => {
  const { replayRecording } = await core();
  for (const [name, answer] of [
    ["missing resource identity", reply({})],
    ["foreign resource identity", reply({ name: "foreign-topic" })],
    ["uncaptured physical body", { ...reply({ name: "synthetic-topic" }), bodySha256: null }],
    [
      "missing uncertainty classification",
      { ...reply({ name: "synthetic-topic" }), unknown: undefined },
    ],
  ])
    await t.test(name, async () => {
      const create = source(
          "CreateTopic",
          { name: "synthetic-topic" },
          { name: "synthetic-topic" },
          "create",
        ),
        publication = {
          ...source(
            "Publish",
            { topic: "synthetic-topic", messages: [{ data: "eA==" }] },
            { messageIds: ["source-id"] },
            "publish",
          ),
          requestId: 2,
          n: 4,
        },
        cleanup = {
          ...source("DeleteTopic", { name: "synthetic-topic" }, {}, "cleanupDelete"),
          requestId: 3,
          n: 6,
        },
        calls = [];
      await replayRecording(
        executionInput([create, publication, cleanup]),
        async (call) => {
          calls.push(call.method);
          return call.method === "CreateTopic" ? answer : reply({});
        },
        { clockReceiptFor: receipt },
      );
      assert.deepEqual(calls, ["CreateTopic"]);
    });
});

test("D config derives the exact source service agent and rejects adjacent identity shapes", async () => {
  const { sourceProjectNumbers } = await import("./pubsub-observation-d/replay.mjs");
  const input = {
    metadata: { project: "synthetic-source" },
    cells: [
      {
        arm: "managed-grant-readback-wait",
        exchanges: [
          {
            category: "iamSetupWrite",
            request: {
              resource: "projects/synthetic-source/subscriptions/source",
              policy: {
                bindings: [
                  {
                    role: "roles/pubsub.subscriber",
                    members: [
                      "serviceAccount:service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com",
                    ],
                  },
                ],
              },
            },
          },
          {
            category: "iamSetupWrite",
            request: {
              resource: "projects/synthetic-destination/topics/dead",
              policy: {
                bindings: [
                  {
                    role: "roles/pubsub.publisher",
                    members: [
                      "serviceAccount:service-123456789@gcp-sa-pubsub.iam.gserviceaccount.com",
                    ],
                  },
                ],
              },
            },
          },
        ],
      },
    ],
  };
  assert.deepEqual(sourceProjectNumbers(input), { "synthetic-source": "123456789" });
  for (const mutate of [
    (x) => x.cells[0].exchanges.pop(),
    (x) => (x.metadata.project = "synthetic-destination"),
    (x) => (x.cells[0].exchanges[0].request.resource = "projects/foreign/subscriptions/source"),
    (x) =>
      (x.cells[0].exchanges[1].request.policy.bindings[0].members = [
        "serviceAccount:service-987654321@gcp-sa-pubsub.iam.gserviceaccount.com",
      ]),
    (x) =>
      (x.cells[0].exchanges[0].request.policy.bindings[0].members = [
        "serviceAccount:service-012345678@gcp-sa-pubsub.iam.gserviceaccount.com",
      ]),
    (x) => (x.cells[0].exchanges[0].request.policy.bindings[0].role = "roles/pubsub.publisher"),
    (x) =>
      (x.cells[0].exchanges[1].request.resource = "projects/synthetic-source/subscriptions/other"),
    (x) => {
      x.cells[0].exchanges[1].request.resource = "projects/synthetic-source/subscriptions/other";
      x.cells[0].exchanges[1].request.policy.bindings[0].role = "roles/pubsub.subscriber";
    },
  ]) {
    const changed = structuredClone(input);
    mutate(changed);
    assert.throws(() => sourceProjectNumbers(changed));
  }
});

test("D refuses local policy drift before writing or restoring bindings", async () => {
  const { replayRecording } = await core(),
    resource = "projects/synthetic/topics/owned";
  const rows = [
    source("CreateTopic", { name: resource }, { name: resource }, "create"),
    source("GetIamPolicy", { resource }, { etag: "AAAA" }, "cleanupIamConflictGet"),
    source(
      "SetIamPolicy",
      { resource, policy: { etag: "AAAA", version: 1, bindings: [] } },
      { etag: "AAAAAAAAAAAB", version: 1 },
      "cleanupIamRestoreWrite",
    ),
  ];
  const calls = [];
  const result = await replayRecording(
    executionInput(rows),
    async (call, row) => {
      calls.push(call.method);
      return call.method === "GetIamPolicy"
        ? reply({
            etag: "BBBB",
            version: 1,
            bindings: [{ role: "roles/synthetic.reader", members: ["synthetic-member"] }],
          })
        : row.reply;
    },
    { clockReceiptFor: receipt },
  );
  assert.deepEqual(calls, ["CreateTopic", "GetIamPolicy"]);
  assert.match(result.results[0].exchanges.at(-1).debt, /policy conflict/);
});
