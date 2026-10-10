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

const publicationProposal = "8238575c8202949f721b59bb9c97ee36b3f0ae701efd552f4169c70fcf0c1c53";
function publicationFixture() {
  const topic = "synthetic-topic",
    subscription = "synthetic-subscription";
  const rows = [
    source("GetSubscription", { subscription }, { name: subscription, topic }, "inspect"),
    source(
      "Publish",
      { topic, messages: [{ data: "eA==" }] },
      { messageIds: ["source-id"] },
      "publish",
    ),
    source(
      "Pull",
      { subscription },
      {
        receivedMessages: [
          {
            ackId: "source-ack",
            message: {
              messageId: "source-id",
              data: "eA==",
              publishTime: "2026-01-01T00:00:00.097Z",
            },
          },
        ],
      },
    ),
  ];
  rows.forEach((r, i) => {
    r.requestId = i + 1;
    r.n = i + 1;
  });
  const input = executionInput(rows);
  input.metadata = {
    ...input.metadata,
    sourceHead: "b".repeat(40),
    packetSha256: digest,
    descriptorSha256: digest,
  };
  input.runtimeInputs = { binarySha256: digest, inputsSha256: digest };
  const options = {
    clockReceiptFor: (r) => ({ ...receipt(r), bodyBytes: 40, bodySha256: digest }),
    timestampDisposition: {
      owner1135: { proposalSha256: publicationProposal },
      source: { ...input.metadata },
      runtimeInputs: input.runtimeInputs,
      cellIds: ["R1"],
    },
  };
  const actual = rows.map((r) => structuredClone(r.reply));
  actual[1] = reply({ messageIds: ["local-id"] });
  actual[2] = reply({
    receivedMessages: [
      {
        ackId: "local-ack",
        message: { messageId: "local-id", data: "eA==", publishTime: rows[1].at },
      },
    ],
  });
  return { input, options, actual };
}
test("D approved REST publication time preserves physical differences and saved delivery invariants", async (t) => {
  const { replayRecording } = await core();
  for (const [name, change, expected] of [
    ["bound publication", () => {}, "MATCH"],
    [
      "missing publication",
      (f) => {
        f.input.cells[0].exchanges.splice(1, 1);
      },
      "NOT_COMPARABLE",
    ],
    [
      "runtime mismatch",
      (f) =>
        (f.options.timestampDisposition.runtimeInputs = {
          ...f.input.runtimeInputs,
          binarySha256: "e".repeat(64),
        }),
      "NOT_COMPARABLE",
    ],
    [
      "source mismatch",
      (f) => (f.options.timestampDisposition.source.sourceHead = "e".repeat(40)),
      "NOT_COMPARABLE",
    ],
    ["nonarray cells", (f) => (f.options.timestampDisposition.cellIds = "R1"), "NOT_COMPARABLE"],
    [
      "wrong topic",
      (f) => {
        f.input.cells[0].exchanges[0].reply.body.topic = "different-topic";
        f.actual[0].body.topic = "different-topic";
      },
      "NOT_COMPARABLE",
    ],
    [
      "wrong proposal",
      (f) => (f.options.timestampDisposition.owner1135.proposalSha256 = digest),
      "NOT_COMPARABLE",
    ],
    ["raw clock binding absent", (f) => (f.options.clockReceiptFor = receipt), "NOT_COMPARABLE"],
    [
      "different ID",
      (f) => (f.actual[2].body.receivedMessages[0].message.messageId = "other-id"),
      "DIVERGES",
    ],
    ["approval absent", (f) => delete f.options.timestampDisposition, "NOT_COMPARABLE"],
    [
      "clock inconsistent",
      (f) =>
        (f.options.clockReceiptFor = (r) => ({
          ...receipt(r),
          body: { clock: "2026-01-01T00:00:01.000Z" },
        })),
      "DIVERGES",
    ],
    [
      "both payloads changed",
      (f) => {
        f.actual[2].body.receivedMessages[0].message.data = "eQ==";
        f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.data = "eQ==";
      },
      "DIVERGES",
    ],
    [
      "local publication instant mismatch",
      (f) =>
        (f.actual[2].body.receivedMessages[0].message.publishTime = "2026-01-01T00:00:00.001Z"),
      "DIVERGES",
    ],
    [
      "other payload",
      (f) => (f.actual[2].body.receivedMessages[0].message.data = "eQ=="),
      "DIVERGES",
    ],
    [
      "other timestamp",
      (f) => (f.actual[2].body.receivedMessages[0].message.expireTime = "2026-01-02T00:00:00.000Z"),
      "DIVERGES",
    ],
    [
      "invalid time",
      (f) =>
        (f.actual[2].body.receivedMessages[0].message.publishTime = "2026-02-30T00:00:00.000Z"),
      "DIVERGES",
    ],
    [
      "source redelivery changed",
      (f) => {
        f.input.cells[0].exchanges.push({
          ...structuredClone(f.input.cells[0].exchanges[2]),
          requestId: 4,
          n: 4,
        });
        f.actual.push(structuredClone(f.actual[2]));
        f.input.cells[0].exchanges[3].reply.body.receivedMessages[0].message.publishTime =
          "2026-01-01T00:00:00.098Z";
      },
      "DIVERGES",
    ],
    [
      "saved value changed",
      (f) => {
        f.input.cells[0].exchanges.push({
          ...structuredClone(f.input.cells[0].exchanges[2]),
          requestId: 4,
          n: 4,
        });
        f.actual.push(structuredClone(f.actual[2]));
        f.actual[3].body.receivedMessages[0].message.publishTime = "2026-01-01T00:00:01.000Z";
      },
      "DIVERGES",
    ],
  ])
    await t.test(name, async () => {
      const f = publicationFixture();
      change(f);
      const r = await replayRecording(
        f.input,
        async (_call, row) => f.actual[row.requestId - 1],
        f.options,
      );
      const row = r.results[0].exchanges.at(-1);
      assert.equal(row.semanticVerdict, expected);
      if (name === "bound publication") {
        assert.equal(row.physicalVerdict, "DIVERGES");
        assert.equal(row.timestampProofs[0].verdict, "MATCH");
        assert.notEqual(row.timestampProofs[0].sourceValue, row.timestampProofs[0].localValue);
      }
    });
});

test("D REST publication time preserves all legal Z precisions across generated instants", async () => {
  const { replayRecording } = await core();
  for (const precision of [0, 3, 6, 9])
    for (let seconds = 0; seconds < 16; seconds++) {
      const f = publicationFixture(),
        prefix = `2026-01-01T00:00:${String(seconds).padStart(2, "0")}`;
      const suffix = precision ? `.${"0".repeat(precision)}` : "";
      f.input.cells[0].exchanges[1].at = `${prefix}${suffix}Z`;
      f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.publishTime = `${prefix}${precision ? `.${"1".repeat(precision)}` : ""}Z`;
      f.actual[2].body.receivedMessages[0].message.publishTime = `${prefix}${suffix}Z`;
      const r = await replayRecording(
        f.input,
        async (_call, row) => f.actual[row.requestId - 1],
        f.options,
      );
      assert.equal(r.results[0].exchanges[2].semanticVerdict, "MATCH");
    }
});

async function nativePublicationFixture({ omitTimestampZero = false } = {}) {
  const { protos } = await import("@google-cloud/pubsub"),
    { requestToWire } = await import("./pubsub-production/grpc.mjs"),
    { createHash } = await import("node:crypto");
  const f = publicationFixture();
  f.input.cells[0].id = "N1";
  f.options.timestampDisposition.cellIds = ["N1"];
  for (const row of f.input.cells[0].exchanges) row.transport = "grpc";
  f.input.cells[0].exchanges[1].reply.body.messageIds = ["11111111111111111"];
  f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.messageId =
    "11111111111111111";
  f.actual[1].body.messageIds = ["22222222222222222"];
  f.actual[2].body.receivedMessages[0].message.messageId = "22222222222222222";
  if (omitTimestampZero) {
    f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.publishTime =
      "2026-01-01T00:00:01Z";
    f.actual[2].body.receivedMessages[0].message.publishTime = "2026-01-01T00:00:00Z";
  } else {
    f.input.cells[0].exchanges[1].at = "2026-01-01T00:00:00.001Z";
    f.actual[2].body.receivedMessages[0].message.publishTime = "2026-01-01T00:00:00.001Z";
  }
  const bind = (r, { omitZero = omitTimestampZero } = {}) => {
    const body = requestToWire(structuredClone(r.body));
    if (omitZero)
      for (const item of body.receivedMessages ?? []) {
        if (item.message?.publishTime?.nanos === 0) delete item.message.publishTime.nanos;
        if (item.message?.publishTime?.seconds === "0") delete item.message.publishTime.seconds;
      }
    const bytes = Buffer.from(
      protos.google.pubsub.v1.PullResponse.encode(
        protos.google.pubsub.v1.PullResponse.fromObject(body),
      ).finish(),
    );
    r.bodyBytes = bytes.length;
    r.bodySha256 = createHash("sha256").update(bytes).digest("hex");
    return bytes;
  };
  bind(f.input.cells[0].exchanges[2].reply);
  bind(f.actual[2]);
  const duplicateMap = (r) => {
    const item = requestToWire(structuredClone(r.body)).receivedMessages[0];
    const message = Buffer.concat([
      Buffer.from(
        protos.google.pubsub.v1.PubsubMessage.encode(
          protos.google.pubsub.v1.PubsubMessage.fromObject(item.message),
        ).finish(),
      ),
      Buffer.from(
        protos.google.pubsub.v1.PubsubMessage.encode({
          attributes: item.message.attributes,
        }).finish(),
      ),
    ]);
    const received = protos.google.pubsub.v1.ReceivedMessage.encode({ ackId: item.ackId })
      .uint32(18)
      .bytes(message)
      .finish();
    const bytes = Buffer.from(
      protos.google.pubsub.v1.PullResponse.encode({}).uint32(10).bytes(received).finish(),
    );
    r.bodyBytes = bytes.length;
    r.bodySha256 = createHash("sha256").update(bytes).digest("hex");
  };
  return {
    ...f,
    bind,
    duplicateMap,
    hash: (bytes) => createHash("sha256").update(bytes).digest("hex"),
  };
}
test("D native source Pull recovers exact captured wire before publication disposition", async (t) => {
  const { replayRecording } = await core();
  for (const [name, alter, expected] of [
    ["captured unary publication", () => {}, "MATCH"],
    [
      "unencoded field cannot be invented",
      (f) => {
        f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.unrecorded = "x";
        f.actual[2].body.receivedMessages[0].message.unrecorded = "x";
      },
      "NOT_COMPARABLE",
    ],

    [
      "equal timestamp retains physical raw difference",
      (f) => {
        f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.publishTime =
          "2026-01-01T00:00:00.001Z";
        f.bind(f.input.cells[0].exchanges[2].reply);
      },
      "MATCH",
    ],

    [
      "attribute wire order",
      (f) => {
        f.input.cells[0].exchanges[1].request.messages[0].attributes = { first: "x", second: "y" };
        f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.attributes = {
          first: "x",
          second: "y",
        };
        f.actual[2].body.receivedMessages[0].message.attributes = { second: "y", first: "x" };
        f.bind(f.input.cells[0].exchanges[2].reply);
        f.bind(f.actual[2]);
      },
      "MATCH",
    ],
    [
      "stored publication time mismatch",
      (f) => {
        f.actual[2].body.receivedMessages[0].message.publishTime = "2026-01-01T00:00:00.002Z";
        f.bind(f.actual[2]);
      },
      "DIVERGES",
    ],

    ["Timestamp zero omission", () => {}, "MATCH"],
    ...["key", "value"].map((field) => [
      `attribute changed ${field}`,
      (f) => {
        f.actual[2].body.receivedMessages[0].message.attributes =
          field === "key" ? { changed: "x" } : { first: "changed" };
        f.bind(f.actual[2]);
      },
      "DIVERGES",
    ]),
    [
      "unknown original wire field",
      (f) => {
        const reply = f.input.cells[0].exchanges[2].reply;
        const raw = f.bind(reply);
        const changed = Buffer.concat([raw, Buffer.from([160, 6, 1])]);
        reply.bodyBytes = changed.length;
        reply.bodySha256 = f.hash(changed);
      },
      "NOT_COMPARABLE",
    ],
    [
      "ordinary repeated message multiplicity",
      (f) => {
        f.actual[2].body.receivedMessages.push(
          structuredClone(f.actual[2].body.receivedMessages[0]),
        );
        f.bind(f.actual[2]);
      },
      "DIVERGES",
    ],
    [
      "duplicate original map entry",
      (f) => {
        const r = f.input.cells[0].exchanges[2].reply;
        r.body.receivedMessages[0].message.attributes = { duplicate: "x" };
        f.input.cells[0].exchanges[1].request.messages[0].attributes = { duplicate: "x" };
        f.actual[2].body.receivedMessages[0].message.attributes = { duplicate: "x" };
        f.bind(f.actual[2]);
        f.duplicateMap(r);
      },
      "NOT_COMPARABLE",
    ],
    [
      "ordinary repeated message order",
      (f) => {
        const r = f.actual[2];
        const second = structuredClone(r.body.receivedMessages[0]);
        second.message.data = "eQ==";
        r.body.receivedMessages.unshift(second);
        f.input.cells[0].exchanges[2].reply.body.receivedMessages.push(structuredClone(second));
        f.bind(r);
        f.bind(f.input.cells[0].exchanges[2].reply);
      },
      "DIVERGES",
    ],
    [
      "Timestamp zero presence remains strict",
      (f) => {
        f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.publishTime =
          "2026-01-01T00:00:01Z";
        f.actual[2].body.receivedMessages[0].message.publishTime = "2026-01-01T00:00:00Z";
        f.input.cells[0].exchanges[1].at = "2026-01-01T00:00:00Z";
        f.options.clockReceiptFor = (r) => ({
          ...receipt(r),
          bodyBytes: 40,
          bodySha256: digest,
          body: { clock: "2026-01-01T00:00:00.000000000Z" },
        });
        f.bind(f.input.cells[0].exchanges[2].reply);
        f.bind(f.actual[2], { omitZero: true });
      },
      "DIVERGES",
    ],
    [
      "source hash mismatch",
      (f) => (f.input.cells[0].exchanges[2].reply.bodySha256 = digest),
      "NOT_COMPARABLE",
    ],
    [
      "source byte count mismatch",
      (f) => f.input.cells[0].exchanges[2].reply.bodyBytes++,
      "NOT_COMPARABLE",
    ],
    ["local raw binding missing", (f) => delete f.actual[2].bodySha256, "NOT_COMPARABLE"],
    [
      "same-length other publication",
      (f) => {
        f.actual[2].body.receivedMessages[0].message.messageId = "33333333333333333";
        f.bind(f.actual[2]);
      },
      "DIVERGES",
    ],
    [
      "other payload",
      (f) => {
        f.actual[2].body.receivedMessages[0].message.data = "eQ==";
        f.bind(f.actual[2]);
      },
      "DIVERGES",
    ],
    [
      "clock mismatch",
      (f) =>
        (f.options.clockReceiptFor = (r) => ({
          ...receipt(r),
          bodyBytes: 40,
          bodySha256: digest,
          body: { clock: "2026-01-01T00:00:02.000Z" },
        })),
      "DIVERGES",
    ],
    ["missing authority", (f) => delete f.options.timestampDisposition, "NOT_COMPARABLE"],
    [
      "counter difference",
      (f) => {
        f.actual[2].body.receivedMessages[0].deliveryAttempt = 2;
        f.bind(f.actual[2]);
      },
      "DIVERGES",
    ],
  ])
    await t.test(name, async () => {
      const f = await nativePublicationFixture({
        omitTimestampZero: name === "Timestamp zero omission",
      });
      alter(f);
      const r = await replayRecording(
        f.input,
        async (_call, row) => f.actual[row.requestId - 1],
        f.options,
      );
      const e = r.results[0].exchanges[2];
      assert.equal(e.semanticVerdict, expected);
      if (name === "Timestamp zero presence remains strict") {
        assert.equal(e.timestampProofs[0].publicationVerdict, "MATCH");
        assert.equal(e.timestampProofs[0].nativeWire.verdict, "DIVERGES");
      }
      if (name === "attribute wire order") {
        assert.equal(e.timestampProofs[0].nativeWire.originalProjectionVerdict, "DIVERGES");
        assert.notDeepEqual(
          e.timestampProofs[0].nativeWire.attributesOrder[0].keys,
          e.timestampProofs[0].nativeWire.attributesOrder[1].keys,
        );
      }
      if (expected === "MATCH") {
        assert.equal(e.physicalVerdict, "DIVERGES");
        assert.equal(e.timestampProofs[0].nativeWire.verdict, "MATCH");
        assert.equal(e.timestampProofs[0].nativeWire.sourceRecovered, true);
        assert.equal(e.timestampProofs[0].nativeWire.localRecovered, true);
        assert.equal(
          f.hash(Buffer.from(e.timestampProofs[0].nativeWire.sourceBodyBase64, "base64")),
          e.timestampProofs[0].nativeWire.sourceSha256,
        );
        assert.equal(
          f.hash(Buffer.from(e.timestampProofs[0].nativeWire.localBodyBase64, "base64")),
          e.timestampProofs[0].nativeWire.localSha256,
        );
        assert.equal(
          e.timestampProofs[0].nativeWire.sourceCandidate,
          name === "Timestamp zero omission" ? 2 : 1,
        );
      }
    });
});

test("D native source Pull retains legal precision and induced scalar widths", async () => {
  const { replayRecording } = await core();
  for (const precision of [0, 3, 6, 9])
    for (let second = 0; second < 8; second++) {
      const f = await nativePublicationFixture(),
        stamp = (sec, fraction) =>
          `2026-01-01T00:00:${String(sec).padStart(2, "0")}${precision ? `.${fraction.slice(0, precision)}` : ""}Z`;
      f.input.cells[0].exchanges[1].at = stamp(second, "899654321");
      f.input.cells[0].exchanges[2].reply.body.receivedMessages[0].message.publishTime = stamp(
        second + 1,
        "021123456",
      );
      f.actual[2].body.receivedMessages[0].message.publishTime = f.input.cells[0].exchanges[1].at;
      f.bind(f.input.cells[0].exchanges[2].reply);
      f.bind(f.actual[2]);
      const r = await replayRecording(
          f.input,
          async (_call, row) => f.actual[row.requestId - 1],
          f.options,
        ),
        e = r.results[0].exchanges[2];
      assert.equal(e.semanticVerdict, "MATCH");
      assert.equal(e.timestampProofs[0].nativeWire.verdict, "MATCH");
      assert.equal(e.physicalVerdict, "DIVERGES");
    }
});

test("D native timestamp disposition leaves forwarded sink and origin evidence unresolved", async () => {
  const { replayRecording } = await core(),
    f = await nativePublicationFixture();
  f.input.cells[0].exchanges[2].category = "sinkPull";
  for (const r of [f.input.cells[0].exchanges[2].reply, f.actual[2]]) {
    r.body.receivedMessages[0].message.attributes = {
      CloudPubSubDeadLetterSourceTopicPublishTime: "2026-01-01T00:00:00.001Z",
    };
    f.bind(r);
  }
  const r = await replayRecording(
      f.input,
      async (_call, row) => f.actual[row.requestId - 1],
      f.options,
    ),
    e = r.results[0].exchanges[2];
  assert.equal(e.semanticVerdict, "NOT_COMPARABLE");
  assert.deepEqual(e.timestampProofs, []);
  assert.ok(
    e.debts.includes("Observed publication timestamp requires source/local clock evidence"),
  );
});
