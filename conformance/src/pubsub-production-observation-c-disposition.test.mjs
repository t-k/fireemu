import test from "node:test";
import assert from "node:assert/strict";
import { replayRecording } from "./pubsub-observation-c/replay-core.mjs";
import {
  createSchedulingDisposition,
  SCHEDULING_APPROVAL,
} from "./pubsub-observation-c/scheduling-disposition.mjs";

const metadata = {
  runId: "0123456789ab",
  sourceHead: "a".repeat(40),
  packetSha256: "b".repeat(64),
  descriptorSha256: "c".repeat(64),
};
const runtimeInputs = { binarySha256: "d".repeat(64), inputsSha256: "e".repeat(64) };
function authority(cellId = "R5") {
  return {
    ...structuredClone(SCHEDULING_APPROVAL),
    source: metadata,
    runtimeInputs,
    cellIds: [cellId],
  };
}
function setup(cellId = "R5", stage = "unfiltered-positive-control") {
  const source = {
    method: "Pull",
    request: { subscription: "control", maxMessages: 3 },
    responseN: 2,
    n: 1,
    at: "2026-10-10T00:00:00.000Z",
    reply: { ok: true, code: "OK", status: 200, body: { receivedMessages: [] } },
  };
  const cell = {
    id: cellId,
    observations: [{ n: 3, stage, subscription: "control", items: [], attempt: 0 }],
    exchanges: [source],
  };
  const publications = new Map(
    [0, 1, 2].map((i) => [
      String(i),
      {
        sourceMessageId: String(i),
        messageId: String(100 + i),
        topic: "topic",
        payload: { data: String(i), attributes: {}, orderingKey: "" },
      },
    ]),
  );
  const subscription = {
    topic: "topic",
    filter: "",
    enableMessageOrdering: false,
    ackDeadlineSeconds: 60,
  };
  return {
    source,
    cell,
    publications,
    subscription,
    session: createSchedulingDisposition({ metadata, runtimeInputs }, cell, authority(cellId)),
  };
}
function delivery(i, ackId = `ack${i}`) {
  return {
    ackId,
    message: { messageId: String(100 + i), data: String(i), attributes: {}, orderingKey: "" },
  };
}
const clockReceiptFor = (source) => ({
  sourceRequestId: source.requestId,
  sourceN: source.n,
  requestedInstant: source.at,
  status: 200,
  body: { clock: source.at },
});
const reply = (items) => ({ ok: true, code: "OK", status: 200, body: { receivedMessages: items } });

test("owner-bound complete control accepts partitions and retains exact evidence separately", () => {
  const f = setup();
  assert.equal(
    f.session.pull(f.source, reply([delivery(2), delivery(0)]), f.publications, f.subscription)
      .kind,
    "control",
  );
  assert.deepEqual(f.session.ackIds("control"), ["ack2", "ack0"]);
  f.session.ack(
    "control",
    ["ack2", "ack0"],
    { ok: true, code: "OK", status: 200, body: {} },
    "2026-10-10T00:00:00.000Z",
  );
  f.session.pull(f.source, reply([delivery(1)]), f.publications, f.subscription);
  f.session.ack(
    "control",
    ["ack1"],
    { ok: true, code: "OK", status: 200, body: {} },
    "2026-10-10T00:00:00.000Z",
  );
  assert.equal(f.session.finish().verdict, "MATCH");
});
test("a matching first batch never waives missing control publications or ACKs", () => {
  const f = setup();
  f.session.pull(f.source, reply([delivery(0)]), f.publications, f.subscription);
  assert.equal(f.session.finish().verdict, "NOT_COMPARABLE");
});
test("foreign IDs, payload drift, token collision, duplicate and maxMessages excess diverge", () => {
  for (const mutate of [
    (items) => {
      items[0].message.messageId = "foreign";
    },
    (items) => {
      items[0].message.data = "wrong";
    },
    (items) => {
      items[1].ackId = items[0].ackId;
    },
    (items) => {
      items.push(structuredClone(items[0]));
    },
    (items) => {
      items.push(delivery(2), delivery(0));
    },
  ]) {
    const f = setup(),
      items = [delivery(0), delivery(1)];
    mutate(items);
    f.session.pull(f.source, reply(items), f.publications, f.subscription);
    assert.equal(f.session.finish().verdict, "DIVERGES");
  }
});
test("no approximate authority or filtered/window expansion is admitted", () => {
  for (const key of [
    "proposalSha256",
    "correctionSha256",
    "independentReviewSha256",
    "owner1203LineSha256",
  ]) {
    const f = setup(),
      a = authority();
    a[key] = "f".repeat(64);
    assert.equal(createSchedulingDisposition({ metadata, runtimeInputs }, f.cell, a), null);
  }
  const f = setup();
  assert.equal(
    f.session.pull(f.source, reply([delivery(0)]), f.publications, {
      ...f.subscription,
      filter: "attributes.env = x",
    }),
    null,
  );
  for (const id of ["R8", "N8", "R13"]) {
    const x = setup(id, "both-target-Seek-followup");
    assert.equal(x.session.pull(x.source, reply([]), x.publications, x.subscription), null);
  }
});
test("ACK refuses stale token and response failures; no fabricated successful effect", () => {
  for (const response of [
    { ok: false, code: "INVALID_ARGUMENT", status: 400, body: {} },
    { ok: true, code: "OK", status: 200, body: {}, unknown: true },
  ]) {
    const f = setup();
    f.session.pull(f.source, reply([delivery(0)]), f.publications, f.subscription);
    f.session.ack("control", ["ack0"], response, "2026-10-10T00:00:00.000Z");
    assert.equal(f.session.finish().verdict, response.unknown ? "NOT_COMPARABLE" : "DIVERGES");
  }
  const f = setup();
  f.session.pull(f.source, reply([delivery(0)]), f.publications, f.subscription);
  f.session.ack(
    "control",
    ["stale"],
    { ok: true, code: "OK", status: 200, body: {} },
    "2026-10-10T00:00:00.000Z",
  );
  assert.equal(f.session.finish().verdict, "DIVERGES");
});

test("R9 allows cross-key interleaving but rejects same-key inversion and outstanding-key overlap", () => {
  for (const order of [
    [0, 1, 2],
    [2, 0, 1],
    [0, 2, 1],
    [1, 0, 2],
  ]) {
    const f = setup("R9", "first-Pull-exact-order");
    f.subscription.enableMessageOrdering = true;
    for (const [i, p] of [...f.publications.values()].entries())
      p.payload.orderingKey = i === 2 ? "B" : "A";
    const items = order.map((i) => ({
      ...delivery(i),
      message: { ...delivery(i).message, orderingKey: i === 2 ? "B" : "A" },
    }));
    f.session.pull(f.source, reply(items), f.publications, f.subscription);
    f.session.ack(
      "control",
      items.map((i) => i.ackId),
      { ok: true, code: "OK", status: 200, body: {} },
      "2026-10-10T00:00:00.000Z",
    );
    assert.equal(f.session.finish().verdict, order[0] === 1 ? "DIVERGES" : "MATCH");
  }
  const f = setup("R9", "first-Pull-exact-order");
  f.subscription.enableMessageOrdering = true;
  f.publications.get("0").payload.orderingKey = "A";
  f.publications.get("1").payload.orderingKey = "A";
  const item = (i) => ({ ...delivery(i), message: { ...delivery(i).message, orderingKey: "A" } });
  f.session.pull(f.source, reply([item(0)]), f.publications, f.subscription);
  f.session.pull(f.source, reply([item(1)]), f.publications, f.subscription);
  assert.equal(f.session.finish().verdict, "DIVERGES");
});

test("Seek finite windows retain forbidden preACK membership and missing/empty uncertainty", () => {
  for (const chosen of [[1], [0], []]) {
    const f = setup("R12", "snapshot-replay");
    f.cell.exchanges.unshift(
      {
        n: -4,
        method: "Pull",
        request: { subscription: "control" },
        reply: {
          ok: true,
          body: { receivedMessages: [{ ackId: "old", message: { messageId: "0" } }] },
        },
      },
      {
        n: -3,
        method: "Acknowledge",
        request: { subscription: "control", ackIds: ["old"] },
        reply: { ok: true },
      },
      { n: -2, method: "CreateSnapshot", request: { name: "snapshot" }, reply: { ok: true } },
      {
        n: -1,
        method: "Seek",
        request: { subscription: "control", snapshot: "snapshot" },
        reply: { ok: true },
      },
    );
    f.source.reply.body.receivedMessages = [{ ackId: "source", message: { messageId: "1" } }];
    f.session.pull(f.source, reply(chosen.map((i) => delivery(i))), f.publications, f.subscription);
    f.session.ack(
      "control",
      chosen.map((i) => `ack${i}`),
      { ok: true, code: "OK", status: 200, body: {} },
      "2026-10-10T00:00:00.000Z",
    );
    assert.equal(
      f.session.finish().verdict,
      chosen.includes(0) ? "DIVERGES" : chosen.length ? "MATCH" : "NOT_COMPARABLE",
    );
  }
});

test("finite control proof exhausts partitions/permutations and every proper subset remains NC", () => {
  for (const order of [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
  ])
    for (let cut = 0; cut <= 3; cut++) {
      const f = setup();
      for (const part of [order.slice(0, cut), order.slice(cut)]) {
        f.session.pull(
          f.source,
          reply(part.map((i) => delivery(i))),
          f.publications,
          f.subscription,
        );
        f.session.ack(
          "control",
          part.map((i) => `ack${i}`),
          { ok: true, code: "OK", status: 200, body: {} },
          "2026-10-10T00:00:00.000Z",
        );
      }
      assert.equal(f.session.finish().verdict, "MATCH");
    }
  for (let mask = 0; mask < 7; mask++) {
    const f = setup(),
      ids = [0, 1, 2].filter((i) => mask & (1 << i));
    f.session.pull(f.source, reply(ids.map((i) => delivery(i))), f.publications, f.subscription);
    f.session.ack(
      "control",
      ids.map((i) => `ack${i}`),
      { ok: true, code: "OK", status: 200, body: {} },
      "2026-10-10T00:00:00.000Z",
    );
    assert.equal(f.session.finish().verdict, "NOT_COMPARABLE");
  }
});

function replayFixture() {
  const topic = "topic",
    subscription = "control";
  let n = 0;
  const exchanges = [],
    observations = [];
  const add = (method, request, body) => {
    const e = {
      n: ++n,
      responseN: ++n,
      requestId: n,
      at: "2026-10-10T00:00:00.000Z",
      transport: "rest",
      category: "other",
      method,
      request,
      reply: { ok: true, code: "OK", status: 200, body },
    };
    exchanges.push(e);
    return e;
  };
  add("CreateTopic", { name: topic }, { name: topic });
  add(
    "CreateSubscription",
    { name: subscription, topic, ackDeadlineSeconds: 60 },
    { name: subscription, topic, ackDeadlineSeconds: 60 },
  );
  add(
    "Publish",
    { topic, messages: [0, 1, 2].map((i) => ({ data: String(i) })) },
    { messageIds: ["0", "1", "2"] },
  );
  for (const ids of [[0, 1], [2]]) {
    const e = add(
      "Pull",
      { subscription, maxMessages: 3 },
      {
        receivedMessages: ids.map((i) => ({
          ackId: `source${i}`,
          message: { messageId: String(i), data: String(i), attributes: {}, orderingKey: "" },
        })),
      },
    );
    observations.push({
      n: ++n,
      stage: "unfiltered-positive-control",
      subscription,
      attempt: 0,
      items: e.reply.body.receivedMessages,
    });
    add("Acknowledge", { subscription, ackIds: ids.map((i) => `source${i}`) }, {});
  }
  return {
    metadata,
    runtimeInputs,
    cells: [{ id: "R5", coordinates: {}, exchanges, observations }],
  };
}
test("approved replay continues original dispatches with actual ACKs and keeps old exact differences", async () => {
  const input = replayFixture(),
    raw = structuredClone(input);
  let pulls = 0,
    acks = [];
  const result = await replayRecording(
    input,
    async (call, source) => {
      if (call.method === "Publish")
        return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
      if (call.method === "Pull")
        return reply((pulls++ === 0 ? [2] : [0, 1]).map((i) => delivery(i)));
      if (call.method === "Acknowledge") acks.push(call.request.ackIds);
      return structuredClone(source.reply);
    },
    { schedulingDisposition: authority(), clockReceiptFor },
  );
  assert.deepEqual(acks, [["ack2"], ["ack0", "ack1"]], JSON.stringify(result.cells[0].exchanges));
  assert.equal(result.cells[0].dispositionVerdict, "MATCH");
  assert.equal(result.cells[0].semanticVerdict, "NOT_COMPARABLE");
  assert.equal(result.cells[0].exchanges.filter((e) => e.schedulingCandidate).length, 4);
  assert.deepEqual(input, raw);
  assert.equal(result.parentClosureReady, false);
});
test("unapproved replay fails closed before fabricating continuation", async () => {
  const input = replayFixture();
  let acknowledgements = 0;
  const result = await replayRecording(input, async (call, source) => {
    if (call.method === "Publish")
      return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
    if (call.method === "Pull") return reply([delivery(2)]);
    if (call.method === "Acknowledge") acknowledgements++;
    return structuredClone(source.reply);
  });
  assert.equal(acknowledgements, 0);
  assert.equal(result.cells[0].semanticVerdict, "NOT_COMPARABLE");
  assert.equal(result.cells[0].dispositionVerdict, undefined);
});

test("approved continuation preserves deliveryAttempt/envelope/status/timestamp differences", async () => {
  for (const mutation of [
    (item) => {
      item.deliveryAttempt = 7;
    },
    (item) => {
      item.message.publishTime = "2026-10-10T00:00:01.000Z";
    },
    (item) => {
      item.unexpected = true;
    },
  ]) {
    const input = replayFixture();
    let pulls = 0;
    const report = await replayRecording(
      input,
      async (call, source) => {
        if (call.method === "Publish")
          return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
        if (call.method === "Pull") {
          const items = (pulls++ === 0 ? [2] : [0, 1]).map((i) => delivery(i));
          mutation(items[0]);
          return reply(items);
        }
        return structuredClone(source.reply);
      },
      { schedulingDisposition: authority(), clockReceiptFor },
    );
    assert.equal(report.cells[0].dispositionVerdict, "DIVERGES");
  }
});

test("empty and nonempty scheduling ACKs preserve observed errors; absent clocks cannot MATCH", async () => {
  for (const empty of [true, false]) {
    const input = replayFixture();
    let pulls = 0,
      acks = 0;
    const report = await replayRecording(
      input,
      async (call, source) => {
        if (call.method === "Publish")
          return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
        if (call.method === "Pull")
          return reply(
            (pulls++ === 0 ? (empty ? [0, 1, 2] : [2]) : empty ? [] : [0, 1]).map((i) =>
              delivery(i),
            ),
          );
        if (call.method === "Acknowledge" && ++acks === 2)
          return {
            ok: false,
            code: "INVALID_ARGUMENT",
            status: 400,
            body: { error: { message: "bad ACK" } },
          };
        return structuredClone(source.reply);
      },
      { schedulingDisposition: authority(), clockReceiptFor },
    );
    assert.equal(report.cells[0].dispositionVerdict, "DIVERGES");
  }
  const input = replayFixture();
  let pulls = 0;
  const report = await replayRecording(
    input,
    async (call, source) => {
      if (call.method === "Publish")
        return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
      if (call.method === "Pull")
        return reply((pulls++ === 0 ? [2] : [0, 1]).map((i) => delivery(i)));
      return structuredClone(source.reply);
    },
    { schedulingDisposition: authority() },
  );
  assert.equal(report.cells[0].dispositionVerdict, "NOT_COMPARABLE");
});

test("approved unchanged source batches keep the existing exact MATCH", async () => {
  const input = replayFixture();
  let pulls = 0;
  const report = await replayRecording(
    input,
    async (call, source) => {
      if (call.method === "Publish")
        return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
      if (call.method === "Pull")
        return reply((pulls++ === 0 ? [0, 1] : [2]).map((i) => delivery(i)));
      return structuredClone(source.reply);
    },
    { schedulingDisposition: authority(), clockReceiptFor },
  );
  assert.equal(report.cells[0].semanticVerdict, "MATCH");
  assert.equal(report.cells[0].dispositionVerdict, "MATCH");
});

test("exact source/runtime pins and ACK lease deadlines remain mandatory", () => {
  const f = setup();
  for (const section of ["source", "runtimeInputs"])
    for (const key of Object.keys(section === "source" ? metadata : runtimeInputs)) {
      const a = authority();
      a[section] = { ...a[section], [key]: "f".repeat(64) };
      assert.equal(createSchedulingDisposition({ metadata, runtimeInputs }, f.cell, a), null);
    }
  f.session.pull(f.source, reply([delivery(0)]), f.publications, f.subscription);
  f.session.ack(
    "control",
    ["ack0"],
    { ok: true, code: "OK", status: 200, body: {} },
    "2026-10-10T00:01:00.000Z",
  );
  assert.equal(f.session.finish().windows[0].acknowledged.length, 0);
  assert.equal(f.session.finish().verdict, "NOT_COMPARABLE");
});

test("acknowledged control marker cannot recur under a fresh token in a later bounded batch", () => {
  const f = setup();
  f.session.pull(
    f.source,
    reply([0, 1, 2].map((i) => delivery(i))),
    f.publications,
    f.subscription,
  );
  f.session.ack(
    "control",
    ["ack0", "ack1", "ack2"],
    { ok: true, code: "OK", status: 200, body: {} },
    "2026-10-10T00:00:00.000Z",
  );
  f.session.pull(f.source, reply([delivery(0, "fresh")]), f.publications, f.subscription);
  assert.equal(f.session.finish().verdict, "DIVERGES");
});

test("three distinct known markers still violate a maxMessages two request", () => {
  const f = setup();
  f.source.request.maxMessages = 2;
  f.session.pull(
    f.source,
    reply([0, 1, 2].map((i) => delivery(i))),
    f.publications,
    f.subscription,
  );
  assert.equal(f.session.finish().verdict, "DIVERGES");
});

test("nanosecond ACK boundary is evaluated without millisecond rounding", () => {
  for (const [at, acked] of [
    ["2026-10-10T00:01:00.000000000Z", true],
    ["2026-10-10T00:01:00.000000001Z", false],
  ]) {
    const f = setup();
    f.source.at = "2026-10-10T00:00:00.000000001Z";
    f.session.pull(f.source, reply([delivery(0)]), f.publications, f.subscription);
    f.session.ack("control", ["ack0"], { ok: true, code: "OK", status: 200, body: {} }, at);
    assert.equal(f.session.finish().windows[0].acknowledged.includes("0"), acked);
  }
});

function preSeekWitnessFixture({
  witnessSubscription = "control",
  witnessSuccess = true,
  witnessData = "2",
} = {}) {
  let n = 0;
  const exchanges = [],
    observations = [];
  const add = (method, request, body) => {
    const e = {
      n: ++n,
      responseN: ++n,
      requestId: n,
      at: "2026-10-10T00:00:00.000Z",
      transport: "rest",
      category: "other",
      method,
      request,
      reply: { ok: true, code: "OK", status: 200, body },
    };
    exchanges.push(e);
    return e;
  };
  add("CreateTopic", { name: "topic" }, { name: "topic" });
  add(
    "CreateSubscription",
    { name: "control", topic: "topic", ackDeadlineSeconds: 60 },
    { name: "control", topic: "topic", ackDeadlineSeconds: 60 },
  );
  if (witnessSubscription !== "control")
    add(
      "CreateSubscription",
      { name: witnessSubscription, topic: "topic", ackDeadlineSeconds: 60 },
      { name: witnessSubscription, topic: "topic", ackDeadlineSeconds: 60 },
    );
  add(
    "Publish",
    { topic: "topic", messages: [0, 1, 2].map((i) => ({ data: String(i) })) },
    { messageIds: ["0", "1", "2"] },
  );
  add("CreateSnapshot", { name: "snapshot", subscription: "control" }, { name: "snapshot" });
  const pre = add(
    "Pull",
    { subscription: witnessSubscription, maxMessages: 3 },
    {
      receivedMessages: [0, 1, 2].map((i) => ({
        ackId: `pre${i}`,
        message: {
          messageId: String(i),
          data: i === 2 ? witnessData : String(i),
          attributes: {},
          orderingKey: "",
        },
      })),
    },
  );
  pre.reply.ok = witnessSuccess;
  add("Acknowledge", { subscription: witnessSubscription, ackIds: ["pre0", "pre1", "pre2"] }, {});
  add("Seek", { subscription: "control", snapshot: "snapshot" }, {});
  for (const ids of [[0, 1], []]) {
    const e = add(
      "Pull",
      { subscription: "control", maxMessages: 3 },
      {
        receivedMessages: ids.map((i) => ({
          ackId: `post${i}`,
          message: { messageId: String(i), data: String(i), attributes: {}, orderingKey: "" },
        })),
      },
    );
    observations.push({
      n: ++n,
      stage: "snapshot-replay",
      subscription: "control",
      items: e.reply.body.receivedMessages,
    });
    if (ids.length)
      add("Acknowledge", { subscription: "control", ackIds: ids.map((i) => `post${i}`) }, {});
  }
  return {
    metadata,
    runtimeInputs,
    cells: [{ id: "R12", coordinates: {}, exchanges, observations }],
  };
}
async function replayPreSeekFixture(input, extraField = false) {
  let pulls = 0;
  return replayRecording(
    input,
    async (call, source) => {
      if (call.method === "Publish")
        return { ...source.reply, body: { messageIds: ["100", "101", "102"] } };
      if (call.method === "Pull")
        return reply(
          (pulls++ < 2 ? [0, 1, 2] : []).map((i) =>
            Object.assign(
              delivery(i, pulls === 1 ? `prelocal${i}` : `postlocal${i}`),
              extraField && pulls === 2 && i === 2 ? { deliveryAttempt: 1 } : {},
            ),
          ),
        );
      return structuredClone(source.reply);
    },
    { schedulingDisposition: authority("R12"), clockReceiptFor },
  );
}
test("Seek uses genuine pre-Seek same-subscription full delivery witness for eligible local extras", async () => {
  const input = preSeekWitnessFixture();
  const original = structuredClone(input);
  const r = await replayPreSeekFixture(input);
  assert.equal(r.cells[0].dispositionVerdict, "MATCH", JSON.stringify(r.cells[0].schedulingProof));
  assert.equal(r.cells[0].semanticVerdict, "DIVERGES");
  assert.deepEqual(input, original);
  assert.equal(r.parentClosureReady, false);
});
test("Seek pre-window witness cannot migrate subscription, success or content", async () => {
  for (const options of [
    { witnessSubscription: "other" },
    { witnessSuccess: false },
    { witnessData: "changed" },
  ]) {
    const r = await replayPreSeekFixture(preSeekWitnessFixture(options));
    assert.notEqual(r.cells[0].dispositionVerdict, "MATCH");
  }
});

test("Seek pre-window witness retains full delivery field presence", async () => {
  const r = await replayPreSeekFixture(preSeekWitnessFixture(), true);
  assert.equal(r.cells[0].dispositionVerdict, "DIVERGES");
});

const nackApproval = {
  proposalSha256: "aab063ec406aa8ad4395b8f21eb251e0157d6a933576ff66ecdd906f89e0961b",
  owner1213LineSha256: "b05cb78d655502359c268032d1893991bb6c4e19a2370cf05f6133c02675f775",
};
function nackFixture() {
  const input = preSeekWitnessFixture();
  input.metadata = {
    ...metadata,
    runId: "567e1cd860a1",
    sourceHead: "3235e54940ff1ece6004d3e78e70548ca6eba85c",
    packetSha256: "285a6220ed6c7e7efdafbe8618a52e3f87aac1be57a0ea7a684ae80b75126c80",
    descriptorSha256: "3b455b9613b20aa89d2ea277962652f110f45847c9b80668a66605517aba5707",
  };
  const c = input.cells[0];
  c.id = "R8";
  c.observations = [];
  c.exchanges = [];
  let n = 0;
  const add = (method, request, body) => {
    const e = {
      n: ++n,
      responseN: ++n,
      requestId: n,
      at: "2026-10-10T00:00:00.000Z",
      transport: "rest",
      category: "other",
      method,
      request,
      reply: { ok: true, code: "OK", status: 200, body },
    };
    c.exchanges.push(e);
    return e;
  };
  const pub = (i) =>
    add(
      "Publish",
      { topic: "topic", messages: [{ data: String(i), orderingKey: i === 2 ? "B" : "A" }] },
      { messageIds: [String(i)] },
    );
  const pull = (ids, stage) => {
    const e = add(
      "Pull",
      { subscription: "control", maxMessages: stage === "outstanding-predecessor" ? 1 : 3 },
      {
        receivedMessages: ids.map((i) => ({
          ackId: `${stage}${i}`,
          message: {
            messageId: String(i),
            data: String(i),
            attributes: {},
            orderingKey: i === 2 ? "B" : "A",
          },
        })),
      },
    );
    c.observations.push({
      n: ++n,
      stage,
      subscription: "control",
      items: e.reply.body.receivedMessages,
    });
    return e;
  };
  add("CreateTopic", { name: "topic" }, { name: "topic" });
  add(
    "CreateSubscription",
    { name: "control", topic: "topic", ackDeadlineSeconds: 60, enableMessageOrdering: true },
    { name: "control", topic: "topic", ackDeadlineSeconds: 60, enableMessageOrdering: true },
  );
  pub(0);
  const initial = pull([0], "outstanding-predecessor");
  pub(1);
  pub(2);
  add(
    "ModifyAckDeadline",
    {
      subscription: "control",
      ackIds: [initial.reply.body.receivedMessages[0].ackId],
      ackDeadlineSeconds: 0,
    },
    {},
  );
  pull([2], "before-predecessor-ACK");
  pull([0], "before-predecessor-ACK");
  add(
    "Acknowledge",
    { subscription: "control", ackIds: ["before-predecessor-ACK2", "before-predecessor-ACK0"] },
    {},
  );
  pull([1], "after-predecessor-ACK");
  add("Acknowledge", { subscription: "control", ackIds: ["after-predecessor-ACK1"] }, {});
  return input;
}
async function replayNack({
  batches = [[0], [0, 2], [], [1]],
  badAck = false,
  authorityChange = null,
  stale = false,
  inputChange = null,
  localChange = null,
} = {}) {
  const input = nackFixture();
  inputChange?.(input);
  const nackAuthority = { ...nackApproval, source: input.metadata, runtimeInputs, cellIds: ["R8"] };
  authorityChange?.(nackAuthority);
  let pulls = 0;
  const actualAcks = [];
  const report = await replayRecording(
    input,
    async (call, source) => {
      if (call.method === "Publish")
        return {
          ...source.reply,
          body: { messageIds: source.reply.body.messageIds.map((x) => String(100 + Number(x))) },
        };
      if (call.method === "Pull") {
        const ids = batches[pulls++] ?? [];
        const result = reply(
          ids.map((i) => {
            const value = delivery(i, `local${pulls}-${i}`);
            value.message.orderingKey = i === 2 ? "B" : "A";
            return value;
          }),
        );
        localChange?.(result, pulls);
        return result;
      }
      if (call.method === "Acknowledge") {
        actualAcks.push(call.request.ackIds);
        if (badAck)
          return { ...source.reply, ok: false, code: "INVALID_ARGUMENT", status: 400, body: {} };
      }
      return structuredClone(source.reply);
    },
    {
      nackDisposition: nackAuthority,
      clockReceiptFor: (source) => ({
        ...clockReceiptFor(source),
        ...(stale ? { body: { clock: "2026-10-10T00:02:00.000Z" } } : {}),
      }),
    },
  );
  return { report, actualAcks };
}
test("approved NACK finite window uses current redelivery ACK and then releases A2", async () => {
  const { report: r, actualAcks } = await replayNack();
  assert.equal(r.cells[0].dispositionVerdict, "MATCH");
  assert.equal(r.cells[0].semanticVerdict, "DIVERGES");
  assert.deepEqual(actualAcks, [["local2-2", "local2-0"], ["local4-1"]]);
  assert.equal(r.parentClosureReady, false);
});
test("NACK window rejects early A2, duplicate, missing, over-limit, failed ACK and unbound authority", async () => {
  for (const options of [
    { batches: [[0], [0, 1, 2], [], [1]] },
    { batches: [[0], [0, 2], [0], [1]] },
    { batches: [[0], [2], [], [1]] },
    { batches: [[0], [0, 2, 2, 2], [], [1]] },
    { badAck: true },
    { authorityChange: (a) => (a.owner1213LineSha256 = "0".repeat(64)) },
    { stale: true },
  ]) {
    const { report } = await replayNack(options);
    assert.notEqual(report.cells[0].dispositionVerdict, "MATCH");
  }
});

test("NACK finite allocation permutations preserve same-key causal release", async () => {
  for (const before of [
    [[0, 2], []],
    [[2, 0], []],
    [[0], [2]],
    [[2], [0]],
    [[], [0, 2]],
  ]) {
    const { report } = await replayNack({ batches: [[0], ...before, [1]] });
    assert.equal(report.cells[0].dispositionVerdict, "MATCH");
  }
});

test("NACK allowance requires exact recording, source, runtime, fresh ACK and full delivery shape", async () => {
  for (const options of [
    { inputChange: (i) => (i.metadata.runId = "abcdef012345") },
    { inputChange: (i) => (i.metadata.sourceHead = "f".repeat(40)) },
    {
      authorityChange: (a) =>
        (a.runtimeInputs = { ...runtimeInputs, binarySha256: "0".repeat(64) }),
    },
    { authorityChange: (a) => (a.cellIds = []) },
    {
      inputChange: (i) => {
        i.cells[0].exchanges.find((e) => e.method === "Acknowledge").request.ackIds = [
          "outstanding-predecessor0",
        ];
      },
    },
    {
      inputChange: (i) => {
        i.cells[0].exchanges
          .filter((e) => e.method === "Acknowledge")
          .forEach((e) => (e.at = "2026-10-10T00:02:00.000Z"));
      },
    },
    {
      localChange: (response, n) => {
        if (n === 2) response.body.receivedMessages[0].deliveryAttempt = 1;
      },
    },
  ]) {
    const { report } = await replayNack(options);
    assert.notEqual(report.cells[0].dispositionVerdict, "MATCH");
  }
});
