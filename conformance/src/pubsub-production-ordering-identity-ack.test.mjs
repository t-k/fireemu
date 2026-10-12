import test from "node:test";
import assert from "node:assert/strict";
import { createBindings } from "./pubsub-production/stream-dlq-compare-core.mjs";
import {
  ORDERING_IDENTITY_CASES,
  createOrderingIdentityAck,
  judgeOrderingCell,
  orderedSubscriptionOf,
  orderingCellResults,
  subscriptionOf,
} from "./pubsub-production/ordering-identity-ack.mjs";

const SUB = "projects/p/subscriptions/fe1-or-r-t-s";
const rest = (op, body) => ({
  method: "POST",
  path: `/v1/${SUB}:${op}`,
  body,
});
const grpc = (op, body) => ({ rpc: `Subscriber/${op}`, body: { subscription: SUB, ...body } });
const data = (text) => Buffer.from(text).toString("base64");
const message = (id, text, orderingKey) => ({
  messageId: id,
  data: data(text),
  ...(orderingKey ? { orderingKey } : {}),
  publishTime: "2026-10-11T00:00:00Z",
});
const delivery = (ack, id, text, key) => ({ ackId: ack, message: message(id, text, key) });

// Source ids s-<text>, local ids l-<text>; publications bound pairwise like the replay does.
function bound(texts) {
  const bindings = createBindings();
  bindings.linkPublish(
    { messages: texts.map(() => ({})) },
    { messageIds: texts.map((t) => `s-${t}`) },
    { messageIds: texts.map((t) => `l-${t}`) },
  );
  return bindings;
}

test("the ordering identity mode is confined to the two original ordering cells", () => {
  assert.deepEqual([...ORDERING_IDENTITY_CASES].toSorted(), ["ordering/grpc", "ordering/rest"]);
});

test("subscription identity comes from the REST path or the gRPC body", () => {
  assert.equal(subscriptionOf(rest("acknowledge", { ackIds: [] })), SUB);
  assert.equal(subscriptionOf(rest("pull", {})), SUB);
  assert.equal(subscriptionOf(grpc("Acknowledge", { ackIds: [] })), SUB);
  for (const bad of [
    { method: "POST", path: `/v1/${SUB}:modifyAckDeadline`, body: {} },
    { method: "POST", path: `/v1/${SUB}`, body: {} },
    { rpc: "Subscriber/Pull", body: {} },
    { rpc: "Subscriber/Pull", body: { subscription: "" } },
    {},
  ])
    assert.throws(() => subscriptionOf(bad), /ordering identity subscription/);
});

test("LOCAL deliveries are acknowledged once the source has acknowledged the same message", () => {
  const ids = createOrderingIdentityAck(bound(["a0", "b0"]));
  // source delivers a0, LOCAL delivers b0 (different key choice)
  ids.observePull(
    SUB,
    { receivedMessages: [delivery("SA0", "s-a0", "a0", "k1")] },
    {
      receivedMessages: [delivery("LB0", "l-b0", "b0", "k2")],
    },
  );
  // source acks a0: LOCAL has not delivered a0, nothing is due
  assert.equal(ids.acknowledge(SUB, ["SA0"]), null);
  // later source delivers b0 and LOCAL delivers a0
  ids.observePull(
    SUB,
    { receivedMessages: [delivery("SB0", "s-b0", "b0", "k2")] },
    {
      receivedMessages: [delivery("LA0", "l-a0", "a0", "k1")],
    },
  );
  // source acks b0: a0 (acknowledged earlier by the source) and b0 are now due locally, in source ack order
  assert.deepEqual(ids.acknowledge(SUB, ["SB0"]), {
    ackIds: ["LA0", "LB0"],
    due: [
      { sourceMessageId: "s-a0", localMessageId: "l-a0" },
      { sourceMessageId: "s-b0", localMessageId: "l-b0" },
    ],
  });
  // nothing is acknowledged twice
  assert.equal(ids.acknowledge(SUB, ["SB0"]), null);
});

test("a redelivered LOCAL message is acknowledged with its latest ackId only", () => {
  const ids = createOrderingIdentityAck(bound(["a0"]));
  ids.observePull(
    SUB,
    { receivedMessages: [] },
    { receivedMessages: [delivery("L1", "l-a0", "a0", "k1")] },
  );
  ids.observePull(
    SUB,
    { receivedMessages: [delivery("S1", "s-a0", "a0", "k1")] },
    {
      receivedMessages: [delivery("L2", "l-a0", "a0", "k1")],
    },
  );
  assert.deepEqual(ids.acknowledge(SUB, ["S1"]).ackIds, ["L2"]);
});

test("identity requires the bound publication and equal data, attributes and ordering key", () => {
  for (const local of [
    delivery("L", "l-a0", "zz", "k1"),
    delivery("L", "l-a0", "a0", "k2"),
    delivery("L", "l-a0", "a0", undefined),
    { ackId: "L", message: { ...message("l-a0", "a0", "k1"), attributes: { x: "1" } } },
    delivery("L", "l-other", "a0", "k1"),
  ]) {
    const ids = createOrderingIdentityAck(bound(["a0", "other"]));
    ids.observePull(
      SUB,
      { receivedMessages: [delivery("S", "s-a0", "a0", "k1")] },
      {
        receivedMessages: [local],
      },
    );
    assert.equal(ids.acknowledge(SUB, ["S"]), null, JSON.stringify(local));
  }
});

test("unknown source acknowledgements and foreign subscriptions are refused", () => {
  const ids = createOrderingIdentityAck(bound(["a0"]));
  ids.observePull(
    SUB,
    { receivedMessages: [delivery("S", "s-a0", "a0", "k1")] },
    {
      receivedMessages: [delivery("L", "l-a0", "a0", "k1")],
    },
  );
  assert.throws(
    () => ids.acknowledge(SUB, ["unknown"]),
    /source acknowledgement without a source delivery/,
  );
  assert.throws(
    () => ids.acknowledge(`${SUB}-other`, ["S"]),
    /source acknowledgement without a source delivery/,
  );
  assert.throws(() => ids.acknowledge(SUB, []), /source acknowledgement ids required/);
  assert.throws(() => ids.acknowledge(SUB, ["S", "S"]), /source acknowledgement ids required/);
  assert.throws(
    () =>
      ids.observePull(
        SUB,
        {
          receivedMessages: [
            delivery("S2", "s-a0", "a0", "k1"),
            delivery("S3", "s-a0", "a0", "k1"),
          ],
        },
        {},
      ),
    /duplicate delivery in one Pull/,
  );
});

// Owner 1392: key choice order is production nondeterminism; per-key order, no keyed/unkeyed mixing in one
// Pull and the cell's delivered message set must match.
const pull = (...items) => ({
  receivedMessages: items.map(([text, key]) => delivery(`x-${text}`, `id-${text}`, text, key)),
});

test("owner 1392 judge accepts a different key choice with equal per-key order and set", () => {
  const source = [
    pull(["n", ""]),
    pull(["a0", "k1"], ["a1", "k1"]),
    pull(["b0", "k2"]),
    pull(["a2", "k1"]),
  ];
  const local = [
    pull(["n", ""]),
    pull(["b0", "k2"]),
    pull(["a0", "k1"], ["a1", "k1"]),
    pull(["a2", "k1"]),
  ];
  assert.deepEqual(judgeOrderingCell(source, local), {
    verdict: "MATCH",
    reason: "owner 1392: per-key order, no keyed/unkeyed mixing and delivered set equal",
  });
});

test("owner 1392 judge refuses per-key reordering, mixing and set differences", () => {
  const source = [pull(["n", ""]), pull(["a0", "k1"], ["a1", "k1"]), pull(["b0", "k2"])];
  assert.deepEqual(
    judgeOrderingCell(source, [
      pull(["n", ""]),
      pull(["a1", "k1"], ["a0", "k1"]),
      pull(["b0", "k2"]),
    ]).reason,
    "owner 1392: per-key order differs (k1)",
  );
  assert.deepEqual(
    judgeOrderingCell(source, [
      pull(["n", ""], ["a0", "k1"]),
      pull(["a1", "k1"]),
      pull(["b0", "k2"]),
    ]).reason,
    "owner 1392: keyed and unkeyed messages mixed in one Pull",
  );
  assert.deepEqual(
    judgeOrderingCell(source, [pull(["n", ""]), pull(["a0", "k1"], ["a1", "k1"])]).reason,
    "owner 1392: delivered message set differs",
  );
  assert.equal(
    judgeOrderingCell(source, [pull(["n", ""]), pull(["a0", "k1"], ["a1", "k1"])]).verdict,
    "DIVERGES",
  );
  // unkeyed messages carry no order obligation
  assert.equal(
    judgeOrderingCell(
      [pull(["n1", ""], ["n2", ""]), pull(["a0", "k1"])],
      [pull(["n2", ""], ["n1", ""]), pull(["a0", "k1"])],
    ).verdict,
    "MATCH",
  );
  // a redelivery keeps the set but repeats inside a key: order is judged on first deliveries
  assert.equal(
    judgeOrderingCell(source, [
      pull(["n", ""]),
      pull(["a0", "k1"]),
      pull(["a0", "k1"], ["a1", "k1"]),
      pull(["b0", "k2"]),
    ]).verdict,
    "MATCH",
  );
});

// Deterministic generator for the hand-rolled properties (no new dependency).
function random(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
}

test("property: any interleaving of whole keys that keeps per-key order is MATCH, any swap inside a key is not", () => {
  const next = random(5);
  for (let i = 0; i < 300; i++) {
    const keys = { k1: ["a0", "a1", "a2", "a3"], k2: ["b0", "b1", "b2"] };
    const interleave = () => {
      const out = [pull(["n", ""])];
      const c = { k1: 0, k2: 0 };
      while (c.k1 < keys.k1.length || c.k2 < keys.k2.length) {
        const k =
          c.k1 >= keys.k1.length
            ? "k2"
            : c.k2 >= keys.k2.length
              ? "k1"
              : next() < 0.5
                ? "k1"
                : "k2";
        const take = 1 + Math.floor(next() * 2);
        const items = keys[k].slice(c[k], c[k] + take).map((t) => [t, k]);
        c[k] += items.length;
        out.push(pull(...items));
      }
      return out;
    };
    const source = interleave(),
      local = interleave();
    assert.equal(judgeOrderingCell(source, local).verdict, "MATCH");
    const swapped = structuredClone(local);
    const flat = swapped
      .flatMap((p) => p.receivedMessages)
      .filter((d) => d.message.orderingKey === "k1");
    [flat[0].message, flat[1].message] = [flat[1].message, flat[0].message];
    assert.equal(judgeOrderingCell(source, swapped).verdict, "DIVERGES");
  }
});

test("the ordered subscription is the one created with message ordering enabled", () => {
  const name = "projects/p/subscriptions/fe1-or-r-s";
  assert.equal(
    orderedSubscriptionOf({
      method: "PUT",
      path: `/v1/${name}`,
      body: { topic: "t", enableMessageOrdering: true },
    }),
    name,
  );
  assert.equal(
    orderedSubscriptionOf({
      rpc: "Subscriber/CreateSubscription",
      body: { name, topic: "t", enableMessageOrdering: true },
    }),
    name,
  );
  for (const request of [
    { method: "PUT", path: `/v1/${name}`, body: { topic: "t" } },
    { method: "PUT", path: `/v1/${name}`, body: { topic: "t", enableMessageOrdering: "true" } },
    {
      rpc: "Subscriber/CreateSubscription",
      body: { name, topic: "t", enableMessageOrdering: false },
    },
    { method: "PUT", path: `/v1/${name}:pull`, body: { enableMessageOrdering: true } },
    { rpc: "Subscriber/CreateSubscription", body: { enableMessageOrdering: true } },
  ])
    assert.equal(orderedSubscriptionOf(request), null, JSON.stringify(request));
});

test("cell results judge the ordered subscription's successful Pulls of each ordering cell", () => {
  const ordered = "projects/p/subscriptions/fe1-or-r-s",
    plain = "projects/p/subscriptions/fe1-or-r-plain";
  const ok = (step, op, request, body) => ({
    case: "ordering/rest",
    step,
    op,
    request,
    response: { status: 200, body },
  });
  const exchanges = (deliveries) => [
    ok(
      "02",
      "createSubscription",
      { method: "PUT", path: `/v1/${ordered}`, body: { enableMessageOrdering: true } },
      {},
    ),
    ok("03", "createSubscription", { method: "PUT", path: `/v1/${plain}`, body: {} }, {}),
    ok("07", "pull", { method: "POST", path: `/v1/${ordered}:pull`, body: {} }, deliveries[0]),
    ok("08", "pull", { method: "POST", path: `/v1/${ordered}:pull`, body: {} }, deliveries[1]),
    ok(
      "17",
      "pull",
      { method: "POST", path: `/v1/${plain}:pull`, body: {} },
      pull(["zz", ""], ["a0", "k1"]),
    ),
    {
      ...ok(
        "19",
        "pull",
        { method: "POST", path: `/v1/${ordered}:pull`, body: {} },
        pull(["qq", "k9"]),
      ),
      response: { status: 500, body: pull(["qq", "k9"]) },
    },
    {
      case: "other/rest",
      op: "pull",
      request: { method: "POST", path: `/v1/${ordered}:pull`, body: {} },
      response: { status: 200, body: pull(["ww", "k3"]) },
    },
  ];
  const success = (row) => row.response?.status >= 200 && row.response.status < 300;
  const source = exchanges([pull(["n", ""]), pull(["a0", "k1"])]);
  const same = orderingCellResults(
    source,
    exchanges([pull(["n", ""]), pull(["a0", "k1"])]),
    success,
  );
  assert.deepEqual(same["ordering/rest"], {
    orderedSubscription: ordered,
    sourcePulls: 2,
    localPulls: 2,
    sourceDelivered: 2,
    localDelivered: 2,
    verdict: "MATCH",
    reason: "owner 1392: per-key order, no keyed/unkeyed mixing and delivered set equal",
  });
  assert.equal(same["ordering/grpc"], undefined);
  const short = orderingCellResults(
    source,
    exchanges([pull(["n", ""]), { receivedMessages: [] }]),
    success,
  );
  assert.equal(short["ordering/rest"].verdict, "DIVERGES");
  assert.equal(short["ordering/rest"].localDelivered, 1);
  assert.throws(
    () =>
      orderingCellResults(
        source.filter((e) => e.step !== "02"),
        source,
        success,
      ),
    /ordered subscription/,
  );
  assert.throws(
    () => orderingCellResults([...source, source[0]], source, success),
    /ordered subscription/,
  );
});
