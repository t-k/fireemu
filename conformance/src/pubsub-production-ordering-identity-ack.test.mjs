import test from "node:test";
import assert from "node:assert/strict";
import { createBindings } from "./pubsub-production/stream-dlq-compare-core.mjs";
import {
  ORDERING_IDENTITY_CASES,
  createOrderingIdentityAck,
  judgeOrderingCell,
  judgeOrderingCellHeldTail,
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
  const { owner1399: _owner1399, ...rest1392 } = same["ordering/rest"];
  assert.deepEqual(rest1392, {
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

// Owner 1399: MATCH when, on both sides, each key's delivered set is a prefix of its publish order, unkeyed and
// keyed are never mixed in a Pull, and the whole-cell difference is only the tail of a key held by an
// unacknowledged delivery at cell end.
const id = (text, key) => ({ data: data(text), attributes: {}, orderingKey: key ?? "" });
const PUBLISHED = [
  ...["a0", "a1", "a2", "a3", "a4"].map((t) => id(t, "k1")),
  ...["b0", "b1", "b2", "b3", "b4"].map((t) => id(t, "k2")),
  id("n", ""),
];
const side = (pulls, acked) => ({ pulls, acked: acked.map(([t, k]) => id(t, k)) });
const r2RestProduction = side(
  [
    pull(["n", ""]),
    pull(["a0", "k1"], ["a1", "k1"]),
    pull(["b0", "k2"]),
    pull(["b1", "k2"]),
    pull(["a2", "k1"]),
    pull(["b2", "k2"]),
    pull(["a3", "k1"], ["a4", "k1"]),
  ],
  [
    ["n", ""],
    ["a0", "k1"],
    ["a1", "k1"],
    ["b0", "k2"],
    ["b1", "k2"],
    ["a2", "k1"],
  ],
);
const r2RestLocal = side(
  [
    pull(["n", ""]),
    pull(["a0", "k1"], ["a1", "k1"]),
    pull(["a2", "k1"]),
    pull(["b0", "k2"]),
    pull(["b1", "k2"]),
    pull(["a3", "k1"]),
    pull(["b2", "k2"], ["b3", "k2"], ["b4", "k2"]),
  ],
  [
    ["n", ""],
    ["a0", "k1"],
    ["a1", "k1"],
    ["a2", "k1"],
    ["b0", "k2"],
    ["b1", "k2"],
  ],
);

test("owner 1399 accepts a difference that is only the tail of a key held at cell end", () => {
  assert.deepEqual(judgeOrderingCellHeldTail(PUBLISHED, r2RestProduction, r2RestLocal), {
    verdict: "MATCH",
    reason:
      "owner 1399: per-key prefixes, no keyed/unkeyed mixing, difference only in held key tails",
  });
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, r2RestLocal, r2RestProduction).verdict,
    "MATCH",
  );
  assert.equal(judgeOrderingCellHeldTail(PUBLISHED, r2RestLocal, r2RestLocal).verdict, "MATCH");
});

test("owner 1399 refuses a gap, an unheld difference, a mixed Pull and a difference beyond the held tail", () => {
  // a non-prefix gap in a key (LOCAL skips a1)
  const gap = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a2", "k1"]), pull(["b0", "k2"])],
    [
      ["n", ""],
      ["a0", "k1"],
      ["a2", "k1"],
    ],
  );
  const gapSource = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"]), pull(["b0", "k2"])],
    [
      ["n", ""],
      ["a0", "k1"],
      ["a1", "k1"],
    ],
  );
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, gapSource, gap).reason,
    "owner 1399: difference in key k1 is not a held tail",
  );
  const gapBoth = side([pull(["n", ""]), pull(["a0", "k1"]), pull(["a2", "k1"])], [["n", ""]]);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, gapBoth, gapBoth).reason,
    "owner 1399: key k1 delivered set is not a prefix of its publish order",
  );
  // a difference in a key that is not held: the shorter side acknowledged its last k2 delivery
  const unheld = structuredClone(r2RestProduction);
  unheld.acked.push(id("b2", "k2"));
  unheld.acked.push(id("a3", "k1"), id("a4", "k1"));
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, unheld, r2RestLocal).reason,
    "owner 1399: difference in key k2 is not a held tail",
  );
  // a key with no delivery at all on one side is not held
  const none = side([pull(["n", ""]), pull(["a0", "k1"])], []);
  const some = side([pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"])], []);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, none, some).reason,
    "owner 1399: difference in key k2 is not a held tail",
  );
  // an unkeyed difference is never a held tail
  const noUnkeyed = side([pull(["a0", "k1"])], []);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, noUnkeyed, side([pull(["n", ""]), pull(["a0", "k1"])], []))
      .reason,
    "owner 1399: unkeyed delivered set differs",
  );
  // a mixed Pull on either side
  const mixed = side([pull(["n", ""], ["a0", "k1"])], []);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, mixed, mixed).reason,
    "owner 1399: keyed and unkeyed messages mixed in one Pull",
  );
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, side([pull(["n", ""]), pull(["a0", "k1"])], []), mixed)
      .reason,
    "owner 1399: keyed and unkeyed messages mixed in one Pull",
  );
  // a difference larger than the held key's tail: the longer side delivered a k1 message that was never published
  const beyond = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"]), pull(["zz", "k1"])],
    [],
  );
  const held = side([pull(["n", ""]), pull(["a0", "k1"])], []);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, held, beyond).reason,
    "owner 1399: difference in key k1 exceeds the held tail",
  );
});

test("property: equal prefixes with any held/acknowledged split are MATCH, unheld shorter prefixes are not", () => {
  const next = random(9);
  const keys = { k1: ["a0", "a1", "a2", "a3", "a4"], k2: ["b0", "b1", "b2", "b3", "b4"] };
  for (let i = 0; i < 300; i++) {
    const make = (lengths, ackAll) => {
      const pulls = [pull(["n", ""])],
        acked = [["n", ""]];
      for (const k of ["k1", "k2"]) {
        const items = keys[k].slice(0, lengths[k]).map((t) => [t, k]);
        for (const item of items) pulls.push(pull(item));
        acked.push(...items.slice(0, ackAll[k] ? items.length : Math.max(0, items.length - 1)));
      }
      return side(pulls, acked);
    };
    const a = { k1: 1 + Math.floor(next() * 5), k2: 1 + Math.floor(next() * 5) },
      b = { k1: 1 + Math.floor(next() * 5), k2: 1 + Math.floor(next() * 5) };
    const heldA = { k1: next() < 0.5, k2: next() < 0.5 },
      heldB = { k1: next() < 0.5, k2: next() < 0.5 };
    // a differing key must be held by its shorter side, and each side holds at most one key (S1)
    const heldBy = ["k1", "k2"].filter((k) => a[k] !== b[k]).map((k) => (a[k] < b[k] ? "a" : "b"));
    const expected =
      ["k1", "k2"].every((k) => a[k] === b[k] || (a[k] < b[k] ? heldA[k] : heldB[k])) &&
      new Set(heldBy).size === heldBy.length;
    const verdict = judgeOrderingCellHeldTail(
      PUBLISHED,
      make(a, { k1: !heldA.k1, k2: !heldA.k2 }),
      make(b, { k1: !heldB.k1, k2: !heldB.k2 }),
    ).verdict;
    assert.equal(verdict, expected ? "MATCH" : "DIVERGES", JSON.stringify({ a, b, heldA, heldB }));
  }
});

test("cell results add the owner 1399 verdict from published order and each side's acknowledgements", () => {
  const ordered = "projects/p/subscriptions/fe1-or-g-s",
    plain = "projects/p/subscriptions/fe1-or-g-plain";
  const ok = (op, body, response) => ({
    case: "ordering/grpc",
    op,
    request: { rpc: `Subscriber/${op}`, body },
    response: { code: 0, body: response },
  });
  const publish = (key, texts) => ({
    case: "ordering/grpc",
    op: "publish",
    request: {
      rpc: "Publisher/Publish",
      body: {
        topic: "t",
        messages: texts.map((t) => ({ data: data(t), ...(key ? { orderingKey: key } : {}) })),
      },
    },
    response: { code: 0, body: {} },
  });
  const success = (e) => e.response?.code === 0;
  const cell = (pulls, acks, extra = []) => [
    ok("createSubscription", { name: ordered, topic: "t", enableMessageOrdering: true }, {}),
    ok("createSubscription", { name: plain, topic: "t" }, {}),
    publish("k1", ["a0", "a1", "a2"]),
    publish("k2", ["b0", "b1"]),
    publish("", ["n"]),
    ...pulls.map((p) => ok("pull", { subscription: ordered }, p)),
    ...acks.map((ackIds) => ok("acknowledge", { subscription: ordered, ackIds }, {})),
    ...extra,
  ];
  // source: n, a0, b0 (b0 acknowledged, a0 held); LOCAL: n, a0, a1, b0 (all acknowledged except a1)
  const source = cell([pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"])], [["x-n", "x-b0"]]);
  const local = cell(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"]), pull(["b0", "k2"])],
    [["x-n", "x-a0", "x-b0"]],
  );
  const held = orderingCellResults(source, local, success)["ordering/grpc"];
  assert.equal(held.verdict, "DIVERGES");
  assert.deepEqual(
    held.owner1399,
    judgeOrderingCellHeldTail(
      [id("a0", "k1"), id("a1", "k1"), id("a2", "k1"), id("b0", "k2"), id("b1", "k2"), id("n", "")],
      side(
        [pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"])],
        [
          ["n", ""],
          ["b0", "k2"],
        ],
      ),
      side(
        [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"]), pull(["b0", "k2"])],
        [
          ["n", ""],
          ["a0", "k1"],
          ["b0", "k2"],
        ],
      ),
    ),
  );
  assert.equal(held.owner1399.verdict, "MATCH");
  // the same difference with a0 acknowledged by the source is not a held tail
  const ackedSource = cell(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"])],
    [["x-n", "x-b0", "x-a0"]],
  );
  assert.equal(
    orderingCellResults(ackedSource, local, success)["ordering/grpc"].owner1399.reason,
    "owner 1399: difference in key k1 is not a held tail",
  );
  // acknowledgements on the plain subscription and unknown ackIds do not count
  const noise = [
    { ...ok("acknowledge", { subscription: plain, ackIds: ["x-a0"] }, {}) },
    ok("acknowledge", { subscription: ordered, ackIds: ["unknown"] }, {}),
  ];
  const noisySource = cell(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"])],
    [["x-n", "x-b0"]],
    noise,
  );
  assert.equal(
    orderingCellResults(noisySource, local, success)["ordering/grpc"].owner1399.verdict,
    "MATCH",
  );
});

test("owner 1399 near misses: one-sided order, one-sided mixing, held gap, redelivery and other cells", () => {
  const base = side([pull(["n", ""]), pull(["a0", "k1"], ["a1", "k1"])], [["n", ""]]);
  // LOCAL alone reverses a key: same set, order broken on one side only
  const reversed = side([pull(["n", ""]), pull(["a1", "k1"], ["a0", "k1"])], [["n", ""]]);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, base, reversed).reason,
    "owner 1399: key k1 delivered set is not a prefix of its publish order",
  );
  // the source alone mixes keyed and unkeyed messages in one Pull
  const mixedSource = side([pull(["n", ""], ["a0", "k1"]), pull(["a1", "k1"])], [["n", ""]]);
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, mixedSource, base).reason,
    "owner 1399: keyed and unkeyed messages mixed in one Pull",
  );
  // a gap on one side while the other side's last delivery is still held
  const gapHeld = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"])],
    [
      ["n", ""],
      ["a0", "k1"],
    ],
  );
  const gap = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a2", "k1"])],
    [
      ["n", ""],
      ["a0", "k1"],
    ],
  );
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, gapHeld, gap).reason,
    "owner 1399: difference in key k1 is not a held tail",
  );
  // a redelivery of an earlier message keeps the prefix
  const redelivered = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"]), pull(["a0", "k1"])],
    [["n", ""]],
  );
  assert.equal(judgeOrderingCellHeldTail(PUBLISHED, base, redelivered).verdict, "MATCH");
});

test("cell results ignore Pulls of another cell on the same subscription name", () => {
  const ordered = "projects/p/subscriptions/fe1-or-g-s";
  const ok = (c, op, body, response) => ({
    case: c,
    op,
    request: { rpc: `Subscriber/${op}`, body },
    response: { code: 0, body: response },
  });
  const publish = (key, texts) => ({
    case: "ordering/grpc",
    op: "publish",
    request: {
      rpc: "Publisher/Publish",
      body: {
        topic: "t",
        messages: texts.map((t) => ({ data: data(t), ...(key ? { orderingKey: key } : {}) })),
      },
    },
    response: { code: 0, body: {} },
  });
  const success = (e) => e.response?.code === 0;
  const cell = (extra) => [
    ok(
      "ordering/grpc",
      "createSubscription",
      { name: ordered, topic: "t", enableMessageOrdering: true },
      {},
    ),
    publish("k1", ["a0", "a1"]),
    ok("ordering/grpc", "pull", { subscription: ordered }, pull(["a0", "k1"])),
    ...extra,
  ];
  const source = cell([]);
  const local = cell([ok("other/grpc", "pull", { subscription: ordered }, pull(["zz", "k1"]))]);
  assert.equal(
    orderingCellResults(source, local, success)["ordering/grpc"].owner1399.verdict,
    "MATCH",
  );
});

// Review 2026-10-12 (M1, S1, S2, S3).
const grpcCell = (cellName, ordered, topic) => {
  const ok = (op, body, response) => ({
    case: cellName,
    op,
    request: { rpc: `Subscriber/${op}`, body },
    response: { code: 0, body: response },
  });
  const publish = (key, texts, publishTopic = topic, code = 0) => ({
    case: cellName,
    op: "publish",
    request: {
      rpc: "Publisher/Publish",
      body: {
        topic: publishTopic,
        messages: texts.map((t) => ({ data: data(t), ...(key ? { orderingKey: key } : {}) })),
      },
    },
    response: { code, body: {} },
  });
  return { ok, publish };
};

test("owner 1399 refuses a cell where an Acknowledge on the ordered subscription failed on either side (M1)", () => {
  const ordered = "projects/p/subscriptions/fe1-or-g-s";
  const { ok, publish } = grpcCell("ordering/grpc", ordered, "t");
  const success = (e) => e.response?.code === 0;
  const failedAck = (ackIds) => ({
    ...ok("acknowledge", { subscription: ordered, ackIds }, {}),
    response: { code: 14 },
  });
  const base = [
    ok("createSubscription", { name: ordered, topic: "t", enableMessageOrdering: true }, {}),
    publish("k1", ["a0", "a1", "a2"]),
    publish("k2", ["b0", "b1", "b2"]),
  ];
  // the review's probe: production delivers and acknowledges a0..a2 and b0..b2; LOCAL delivers a0 and b0 and its acks fail
  const source = [
    ...base,
    ...["a0", "a1", "a2"].map((t) => ok("pull", { subscription: ordered }, pull([t, "k1"]))),
    ...["b0", "b1", "b2"].map((t) => ok("pull", { subscription: ordered }, pull([t, "k2"]))),
    ok(
      "acknowledge",
      { subscription: ordered, ackIds: ["x-a0", "x-a1", "x-a2", "x-b0", "x-b1", "x-b2"] },
      {},
    ),
  ];
  const local = [
    ...base,
    ok("pull", { subscription: ordered }, pull(["a0", "k1"])),
    ok("pull", { subscription: ordered }, pull(["b0", "k2"])),
    failedAck(["x-a0"]),
  ];
  const reason = "owner 1399: an Acknowledge on the ordered subscription was not successful";
  assert.equal(
    orderingCellResults(source, local, success)["ordering/grpc"].owner1399.reason,
    reason,
  );
  // the same failure on the source side
  const sourceFailed = [
    ...source.slice(0, -1),
    failedAck(["x-a0", "x-a1", "x-a2", "x-b0", "x-b1", "x-b2"]),
  ];
  assert.equal(
    orderingCellResults(sourceFailed, source, success)["ordering/grpc"].owner1399.reason,
    reason,
  );
  // near miss: identical successful cells stay MATCH; a failed Acknowledge on another subscription does not count
  assert.equal(
    orderingCellResults(source, source, success)["ordering/grpc"].owner1399.verdict,
    "MATCH",
  );
  const otherSub = [
    ...source,
    {
      ...ok("acknowledge", { subscription: `${ordered}-plain`, ackIds: ["x"] }, {}),
      response: { code: 14 },
    },
  ];
  assert.equal(
    orderingCellResults(source, otherSub, success)["ordering/grpc"].owner1399.verdict,
    "MATCH",
  );
});

test("owner 1399 allows at most one held key per side (S1)", () => {
  // source holds k2 (b0 unacked, shorter), LOCAL holds k1 (a0 unacked, shorter): one held key per side
  const source = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["a1", "k1"]), pull(["b0", "k2"])],
    [
      ["n", ""],
      ["a0", "k1"],
    ],
  );
  const local = side(
    [pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"]), pull(["b1", "k2"])],
    [
      ["n", ""],
      ["b0", "k2"],
    ],
  );
  assert.equal(judgeOrderingCellHeldTail(PUBLISHED, source, local).verdict, "MATCH");
  // the review's probe shape: one side holds two keys
  const both = side([pull(["n", ""]), pull(["a0", "k1"]), pull(["b0", "k2"])], [["n", ""]]);
  const full = side(
    [
      pull(["n", ""]),
      pull(["a0", "k1"]),
      pull(["a1", "k1"]),
      pull(["b0", "k2"]),
      pull(["b1", "k2"]),
    ],
    [["n", ""]],
  );
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, full, both).reason,
    "owner 1399: more than one held key on one side",
  );
  assert.equal(
    judgeOrderingCellHeldTail(PUBLISHED, both, full).reason,
    "owner 1399: more than one held key on one side",
  );
});

test("owner 1399 refuses duplicate message identities in the publish order (S2)", () => {
  const order = [id("x", "k1"), id("y", "k1"), id("x", "k1")];
  const source = side([pull(["x", "k1"]), pull(["y", "k1"])], []);
  const local = side([pull(["x", "k1"])], []);
  assert.equal(
    judgeOrderingCellHeldTail(order, source, local).reason,
    "owner 1399: duplicate message identity in the publish order",
  );
  assert.equal(judgeOrderingCellHeldTail(order, source, source).verdict, "DIVERGES");
  assert.equal(
    judgeOrderingCellHeldTail([id("x", "k1"), id("y", "k1")], source, source).verdict,
    "MATCH",
  );
});

test("publish order uses only successful publishes to the ordered subscription's topic (S3)", () => {
  const ordered = "projects/p/subscriptions/fe1-or-g-s";
  const { ok, publish } = grpcCell("ordering/grpc", ordered, "projects/p/topics/t");
  const success = (e) => e.response?.code === 0;
  const cell = (noise) => [
    ok(
      "createSubscription",
      { name: ordered, topic: "projects/p/topics/t", enableMessageOrdering: true },
      {},
    ),
    ...noise,
    publish("k1", ["a0", "a1"]),
    ok("pull", { subscription: ordered }, pull(["a0", "k1"])),
    ok("pull", { subscription: ordered }, pull(["a1", "k1"])),
  ];
  for (const noise of [
    [publish("k1", ["zz"], "projects/p/topics/other")],
    [publish("k1", ["zz"], "projects/p/topics/t", 9)],
  ]) {
    const exchanges = cell(noise);
    assert.equal(
      orderingCellResults(exchanges, exchanges, success)["ordering/grpc"].owner1399.verdict,
      "MATCH",
      JSON.stringify(noise),
    );
  }
  // near miss: a successful publish to the same topic does enter the order (zz becomes the first k1 message)
  const counted = cell([publish("k1", ["zz"])]);
  assert.equal(
    orderingCellResults(counted, counted, success)["ordering/grpc"].owner1399.reason,
    "owner 1399: key k1 delivered set is not a prefix of its publish order",
  );
  // REST publishes are matched by the topic in their path
  const restCell = [
    {
      case: "ordering/rest",
      op: "createSubscription",
      request: {
        method: "PUT",
        path: `/v1/${ordered}`,
        body: { topic: "projects/p/topics/t", enableMessageOrdering: true },
      },
      response: { status: 200, body: {} },
    },
    {
      case: "ordering/rest",
      op: "publish",
      request: {
        method: "POST",
        path: "/v1/projects/p/topics/other:publish",
        body: { messages: [{ data: data("zz"), orderingKey: "k1" }] },
      },
      response: { status: 200, body: {} },
    },
    {
      case: "ordering/rest",
      op: "publish",
      request: {
        method: "POST",
        path: "/v1/projects/p/topics/t:publish",
        body: { messages: [{ data: data("a0"), orderingKey: "k1" }] },
      },
      response: { status: 200, body: {} },
    },
    {
      case: "ordering/rest",
      op: "pull",
      request: { method: "POST", path: `/v1/${ordered}:pull`, body: {} },
      response: { status: 200, body: pull(["a0", "k1"]) },
    },
  ];
  const restOk = (e) => e.response?.status >= 200 && e.response.status < 300;
  assert.equal(
    orderingCellResults(restCell, restCell, restOk)["ordering/rest"].owner1399.verdict,
    "MATCH",
  );
});

test("only Acknowledge failures and exact REST publish paths affect the 1399 inputs (review near misses)", () => {
  const ordered = "projects/p/subscriptions/fe1-or-r-s";
  const restOk = (e) => e.response?.status >= 200 && e.response.status < 300;
  const ex = (op, path, body, status, response = {}) => ({
    case: "ordering/rest",
    op,
    request: { method: "POST", path, body },
    response: { status, body: response },
  });
  const cell = (extra) => [
    {
      case: "ordering/rest",
      op: "createSubscription",
      request: {
        method: "PUT",
        path: `/v1/${ordered}`,
        body: { topic: "projects/p/topics/t", enableMessageOrdering: true },
      },
      response: { status: 200, body: {} },
    },
    ex(
      "publish",
      "/v1/projects/p/topics/t:publish",
      { messages: [{ data: data("a0"), orderingKey: "k1" }] },
      200,
    ),
    ex("pull", `/v1/${ordered}:pull`, {}, 200, pull(["a0", "k1"])),
    ...extra,
  ];
  // a failed Pull on the ordered subscription is not an Acknowledge failure
  const failedPull = cell([ex("pull", `/v1/${ordered}:pull`, {}, 503, {})]);
  assert.equal(
    orderingCellResults(failedPull, failedPull, restOk)["ordering/rest"].owner1399.verdict,
    "MATCH",
  );
  // a publish whose REST path only starts like ":publish" does not enter the order
  const lookalike = cell([
    ex(
      "publish",
      "/v1/projects/p/topics/t:publishBatch",
      { messages: [{ data: data("zz"), orderingKey: "k1" }] },
      200,
    ),
  ]);
  const reordered = [lookalike[0], lookalike[3], ...lookalike.slice(1, 3)];
  assert.equal(
    orderingCellResults(reordered, reordered, restOk)["ordering/rest"].owner1399.verdict,
    "MATCH",
  );
});
