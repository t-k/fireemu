import test from "node:test";
import assert from "node:assert/strict";
import { compareObservation } from "./pubsub-observation/compare-core.mjs";

// Fixtures follow the H1 R11/N13 rows (ordering-enabled subscription, seven unkeyed messages and
// one keyed message published in two requests, then Pull, Acknowledge, Pull, Acknowledge) with
// placeholder resource names, message ids and ack ids.
const SUB = "projects/p/subscriptions/s";
const TOPIC = "projects/p/topics/t";
const RUN = "012345abcdef";
const REASON_NC_PULL = "ACK selector unresolved; no shape selection inferred";
const REASON_NC_ACK = "missing or conflicting ack binding";
const REASON_SET = "delivered message set differs";
const REASON_PARTITION = "Pull partition differs";
const REASON_DUPLICATE = "Pull duplicate delivery differs";
const REASON_ORIGIN = "ACK originates from a different Pull";

const b64 = (text) => Buffer.from(text).toString("base64");
const UNKEYED = [
  { data: b64("one") },
  { data: b64("two"), attributes: { color: "red", n: "1" } },
  { attributes: { only: "attributes" } },
  { attributes: { k: "empty data" } },
  { data: b64("AP+A") },
  { data: b64("unicode") },
  { data: b64("x") },
];
const KEYED = { data: b64("keyed"), orderingKey: "k1" };

const ok = (body, bodyBytes = 40) => ({
  ok: true,
  status: 200,
  code: "OK",
  body,
  bodyBytes,
  unknown: false,
});
let counter = 0;
function exchange(method, request, response, extra = {}) {
  counter += 1;
  return {
    n: counter * 2,
    dispatchN: counter * 2 - 1,
    at: new Date(1000 * counter).toISOString(),
    durationMs: 1,
    case: "R11/rest",
    transport: "rest",
    op: method[0].toLowerCase() + method.slice(1),
    method,
    category: "target",
    request: { body: request },
    response,
    ...extra,
  };
}
const publish = (messages, ids) =>
  exchange("Publish", { topic: TOPIC, messages }, ok({ messageIds: ids }));
const pull = (received) =>
  exchange(
    "Pull",
    { subscription: SUB, maxMessages: 16, returnImmediately: true },
    ok(received.length ? { receivedMessages: received } : {}),
  );
const ack = (ids) => exchange("Acknowledge", { subscription: SUB, ackIds: ids }, ok({}, 3));
const modack = (ids) =>
  exchange(
    "ModifyAckDeadline",
    { subscription: SUB, ackIds: ids, ackDeadlineSeconds: 10 },
    ok({}, 3),
  );
// Message ids are numeric strings, as production's are, and differ between the two sides.
const idBase = (tag) => (tag.startsWith("src") ? 2000000000000000 : 3000000000000000);
const pubId = (tag, index) => String(idBase(tag) + index);
const delivered = (tag, message, index) => ({
  ackId: `${tag}-ack-${index}`,
  message: {
    ...message,
    messageId: pubId(tag, 100 + index),
    publishTime: "2026-10-11T07:56:53.705Z",
  },
});
const deliveries = (tag, messages, offset = 0) =>
  messages.map((m, i) => delivered(tag, m, i + offset));
const wireMessage = (m) => ({ ...m });

function observation(tag, exchanges) {
  return {
    runId: RUN,
    packetSha256: "b".repeat(64),
    descriptorSha256: "c".repeat(64),
    evidenceKind: "fixture",
    cells: [{ id: "R11", group: "G1", coordinate: "/conditions/6/cases/0", debts: [], exchanges }],
  };
}
// The recorded subscription configuration of a cell. `subscription` is "ordered" or "plain" for a
// CreateSubscription row with enableMessageOrdering true or absent, and "none" for no such row.
const createSubscription = (ordered) =>
  exchange(
    "CreateSubscription",
    {
      name: SUB,
      topic: TOPIC,
      ackDeadlineSeconds: 10,
      ...(ordered ? { enableMessageOrdering: true } : {}),
    },
    ok({ name: SUB, topic: TOPIC, ...(ordered ? { enableMessageOrdering: true } : {}) }),
  );
// One side of an R11-shaped cell. `first` and `second` are the messages delivered by the two
// Pulls; `ackFirst` and `ackSecond` choose which delivered ack ids the Acknowledges send.
function side(tag, { first, second, ackFirst, ackSecond, subscription = "none" }) {
  const one = deliveries(tag, first);
  const two = deliveries(tag, second, first.length);
  const unkeyed = UNKEYED.map(wireMessage);
  const ids = (n, offset) => Array.from({ length: n }, (_, i) => pubId(tag, offset + i));
  // The configuration row sits last so that the row positions below stay stable; the comparator
  // reads it from anywhere in the cell.
  const rows = [
    publish(unkeyed, ids(7, 0)),
    publish([wireMessage(KEYED)], ids(1, 7)),
    pull(one),
    ack((ackFirst ?? one).map((d) => d.ackId)),
    pull(two),
    ack((ackSecond ?? two).map((d) => d.ackId)),
    ...(subscription === "none" ? [] : [createSubscription(subscription === "ordered")]),
  ];
  return { rows, one, two };
}
const compareCells = (source, local) =>
  compareObservation(observation("s", source), observation("l", local)).cells[0];
const pullRows = (cell) => cell.rows.filter((r) => r.method === "Pull");
const ackRows = (cell) => cell.rows.filter((r) => r.method === "Acknowledge");

const sevenUnkeyed = UNKEYED.map(wireMessage);
const eight = [...sevenUnkeyed, wireMessage(KEYED)];

function r11(sourceTag = "src", localTag = "loc") {
  const source = side(sourceTag, { first: sevenUnkeyed, second: [KEYED] });
  // The local run delivers all eight messages in Pull 1 and nothing in Pull 2. Its second
  // Acknowledge can only use the keyed message's ack id from Pull 1, as the recorded replay did.
  const localFirst = deliveries(localTag, eight);
  const localRows = [
    publish(
      UNKEYED.map(wireMessage),
      Array.from({ length: 7 }, (_, i) => pubId(localTag, i)),
    ),
    publish([wireMessage(KEYED)], [pubId(localTag, 7)]),
    pull(localFirst),
    ack(localFirst.slice(0, 7).map((d) => d.ackId)),
    pull([]),
    ack([localFirst[7].ackId]),
  ];
  return { source: source.rows, local: localRows };
}

test("R11/N13 shape: a different delivered set in each Pull is DIVERGES, not NOT_COMPARABLE", () => {
  const { source, local } = r11();
  const cell = compareCells(source, local);
  const [pull1, pull2] = pullRows(cell);
  assert.equal(pull1.verdict, "DIVERGES");
  assert.equal(pull1.reason, REASON_PARTITION);
  assert.deepEqual(pull1.selection, {
    source: { unkeyed: 7, keyed: 0 },
    local: { unkeyed: 7, keyed: 1 },
  });
  assert.equal(pull2.verdict, "DIVERGES");
  assert.equal(pull2.reason, REASON_PARTITION);
  assert.deepEqual(pull2.selection, {
    source: { unkeyed: 0, keyed: 1 },
    local: { unkeyed: 0, keyed: 0 },
  });
  assert.equal(cell.verdict, "DIVERGES");
});

test("R11/N13 shape: the second Acknowledge may not be satisfied by the first local Pull", () => {
  const { source, local } = r11();
  const [ack1, ack2] = ackRows(compareCells(source, local));
  assert.equal(ack1.verdict, "NOT_COMPARABLE");
  assert.equal(ack1.reason, REASON_NC_ACK);
  assert.equal(ack2.verdict, "DIVERGES");
  assert.equal(ack2.reason, REASON_ORIGIN);
});

test("equal selection with different order, ack ids, message ids and times stays NOT_COMPARABLE", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const reordered = [sevenUnkeyed[6], ...sevenUnkeyed.slice(0, 6)];
  const local = side("loc", { first: reordered, second: [KEYED] });
  const cell = compareCells(source.rows, local.rows);
  for (const row of pullRows(cell)) {
    assert.equal(row.verdict, "NOT_COMPARABLE");
    assert.equal(row.reason, REASON_NC_PULL);
  }
  for (const row of ackRows(cell)) {
    assert.equal(row.verdict, "NOT_COMPARABLE");
    assert.equal(row.reason, REASON_NC_ACK);
  }
  assert.equal(cell.verdict, "NOT_COMPARABLE");
});

test("equal-set ACK-selector cases never become MATCH through the new rules", () => {
  const source = side("src", { first: eight, second: [] });
  const local = side("loc", { first: eight, second: [] });
  const cell = compareCells(source.rows, local.rows);
  const [pull1, pull2] = pullRows(cell);
  assert.equal(pull1.verdict, "NOT_COMPARABLE");
  // Pull 2 is empty on both sides and carries no ack id: the existing judge decides, as before.
  assert.equal(pull2.verdict, "MATCH");
  // Acknowledge 1 names real ack ids and stays unresolved; Acknowledge 2 names none, as before.
  const [ack1, ack2] = ackRows(cell);
  assert.equal(ack1.verdict, "NOT_COMPARABLE");
  assert.equal(ack2.verdict, "MATCH");
  assert.equal(cell.verdict, "NOT_COMPARABLE");
});

test("a missing delivered message, an extra one and a changed payload are DIVERGES", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const variants = {
    missing: sevenUnkeyed.slice(0, 6),
    extra: [...sevenUnkeyed, { data: b64("extra") }],
    data: [{ data: b64("ONE") }, ...sevenUnkeyed.slice(1)],
    attributes: [{ ...sevenUnkeyed[0], attributes: { a: "b" } }, ...sevenUnkeyed.slice(1)],
    attributeValue: [
      sevenUnkeyed[0],
      { ...sevenUnkeyed[1], attributes: { color: "blue", n: "1" } },
      ...sevenUnkeyed.slice(2),
    ],
    orderingKey: [{ ...sevenUnkeyed[0], orderingKey: "k9" }, ...sevenUnkeyed.slice(1)],
  };
  for (const [name, first] of Object.entries(variants)) {
    const local = side("loc", { first, second: [KEYED] });
    const [pull1] = pullRows(compareCells(source.rows, local.rows));
    assert.equal(pull1.verdict, "DIVERGES", name);
    assert.equal(pull1.reason, REASON_SET, name);
  }
});

test("duplicate content is compared as a multiset", () => {
  const twice = [sevenUnkeyed[0], sevenUnkeyed[0], sevenUnkeyed[1]];
  const source = side("src", { first: twice, second: [] });
  for (const first of [
    [sevenUnkeyed[0], sevenUnkeyed[1], sevenUnkeyed[1]],
    [sevenUnkeyed[0], sevenUnkeyed[1]],
    [sevenUnkeyed[0], sevenUnkeyed[0], sevenUnkeyed[0], sevenUnkeyed[1]],
  ]) {
    const local = side("loc", { first, second: [] });
    const [pull1] = pullRows(compareCells(source.rows, local.rows));
    assert.equal(pull1.verdict, "DIVERGES");
  }
  const same = side("loc", {
    first: [sevenUnkeyed[1], sevenUnkeyed[0], sevenUnkeyed[0]],
    second: [],
  });
  assert.equal(pullRows(compareCells(source.rows, same.rows))[0].verdict, "NOT_COMPARABLE");
});

test("empty attributes and absent attributes are the same message", () => {
  const source = side("src", { first: [{ data: b64("x") }], second: [] });
  const local = side("loc", { first: [{ data: b64("x"), attributes: {} }], second: [] });
  assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "NOT_COMPARABLE");
});

test("attribute member order does not change message identity", () => {
  const a = { data: b64("x"), attributes: { a: "1", b: "2" } };
  const b = { data: b64("x"), attributes: { b: "2", a: "1" } };
  const source = side("src", { first: [a], second: [] });
  const local = side("loc", { first: [b], second: [] });
  assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "NOT_COMPARABLE");
});

test("keyed messages keep their per-key order, while different keys may interleave", () => {
  const k = (key, name) => ({ data: b64(name), orderingKey: key });
  const a0 = k("A", "a0"),
    a1 = k("A", "a1"),
    b0 = k("B", "b0");
  const ordered = { subscription: "ordered" };
  const source = side("src", { first: [a0, a1, b0], second: [], ...ordered });
  const interleaved = side("loc", { first: [b0, a0, a1], second: [], ...ordered });
  assert.equal(pullRows(compareCells(source.rows, interleaved.rows))[0].verdict, "NOT_COMPARABLE");
  const swapped = side("loc", { first: [a1, a0, b0], second: [], ...ordered });
  const [row] = pullRows(compareCells(source.rows, swapped.rows));
  assert.equal(row.verdict, "DIVERGES");
  assert.equal(row.reason, REASON_SET);
});

test("the unkeyed set and keyed set are separate: one keyed message is not an unkeyed one", () => {
  const source = side("src", { first: [{ data: b64("m") }], second: [] });
  const local = side("loc", { first: [{ data: b64("m"), orderingKey: "k1" }], second: [] });
  assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "DIVERGES");
});

test("a bound message id must be the one the local run delivered", () => {
  // Two publications carry identical content. Production delivers the first, the local run the
  // second; only the publication binding tells them apart.
  const content = { data: b64("same") };
  const make = (tag, deliveredIndex) => {
    const d = delivered(tag, content, 0);
    d.message.messageId = pubId(tag, deliveredIndex);
    return [
      publish([content, content], [pubId(tag, 0), pubId(tag, 1)]),
      exchange(
        "Pull",
        { subscription: SUB, maxMessages: 16, returnImmediately: true },
        ok({ receivedMessages: [d] }),
      ),
    ];
  };
  const source = make("src", 0);
  assert.equal(compareCells(source, make("loc", 0)).rows[1].verdict, "NOT_COMPARABLE");
  const other = compareCells(source, make("loc", 1)).rows[1];
  assert.equal(other.verdict, "DIVERGES");
  assert.equal(other.reason, REASON_SET);
});

test("an unbound message id falls back to content and never diverges on its own", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  // Drop the Publish rows from both sides so no message id is bound.
  const cell = compareCells(source.rows.slice(2), local.rows.slice(2));
  assert.equal(pullRows(cell)[0].verdict, "NOT_COMPARABLE");
});

test("a Pull whose request differs is not judged on its selection", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: eight, second: [] });
  local.rows[2].request.body.maxMessages = 3;
  const [pull1] = pullRows(compareCells(source.rows, local.rows));
  assert.equal(pull1.verdict, "NOT_COMPARABLE");
  assert.equal(pull1.reason, REASON_NC_PULL);
});

test("unknown or failed Pull responses are not judged on their selection, on either side", () => {
  for (const update of [
    { unknown: true },
    { ok: false, status: 500, code: "INTERNAL" },
    { status: 418, ok: false, code: "UNKNOWN" },
    { status: 302, ok: false, code: "UNKNOWN" },
  ]) {
    const bad = (rows) => Object.assign(rows[2].response, update);
    const sourceFirst = side("src", { first: eight, second: [] });
    bad(sourceFirst.rows);
    const localFirst = side("loc", { first: sevenUnkeyed, second: [KEYED] });
    assert.notEqual(
      pullRows(compareCells(sourceFirst.rows, localFirst.rows))[0].verdict,
      "DIVERGES",
      `source ${JSON.stringify(update)}`,
    );
    const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
    const local = side("loc", { first: eight, second: [] });
    bad(local.rows);
    assert.notEqual(
      pullRows(compareCells(source.rows, local.rows))[0].verdict,
      "DIVERGES",
      `local ${JSON.stringify(update)}`,
    );
  }
});

test("a raw (undecoded) Pull body on either side is not judged on its selection", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: eight, second: [] });
  source.rows[2].response.body = { raw: "<html>unexpected</html>" };
  assert.notEqual(pullRows(compareCells(source.rows, local.rows))[0].verdict, "DIVERGES");
  const other = side("src", { first: eight, second: [] });
  const raw = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  raw.rows[2].response.body = { raw: "<html>unexpected</html>", ackId: "x" };
  assert.notEqual(pullRows(compareCells(other.rows, raw.rows))[0].verdict, "DIVERGES");
});

test("a Pull that differs in transport or category is not judged on its selection", () => {
  for (const update of [{ transport: "grpc" }, { category: "get" }, { method: "Seek" }]) {
    const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
    const local = side("loc", { first: eight, second: [] });
    Object.assign(local.rows[2], update);
    const [pull1] = pullRows(compareCells(source.rows, local.rows));
    if (pull1) assert.notEqual(pull1.verdict, "DIVERGES", JSON.stringify(update));
    const row = compareCells(source.rows, local.rows).rows[2];
    assert.notEqual(row.verdict, "DIVERGES", JSON.stringify(update));
  }
});

test("only Pull responses are judged on their delivered selection", () => {
  const body = (messages) => ({ receivedMessages: deliveries("x", messages) });
  const odd = (tag, messages) => {
    const row = exchange(
      "Seek",
      { subscription: SUB, time: "2026-10-11T00:00:00Z" },
      ok(body(messages)),
    );
    return [row];
  };
  const cell = compareCells(odd("src", [sevenUnkeyed[0]]), odd("loc", [sevenUnkeyed[1]]));
  assert.notEqual(cell.rows[0].verdict, "DIVERGES");
  assert.equal(cell.rows[0].reason, REASON_NC_PULL);
});

test("a malformed or non-array receivedMessages list never crashes and is not judged", () => {
  for (const bad of [{ a: 1 }, 7, "none", [null], [{ ackId: "a" }], [{ message: "m" }]]) {
    const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
    const local = side("loc", { first: eight, second: [] });
    local.rows[2].response.body = { receivedMessages: bad, ackId: "x" };
    const [pull1] = pullRows(compareCells(source.rows, local.rows));
    assert.equal(pull1.verdict, "NOT_COMPARABLE", JSON.stringify(bad));
    assert.equal(pull1.reason, REASON_NC_PULL);
  }
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: eight, second: [] });
  local.rows[2].response.body = {
    receivedMessages: [{ ackId: "a", message: { data: "eA==", attributes: ["x"] } }],
  };
  assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "NOT_COMPARABLE");
});

test("a delivered message without a message id falls back to content identity", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  // Production's Pull ids are bound to the publications; the local response omits them.
  source.rows[2].response.body.receivedMessages.forEach((d, i) => {
    d.message.messageId = pubId("src", i);
  });
  for (const d of local.rows[2].response.body.receivedMessages) delete d.message.messageId;
  assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "NOT_COMPARABLE");
});

test("a keyed message that only one side delivered is a difference", () => {
  const a0 = { data: b64("a0"), orderingKey: "A" };
  const b0 = { data: b64("b0"), orderingKey: "B" };
  for (const [one, other] of [
    [[a0], [a0, b0]],
    [[a0, b0], [a0]],
    [[a0], [b0]],
  ]) {
    const source = side("src", { first: one, second: [] });
    const local = side("loc", { first: other, second: [] });
    assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "DIVERGES");
  }
});

test("an Acknowledge on a different transport is not judged on its ack origin", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  local.rows[5].request.body.ackIds = [local.one[0].ackId];
  local.rows[5].transport = "grpc";
  const [, ack2] = ackRows(compareCells(source.rows, local.rows));
  assert.notEqual(ack2.verdict, "DIVERGES");
});

test("acknowledge requests of different length are not judged on their ack origin", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  local.rows[5].request.body.ackIds = [local.one[0].ackId, local.two[0].ackId];
  const [, ack2] = ackRows(compareCells(source.rows, local.rows));
  assert.notEqual(ack2.verdict, "DIVERGES");
});

test("an Acknowledge without ack ids keeps its existing verdict", () => {
  const source = side("src", { first: sevenUnkeyed, second: [] });
  const local = side("loc", { first: sevenUnkeyed, second: [] });
  const [, ack2] = ackRows(compareCells(source.rows, local.rows));
  assert.equal(ack2.verdict, "MATCH");
});

test("empty Pulls on both sides keep their existing verdict", () => {
  const source = side("src", { first: [], second: [] });
  const local = side("loc", { first: [], second: [] });
  const cell = compareCells(source.rows, local.rows);
  for (const row of pullRows(cell)) assert.equal(row.verdict, "MATCH");
});

test("an empty source Pull against a delivering local Pull is DIVERGES", () => {
  const source = side("src", { first: [], second: [] });
  const local = side("loc", { first: [sevenUnkeyed[0]], second: [] });
  const [pull1] = pullRows(compareCells(source.rows, local.rows));
  assert.equal(pull1.verdict, "DIVERGES");
  assert.equal(pull1.reason, REASON_SET);
});

test("the Acknowledge of the corresponding Pull keeps its existing NOT_COMPARABLE", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  for (const row of ackRows(compareCells(source.rows, local.rows))) {
    assert.equal(row.verdict, "NOT_COMPARABLE");
    assert.equal(row.reason, REASON_NC_ACK);
  }
});

test("an ack id taken from an earlier local Pull diverges even when every selection is equal", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  // Local Acknowledge 2 sends an ack id of local Pull 1 instead of the one Pull 2 delivered.
  local.rows[5].request.body.ackIds = [local.one[0].ackId];
  const [, ack2] = ackRows(compareCells(source.rows, local.rows));
  assert.equal(ack2.verdict, "DIVERGES");
  assert.equal(ack2.reason, REASON_ORIGIN);
});

test("the reverse cross-Pull case also diverges: production acks Pull 1 ids, local acks Pull 2 ids", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  source.rows[5].request.body.ackIds = [source.one[3].ackId];
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  const [, ack2] = ackRows(compareCells(source.rows, local.rows));
  assert.equal(ack2.verdict, "DIVERGES");
});

test("ModifyAckDeadline follows the same ack origin rule", () => {
  const rows = (tag, crossing) => {
    const one = deliveries(tag, [sevenUnkeyed[0]]);
    const two = deliveries(tag, [sevenUnkeyed[1]], 1);
    return [
      publish([sevenUnkeyed[0], sevenUnkeyed[1]], [pubId(tag, 0), pubId(tag, 1)]),
      pull(one),
      pull(two),
      modack([(crossing ? one : two)[0].ackId]),
    ];
  };
  const good = compareCells(rows("src", false), rows("loc", false));
  assert.equal(good.rows[3].verdict, "NOT_COMPARABLE");
  const bad = compareCells(rows("src", false), rows("loc", true));
  assert.equal(bad.rows[3].verdict, "DIVERGES");
  assert.equal(bad.rows[3].reason, REASON_ORIGIN);
});

test("an ack id that no earlier Pull delivered is left to the existing binding rule", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  local.rows[3].request.body.ackIds = ["invalid-ack-for-observation"];
  const [ack1] = ackRows(compareCells(source.rows, local.rows));
  assert.equal(ack1.verdict, "NOT_COMPARABLE");
  assert.equal(ack1.reason, REASON_NC_ACK);
});

test("an ack id issued after the Acknowledge does not count as its origin", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  // Local Acknowledge 1 names an ack id that Pull 2 delivers later: not an origin yet.
  local.rows[3].request.body.ackIds = [local.two[0].ackId];
  const [ack1] = ackRows(compareCells(source.rows, local.rows));
  assert.equal(ack1.verdict, "NOT_COMPARABLE");
});

test("ack origins are per cell", () => {
  const source = side("src", { first: sevenUnkeyed, second: [KEYED] });
  const local = side("loc", { first: sevenUnkeyed, second: [KEYED] });
  const otherSource = side("src2", { first: sevenUnkeyed, second: [KEYED] });
  const otherLocal = side("loc2", { first: sevenUnkeyed, second: [KEYED] });
  const src = observation("s", source.rows);
  const loc = observation("l", local.rows);
  src.cells.push({ ...src.cells[0], id: "N13", exchanges: otherSource.rows });
  loc.cells.push({ ...loc.cells[0], id: "N13", exchanges: otherLocal.rows });
  // The second cell's local Acknowledge 2 names an ack id that only the first cell's Pull 1
  // delivered. It is no origin inside the second cell, so the existing rule decides.
  otherLocal.rows[5].request.body.ackIds = [local.one[0].ackId];
  const report = compareObservation(src, loc);
  const [, ack2] = report.cells[1].rows.filter((r) => r.method === "Acknowledge");
  assert.equal(ack2.verdict, "NOT_COMPARABLE");
  assert.equal(ack2.reason, REASON_NC_ACK);
});

const ONE = sevenUnkeyed[0];
const TWO = sevenUnkeyed[1];
const withAck = (ackId, message) => ({
  ackId,
  message: { ...message, messageId: "1", publishTime: "t" },
});
const pullOf = (...received) => pull(received);

test("absent data and empty data are the same message", () => {
  const source = side("src", { first: [{ attributes: { k: "v" } }], second: [] });
  const local = side("loc", { first: [{ data: "", attributes: { k: "v" } }], second: [] });
  assert.equal(pullRows(compareCells(source.rows, local.rows))[0].verdict, "NOT_COMPARABLE");
});

test("an Acknowledge against a ModifyAckDeadline is not judged on its ack origin", () => {
  const rows = (tag, kind) => {
    const one = deliveries(tag, [ONE]);
    const two = deliveries(tag, [TWO], 1);
    return [pull(one), pull(two), kind === "ack" ? ack([two[0].ackId]) : modack([one[0].ackId])];
  };
  const cell = compareCells(rows("src", "ack"), rows("loc", "modack"));
  assert.notEqual(cell.rows[2].verdict, "DIVERGES");
});

test("an ack id no earlier Pull delivered on the production side is not an origin", () => {
  const rows = (tag, ackId) => {
    const one = deliveries(tag, [ONE]);
    return [pull(one), pull(deliveries(tag, [TWO], 1)), ack([ackId ?? one[0].ackId])];
  };
  const cell = compareCells(rows("src", "never-delivered"), rows("loc"));
  assert.equal(cell.rows[2].verdict, "NOT_COMPARABLE");
  assert.equal(cell.rows[2].reason, REASON_NC_ACK);
});

test("one crossed ack id among correct ones makes the Acknowledge DIVERGES", () => {
  const rows = (tag, crossing) => {
    const one = deliveries(tag, [ONE]);
    const two = deliveries(tag, [TWO], 1);
    const second = crossing ? [one[0].ackId] : [two[0].ackId];
    return [pull(one), pull(two), ack([two[0].ackId, ...second])];
  };
  const mixed = compareCells(rows("src", false), rows("loc", true));
  assert.equal(mixed.rows[2].verdict, "DIVERGES");
  assert.equal(mixed.rows[2].reason, REASON_ORIGIN);
  const fine = compareCells(rows("src", false), rows("loc", false));
  assert.equal(fine.rows[2].verdict, "NOT_COMPARABLE");
});

test("an unknown or failed Pull is no origin for an ack id, on either side", () => {
  for (const update of [{ unknown: true }, { ok: false, status: 500, code: "INTERNAL" }]) {
    for (const badSide of ["source", "local"]) {
      const rows = (tag, bad) => {
        const first = pull(deliveries(tag, [ONE]));
        if (bad) Object.assign(first.response, update);
        const second = deliveries(tag, [TWO], 1);
        const acked = bad ? first.response.body.receivedMessages[0].ackId : second[0].ackId;
        return [first, pull(second), ack([acked])];
      };
      const peer = (tag) => {
        // The other side acks the ack id of its own second Pull.
        const first = pull(deliveries(tag, [ONE]));
        const second = deliveries(tag, [TWO], 1);
        return [first, pull(second), ack([second[0].ackId])];
      };
      const cell =
        badSide === "source"
          ? compareCells(rows("src", true), peer("loc"))
          : compareCells(peer("src"), rows("loc", true));
      assert.notEqual(cell.rows[2].verdict, "DIVERGES", `${badSide} ${JSON.stringify(update)}`);
    }
  }
});

test("source and local ack origins are tracked separately even for equal ack id strings", () => {
  const source = [pullOf(withAck("same", ONE)), pullOf(), ack(["same"])];
  const local = [pullOf(), pullOf(withAck("same", ONE)), ack(["same"])];
  const cell = compareCells(source, local);
  assert.equal(cell.rows[2].verdict, "DIVERGES");
  assert.equal(cell.rows[2].reason, REASON_ORIGIN);
});

// Reference model for the Pull selection rule, independent of the production code path: the
// unkeyed messages compare as a multiset, and the keyed ones as one ordered list per key when the
// subscription orders messages, as a multiset otherwise.
function modelSelection(messages, ordered) {
  const unkeyed = [];
  const keyed = new Map();
  for (const m of messages) {
    const identity = `${m.data ?? ""}|${JSON.stringify(Object.entries(m.attributes ?? {}).toSorted())}`;
    if (!m.orderingKey) unkeyed.push(identity);
    else if (ordered) keyed.set(m.orderingKey, [...(keyed.get(m.orderingKey) ?? []), identity]);
    else unkeyed.push(`${m.orderingKey}|${identity}`);
  }
  return { unkeyed: unkeyed.toSorted(), keyed: [...keyed.entries()].toSorted() };
}

function generator(seed) {
  let state = seed >>> 0;
  return (bound) => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state % bound;
  };
}

for (const subscription of ["ordered", "plain", "none"]) {
  test(`generated Pull pairs follow the selection model (${subscription}), and never MATCH`, () => {
    const next = generator(20261011);
    const keys = ["", "", "", "A", "B"];
    const shuffle = (list) => {
      const out = [...list];
      for (let i = out.length - 1; i > 0; i--) {
        const j = next(i + 1);
        [out[i], out[j]] = [out[j], out[i]];
      }
      return out;
    };
    const randomMessages = () =>
      Array.from({ length: next(6) }, () => {
        const key = keys[next(keys.length)];
        return {
          data: b64(`m${next(4)}`),
          ...(next(3) === 0 ? { attributes: { a: String(next(2)) } } : {}),
          ...(key ? { orderingKey: key } : {}),
        };
      });
    let diverged = 0,
      undecided = 0;
    for (let trial = 0; trial < 400; trial++) {
      const messages = randomMessages();
      const peer = next(3) === 0 ? randomMessages() : shuffle(messages);
      const source = side("src", { first: messages, second: [], subscription });
      const local = side("loc", { first: peer, second: [], subscription });
      const [row] = pullRows(compareCells(source.rows, local.rows));
      const a = modelSelection(messages, subscription === "ordered"),
        b = modelSelection(peer, subscription === "ordered");
      const equal = JSON.stringify(a) === JSON.stringify(b);
      const bothEmpty = messages.length === 0 && peer.length === 0;
      if (bothEmpty) {
        assert.equal(row.verdict, "MATCH");
      } else if (equal) {
        assert.equal(row.verdict, "NOT_COMPARABLE", JSON.stringify({ messages, peer }));
        assert.equal(row.reason, REASON_NC_PULL);
        undecided += 1;
      } else {
        assert.equal(row.verdict, "DIVERGES", JSON.stringify({ messages, peer }));
        // One Pull per side, so the cell totals equal the Pull: the difference is a content one.
        assert.equal(row.reason, REASON_SET);
        diverged += 1;
      }
    }
    assert.ok(diverged > 40 && undecided > 40, `diverged ${diverged}, undecided ${undecided}`);
  });
}

// Review S1: per-key order is only a guarantee of a subscription with message ordering.
test("S1: keyed order differences count only on an ordering-enabled subscription", () => {
  const k = (key, name) => ({ data: b64(name), orderingKey: key });
  const a0 = k("A", "a0"),
    a1 = k("A", "a1");
  const pair = (subscription, localSubscription = subscription) => {
    const source = side("src", { first: [a0, a1], second: [], subscription });
    const local = side("loc", { first: [a1, a0], second: [], subscription: localSubscription });
    return pullRows(compareCells(source.rows, local.rows))[0];
  };
  assert.equal(pair("ordered").verdict, "DIVERGES");
  assert.equal(pair("ordered").reason, REASON_SET);
  for (const unproven of [
    pair("plain"),
    pair("none"),
    pair("ordered", "plain"),
    pair("plain", "ordered"),
  ]) {
    assert.equal(unproven.verdict, "NOT_COMPARABLE");
    assert.equal(unproven.reason, REASON_NC_PULL);
  }
  // Without ordering a keyed message still has its key: a different key is a different message.
  const source = side("src", { first: [a0], second: [], subscription: "plain" });
  const other = side("loc", { first: [k("B", "a0")], second: [], subscription: "plain" });
  assert.equal(pullRows(compareCells(source.rows, other.rows))[0].verdict, "DIVERGES");
});

test("S1: the ordering flag is read for the subscription the Pull names", () => {
  const k = (key, name) => ({ data: b64(name), orderingKey: key });
  const a0 = k("A", "a0"),
    a1 = k("A", "a1");
  const make = (tag, first) => {
    const rows = side(tag, { first, second: [], subscription: "ordered" }).rows;
    // An ordering-enabled subscription other than the one pulled from does not enable order.
    rows[rows.length - 1].request.body.name = "projects/p/subscriptions/other";
    return rows;
  };
  const cell = compareCells(make("src", [a0, a1]), make("loc", [a1, a0]));
  assert.equal(pullRows(cell)[0].verdict, "NOT_COMPARABLE");
  // A failed or unknown CreateSubscription is no configuration either.
  for (const update of [{ ok: false, status: 409, code: "ALREADY_EXISTS" }, { unknown: true }]) {
    const failed = (tag, first) => {
      const rows = side(tag, { first, second: [], subscription: "ordered" }).rows;
      Object.assign(rows.at(-1).response, update);
      return rows;
    };
    assert.equal(
      pullRows(compareCells(failed("src", [a0, a1]), failed("loc", [a1, a0])))[0].verdict,
      "NOT_COMPARABLE",
      JSON.stringify(update),
    );
  }
  // Only a CreateSubscription request records the flag.
  const other = (tag, first) => {
    const rows = side(tag, { first, second: [], subscription: "ordered" }).rows;
    rows.at(-1).method = "UpdateSubscription";
    return rows;
  };
  assert.equal(
    pullRows(compareCells(other("src", [a0, a1]), other("loc", [a1, a0])))[0].verdict,
    "NOT_COMPARABLE",
  );
});

// Review S2: misaligned cells keep their previous behavior.
test("S2: a cell with different exchange counts produces no new DIVERGES", () => {
  const one = deliveries("src", [ONE]);
  const source = [pull([]), pull(one), ack([one[0].ackId])];
  const lone = deliveries("loc", [ONE]);
  const local = [pull(lone), ack([lone[0].ackId])];
  const cell = compareCells(source, local);
  assert.ok(cell.debts.includes("different exchange cardinality"));
  assert.ok(cell.rows.every((r) => r.verdict !== "DIVERGES"));
  assert.equal(cell.verdict, "NOT_COMPARABLE");
  // The same holds for the ack origin rule: positions 1 and 0 would otherwise look crossed.
  const reversed = compareCells(local, source);
  assert.ok(reversed.rows.every((r) => r.verdict !== "DIVERGES"));
});

test("S2: a misaligned cell does not pair same-method rows by position either", () => {
  const rows = (tag, extra) => {
    const first = deliveries(tag, [ONE]);
    const second = deliveries(tag, [TWO], 1);
    return [
      pull(first),
      pull(second),
      ack([(extra ? first : second)[0].ackId]),
      ...(extra ? [pull([])] : []),
    ];
  };
  // Row 2 pairs an Acknowledge of Pull 1 with one of Pull 0: crossed if the rows were aligned.
  const cell = compareCells(rows("src", false), rows("loc", true));
  assert.ok(cell.debts.includes("different exchange cardinality"));
  assert.equal(cell.rows[2].verdict, "NOT_COMPARABLE");
  assert.equal(cell.rows[2].reason, REASON_NC_ACK);
});

test("S2: the same shape with equal exchange counts still diverges", () => {
  const one = deliveries("src", [ONE]);
  const lone = deliveries("loc", [ONE]);
  const source = [pull([]), pull(one), ack([one[0].ackId])];
  const local = [pull(lone), pull([]), ack([lone[0].ackId])];
  const cell = compareCells(source, local);
  assert.equal(cell.debts.length, 0);
  assert.equal(cell.verdict, "DIVERGES");
  assert.equal(cell.rows[2].reason, REASON_ORIGIN);
});

// Review S4: the reason says whether content or only the split across Pulls differs.
test("S4: an empty production Pull against a delivering local Pull is a partition difference", () => {
  const rows = (tag, firstMessages, secondMessages) => [
    pull(deliveries(tag, firstMessages)),
    pull(deliveries(tag, secondMessages, firstMessages.length)),
  ];
  const cell = compareCells(rows("src", [], [ONE, TWO]), rows("loc", [ONE, TWO], []));
  const [pull1, pull2] = pullRows(cell);
  assert.equal(pull1.verdict, "DIVERGES");
  assert.equal(pull1.reason, REASON_PARTITION);
  assert.equal(pull2.reason, REASON_PARTITION);
  // A partial production Pull against a fuller local Pull, rest delivered later.
  const partial = compareCells(rows("src", [ONE], [TWO]), rows("loc", [ONE, TWO], []));
  assert.deepEqual(
    pullRows(partial).map((r) => [r.verdict, r.reason]),
    [
      ["DIVERGES", REASON_PARTITION],
      ["DIVERGES", REASON_PARTITION],
    ],
  );
});

test("S4: a different overall set is a set difference, not a partition", () => {
  const rows = (tag, firstMessages, secondMessages) => [
    pull(deliveries(tag, firstMessages)),
    pull(deliveries(tag, secondMessages, firstMessages.length)),
  ];
  const cell = compareCells(rows("src", [ONE], [TWO]), rows("loc", [ONE, TWO], [TWO]));
  assert.deepEqual(
    pullRows(cell).map((r) => r.reason),
    [REASON_SET, REASON_NC_PULL],
  );
  const changed = compareCells(rows("src", [ONE], [TWO]), rows("loc", [ONE], [sevenUnkeyed[2]]));
  assert.deepEqual(
    pullRows(changed).map((r) => [r.verdict, r.reason]),
    [
      ["NOT_COMPARABLE", REASON_NC_PULL],
      ["DIVERGES", REASON_SET],
    ],
  );
});

test("S4: an unjudgeable Pull in the cell keeps a split difference a set difference", () => {
  const rows = (tag, bad) => {
    const third = pull(deliveries(tag, [], 9));
    if (bad) Object.assign(third.response, { unknown: true });
    return [pull(deliveries(tag, bad ? [] : [ONE, TWO])), pull(deliveries(tag, [], 2)), third];
  };
  const cell = compareCells(rows("src", false), rows("loc", true));
  assert.equal(pullRows(cell)[0].verdict, "DIVERGES");
  assert.equal(pullRows(cell)[0].reason, REASON_SET);
});

test("S4: an unjudgeable or malformed Pull of the cell hides no partition claim", () => {
  const source = [pull(deliveries("src", [ONE])), pull([]), pull([])];
  const local = [pull([]), pull([]), pull(deliveries("loc", [ONE]))];
  // Control: all three Pulls are judgeable and the overall delivery is equal.
  assert.equal(pullRows(compareCells(source, local))[0].reason, REASON_PARTITION);
  // The third local Pull is unknown: its messages cannot balance the totals.
  const unknown = [pull([]), pull([]), pull(deliveries("loc", [ONE]))];
  Object.assign(unknown[2].response, { unknown: true });
  assert.equal(pullRows(compareCells(source, unknown))[0].reason, REASON_SET);
  // The third source Pull is malformed: it cannot be skipped either.
  const malformed = [pull(deliveries("src", [ONE])), pull([]), pull([])];
  malformed[2].response.body = { receivedMessages: "junk" };
  const balanced = [pull([]), pull(deliveries("loc", [ONE])), pull([])];
  const cell = compareCells(malformed, balanced);
  assert.equal(pullRows(cell)[0].verdict, "DIVERGES");
  assert.equal(pullRows(cell)[0].reason, REASON_SET);
});

test("S4: a duplicate message id inside one Pull has its own reason", () => {
  const dup = (tag) => {
    const first = delivered(tag, ONE, 0);
    const second = { ...delivered(tag, ONE, 1), message: { ...first.message } };
    return [pull([first, second])];
  };
  const single = (tag) => [pull(deliveries(tag, [ONE]))];
  for (const [source, local] of [
    [dup("src"), single("loc")],
    [single("src"), dup("loc")],
  ]) {
    const [row] = pullRows(compareCells(source, local));
    assert.equal(row.verdict, "DIVERGES");
    assert.equal(row.reason, REASON_DUPLICATE);
  }
  // A duplicate keeps its reason even when the overall delivery of the cell is equal.
  const twice = [...dup("src"), pull([])];
  const spread = [pull(deliveries("loc", [ONE])), pull(deliveries("loc", [ONE], 1))];
  const [split] = pullRows(compareCells(twice, spread));
  assert.equal(split.reason, REASON_DUPLICATE);
  // Deliveries without any messageId are not duplicates of each other.
  const bare = (tag, messages) => {
    const row = pull(deliveries(tag, messages));
    for (const d of row.response.body.receivedMessages) delete d.message.messageId;
    return [row];
  };
  const [plain] = pullRows(compareCells(bare("src", [ONE, TWO]), bare("loc", [ONE])));
  assert.equal(plain.reason, REASON_SET);
  // Two publications with equal content are two messages, not a duplicate.
  const twin = (tag) => [pull(deliveries(tag, [ONE, ONE]))];
  const [row] = pullRows(compareCells(twin("src"), single("loc")));
  assert.equal(row.reason, REASON_SET);
});

test("a gRPC-shaped Pull pair compares equal selections as unresolved and changed payloads as DIVERGES", () => {
  const grpcPull = (tag, messages) => {
    const received = deliveries(tag, messages);
    for (const d of received) {
      d.message.attributes ??= {};
      d.message.orderingKey = "";
    }
    const row = pull(received);
    return Object.assign(row, { transport: "grpc", case: "R11/grpc" });
  };
  const grpc = (row) => {
    delete row.response.status;
    row.response.code = "OK";
    return row;
  };
  const same = compareCells([grpc(grpcPull("src", [ONE]))], [grpc(grpcPull("loc", [ONE]))]);
  assert.equal(same.rows[0].verdict, "NOT_COMPARABLE");
  assert.equal(same.rows[0].reason, REASON_NC_PULL);
  const changed = compareCells([grpc(grpcPull("src", [ONE]))], [grpc(grpcPull("loc", [TWO]))]);
  assert.equal(changed.rows[0].verdict, "DIVERGES");
});

test("an omitted Acknowledge with crossed origins stays NOT_COMPARABLE", () => {
  const rows = (tag, crossing) => {
    const one = deliveries(tag, [ONE]);
    const two = deliveries(tag, [TWO], 1);
    const row = ack([(crossing ? one : two)[0].ackId]);
    row.request.body.omitted = { length: 5000, sha256: "d".repeat(64) };
    return [pull(one), pull(two), row];
  };
  const cell = compareCells(rows("src", false), rows("loc", true));
  assert.equal(cell.rows[2].verdict, "NOT_COMPARABLE");
  assert.equal(cell.rows[2].reason, "omitted request payload requires exact reconstruction proof");
});
