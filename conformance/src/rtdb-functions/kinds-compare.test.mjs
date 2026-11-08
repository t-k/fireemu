import { test } from "node:test";
import assert from "node:assert/strict";
import { compareRecordings, normalizeFrame } from "./kinds-compare.mjs";
import { MASKED_NONCE } from "./kinds-mask.mjs";
import { buildSteps, transitions } from "./kinds-sequence.mjs";
import { perfectFrames } from "./kinds-world.fake.mjs";

const steps = buildSteps(MASKED_NONCE);
const ID = Buffer.alloc(20).toString("base64");
const TIME = "2026-01-01T00:00:00.000Z";
const TRACE = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
const idOf = (n) => Buffer.alloc(20, (n % 250) + 1).toString("base64");
const stamp = (frames) =>
  frames.map((f, i) => {
    const copy = structuredClone(f);
    if (copy.generation === 1) {
      copy.event.context.eventId = idOf(i);
      copy.event.context.timestamp = TIME;
    } else {
      copy.event.id = idOf(i);
      copy.event.time = TIME;
      copy.event.extras = { traceparent: TRACE };
    }
    return copy;
  });
// perfectFrames numbers its event ids by position, so two stamped copies agree row by row
const base = () => stamp(perfectFrames(steps));

test("identical recordings match in every row", () => {
  const result = compareRecordings({ production: base(), local: base() });
  assert.equal(result.totals.difference, 0);
  assert.equal(result.totals.match, result.totals.rows);
  assert.equal(result.totals.rows, 121);
  assert.deepEqual(result.unattributed, { production: [], local: [] });
});

test("per-delivery values compare by form, not by value", () => {
  const local = base().map((f) => {
    if (f.generation === 1) f.event.context.eventId = idOf(200);
    else {
      f.event.id = idOf(201);
      f.event.extras.traceparent = TRACE.replace("0af7", "1bf7");
    }
    return f;
  });
  assert.equal(compareRecordings({ production: base(), local }).totals.difference, 0);
  // the form changes: a uuid id, a nine-digit time
  const uuid = base().map((f) => {
    if (f.generation === 2) f.event.id = "00000000-0000-4000-8000-000000000000";
    return f;
  });
  const result = compareRecordings({ production: base(), local: uuid });
  assert.ok(result.rows.some((r) => r.differences.some((d) => d.path.endsWith(".frame.event.id"))));
  const nanos = base().map((f) => {
    if (f.generation === 2) f.event.time = "2026-01-01T00:00:00.000000000Z";
    return f;
  });
  assert.ok(compareRecordings({ production: base(), local: nanos }).totals.difference > 0);
});

test("a missing row, an extra row and a changed member are differences", () => {
  const production = base();
  const withoutOne = production.filter((_, i) => i !== 5);
  assert.equal(compareRecordings({ production, local: withoutOne }).totals.difference, 1);
  assert.equal(
    compareRecordings({ production: withoutOne, local: production }).totals.difference,
    1,
  );
  const local = base();
  const v2 = local.findIndex((f) => f.generation === 2 && f.handler === "k9UpdatedV2");
  local[v2].event.extras.surprise = true;
  const result = compareRecordings({ production, local });
  assert.equal(result.totals.difference, 1);
  const row = result.rows.find((r) => r.verdict === "DIFFERENCE");
  assert.deepEqual(
    row.differences.map((d) => d.path),
    ["$[0].frame.event.extras.surprise"],
  );
  assert.equal(row.differences[0].production, "<absent>");
  const value = base();
  const idx = value.findIndex((f) => f.handler === "k9CreatedV2");
  value[idx].event.data.value = { value: 1, run: MASKED_NONCE, more: 1 };
  // a different value fits no write: it is unattributed on its side and its row is missing there
  const moved = compareRecordings({ production, local: value });
  assert.equal(moved.unattributed.local.length, 1);
  assert.equal(moved.totals.difference, 1);
});

test("a redelivery under the same event id is one event with a delivery count", () => {
  const production = base();
  const local = base();
  local.push(structuredClone(local[3]));
  const result = compareRecordings({ production, local });
  assert.equal(result.totals.difference, 1);
  assert.deepEqual(
    result.rows.find((r) => r.verdict === "DIFFERENCE").differences.map((d) => d.path),
    ["$[0].deliveries"],
  );
});

test("frames that fit no write are reported apart and never matched", () => {
  const stray = structuredClone(base()[0]);
  stray.event.params.id = "nobody";
  const result = compareRecordings({ production: [stray], local: [] });
  assert.equal(result.unattributed.production.length, 1);
  assert.equal(result.totals.rows, 0);
});

test("the user is masked and token keys compare as a set; claim values compare exactly", () => {
  const make = (uid, keys, claims) => ({
    handler: "k9CreatedV1",
    generation: 1,
    seq: 3,
    receivedAt: "later",
    event: {
      context: {
        eventId: ID,
        timestamp: TIME,
        contextKeys: ["auth", "authType"],
        params: { group: "gc", id: "u1" },
        authType: "USER",
        auth: { uid, tokenKeys: keys, claims },
      },
      data: { exists: true, key: "u1", value: { value: 1, run: MASKED_NONCE } },
    },
  });
  const same = compareRecordings({
    production: [make("one", ["a", "b"], { k9n: 3 })],
    local: [make("two", ["b", "a"], { k9n: 3 })],
  });
  assert.equal(same.totals.difference, 0);
  for (const local of [
    make("two", ["b"], { k9n: 3 }),
    make("two", ["a", "b"], { k9n: 4 }),
    make("two", ["a", "b", "c"], { k9n: 3 }),
  ])
    assert.equal(
      compareRecordings({ production: [make("one", ["a", "b"], { k9n: 3 })], local: [local] })
        .totals.difference,
      1,
    );
  const normalized = normalizeFrame(make("secret-uid", ["x"], {}));
  assert.equal(normalized.event.context.auth.uid, "<uid>");
  assert.equal(JSON.stringify(normalized).includes("secret-uid"), false);
  const v2 = normalizeFrame({
    handler: "k9CreatedV2",
    generation: 2,
    seq: 1,
    event: { id: ID, time: TIME, eventKeys: [], authType: "app_user", authId: "secret-uid" },
  });
  assert.equal(v2.event.authId, "<uid>");
  const admin = normalizeFrame({
    handler: "k9CreatedV2",
    generation: 2,
    seq: 1,
    event: { id: ID, time: TIME, eventKeys: [], authType: "unknown", authId: null },
  });
  assert.equal(admin.event.authId, null);
});

test("sequence numbers, receive times and the write stamp are not compared", () => {
  const a = base();
  const b = base().map((f, i) => ({ ...f, seq: 99 + i, receivedAt: `t${i}`, n: i, step: "x" }));
  assert.equal(compareRecordings({ production: a, local: b }).totals.difference, 0);
  assert.ok(transitions(steps).length === 21);
});
