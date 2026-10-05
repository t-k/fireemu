// The ladders of the publish limits: a boundary is searched between a value known to be accepted and one
// known to be refused, with a fixed number of requests, and an answer that does not say whether the
// value was accepted ends the search (nothing is sent twice).

import assert from "node:assert/strict";
import test from "node:test";
import { acceptance, bisect, bracket, stepsNeeded } from "./eventarc-production/bisect.mjs";

function random(seed) {
  let state = seed;
  return (n) => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state % n;
  };
}

test("it finds the boundary of a monotone limit between an accepted and a refused value", async () => {
  const next = random(11);
  for (let round = 0; round < 500; round += 1) {
    const low = next(1000);
    const high = low + 1 + next(100_000);
    const limit = low + next(high - low); // the largest accepted value
    const asked = [];
    const result = await bisect({
      low,
      high,
      maxSteps: 64,
      accepts: async (n) => {
        asked.push(n);
        return n <= limit;
      },
    });
    assert.equal(result.accepted, limit, `low ${low} high ${high} limit ${limit}`);
    assert.equal(result.refused, limit + 1);
    assert.equal(result.unknown, false);
    assert.equal(new Set(asked).size, asked.length, "no value is sent twice");
    assert.ok(asked.every((n) => n > low && n < high), "only values between the two known ones");
    assert.ok(asked.length <= stepsNeeded(high - low));
  }
});

test("the number of requests is bounded by maxSteps, and the answer then names the interval left", async () => {
  const asked = [];
  const result = await bisect({
    low: 8,
    high: 255,
    maxSteps: 3,
    accepts: async (n) => {
      asked.push(n);
      return n <= 100;
    },
  });
  assert.equal(asked.length, 3);
  assert.ok(result.accepted <= 100 && result.refused > 100);
  assert.ok(result.refused - result.accepted > 1, "the boundary is not pinned yet");
  assert.equal(result.unknown, false);
});

test("an answer that is neither accepted nor refused ends the search at once and is not asked again", async () => {
  const asked = [];
  const result = await bisect({
    low: 0,
    high: 1000,
    maxSteps: 20,
    accepts: async (n) => {
      asked.push(n);
      return asked.length === 2 ? null : n <= 300;
    },
  });
  assert.equal(asked.length, 2);
  assert.equal(result.unknown, true);
  assert.ok(result.accepted < result.refused);
});

test("neighbours need no request, and a degenerate interval is refused", async () => {
  const result = await bisect({ low: 5, high: 6, maxSteps: 5, accepts: async () => assert.fail("asked") });
  assert.deepEqual(result, { accepted: 5, refused: 6, steps: 0, unknown: false });
  await assert.rejects(() => bisect({ low: 6, high: 6, maxSteps: 5, accepts: async () => true }), /low must be below high/);
  await assert.rejects(() => bisect({ low: 1, high: 9, maxSteps: 0, accepts: async () => true }), /maxSteps/);
});

test("stepsNeeded is the number of halvings of an interval", () => {
  assert.equal(stepsNeeded(1), 0);
  assert.equal(stepsNeeded(2), 1);
  assert.equal(stepsNeeded(3), 2);
  assert.equal(stepsNeeded(4), 2);
  assert.equal(stepsNeeded(5), 3);
  assert.equal(stepsNeeded(786_432), 20);
});

test("acceptance: only a 2xx is accepted, a 4xx other than a rate or time limit is refused, anything else is not an answer", () => {
  assert.equal(acceptance({ status: 200, unknown: false }), true);
  assert.equal(acceptance({ status: 204, unknown: false }), true);
  for (const status of [400, 404, 413, 422, 403, 401]) assert.equal(acceptance({ status, unknown: false }), false, String(status));
  for (const status of [408, 429, 500, 503, 301, 100, 501, null]) assert.equal(acceptance({ status, unknown: false }), null, String(status));
  assert.equal(acceptance({ status: 200, unknown: true }), null);
  assert.equal(acceptance({ status: 400, unknown: true }), null);
  assert.equal(acceptance(undefined), null);
});

test("bracket: the ladder stops at the first refused value and names the last accepted one before it", async () => {
  const next = random(5);
  for (let round = 0; round < 300; round += 1) {
    const values = [];
    let value = 1 + next(10);
    for (let i = 0; i < 1 + next(5); i += 1) {
      values.push(value);
      value += 1 + next(1000);
    }
    const limit = next(value + 10); // the largest accepted value
    const asked = [];
    const result = await bracket({
      start: 0,
      values,
      accepts: async (n) => {
        asked.push(n);
        return n <= limit;
      },
    });
    const firstRefused = values.find((n) => n > limit) ?? null;
    assert.equal(result.high, firstRefused);
    assert.equal(result.low, values.filter((n) => n <= limit).at(-1) ?? 0);
    assert.equal(result.unknown, false);
    assert.deepEqual(asked, firstRefused === null ? values : values.slice(0, values.indexOf(firstRefused) + 1));
  }
});

test("bracket: an answer that does not say ends the ladder and is not asked again", async () => {
  const asked = [];
  const result = await bracket({
    start: 0,
    values: [10, 20, 30],
    accepts: async (n) => {
      asked.push(n);
      return n === 10 ? true : null;
    },
  });
  assert.deepEqual(asked, [10, 20]);
  assert.deepEqual(result, { low: 10, high: null, unknown: true });
});

test("bracket: values must rise above the start", async () => {
  await assert.rejects(() => bracket({ start: 5, values: [5, 6], accepts: async () => true }), /rise/);
  await assert.rejects(() => bracket({ start: 0, values: [3, 2], accepts: async () => true }), /rise/);
  await assert.rejects(() => bracket({ start: 0, values: [], accepts: async () => true }), /rise/);
});

test("boundaries of the guards: one step is allowed, a 300 is not a 2xx, equal ladder values do not rise", async () => {
  const one = await bisect({ low: 0, high: 2, maxSteps: 1, accepts: async () => true });
  assert.deepEqual(one, { accepted: 1, refused: 2, steps: 1, unknown: false });
  assert.equal(acceptance({ status: 299, unknown: false }), true);
  assert.equal(acceptance({ status: 300, unknown: false }), null);
  assert.equal(acceptance({ status: 399, unknown: false }), null);
  assert.equal(acceptance({ status: 400, unknown: false }), false);
  assert.equal(acceptance({ status: 499, unknown: false }), false);
  assert.equal(acceptance({ status: 500, unknown: false }), null);
  await assert.rejects(() => bracket({ start: 0, values: [3, 3], accepts: async () => true }), /rise/);
  await assert.rejects(() => bracket({ start: 0, values: [1, 3, 3], accepts: async () => true }), /rise/);
  const ok = await bracket({ start: 0, values: [1, 2], accepts: async () => true });
  assert.deepEqual(ok, { low: 2, high: null, unknown: false });
});
