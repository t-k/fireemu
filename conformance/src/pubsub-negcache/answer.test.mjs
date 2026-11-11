import assert from "node:assert/strict";
import test from "node:test";

import { classify, latencyClass, FAST_MS, SLOW_MS } from "./answer.mjs";

const err = (status, code) =>
  JSON.stringify({ error: { code: status, message: "m", status: code } });

test("latency classes at the boundaries", () => {
  assert.equal(latencyClass(0), "fast");
  assert.equal(latencyClass(FAST_MS), "fast");
  assert.equal(latencyClass(FAST_MS + 1), "ambiguous");
  assert.equal(latencyClass(SLOW_MS - 1), "ambiguous");
  assert.equal(latencyClass(SLOW_MS), "slow");
  assert.equal(latencyClass(NaN), "unknown");
  assert.equal(latencyClass(-1), "unknown");
  assert.equal(latencyClass(undefined), "unknown");
});

test("complete answers are known", () => {
  assert.equal(classify({ status: 200, bodyText: "{}", headersMs: 300 }).kind, "ok");
  assert.equal(classify({ status: 200, bodyText: "", headersMs: 300 }).kind, "ok");
  const notFound = classify({ status: 404, bodyText: err(404, "NOT_FOUND"), headersMs: 20 });
  assert.deepEqual(
    [notFound.kind, notFound.status, notFound.code, notFound.latency],
    ["error", 404, "NOT_FOUND", "fast"],
  );
  assert.equal(
    classify({ status: 409, bodyText: err(409, "ALREADY_EXISTS"), headersMs: 300 }).kind,
    "error",
  );
  assert.equal(
    classify({ status: 400, bodyText: err(400, "INVALID_ARGUMENT"), headersMs: 300 }).kind,
    "error",
  );
});

test("near misses are unknown: statuses below 200, 3xx, 5xx", () => {
  for (const status of [100, 199, 301, 302, 304, 399, 500, 502, 503, 504])
    assert.equal(
      classify({ status, bodyText: "{}", headersMs: 100 }).kind,
      "unknown",
      String(status),
    );
  assert.equal(
    classify({ status: 500, bodyText: err(500, "INTERNAL"), headersMs: 100 }).kind,
    "unknown",
  );
});

test("near misses are unknown: transport failure, unreadable or mismatched bodies", () => {
  assert.equal(classify({ failure: "timeout", headersMs: 1 }).kind, "unknown");
  assert.equal(classify({ status: 200, failure: "reset", bodyText: "{}" }).kind, "unknown");
  assert.equal(classify({ headersMs: 1 }).kind, "unknown");
  assert.equal(classify({ status: 200, bodyText: "<html>" }).kind, "unknown");
  assert.equal(classify({ status: 404, bodyText: "<html>" }).kind, "unknown");
  assert.equal(classify({ status: 404, bodyText: err(404, "ALREADY_EXISTS") }).kind, "unknown");
  assert.equal(classify({ status: 404, bodyText: "{}" }).kind, "unknown");
  assert.equal(classify({ status: 409, bodyText: err(409, "NOT_FOUND") }).kind, "unknown");
  assert.equal(
    classify({ status: 200, bodyText: JSON.stringify({ error: { status: "NOT_FOUND" } }) }).kind,
    "unknown",
  );
});

test("an operation that is not done is unknown", () => {
  assert.equal(
    classify({ status: 200, bodyText: JSON.stringify({ name: "operations/x", done: false }) }).kind,
    "unknown",
  );
});

test("the latency classes use the recorded boundaries", () => {
  assert.equal(FAST_MS, 60);
  assert.equal(SLOW_MS, 120);
  assert.equal(latencyClass(60), "fast");
  assert.equal(latencyClass(61), "ambiguous");
  assert.equal(latencyClass(119), "ambiguous");
  assert.equal(latencyClass(120), "slow");
});

test("a 300 is unknown and the unknown answer has null fields", () => {
  assert.equal(classify({ status: 300, bodyText: "{}", headersMs: 100 }).kind, "unknown");
  assert.deepEqual(classify({ failure: "x", headersMs: 100 }), {
    kind: "unknown",
    status: null,
    code: null,
    body: null,
    latency: "ambiguous",
  });
  assert.deepEqual(classify({ status: 500, bodyText: "{}", headersMs: 100 }), {
    kind: "unknown",
    status: 500,
    code: null,
    body: null,
    latency: "ambiguous",
  });
});
