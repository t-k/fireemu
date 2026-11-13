import "../storage-signed-put/test-preload.mjs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { judgeAnswer, judgeJournal, parseXmlError, settlement } from "./judge.mjs";
import { compare } from "./compare.mjs";

const answer = (body, extra = {}) => {
  const bytes = Buffer.from(body);
  return {
    case: "P2",
    method: "GET",
    status: 404,
    bodyBase64: bytes.toString("base64"),
    bodyBytes: bytes.length,
    headers: {},
    ...extra,
  };
};

// shape-from-code: signed-put's judge tests and fixtures contain neither of these recordings.
// storage.rs missing_bucket_response and api_error::gcs specify this envelope; this is not a production capture.
const missing =
  '{"error":{"code":404,"message":"The specified bucket does not exist.","errors":[{"domain":"global","reason":"notFound","message":"The specified bucket does not exist."}]}}';

test("shape-from-code: missing bucket JSON preserves exact bytes and extracts the GCS error", () => {
  const row = judgeAnswer(answer(missing));
  assert.deepEqual(row.json, {
    code: 404,
    message: "The specified bucket does not exist.",
    reason: "notFound",
  });
  assert.equal(row.bodyBytes, Buffer.byteLength(missing));
  assert.equal(row.sha256, createHash("sha256").update(missing).digest("hex"));
  assert.equal(row.known, true);
});

test("shape-from-code: unconfigured bucket OPTIONS is 200 with no Access-Control headers", () => {
  // storage_cors.rs documents the recorded status and absence of CORS headers, but no full header capture.
  const row = judgeAnswer(answer("", { case: "R3", method: "OPTIONS", status: 200, headers: {} }));
  assert.equal(row.shape, "empty");
  assert.equal(row.known, true);
  assert.deepEqual(row.headers, {});
  assert.equal(row.bodyBytes, 0);
});

test("body layout is based on recorded bytes and digest, never reserialized JSON", () => {
  const pretty = JSON.stringify(JSON.parse(missing), null, 2) + "\n";
  const a = judgeAnswer(answer(missing));
  const b = judgeAnswer(answer(pretty));
  assert.deepEqual(a.json, b.json);
  assert.notEqual(a.bodyBytes, b.bodyBytes);
  assert.match(compare([a], [b])[0].verdict, /DIFFERS\(bodyBytes,sha256\)/);
  assert.equal(judgeAnswer(answer(missing, { bodyBytes: 1 })).known, false);
  assert.equal(judgeAnswer(answer("日本", { bodyBytes: 2 })).known, false);
});

test("documented XML errors need a complete Error document and Code and Message", () => {
  const xml =
    '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist.</Message></Error>';
  assert.deepEqual(judgeAnswer(answer(xml)).xml, {
    Code: "NoSuchBucket",
    Message: "The specified bucket does not exist.",
  });
  assert.deepEqual(
    parseXmlError("<Error><Code>NoSuchBucket</Code><Message>a &amp; b</Message></Error>"),
    { Code: "NoSuchBucket", Message: "a & b" },
  );
  for (const value of [
    "<Error/>",
    "<Error><Code>X</Code></Error>",
    `<html>${xml}</html>`,
    `${xml}junk`,
    '<!DOCTYPE Error SYSTEM "file:///etc/passwd">' + xml,
    "<Error><Code>X</Code><Code>Y</Code><Message>m</Message></Error>",
    "<Error><Code>X</Code><Message>&unknown;</Message></Error>",
    "<Error><Code>X</Code><Message>m</Message><Unknown>x</Unknown></Error>",
  ])
    assert.equal(parseXmlError(value), null);
});

test("unknown, unrecorded, missing and duplicate cases are never accepted", () => {
  const row = judgeAnswer(answer(missing));
  assert.equal(compare([row], [row])[0].verdict, "MATCH");
  for (const value of [
    answer("html"),
    answer('{"unexpected":true}'),
    answer('{"error":{"code":404,"message":"m","extra":true}}'),
    answer(missing, { unknown: true }),
    answer(missing, { status: 503 }),
    answer(missing, { withheld: true }),
  ]) {
    const unknown = judgeAnswer(value);
    assert.equal(unknown.known, false);
    assert.equal(compare([unknown], [unknown])[0].verdict, "NEEDS-REVIEW");
  }
  assert.equal(compare([row], [])[0].verdict, "NEEDS-REVIEW");
  assert.equal(compare([row, row], [row])[0].verdict, "NEEDS-REVIEW");
  assert.equal(compare([], [row])[0].verdict, "NEEDS-REVIEW");
  const interrupted = judgeJournal([{ phase: "before", n: 1, case: "W1", method: "POST" }]);
  assert.equal(interrupted[0].known, false);
});

test("seeded header extraction keeps all names sorted and exact selected values", () => {
  let seed = 0xc0ffee;
  const names = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Expose-Headers",
    "Vary",
    "Content-Length",
    "Date",
    "ETag",
    "X-Custom",
  ];
  for (let i = 0; i < 200; i++) {
    const headers = {};
    for (const name of names) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      if ((seed >>> 16) & 1)
        headers[(seed >>> 17) & 1 ? name.toUpperCase() : name] = String(seed % 1000);
    }
    const row = judgeAnswer(answer(missing, { headers }));
    const expectedNames = Object.keys(headers)
      .map((name) => name.toLowerCase())
      .toSorted();
    assert.deepEqual(row.headerNames, expectedNames);
    for (const [name, value] of Object.entries(headers)) {
      const lower = name.toLowerCase();
      assert.equal(
        row.headers[lower],
        lower.startsWith("access-control-") || ["vary", "content-length"].includes(lower)
          ? value
          : undefined,
      );
    }
  }
});

test("204 comparisons distinguish an absent Content-Length from an explicit zero", () => {
  const a = judgeAnswer(answer("", { case: "F2", method: "DELETE", status: 204 }));
  const b = judgeAnswer(
    answer("", { case: "F2", method: "DELETE", status: 204, headers: { "Content-Length": "0" } }),
  );
  assert.equal(compare([a], [b])[0].verdict, "DIFFERS(headerNames,headers)");
});

test("JSON error recognition requires each recorded layout constraint", () => {
  const valid = { error: { code: 400, message: "bad", errors: [{ reason: "invalid" }] } };
  const row = (value, status = 400) => judgeAnswer(answer(JSON.stringify(value), { status }));
  assert.equal(row(valid).shape, "json-error");
  for (const [value, status] of [
    [{ ...valid, extra: true }, 400],
    [{ error: { ...valid.error, extra: true } }, 400],
    [{ error: { ...valid.error, code: 399 } }, 399],
    [{ error: { ...valid.error, code: 500 } }, 500],
    [{ error: { ...valid.error, code: 400.5 } }, 400],
    [valid, 401],
    [{ error: { ...valid.error, message: 1 } }, 400],
    [{ error: { ...valid.error, errors: [] } }, 400],
    [{ error: { ...valid.error, errors: {} } }, 400],
    [{ error: { ...valid.error, errors: [null] } }, 400],
    [{ error: { ...valid.error, errors: [{}] } }, 400],
    [{ error: { ...valid.error, errors: [{ reason: "x", extra: true }] } }, 400],
  ])
    assert.equal(row(value, status).shape, "unrecorded", JSON.stringify(value));
  assert.deepEqual(row({ error: {} }).json, { code: null, message: null, reason: null });
  assert.equal(row({ error: { code: 499, message: "x" } }, 499).shape, "json-error");
});

test("recorded shapes and byte metadata require exact boundaries", () => {
  const xml = "<Error><Code>X</Code><Message>m</Message></Error>";
  for (const status of [399, 500])
    assert.equal(judgeAnswer(answer(xml, { status })).shape, "unrecorded");
  for (const status of [400, 499])
    assert.equal(judgeAnswer(answer(xml, { status })).shape, "xml-error");
  for (const [method, status, shape] of [
    ["OPTIONS", 200, "empty"],
    ["OPTIONS", 201, "unrecorded"],
    ["DELETE", 204, "empty"],
    ["GET", 204, "unrecorded"],
  ])
    assert.equal(judgeAnswer(answer("", { method, status })).shape, shape);
  for (const [id, status, shape] of [
    ["C5", 200, "media"],
    ["C6", 200, "media"],
    ["C5", 201, "unrecorded"],
    ["P2", 200, "unrecorded"],
  ])
    assert.equal(judgeAnswer(answer("fire", { case: id, status })).shape, shape);
  for (const extra of [
    { headersRedacted: true },
    { bodyBytes: null },
    { bodyBytes: 4.5 },
    { bodyBase64: "ZmlyZQ" },
  ])
    assert.equal(judgeAnswer(answer("fire", { case: "C5", status: 200, ...extra })).known, false);
});

test("settlement retains exact ownership and uncertainty state across reads", () => {
  const e = (action, status, extra = {}) => ({
    phase: "after",
    resource: "r",
    action,
    status,
    ...extra,
  });
  const state = (...entries) => settlement(entries).unresolved[0];
  assert.deepEqual(settlement([e("read", 200, { showsResource: true })]), {
    closureReady: true,
    unresolved: [],
  });
  assert.equal(state(e("create", 200), e("delete", 503), e("read", 404)).unknownDelete, true);
  assert.equal(
    state(e("create", 503), e("read", 200, { showsResource: true })).unknownCreate,
    false,
  );
  assert.equal(state(e("create", 200), e("delete", 204), e("create", 503)).deleted, false);
  assert.equal(
    state(e("create", 200), e("delete", 204), e("read", 200, { showsResource: true })).deleted,
    false,
  );
  assert.equal(
    state(e("create", 200), e("delete", 503), e("read", 404, { session: "a2" })),
    undefined,
  );
  assert.equal(
    settlement([
      { phase: "before", n: 1, resource: "r", action: "create" },
      { ...e("create", 409), n: 1 },
    ]).closureReady,
    true,
  );
  assert.equal(
    settlement([{ phase: "other", resource: "r", action: "create" }]).closureReady,
    true,
  );
  assert.equal(settlement([e("create", 200, { resource: "" }), e("", 200)]).closureReady, true);
});

test("comparison rejects a single unknown row on either side", () => {
  const row = judgeAnswer(answer(missing));
  const unknown = { ...row, known: false };
  assert.equal(compare([row], [unknown])[0].verdict, "NEEDS-REVIEW");
  assert.equal(compare([unknown], [row])[0].verdict, "NEEDS-REVIEW");
  assert.equal(compare([row], [row, row])[0].verdict, "NEEDS-REVIEW");
});
