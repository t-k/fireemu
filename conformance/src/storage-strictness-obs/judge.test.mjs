import "../storage-signed-put/test-preload.mjs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { judgeAnswer, judgeJournal, parseXmlError } from "./judge.mjs";
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
