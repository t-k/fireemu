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

test("settlement records independent creation and deletion evidence", () => {
  const event = (action, status, extra = {}) => ({
    phase: "after",
    resource: "r",
    action,
    status,
    ...extra,
  });
  const only = (...events) => settlement(events).unresolved[0];
  assert.deepEqual(only(event("create", 503)), {
    resource: "r",
    confirmed: false,
    unknownCreate: true,
    unknownDelete: false,
    deleted: false,
    absent: false,
    reason: "unconfirmed create",
  });
  assert.deepEqual(only(event("delete", 503)), {
    resource: "r",
    confirmed: false,
    unknownCreate: false,
    unknownDelete: true,
    deleted: false,
    absent: false,
    reason: "unknown delete",
  });
  assert.deepEqual(only(event("create", 200)), {
    resource: "r",
    confirmed: true,
    unknownCreate: false,
    unknownDelete: false,
    deleted: false,
    absent: false,
    reason: "created, not deleted and read back absent",
  });
  assert.equal(only(event("create", 200), event("delete", 204)).deleted, true);
  assert.equal(
    only(event("create", 200), event("read", 404, { session: "a2" }), event("create", 200)).absent,
    false,
  );
  assert.equal(
    only(event("create", 200), event("read", 404, { session: "a2" }), event("delete", 503)).absent,
    false,
  );
  assert.equal(
    only(event("create", 200), event("read", 404, { session: "a2" }), event("delete", 204)).absent,
    false,
  );
  assert.equal(
    only(event("create", 503), event("read", 404, { session: "a2" })).unknownCreate,
    true,
  );
  assert.equal(only(event("create", 200), event("delete", 503), event("read", 404)).absent, false);
  assert.equal(only(event("create", 200), event("read", 200)).confirmed, true);
  assert.equal(
    only(event("create", 503), event("read", 503, { showsResource: true })).unknownCreate,
    true,
  );
});

test("row extraction preserves null fields and exact media byte layout", () => {
  const row = judgeAnswer(answer(JSON.stringify({ error: { code: 404, message: "missing" } })));
  assert.deepEqual(row.json, { code: 404, message: "missing", reason: null });
  assert.equal(row.xml, null);
  const media = judgeAnswer(answer("fire", { case: "C5", status: 200 }));
  assert.equal(media.json, null);
  assert.equal(media.xml, null);
  assert.equal(media.bodyBytes, 4);
  assert.equal(media.known, true);
  for (const extra of [{ bodyBytes: 0 }, { bodyBytes: 5 }, { bodyBase64: "ZmlyZQ==\n" }])
    assert.equal(judgeAnswer(answer("fire", { case: "C5", status: 200, ...extra })).known, false);
  for (const body of ["fir", "fires", "Fire"])
    assert.equal(judgeAnswer(answer(body, { case: "C5", status: 200 })).shape, "unrecorded");
});

test("comparison command succeeds only for a nonempty set of matches", async () => {
  const { spawnSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const dir = mkdtempSync(join(tmpdir(), "strictness-compare-"));
  try {
    const production = join(dir, "production.json");
    const journal = join(dir, "journal.jsonl");
    const before = { phase: "before", n: 1, case: "C5", method: "GET" };
    const after = { ...answer("fire", { case: "C5", status: 200 }), phase: "after", n: 1 };
    const invoke = () =>
      spawnSync(
        process.execPath,
        [fileURLToPath(new URL("./compare.mjs", import.meta.url)), production, journal],
        { encoding: "utf8" },
      );
    writeFileSync(journal, [before, after].map(JSON.stringify).join("\n") + "\n");
    writeFileSync(production, JSON.stringify([judgeAnswer(after)]));
    assert.equal(invoke().status, 0);
    writeFileSync(production, JSON.stringify([{ ...judgeAnswer(after), status: 201 }]));
    assert.equal(invoke().status, 1);
    writeFileSync(production, "[]");
    writeFileSync(journal, "\n");
    assert.equal(invoke().status, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("each unknown signal alone makes a create unconfirmed: a before-only entry, an unknown flag, an unknown status", () => {
  const r = "/storage/v1/b/fireemu-obs-ss-00000000";
  const cases = [
    [{ phase: "before", n: 1, action: "create", resource: r }],
    [{ phase: "after", n: 1, action: "create", resource: r, status: 200, unknown: true }],
    [{ phase: "after", n: 1, action: "create", resource: r, status: 503 }],
    [{ phase: "after", n: 1, action: "create", resource: r, status: 302 }],
  ];
  for (const entries of cases) {
    const reasons = settlement(entries).unresolved.map((s) => s.reason);
    assert.deepEqual(reasons, ["unconfirmed create"], JSON.stringify(entries));
  }
});

test("an A2 read that answers 200 without the resource never settles a confirmed create as absent", () => {
  const r = "/storage/v1/b/fireemu-obs-ss-00000000";
  const entries = [
    { phase: "after", n: 1, action: "create", resource: r, status: 200 },
    {
      phase: "after",
      n: 1,
      session: "a2",
      action: "read",
      resource: r,
      status: 200,
      showsResource: false,
    },
  ];
  assert.equal(settlement(entries).unresolved.length, 1);
  entries[1] = { ...entries[1], status: 404 };
  assert.equal(settlement(entries).unresolved.length, 0);
});
