import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { evaluateRewriteAttempts } from "./storage-object/rewrite-attempts.mjs";

const bucket = "example.firebasestorage.app";
const recipe = () =>
  buildCorpus({ bucket, prefix: "owned/run-012345/" }).recipes.find(
    (entry) => entry.id === "storage-object/gcs/copy-rewrite",
  );
const body = (value) => Buffer.from(JSON.stringify(value)).toString("base64");
const firstQuery = () => ({
  ifGenerationMatch: "0",
  ifSourceGenerationMatch: "9007199254740993",
  ifSourceMetagenerationMatch: "7",
});
const unfinished = (token, total = "2") => ({
  kind: "storage#rewriteResponse",
  totalBytesRewritten: total,
  objectSize: "5",
  done: false,
  rewriteToken: token,
});
const finished = (entry, total = "5") => ({
  kind: "storage#rewriteResponse",
  totalBytesRewritten: total,
  objectSize: "5",
  done: true,
  resource: {
    kind: "storage#object",
    bucket,
    name: entry.objects[2],
    size: "5",
    generation: "9007199254740994",
  },
});
const attempt = (stepId, query, value) => ({
  stepId,
  query,
  status: 200,
  bodyBase64: body(value),
});
const evaluate = (entry, attempts) => evaluateRewriteAttempts({ recipe: entry, attempts, bucket });

test("a single completed rewrite matches supplied records without authorizing a send", () => {
  const entry = recipe();
  const attempts = [attempt("rewrite-0", firstQuery(), finished(entry))];
  const original = structuredClone(attempts);
  assert.deepEqual(evaluate(entry, attempts), {
    status: "MATCHED_SUPPLIED_REWRITE",
    attempts: 1,
    objectSize: "5",
    destinationName: entry.objects[2],
    sendAuthorized: false,
    cleanupAuthorized: false,
  });
  assert.deepEqual(attempts, original);
});

test("an unfinished response links the exact opaque token to the next declared slot", () => {
  const entry = recipe();
  const token = "opaque+/= token";
  const attempts = [
    attempt("rewrite-0", firstQuery(), unfinished(token)),
    attempt("rewrite-1", { rewriteToken: token }, finished(entry)),
  ];
  assert.equal(evaluate(entry, attempts).attempts, 2);
  for (const changed of [
    [{ ...attempts[0], stepId: "rewrite-1" }, attempts[1]],
    [attempts[0], { ...attempts[1], stepId: "rewrite-2" }],
    [attempts[0], { ...attempts[1], query: { rewriteToken: token + "x" } }],
    [attempts[0], { ...attempts[1], query: { rewriteToken: token, extra: "x" } }],
    [attempts[0], { ...attempts[1], query: {} }],
  ])
    assert.throws(() => evaluate(entry, changed));
  assert.throws(() => evaluate(entry, [attempts[0]]), { code: "INCOMPLETE_REWRITE" });
  assert.throws(() => evaluate(entry, [...attempts, attempts[1]]));
});

test("first request requires the destination guard and both decimal source guards", () => {
  const entry = recipe();
  const good = attempt("rewrite-0", firstQuery(), finished(entry));
  for (const query of [
    { ...firstQuery(), ifGenerationMatch: "1" },
    { ...firstQuery(), ifSourceGenerationMatch: "0" },
    { ...firstQuery(), ifSourceMetagenerationMatch: "01" },
    { ...firstQuery(), rewriteToken: "fabricated" },
    { ifGenerationMatch: "0" },
  ])
    assert.throws(() => evaluate(entry, [{ ...good, query }]));
});

test("success response requires typed progress, completion and destination identity", () => {
  const entry = recipe();
  const good = attempt("rewrite-0", firstQuery(), finished(entry));
  for (const changed of [
    { ...finished(entry), kind: "other" },
    { ...finished(entry), done: "true" },
    { ...finished(entry), totalBytesRewritten: "4" },
    { ...finished(entry), objectSize: "05" },
    { ...finished(entry), rewriteToken: "extra" },
    { ...finished(entry), resource: undefined },
    { ...finished(entry), resource: { ...finished(entry).resource, bucket: "wrong" } },
    { ...finished(entry), resource: { ...finished(entry).resource, name: entry.objects[1] } },
    { ...finished(entry), resource: { ...finished(entry).resource, size: "4" } },
  ])
    assert.throws(() => evaluate(entry, [{ ...good, bodyBase64: body(changed) }]));
  assert.throws(() => evaluate(entry, [{ ...good, status: 404 }]));
});

test("unfinished progress requires a bounded token, no resource and nondecreasing counts", () => {
  const entry = recipe();
  const good = [
    attempt("rewrite-0", firstQuery(), unfinished("token", "4")),
    attempt("rewrite-1", { rewriteToken: "token" }, finished(entry)),
  ];
  for (const changed of [
    { ...unfinished("token"), rewriteToken: "" },
    { ...unfinished("x".repeat(4097)) },
    { ...unfinished("token"), resource: finished(entry).resource },
    { ...unfinished("token"), totalBytesRewritten: "6" },
  ])
    assert.throws(() => evaluate(entry, [{ ...good[0], bodyBase64: body(changed) }, good[1]]));
  assert.throws(() =>
    evaluate(entry, [good[0], { ...good[1], bodyBase64: body(finished(entry, "3")) }]),
  );
  assert.throws(() =>
    evaluate(entry, [
      good[0],
      { ...good[1], bodyBase64: body({ ...finished(entry), objectSize: "6" }) },
    ]),
  );
});

test("raw response and declared slot bounds reject malformed or forged records", () => {
  const entry = recipe();
  const good = attempt("rewrite-0", firstQuery(), finished(entry));
  for (const bad of [
    "?",
    Buffer.from("{").toString("base64"),
    Buffer.alloc(1024 * 1024 + 1).toString("base64"),
  ])
    assert.throws(() => evaluate(entry, [{ ...good, bodyBase64: bad }]));
  assert.throws(() =>
    evaluate(
      entry,
      Array.from({ length: 9 }, () => good),
    ),
  );
  const altered = structuredClone(entry);
  altered.steps.find((step) => step.id === "rewrite-0").path = "/wrong";
  assert.throws(() => evaluate(altered, [good]));
  const unbound = structuredClone(entry);
  unbound.steps.find((step) => step.id === "rewrite-0").query.ifSourceGenerationMatch = "42";
  assert.throws(() => evaluate(unbound, [good]), { code: "INVALID_DECLARATION" });
});

test("the eighth unfinished response remains incomplete and numeric fields keep uint64 bounds", () => {
  const entry = recipe();
  const attempts = Array.from({ length: 8 }, (_, index) =>
    attempt(
      `rewrite-${index}`,
      index === 0 ? firstQuery() : { rewriteToken: `token-${index - 1}` },
      unfinished(`token-${index}`, String(Math.min(index, 5))),
    ),
  );
  assert.throws(() => evaluate(entry, attempts), { code: "INCOMPLETE_REWRITE" });
  const complete = attempts.map((item) => ({ ...item }));
  complete[7].bodyBase64 = body(finished(entry));
  assert.equal(evaluate(entry, complete).attempts, 8);
  const tooLarge = attempt("rewrite-0", firstQuery(), {
    ...finished(entry),
    totalBytesRewritten: "18446744073709551616",
    objectSize: "18446744073709551616",
  });
  assert.throws(() => evaluate(entry, [tooLarge]), { code: "INVALID_PROGRESS" });
});

test("token bytes, intermediate progress and object size are stable across three calls", () => {
  const entry = recipe();
  const records = [
    attempt("rewrite-0", firstQuery(), unfinished("first", "4")),
    attempt("rewrite-1", { rewriteToken: "first" }, unfinished("second", "4")),
    attempt("rewrite-2", { rewriteToken: "second" }, finished(entry)),
  ];
  assert.equal(evaluate(entry, records).attempts, 3);
  const longToken = "x".repeat(4097);
  assert.throws(() =>
    evaluate(entry, [
      { ...records[0], bodyBase64: body(unfinished(longToken, "4")) },
      { ...records[1], query: { rewriteToken: longToken } },
      records[2],
    ]),
  );
  assert.throws(
    () =>
      evaluate(entry, [
        records[0],
        { ...records[1], bodyBase64: body(unfinished("second", "3")) },
        records[2],
      ]),
    { code: "INVALID_PROGRESS" },
  );
  assert.throws(
    () =>
      evaluate(entry, [
        records[0],
        { ...records[1], bodyBase64: body({ ...unfinished("second", "4"), objectSize: "6" }) },
        records[2],
      ]),
    { code: "INVALID_PROGRESS" },
  );
});

test("a declaration cannot relabel the observed source generation field", () => {
  const entry = recipe();
  const initial = attempt("rewrite-0", firstQuery(), finished(entry));
  entry.steps.find((step) => step.id === "rewrite-0").query.ifSourceGenerationMatch.field =
    "metageneration";
  assert.throws(() => evaluate(entry, [initial]), { code: "INVALID_DECLARATION" });
});

test("the first rewrite declaration retains its metadata override and JSON header", () => {
  const entry = recipe();
  const initial = attempt("rewrite-0", firstQuery(), finished(entry));
  const changedBody = structuredClone(entry);
  changedBody.steps.find((step) => step.id === "rewrite-0").body.json.contentType = "other/type";
  assert.throws(() => evaluate(changedBody, [initial]), { code: "INVALID_DECLARATION" });
  const changedHeader = structuredClone(entry);
  changedHeader.steps.find((step) => step.id === "rewrite-0").headers["content-type"] =
    "text/plain";
  assert.throws(() => evaluate(changedHeader, [initial]), { code: "INVALID_DECLARATION" });
});
