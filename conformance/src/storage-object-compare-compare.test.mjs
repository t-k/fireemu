import assert from "node:assert/strict";
import test from "node:test";
import {
  align,
  compareRecipe,
  differences,
  jsonDifferences,
  STANDIN_HEADER,
  summarize,
} from "./storage-object-compare/compare.mjs";

const row = (n, over = {}) => ({
  n,
  method: "GET",
  route: "GET /storage/v1/b/<BUCKET>/o/<NAME>",
  path: `/storage/v1/b/<BUCKET>/o/storage-object/<RUN>/a${n}.bin`,
  query: [],
  status: 200,
  contentType: "application/json; charset=UTF-8",
  headers: { "content-type": "application/json; charset=UTF-8", "cache-control": "private" },
  body: { type: "json", value: { name: "x", size: "5" } },
  ...over,
});
const same = (rows) => rows.map((item) => structuredClone(item));
const outcomes = (results) => results.map((result) => result.outcome);

test("alignment pairs equal keys in order, and reports what only one side has", () => {
  assert.deepEqual(align(["a", "b", "c"], ["a", "b", "c"]), [
    [0, 0],
    [1, 1],
    [2, 2],
  ]);
  assert.deepEqual(align(["a", "x", "c"], ["a", "c"]), [
    [0, 0],
    [1, null],
    [2, 1],
  ]);
  assert.deepEqual(align(["a", "c"], ["a", "y", "c"]), [
    [0, 0],
    [null, 1],
    [1, 2],
  ]);
  assert.deepEqual(align([], ["a"]), [[null, 0]]);
  assert.deepEqual(align(["a"], []), [[0, null]]);
  assert.deepEqual(
    align([{ k: 1 }], [{ k: 1 }], (value) => value.k),
    [[0, 0]],
  );
  // Repeated keys pair in order.
  assert.deepEqual(align(["a", "a"], ["a", "a", "a"]), [
    [0, 0],
    [1, 1],
    [null, 2],
  ]);
});

test("JSON differences name the path, include absent members, and stop at the limit", () => {
  assert.deepEqual(jsonDifferences({ a: 1 }, { a: 1 }), []);
  assert.deepEqual(jsonDifferences({ a: 1, b: { c: 2 } }, { a: 1, b: { c: 3 } }), [
    { path: "$.b.c", production: 2, local: 3 },
  ]);
  assert.deepEqual(jsonDifferences({ a: 1 }, {}), [
    { path: "$.a", production: 1, local: "<absent>" },
  ]);
  assert.deepEqual(jsonDifferences({}, { a: 1 }), [
    { path: "$.a", production: "<absent>", local: 1 },
  ]);
  assert.deepEqual(jsonDifferences({ items: [1, 2] }, { items: [1, 3] }), [
    { path: "$.items[1]", production: 2, local: 3 },
  ]);
  assert.deepEqual(jsonDifferences({ items: [1] }, { items: [1, 2] }), [
    { path: "$.items", production: [1], local: [1, 2] },
  ]);
  assert.deepEqual(jsonDifferences(1, "1"), [{ path: "$", production: 1, local: "1" }]);
  const many = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`k${i}`, i]));
  assert.equal(jsonDifferences(many, {}).length, 8);
});

test("identical exchanges have no differences", () => {
  assert.deepEqual(differences(row(1), row(1)), []);
});

test("each part of an exchange is compared: status, the exact content type, the headers, the body, the request", () => {
  assert.deepEqual(differences(row(1), row(1, { status: 404 })), [
    { kind: "status", production: 200, local: 404 },
  ]);
  assert.deepEqual(
    differences(row(1), row(1, { contentType: "application/json; charset=utf-8" })),
    [
      {
        kind: "contentType",
        production: "application/json; charset=UTF-8",
        local: "application/json; charset=utf-8",
      },
    ],
  );
  const missing = row(1, { headers: { "content-type": "application/json; charset=UTF-8" } });
  assert.deepEqual(differences(row(1), missing), [
    { kind: "missingHeader", header: "cache-control", production: "private" },
  ]);
  assert.deepEqual(differences(missing, row(1)), [
    { kind: "extraHeader", header: "cache-control", local: "private" },
  ]);
  assert.deepEqual(
    differences(
      row(1),
      row(1, {
        headers: { "content-type": "application/json; charset=UTF-8", "cache-control": "no-cache" },
      }),
    ),
    [{ kind: "headerValue", header: "cache-control", production: "private", local: "no-cache" }],
  );
  assert.deepEqual(
    differences(row(1), row(1, { body: { type: "json", value: { name: "x", size: "6" } } })),
    [{ kind: "body", path: "$.size", production: "5", local: "6" }],
  );
  assert.deepEqual(differences(row(1), row(1, { body: { type: "text", value: "x" } })), [
    { kind: "bodyType", production: "json", local: "text" },
  ]);
  assert.deepEqual(differences(row(1), row(1, { query: [["alt", "media"]] })), [
    { kind: "requestQuery", production: [], local: [["alt", "media"]] },
  ]);
});

test("the content-type header is judged once, as the content type, and not again as a header", () => {
  const other = row(1, {
    contentType: "text/plain",
    headers: { "content-type": "text/plain", "cache-control": "private" },
  });
  assert.deepEqual(
    differences(row(1), other).map((diff) => diff.kind),
    ["contentType"],
  );
});

test("text, bytes and empty bodies are compared whole", () => {
  const text = (value) => row(1, { body: { type: "text", value } });
  assert.deepEqual(differences(text("a"), text("a")), []);
  assert.deepEqual(differences(text("a"), text("b")), [
    { kind: "body", production: "a", local: "b" },
  ]);
  const bytes = (sha256, length = 4) => row(1, { body: { type: "bytes", length, sha256 } });
  assert.deepEqual(differences(bytes("x"), bytes("x")), []);
  assert.deepEqual(differences(bytes("x"), bytes("y")), [
    { kind: "body", production: { length: 4, sha256: "x" }, local: { length: 4, sha256: "y" } },
  ]);
  assert.deepEqual(differences(bytes("x"), bytes("x", 5)).length, 1);
  const empty = row(1, { body: { type: "empty" } });
  assert.deepEqual(differences(empty, empty), []);
});

test("a recipe is compared pair by pair: MATCH, DIVERGENCE with the differences, and the exchanges one side lacks", () => {
  const production = [row(1), row(2), row(3), row(4)];
  const local = same(production);
  local[1].status = 404;
  local.splice(2, 1);
  local.push(row(9, { path: "/storage/v1/b/<BUCKET>/o/storage-object/<RUN>/extra.bin" }));
  const results = compareRecipe({ production, local });
  assert.deepEqual(outcomes(results), [
    "MATCH",
    "DIVERGENCE",
    "ONLY_PRODUCTION",
    "MATCH",
    "ONLY_LOCAL",
  ]);
  assert.deepEqual(results[1], {
    outcome: "DIVERGENCE",
    n: 2,
    route: production[1].route,
    differences: [{ kind: "status", production: 200, local: 404 }],
  });
  assert.equal(results[2].n, 3);
  assert.equal(results[4].local.path.endsWith("extra.bin"), true);
  assert.deepEqual(summarize(results), {
    MATCH: 2,
    DIVERGENCE: 1,
    LOCAL_UNIMPLEMENTED: 0,
    ONLY_PRODUCTION: 1,
    ONLY_LOCAL: 1,
  });
});

test("pairs are aligned by method, path and the names of the query, not by its values", () => {
  const production = [row(1, { query: [["ifGenerationMatch", "<GEN:1>"]] })];
  const local = [row(1, { query: [["ifGenerationMatch", "<GEN:2>"]] })];
  const [result] = compareRecipe({ production, local });
  assert.equal(result.outcome, "DIVERGENCE");
  assert.equal(result.differences[0].kind, "requestQuery");
  assert.deepEqual(
    outcomes(compareRecipe({ production, local: [row(1, { query: [["alt", "media"]] })] })),
    ["ONLY_PRODUCTION", "ONLY_LOCAL"],
  );
});

test("an exchange fireemu answered 501 to is LOCAL_UNIMPLEMENTED, whatever else differs", () => {
  const production = [row(1, { status: 200 })];
  const local = [row(1, { status: 501, contentType: null, headers: {}, body: { type: "empty" } })];
  assert.deepEqual(compareRecipe({ production, local }), [
    {
      outcome: "LOCAL_UNIMPLEMENTED",
      n: 1,
      route: production[0].route,
      reason: "fireemu answered 501",
      productionStatus: 200,
      localStatus: 501,
    },
  ]);
  // A 501 that production answered too is an ordinary pair.
  assert.deepEqual(outcomes(compareRecipe({ production: [row(1, { status: 501 })], local })), [
    "DIVERGENCE",
  ]);
});

test("an exchange the rehearsal stand-in answered is LOCAL_UNIMPLEMENTED, never MATCH", () => {
  const production = [row(1)];
  const local = [
    row(1, {
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "private",
        [STANDIN_HEADER]: "1",
      },
    }),
  ];
  const [result] = compareRecipe({ production, local });
  assert.equal(result.outcome, "LOCAL_UNIMPLEMENTED");
  assert.equal(result.reason, "answered by the rehearsal stand-in");
  assert.equal(result.localStatus, 200);
});

test("an empty comparison has nothing", () => {
  assert.deepEqual(compareRecipe({ production: [], local: [] }), []);
  assert.deepEqual(summarize([]), {
    MATCH: 0,
    DIVERGENCE: 0,
    LOCAL_UNIMPLEMENTED: 0,
    ONLY_PRODUCTION: 0,
    ONLY_LOCAL: 0,
  });
});
