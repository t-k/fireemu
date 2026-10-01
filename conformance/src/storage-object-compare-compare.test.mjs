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

test("alignment finds the best pairing from either end of both lists", () => {
  assert.deepEqual(align(["x"], ["a", "x"]), [
    [null, 0],
    [0, 1],
  ]);
  assert.deepEqual(align(["x", "a"], ["a", "a"]), [
    [0, null],
    [1, 0],
    [null, 1],
  ]);
  assert.deepEqual(align(["a", "x"], ["x"]), [
    [0, null],
    [1, 0],
  ]);
  assert.deepEqual(
    align(["x", "y"], ["y", "x"]).filter(([i, j]) => i !== null && j !== null).length,
    1,
  );
});

test("JSON differences against a value of another kind are one difference at that path", () => {
  assert.deepEqual(jsonDifferences({ a: 1 }, 5), [{ path: "$", production: { a: 1 }, local: 5 }]);
  assert.deepEqual(jsonDifferences(5, { a: 1 }), [{ path: "$", production: 5, local: { a: 1 } }]);
  assert.deepEqual(jsonDifferences({ a: 1 }, null), [
    { path: "$", production: { a: 1 }, local: null },
  ]);
  assert.deepEqual(jsonDifferences([1], { 0: 1 }), [
    { path: "$", production: [1], local: { 0: 1 } },
  ]);
  const items = Array.from({ length: 20 }, (_, i) => i);
  assert.equal(jsonDifferences({ items }, { items: items.map((i) => i + 100) }).length, 8);
  assert.equal(
    jsonDifferences(
      items,
      items.map((i) => i + 100),
    ).length,
    8,
  );
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
  // The member order is judged only while there is room: a full list is not extended.
  const swapped = jsonDifferences({ a: 1, b: 2 }, { b: 2, a: 1 });
  assert.equal(swapped.length, 1);
  assert.equal(swapped[0].memberOrder, true);
  const full = jsonDifferences({ a: 1, b: 2 }, { b: 3, a: 1 }, "$", 1);
  assert.deepEqual(full, [{ path: "$.b", production: 2, local: 3 }]);
  assert.equal(jsonDifferences({ a: 1, b: 2 }, { b: 3, a: 1 }, "$", 2).length, 2);
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
    TAINTED: 0,
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
    TAINTED: 0,
    ONLY_PRODUCTION: 0,
    ONLY_LOCAL: 0,
  });
});

test("the same members in another order are a difference of their own, at any depth", () => {
  const order = (a, b) => jsonDifferences(a, b);
  assert.deepEqual(order({ a: 1, b: 2 }, { b: 2, a: 1 }), [
    { path: "$", memberOrder: true, production: ["a", "b"], local: ["b", "a"] },
  ]);
  assert.deepEqual(order({ o: { a: 1, b: 2 } }, { o: { b: 2, a: 1 } }), [
    { path: "$.o", memberOrder: true, production: ["a", "b"], local: ["b", "a"] },
  ]);
  assert.deepEqual(order({ a: 1, b: 2 }, { a: 1, b: 2 }), []);
  // Another set of members is a difference of members, not of order.
  assert.deepEqual(
    order({ a: 1, b: 2 }, { b: 2, c: 3 }).map((diff) => diff.memberOrder ?? false),
    [false, false],
  );
  const rows = (keys) =>
    row(1, { body: { type: "json", value: Object.fromEntries(keys.map((key) => [key, 1])) } });
  assert.deepEqual(
    differences(rows(["a", "b"]), rows(["b", "a"])).map((diff) => diff.kind),
    ["memberOrder"],
  );
});

test("the body layout is compared where both sides know it, and only then", () => {
  const layout = (value) => row(1, { layout: value });
  assert.deepEqual(differences(layout(74), layout(74)), []);
  assert.deepEqual(differences(layout(74), layout(0)), [
    { kind: "bodyLayout", production: 74, local: 0 },
  ]);
  assert.deepEqual(differences(layout(0), layout(74)), [
    { kind: "bodyLayout", production: 0, local: 74 },
  ]);
  assert.deepEqual(differences(layout(74), layout(null)), []);
  assert.deepEqual(differences(layout(null), layout(0)), []);
  assert.deepEqual(differences(layout(74), row(1)), []);
  // The layout is judged even when the parsed body is equal.
  assert.deepEqual(
    differences(layout(74), layout(0)).map((diff) => diff.kind),
    ["bodyLayout"],
  );
});

test("after a stand-in answer that disagrees with production, the rest of the recipe is TAINTED, never MATCH or DIVERGENCE", () => {
  const stand = {
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "private",
    [STANDIN_HEADER]: "1",
  };
  const production = [row(1), row(2, { status: 412 }), row(3), row(4), row(5)];
  const local = same(production);
  local[1] = { ...local[1], status: 400, headers: stand };
  local[2].status = 404;
  local.splice(3, 1);
  local.push(row(9, { path: "/storage/v1/b/<BUCKET>/o/storage-object/<RUN>/extra.bin" }));
  const results = compareRecipe({ production, local });
  assert.deepEqual(outcomes(results), [
    "MATCH",
    "LOCAL_UNIMPLEMENTED",
    "TAINTED",
    "TAINTED",
    "TAINTED",
    "TAINTED",
  ]);
  assert.deepEqual(results[2], {
    outcome: "TAINTED",
    n: 3,
    route: production[2].route,
    was: "DIVERGENCE",
  });
  assert.equal(results[3].was, "ONLY_PRODUCTION");
  assert.equal(results.at(-1).was, "ONLY_LOCAL");
  assert.equal(results.at(-1).n, null);
  assert.deepEqual(summarize(results).TAINTED, results.length - 2);
});

test("a stand-in answer that agrees with production taints nothing", () => {
  const stand = {
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "private",
    [STANDIN_HEADER]: "1",
  };
  const production = [row(1, { status: 412 }), row(2)];
  const local = same(production);
  local[0].headers = stand;
  assert.deepEqual(outcomes(compareRecipe({ production, local })), [
    "LOCAL_UNIMPLEMENTED",
    "MATCH",
  ]);
});

test("a later stand-in answer after the taint stays LOCAL_UNIMPLEMENTED", () => {
  const stand = {
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "private",
    [STANDIN_HEADER]: "1",
  };
  const production = [row(1, { status: 412 }), row(2), row(3)];
  const local = same(production);
  local[0] = { ...local[0], status: 400, headers: stand };
  local[2].headers = stand;
  assert.deepEqual(outcomes(compareRecipe({ production, local })), [
    "LOCAL_UNIMPLEMENTED",
    "TAINTED",
    "LOCAL_UNIMPLEMENTED",
  ]);
});

test("a stand-in answer whose body disagrees with production in an object's state taints the rest; a difference in a server's own format does not", () => {
  const stand = {
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "private",
    [STANDIN_HEADER]: "1",
  };
  const object = (extra) => ({
    type: "json",
    value: { name: "x", metageneration: "2", metadata: { a: "1" }, ...extra },
  });
  const run = (production, local) =>
    outcomes(
      compareRecipe({
        production: [row(1, { body: production }), row(2)],
        local: [row(1, { body: local, headers: stand }), row(2)],
      }),
    );
  const base = object({ generation: "<GEN:1>", etag: "<ETAG:1>" });
  // Formats of the server that answered: the object is in the state production had.
  assert.deepEqual(run(base, object({ generation: "1", etag: '"1-1"' })), [
    "LOCAL_UNIMPLEMENTED",
    "MATCH",
  ]);
  for (const state of [
    { metageneration: "3" },
    { metadata: { a: "2" } },
    { contentType: "text/plain" },
    { contentEncoding: "gzip" },
    { contentDisposition: "attachment" },
    { contentLanguage: "ja" },
    { cacheControl: "no-cache" },
    { size: "9" },
    { crc32c: "AAAAAA==" },
    { md5Hash: "AAAAAAAAAAAAAAAAAAAAAA==" },
  ])
    assert.deepEqual(run(base, object({ generation: "<GEN:1>", etag: "<ETAG:1>", ...state })), [
      "LOCAL_UNIMPLEMENTED",
      "TAINTED",
    ]);
});

test("the taint check looks at the state members whatever else differs before them, and only at those exact members", () => {
  const stand = {
    "content-type": "application/json; charset=UTF-8",
    "cache-control": "private",
    [STANDIN_HEADER]: "1",
  };
  // Nine members that sort before the state members and differ: more than the capped list of body differences holds.
  const many = (value, extra) => ({
    type: "json",
    value: {
      ...Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`a${i}`, `${value}${i}`])),
      metageneration: "2",
      size: "5",
      ...extra,
    },
  });
  const run = (production, local) =>
    outcomes(
      compareRecipe({
        production: [row(1, { body: production }), row(2)],
        local: [row(1, { body: local, headers: stand }), row(2)],
      }),
    );
  assert.deepEqual(run(many("p"), many("l", { metageneration: "3" })), [
    "LOCAL_UNIMPLEMENTED",
    "TAINTED",
  ]);
  assert.deepEqual(run(many("p"), many("l", { size: "6" })), ["LOCAL_UNIMPLEMENTED", "TAINTED"]);
  assert.deepEqual(run(many("p"), many("l")), ["LOCAL_UNIMPLEMENTED", "MATCH"]);
  // A member that only starts with a state member's name is not state.
  for (const name of ["sizeX", "metadataX", "metagenerationX", "xsize", "crc32cc"])
    assert.deepEqual(run(many("p", { [name]: "1" }), many("p", { [name]: "2" })), [
      "LOCAL_UNIMPLEMENTED",
      "MATCH",
    ]);
  // A body that is not JSON on one side is not compared member by member.
  assert.deepEqual(
    outcomes(
      compareRecipe({
        production: [row(1, { body: many("p") }), row(2)],
        local: [row(1, { body: { type: "text", value: "x" }, headers: stand }), row(2)],
      }),
    ),
    ["LOCAL_UNIMPLEMENTED", "MATCH"],
  );
});
