// The FS-ENT-ORACLE O-8A corpus (packet o8a, part A): the production observations the pipeline
// fixes still need. Program ids are `fs-ent-pipeline/o8a/<area>-<group>`.
//
//   framing     how a response is cut: bare reads of 5 to 5000 small documents and of documents
//               of 100 KB to 950 KB, over REST and gRPC (summary-only programs: their answers are
//               summarised, not kept; see framing-summary.mjs)
//   names       `select` of `__name__` in the forms beside the one already recorded
//   dupquote    the duplicate quoted projection path that answered a server error, repeated
//   precedence  malformed bodies against the Enterprise database, and malformed plus invalid
//   nesting     function chains and literal containers at the depths the official emulator limits
//   base64      line breaks, mixed alphabets and the proto field name in a bytesValue, outside
//               executePipeline (commit, a read back, and a runQuery cursor)
//
// Not here: the Standard database and the non-owner caller of the precedence question (the
// recorder addresses one named database as the owner), and createDocument (not a reviewed method
// of the recorder).

import { bytes, int, ref, str } from "../fs-query-index/values.mjs";
import {
  eq,
  fld,
  fn,
  limit,
  read,
  readGrpc,
  seedBatch,
  select,
  stage,
  where,
} from "./builders.mjs";
import { defineArea } from "./o6-corpus.mjs";

export const O8A_PREFIX = "fs-ent-pipeline/o8a/";

const define = (area, groups) => defineArea(area, groups, O8A_PREFIX);

// --- generators ---

/** A function chain of `depth` `array` calls over the field `i`. */
export function functionChain(depth) {
  let value = fld("i");
  for (let level = 0; level < depth; level += 1) value = fn("array", value);
  return value;
}

/** An array or map literal nested `depth` containers deep around the integer 1. */
export function literalChain(kind, depth) {
  let value = int(1);
  for (let level = 0; level < depth; level += 1) {
    value =
      kind === "array"
        ? { arrayValue: { values: [value] } }
        : { mapValue: { fields: { k: value } } };
  }
  return value;
}

/** The fields of a document with a `pad` string of exactly `length` characters. */
export function documentOfSize(length) {
  const unit = "abcdefghij";
  return {
    n: int(length),
    pad: str(unit.repeat(Math.ceil(length / unit.length)).slice(0, length)),
  };
}

const BASE64_LINE = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0";

/**
 * The base64 texts of N6, with the JSON field that carries them. The MIME form breaks after 76
 * characters, as a mail encoder does.
 */
export function base64Variants() {
  return [
    { label: "control", field: "bytesValue", value: "QUJD" },
    { label: "lf", field: "bytesValue", value: "QUJD\nQUJD" },
    { label: "cr", field: "bytesValue", value: "QUJD\rQUJD" },
    { label: "crlf", field: "bytesValue", value: "QUJD\r\nQUJD" },
    { label: "mime-76", field: "bytesValue", value: `${BASE64_LINE}\r\nQUJD` },
    { label: "mime-76-lf", field: "bytesValue", value: `${BASE64_LINE}\nQUJD` },
    { label: "mixed-plus-underscore", field: "bytesValue", value: "+_AA" },
    { label: "mixed-minus-slash", field: "bytesValue", value: "-/AA" },
    { label: "urlsafe", field: "bytesValue", value: "-_AA" },
    { label: "unpadded", field: "bytesValue", value: "QQ" },
    { label: "proto-name", field: "bytes_value", value: "QUJD" },
  ];
}

// --- framing ---

const smallDocs = (name, count) =>
  Array.from({ length: count }, (_, i) => [
    `${name}/d${String(i + 1).padStart(4, "0")}`,
    { n: int(i + 1), g: str("x") },
  ]);

/** Programs whose answers are summarised into `fs-ent-pipeline-framing.json`, not kept. */
export const SUMMARY_ONLY = new Set([`${O8A_PREFIX}framing-small`, `${O8A_PREFIX}framing-large`]);

const both = (name, from, ...stages) => [
  read(`${name}-rest`, from, ...stages),
  readGrpc(`${name}-grpc`, from, ...stages),
];

const framingSmall = {
  id: "small",
  seed: [
    ...smallDocs("f5", 5),
    ...smallDocs("f50", 50),
    ...smallDocs("f500", 500),
    ...smallDocs("f5000", 5000),
  ],
  steps: [
    ...both("f5", "f5"),
    ...both("f50", "f50"),
    ...both("f500", "f500"),
    ...both("f5000", "f5000"),
    ...both("f5000-select", "f5000", select({ n: fld("n") })),
    ...both("f5000-limit", "f5000", limit(1500)),
  ],
};

/** Documents that are too big for one commit together are written in commits of a few. */
const largeWrites = (name, count, length, perCommit) =>
  Array.from({ length: Math.ceil(count / perCommit) }, (_, part) =>
    seedBatch(
      `seed-${name}-${part + 1}`,
      Array.from({ length: Math.min(perCommit, count - part * perCommit) }, (_, i) => [
        `${name}/d${String(part * perCommit + i + 1).padStart(2, "0")}`,
        documentOfSize(length),
      ]),
    ),
  );

const framingLarge = {
  id: "large",
  seed: [],
  steps: [
    ...largeWrites("l12", 12, 400_000, 4),
    ...largeWrites("l3", 3, 950_000, 1),
    ...largeWrites("m30", 30, 100_000, 10),
    ...both("l12", "l12"),
    ...both("l3", "l3"),
    ...both("m30", "m30"),
  ],
};

// --- select of __name__ ---

const name = fld("__name__");
const names = {
  id: "main",
  seed: [["ns/d1", { i: int(1), n: int(2) }]],
  steps: [
    ...both("alone", "ns", select({ __name__: name })),
    ...both("beside-alias", "ns", select({ __name__: name, a: fld("i") })),
    read("quoted-alias", "ns", select({ "`__name__`": name })),
    read("quoted-value", "ns", select({ __name__: fld("`__name__`") })),
    ...both("second-alias", "ns", select({ __name__: name, nm: name })),
    ...both("then-limit", "ns", select({ __name__: name }), limit(1)),
    read("then-where", "ns", select({ __name__: name }), where(eq(name, ref("ns/d1")))),
    read("from-field", "ns", select({ __name__: fld("i") })),
  ],
};

// --- the duplicate quoted path ---

const dupquote = {
  id: "main",
  seed: [["dq/d1", { i: int(1), n: int(2) }]],
  steps: [
    read("same-1", "dq", select({ a: fld("i"), "`a`": fld("i") })),
    read("same-2", "dq", select({ a: fld("i"), "`a`": fld("i") })),
    read("same-3", "dq", select({ a: fld("i"), "`a`": fld("i") })),
    read("different-values", "dq", select({ a: fld("i"), "`a`": fld("n") })),
    read("swapped-order", "dq", select({ "`a`": fld("i"), a: fld("i") })),
    read("dotted", "dq", select({ "a.b": fld("i"), "`a.b`": fld("n") })),
    read("quoted-alone", "dq", select({ "`a`": fld("i") })),
    read("plain-pair", "dq", select({ a: fld("i"), b: fld("n") })),
  ],
};

// --- malformed bodies ---

const valid = (...stages) => ({ structuredPipeline: { pipeline: { stages } } });
const collectionStage = stage("collection", { referenceValue: "/pr" });
const raw = (id, text) => ({ id, rpc: "executePipeline", rawBody: text });
const rawJson = (id, body) => raw(id, JSON.stringify(body));

const precedence = {
  id: "main",
  seed: [["pr/d1", { i: int(1) }]],
  steps: [
    raw("empty-body", ""),
    raw("not-json", "not json"),
    raw("truncated", JSON.stringify(valid(collectionStage)).slice(0, 40)),
    raw("empty-object", "{}"),
    raw("null-pipeline", '{"structuredPipeline": null}'),
    rawJson("top-level-unknown", { ...valid(collectionStage), bogus: 1 }),
    rawJson("stage-unknown-member", valid({ ...collectionStage, bogus: 1 })),
    rawJson(
      "bad-integer",
      valid(collectionStage, stage("select", map2({ v: { integerValue: "abc" } }))),
    ),
    rawJson(
      "string-number",
      valid(collectionStage, stage("select", map2({ v: { stringValue: 5 } }))),
    ),
    rawJson(
      "unknown-value-type",
      valid(collectionStage, stage("select", map2({ v: { bogusValue: 1 } }))),
    ),
    rawJson(
      "malformed-and-unknown-stage",
      valid(collectionStage, stage("nope_stage", map2({ v: { integerValue: "abc" } }))),
    ),
    rawJson(
      "malformed-and-unknown-function",
      valid(
        collectionStage,
        stage(
          "select",
          map2({ v: { functionValue: { name: "nope_fn", args: [{ integerValue: "abc" }] } } }),
        ),
      ),
    ),
    // Controls: well-formed bodies with a refused pipeline and with an answer.
    rawJson("unknown-stage", valid(collectionStage, stage("nope_stage"))),
    rawJson("well-formed", valid(collectionStage)),
  ],
};

function map2(fields) {
  return { mapValue: { fields } };
}

// --- nesting ---

const nest = (id, value, grpc = false) => (grpc ? readGrpc : read)(id, "ne", select({ v: value }));
const nesting = {
  id: "main",
  seed: [["ne/d1", { i: int(1) }]],
  steps: [
    ...[20, 32, 33, 47, 48, 100].flatMap((depth) => [
      nest(`chain-${depth}`, functionChain(depth)),
      nest(`chain-${depth}-grpc`, functionChain(depth), true),
    ]),
    ...[20, 21].flatMap((depth) => [
      nest(`array-${depth}`, literalChain("array", depth)),
      nest(`map-${depth}`, literalChain("map", depth)),
    ]),
    nest("array-21-grpc", literalChain("array", 21), true),
    nest("map-21-grpc", literalChain("map", 21), true),
  ],
};

// --- base64 ---

const commitRaw = (id, text) => ({ id, rpc: "commit", rawBody: text });
const variants = base64Variants();
const cursor = (label, value) => ({
  id: `cursor-${label}`,
  rpc: "runQuery",
  rawBody: JSON.stringify({
    structuredQuery: {
      from: [{ collectionId: "bq" }],
      orderBy: [{ field: { fieldPath: "b" }, direction: "ASCENDING" }],
      startAt: { values: [{ bytesValue: value }], before: true },
    },
  }),
});
const base64 = {
  id: "main",
  seed: ["AQ==", "Ag==", "Aw=="].map((b, i) => [`bq/q${i + 1}`, { b: bytes(b) }]),
  steps: [
    ...variants.flatMap(({ label, field, value }) => [
      commitRaw(
        `write-${label}`,
        JSON.stringify({
          writes: [{ update: { name: `{docs}/bw/${label}`, fields: { b: { [field]: value } } } }],
        }),
      ),
      { id: `get-${label}`, rpc: "get", parent: `bw/${label}` },
    ]),
    cursor("control", "Ag=="),
    cursor("lf", "Ag==\n"),
    cursor("crlf", "A\r\ng=="),
  ],
};

export const O8A_AREAS = {
  framing: define("framing", [framingSmall, framingLarge]),
  names: define("names", [names]),
  dupquote: define("dupquote", [dupquote]),
  precedence: define("precedence", [precedence]),
  nesting: define("nesting", [nesting]),
  base64: define("base64", [base64]),
};

export const O8A_PROGRAMS = Object.values(O8A_AREAS).flat();
