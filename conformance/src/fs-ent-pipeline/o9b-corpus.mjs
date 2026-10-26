// The FS-ENT-ORACLE O-9b corpus: `is_type` over every type name, for a missing field and for one
// field of each stored kind. O-9's `types-main` asked `is_absent(is_type(...))` beside the other
// aliases, and `is_absent` takes a field reference, so production refused every step as a whole
// and recorded nothing about `is_type`. Here each step is one select of twenty aliases, one per
// type name, of a single call shape, so one refusal costs one table and nothing else.
//
// It also holds the out-of-sample checks of the scan-order rule found in O-9 (the order of a read
// without a sort is ascending CRC-32 of the document id): three collections of fresh ids, written
// in an order that is neither name order nor CRC order, and a collection group with several
// documents under one parent. The predicted orders are computed here, stated in the packet and
// compared with the recording afterwards.
//
// Program ids: `fs-ent-pipeline/o9b/types-matrix`, `order-fresh` and `cg-parent`. Reads only.

import {
  arr,
  bool,
  bytes,
  dbl,
  geo,
  int,
  map,
  nul,
  ref,
  str,
  ts,
} from "../fs-query-index/values.mjs";
import { collectionGroup, fld, fn, read, readFrom, select } from "./builders.mjs";
import { defineArea } from "./o6-corpus.mjs";
import { TYPE_NAMES } from "./o9-corpus.mjs";

export const O9B_PREFIX = "fs-ent-pipeline/o9b/";

const MISSING = fld("zz");

/** One field of each stored kind a document can hold here (a vector is left out). */
export const KIND_FIELDS = [
  ["knull", nul()],
  ["kbool", bool(true)],
  ["kint", int(1)],
  ["kdouble", dbl(1.5)],
  ["kstring", str("a")],
  ["kbytes", bytes("AQ==")],
  ["kts", ts("2020-01-01T00:00:00Z")],
  ["kgeo", geo(1, 2)],
  ["karr", arr(int(1))],
  ["kmap", map({ a: int(1) })],
  ["kref", ref("tm/d1")],
];

/** A select of one alias per type name: `<name>: wrap(is_type(value, name))`. */
const table = (id, wrap, value) =>
  read(
    id,
    "tm",
    select(
      Object.fromEntries(TYPE_NAMES.map((name) => [name, wrap(fn("is_type", value, str(name)))])),
    ),
  );

const typesMatrix = {
  id: "matrix",
  seed: [["tm/d1", Object.fromEntries(KIND_FIELDS)]],
  steps: [
    table("missing", (call) => call, MISSING),
    table("missing-not", (call) => fn("not", call), MISSING),
    table("missing-is-error", (call) => fn("is_error", call), MISSING),
    ...KIND_FIELDS.map(([field]) => table(`present-${field.slice(1)}`, (call) => call, fld(field))),
  ],
};

// --- the scan-order rule, out of sample ---

/** CRC-32 (IEEE, as zlib computes it) of the UTF-8 bytes of a string. */
export function crc32(text) {
  let crc = 0xffffffff;
  for (const byte of Buffer.from(text)) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** The predicted read order of some ids: ascending CRC-32. */
export const predictedOrder = (ids) => ids.toSorted((a, b) => crc32(a) - crc32(b));

/** Fresh ids, in the order they are written (neither name order nor CRC order). */
export const FRESH_ID_SETS = {
  oc1: [
    "delta",
    "alpha",
    "echo",
    "charlie",
    "bravo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
  ],
  oc2: ["9", "10", "100", "1", "2", "25", "30", "8", "77", "600", "4", "11"],
  oc3: ["Zed", "zed", "a-b", "a_b", "P5", "p5", "b2", "B2", "m.n", "Q7", "q7", "x-y"],
};

const numbered = (coll, ids) => ids.map((id, i) => [`${coll}/${id}`, { n: int(i + 1) }]);

const orderFresh = {
  id: "fresh",
  seed: Object.entries(FRESH_ID_SETS).flatMap(([coll, ids]) => numbered(coll, ids)),
  steps: Object.keys(FRESH_ID_SETS).map((coll) => read(`${coll}-bare`, coll)),
};

/** Documents of a collection group `pitems`: top level, and under two parents. */
export const GROUP_IDS = {
  top: ["tu3", "tu1", "tu2"],
  a: ["hh1", "gg2", "ff3", "ee4", "dd5", "cc6"],
  b: ["v2", "v1", "v3"],
};
const cgParent = {
  id: "parent",
  seed: [
    ...numbered("pp/a/pitems", GROUP_IDS.a),
    ...numbered("pitems", GROUP_IDS.top),
    ...numbered("pp/b/pitems", GROUP_IDS.b),
  ],
  steps: [
    readFrom("group-bare", collectionGroup("pitems")),
    read("top-bare", "pitems"),
    read("a-bare", "pp/a/pitems"),
    read("b-bare", "pp/b/pitems"),
  ],
};

export const O9B_AREAS = {
  types: defineArea("types", [typesMatrix], O9B_PREFIX),
  order: defineArea("order", [orderFresh], O9B_PREFIX),
  cg: defineArea("cg", [cgParent], O9B_PREFIX),
};
export const O9B_PROGRAMS = Object.values(O9B_AREAS).flat();
