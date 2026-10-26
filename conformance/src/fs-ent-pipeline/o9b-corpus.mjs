// The FS-ENT-ORACLE O-9b corpus: `is_type` over every type name, for a missing field and for one
// field of each stored kind. O-9's `types-main` asked `is_absent(is_type(...))` beside the other
// aliases, and `is_absent` takes a field reference, so production refused every step as a whole
// and recorded nothing about `is_type`. Here each step is one select of twenty aliases, one per
// type name, of a single call shape, so one refusal costs one table and nothing else.
// Program id: `fs-ent-pipeline/o9b/types-matrix`. Reads only.

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
import { fld, fn, read, select } from "./builders.mjs";
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

export const O9B_AREAS = { types: defineArea("types", [typesMatrix], O9B_PREFIX) };
export const O9B_PROGRAMS = Object.values(O9B_AREAS).flat();
