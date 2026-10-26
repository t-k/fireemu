// The FS-ENT-ORACLE O-8D corpus (part B, third envelope): the stages `union`, `unnest` and
// `sample`, in the form the SDK sends them, over a small collection (and a second one for the
// union). Program ids are `fs-ent-pipeline/o8d/<area>-<group>`.

import { arr, int, nul, str } from "../fs-query-index/values.mjs";
import {
  asc,
  collection,
  eq,
  fld,
  gt,
  limit,
  read,
  select,
  sort,
  stage,
  where,
} from "./builders.mjs";
import { sample, union, unnest } from "./o8-cases.mjs";
import { defineArea } from "./o6-corpus.mjs";

export const O8D_PREFIX = "fs-ent-pipeline/o8d/";

/** Collections some step reads and no program writes: an empty union input. */
export const O8D_EMPTY = new Set(["sw"]);

const s = str;
const i = int;

const SU = "su";
const SV = "sv";
const rows = [
  ["su/a", { n: i(1), tags: arr(s("x"), s("y")), g: s("p") }],
  ["su/b", { n: i(2), tags: arr(), g: s("q") }],
  ["su/c", { n: i(3), tags: nul(), g: s("p") }],
  ["su/d", { n: i(4), tags: s("str"), g: s("q") }],
  ["su/e", { n: i(5), g: s("p") }],
  ["sv/y", { n: i(11) }],
  ["sv/z", { n: i(10), tags: arr(s("z")), g: s("r") }],
];
const only = (num) => where(eq(fld("n"), i(num)));
const other = collection(SV);

const stages = {
  id: "main",
  seed: rows,
  steps: [
    // union
    read("union-other", SU, union(other)),
    read("union-itself", SU, union(collection(SU))),
    read("union-then-sort", SU, union(other), sort(asc(fld("n")))),
    read("union-then-limit", SU, union(other), limit(3)),
    read("union-inner-where", SU, union(other, where(gt(fld("n"), i(10))))),
    read("union-inner-select", SU, union(other, select({ n: fld("n") }))),
    read("union-empty-input", SU, union(collection("sw"))),
    read("union-of-union", SU, union(other, union(collection(SU)))),
    read("union-after-select", SU, select({ n: fld("n") }), union(other)),
    read("union-int-argument", SU, stage("union", i(1))),
    read("union-no-arguments", SU, stage("union")),
    read("union-two-arguments", SU, stage("union", { pipelineValue: { stages: [other] } }, i(1))),
    read("union-no-stages", SU, stage("union", { pipelineValue: { stages: [] } })),
    // unnest
    read("unnest-tags", SU, unnest(fld("tags"), "t")),
    read("unnest-empty-array", SU, only(2), unnest(fld("tags"), "t")),
    read("unnest-null", SU, only(3), unnest(fld("tags"), "t")),
    read("unnest-string", SU, only(4), unnest(fld("tags"), "t")),
    read("unnest-absent", SU, only(5), unnest(fld("tags"), "t")),
    read("unnest-index-field", SU, only(1), unnest(fld("tags"), "t", "idx")),
    read("unnest-alias-is-field", SU, only(1), unnest(fld("tags"), "tags")),
    read("unnest-alias-is-other-field", SU, only(1), unnest(fld("tags"), "g")),
    read("unnest-dotted-alias", SU, only(1), unnest(fld("tags"), "a.b")),
    read("unnest-reserved-alias", SU, only(1), unnest(fld("tags"), "__name__")),
    read("unnest-index-is-alias", SU, only(1), unnest(fld("tags"), "t", "t")),
    read(
      "unnest-literal-array",
      SU,
      only(1),
      unnest({ arrayValue: { values: [i(1), i(2)] } }, "v"),
    ),
    read("unnest-then-where", SU, unnest(fld("tags"), "t"), where(eq(fld("t"), s("x")))),
    read("unnest-twice", SU, only(1), unnest(fld("tags"), "t"), unnest(fld("tags"), "u")),
    read("unnest-one-argument", SU, only(1), stage("unnest", fld("tags"))),
    read("unnest-three-arguments", SU, only(1), stage("unnest", fld("tags"), fld("t"), fld("u"))),
    // sample
    read("sample-documents-2", SU, sample(2, "documents")),
    read("sample-documents-0", SU, sample(0, "documents")),
    read("sample-documents-10", SU, sample(10, "documents")),
    read("sample-documents-negative", SU, sample(-1, "documents")),
    read("sample-documents-fraction", SU, sample(1.5, "documents")),
    read("sample-percent-0", SU, sample(0, "percent")),
    read("sample-percent-50", SU, sample(0.5, "percent")),
    read("sample-percent-100", SU, sample(1, "percent")),
    read("sample-percent-150", SU, sample(1.5, "percent")),
    read("sample-percent-negative", SU, sample(-0.5, "percent")),
    read("sample-mode-invalid", SU, sample(2, "rows")),
    read("sample-mode-int", SU, stage("sample", i(2), i(1))),
    read("sample-rate-string", SU, stage("sample", s("2"), s("documents"))),
    read("sample-one-argument", SU, stage("sample", i(2))),
    read("sample-three-arguments", SU, stage("sample", i(2), s("documents"), s("x"))),
    read("sample-after-where", SU, where(gt(fld("n"), i(1))), sample(2, "documents")),
    read("sample-then-limit", SU, sample(4, "documents"), limit(1)),
  ],
};

export const O8D_AREAS = {
  stages: defineArea("stages", [stages], O8D_PREFIX),
};

export const O8D_PROGRAMS = Object.values(O8D_AREAS).flat();
