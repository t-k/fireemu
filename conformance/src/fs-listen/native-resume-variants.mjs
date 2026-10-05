// The resume-variant programs of packet L1b: what decides production's answer to a Listen resume.
// L1 recorded two answer kinds for the same request shape (a replay with a boundary after each
// commit, and an exact diff with a count-only existence filter); these programs vary one thing at
// a time (the kind of token, the number of commits since it, the expected count, the kind of
// change, the age of the token, a repeated resume) so a later reading can say which of them
// decides it. They only record; nothing here decides. Programs and rows are data, run by
// `native-run.mjs` in the same way as the L1 programs.

import { CONDITION, docsFor, inGroup, openAndWait } from "./native-programs.mjs";

/** The ceiling of harness requests a production recording of these programs is held to. */
export const RESUME_VARIANT_REQUEST_CEILING = 90;

/** Three documents are in the query and one is outside it, so the query holds 3 at the start. */
const seedWrites = (tag) => [
  { doc: "a", fields: { n: 1, g: tag } },
  { doc: "b", fields: { n: 1, g: tag } },
  { doc: "c", fields: { n: 1, g: tag } },
  { doc: "d", fields: { n: 1, g: `${tag}-out` } },
];

/** Opens a resume of `token`, waits for CURRENT, records `row`, and closes. */
const resumeRow = (stream, row, token, target = {}) => [
  {
    do: "open",
    stream,
    targets: [{ id: 1, query: inGroup(row.tag), resume: token, ...target }],
  },
  { do: "wait", stream, until: { current: 1 } },
  { do: "record", row: row.name, stream },
  { do: "close", stream },
];

/**
 * One grid: a token of `tokenKind`, resumed with 0, 1, 1 (again), 1, 2, 2, 2 and 3 commits since,
 * with no expected count, a right one (the 3 documents the client holds) and a wrong one (4).
 * `afterChange` takes the token after a first change to the documents, as the L1 `current` row did.
 */
function grid(name, tokenKind, { afterChange = false } = {}) {
  const id = `native/resume-grid-${name}`;
  const row = (suffix) => ({ tag: name, name: `${id}/${suffix}` });
  return {
    id,
    conditions: [CONDITION.resume],
    docs: docsFor(name),
    steps: [
      { do: "commit", writes: seedWrites(name) },
      ...openAndWait("first", [{ id: 1, query: inGroup(name) }], `${id}/first`),
      ...(afterChange
        ? [
            { do: "write", doc: "a", fields: { n: 2, g: name } },
            { do: "wait", stream: "first", until: { docChanges: 1 } },
          ]
        : []),
      { do: "save", stream: "first", id: 1, token: "T", kind: tokenKind },
      { do: "close", stream: "first" },
      ...resumeRow("k0", row("k0"), "T"),
      { do: "write", doc: "a", fields: { n: 3, g: name } },
      ...resumeRow("k1", row("k1"), "T"),
      ...resumeRow("k1r", row("k1-repeat"), "T"),
      ...resumeRow("k1e", row("k1-expected"), "T", { expectedCount: 3 }),
      { do: "write", doc: "b", fields: { n: 3, g: name } },
      ...resumeRow("k2", row("k2"), "T"),
      ...resumeRow("k2e", row("k2-expected"), "T", { expectedCount: 3 }),
      ...resumeRow("k2w", row("k2-wrong"), "T", { expectedCount: 4 }),
      { do: "delete", doc: "c" },
      ...resumeRow("k3", row("k3"), "T"),
    ],
  };
}

/** One change of each kind, each resumed from the token of the stream that answered the one before. */
const kinds = {
  id: "native/resume-kinds",
  conditions: [CONDITION.resume],
  docs: docsFor("kinds"),
  steps: [
    { do: "commit", writes: seedWrites("kinds") },
    ...openAndWait("first", [{ id: 1, query: inGroup("kinds") }], "native/resume-kinds/first"),
    { do: "save", stream: "first", id: 1, token: "T0", kind: "global" },
    { do: "close", stream: "first" },
    { do: "write", doc: "a", fields: { n: 2, g: "kinds" } },
    {
      do: "open",
      stream: "modify",
      targets: [{ id: 1, query: inGroup("kinds"), resume: "T0" }],
    },
    { do: "wait", stream: "modify", until: { current: 1 } },
    { do: "record", row: "native/resume-kinds/modify", stream: "modify" },
    { do: "save", stream: "modify", id: 1, token: "T1", kind: "global" },
    { do: "close", stream: "modify" },
    { do: "write", doc: "d", fields: { n: 2, g: "kinds" } },
    { do: "open", stream: "enter", targets: [{ id: 1, query: inGroup("kinds"), resume: "T1" }] },
    { do: "wait", stream: "enter", until: { current: 1 } },
    { do: "record", row: "native/resume-kinds/enter", stream: "enter" },
    { do: "save", stream: "enter", id: 1, token: "T2", kind: "global" },
    { do: "close", stream: "enter" },
    { do: "write", doc: "c", fields: { n: 2, g: "kinds-out" } },
    { do: "open", stream: "leave", targets: [{ id: 1, query: inGroup("kinds"), resume: "T2" }] },
    { do: "wait", stream: "leave", until: { current: 1 } },
    { do: "record", row: "native/resume-kinds/leave", stream: "leave" },
    { do: "save", stream: "leave", id: 1, token: "T3", kind: "global" },
    { do: "close", stream: "leave" },
    { do: "delete", doc: "b" },
    { do: "open", stream: "delete", targets: [{ id: 1, query: inGroup("kinds"), resume: "T3" }] },
    { do: "wait", stream: "delete", until: { current: 1 } },
    { do: "record", row: "native/resume-kinds/delete", stream: "delete" },
    { do: "close", stream: "delete" },
  ],
};

/** Three tokens taken together, resumed at 30 s (1 change), 5 min (1 change) and 5 min (2 changes). */
const age = {
  id: "native/resume-age",
  conditions: [CONDITION.resume],
  docs: docsFor("age"),
  steps: [
    { do: "commit", writes: seedWrites("age") },
    ...openAndWait("f1", [{ id: 1, query: inGroup("age") }], "native/resume-age/first"),
    ...openAndWait("f2", [{ id: 1, query: inGroup("age") }]),
    ...openAndWait("f3", [{ id: 1, query: inGroup("age") }]),
    { do: "save", stream: "f1", id: 1, token: "Ta", kind: "global" },
    { do: "save", stream: "f2", id: 1, token: "Tb", kind: "global" },
    { do: "save", stream: "f3", id: 1, token: "Tc", kind: "global" },
    { do: "close", stream: "f1" },
    { do: "close", stream: "f2" },
    { do: "close", stream: "f3" },
    { do: "write", doc: "a", fields: { n: 2, g: "age" } },
    { do: "sleep", ms: 30_000 },
    ...resumeRow("ra", { tag: "age", name: "native/resume-age/age-30s-k1" }, "Ta"),
    { do: "sleep", ms: 270_000 },
    ...resumeRow("rb", { tag: "age", name: "native/resume-age/age-5m-k1" }, "Tb"),
    { do: "write", doc: "b", fields: { n: 2, g: "age" } },
    ...resumeRow("rc", { tag: "age", name: "native/resume-age/age-5m-k2" }, "Tc"),
  ],
};

export const RESUME_VARIANT_PROGRAMS = [
  grid("g0", "global"),
  grid("tc", "current"),
  grid("gc", "global", { afterChange: true }),
  kinds,
  age,
];
