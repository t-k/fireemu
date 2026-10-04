// The native Listen programs of FS-LISTEN-SDK packet L1 (direct gRPC, the owner's access token,
// so Security Rules play no part): what production does for each Listen request shape the
// closure names. A program is data; `native-run.mjs` interprets it and only records. Documents
// live under one collection per kind, with the run id in each name so a leftover is found by its
// prefix.

export const CONDITION = {
  protocol: "FS-LISTEN-SDK/native-target-protocol",
  resume: "FS-LISTEN-SDK/raw-resume-token",
  filter: "FS-LISTEN-SDK/existence-filter-reconnect",
  subscription: "FS-LISTEN-SDK/default-subscription",
  atomic: "FS-TRANSACTION/commit-atomic-visibility",
};

/** Collections the programs write, for the cleanup sweep. */
export const COLLECTION = "lsn_native";
export const CHILD_COLLECTION = "lsn_native_child";

/** Each program owns its documents (the tag is in every name) and its own `g` group. */
const docsFor = (tag) => ({
  a: `${COLLECTION}/{run}-${tag}-a`,
  b: `${COLLECTION}/{run}-${tag}-b`,
  c: `${COLLECTION}/{run}-${tag}-c`,
  d: `${COLLECTION}/{run}-${tag}-d`,
});
const inGroup = (g) => ({ collection: COLLECTION, where: [["g", g]] });

/** Open a stream on `targets` and wait for every target's CURRENT. */
const openAndWait = (stream, targets, rowName) => [
  { do: "open", stream, targets },
  ...targets
    .filter((t) => !t.once)
    .map((t) => ({ do: "wait", stream, until: { current: t.id }, settleMs: 0 })),
  { do: "settle" },
  ...(rowName ? [{ do: "record", row: rowName, stream }] : []),
];

/** target-lifecycle: add, change, same-data write, remove and re-add on one stream. */
const targetLifecycle = {
  id: "native/target-lifecycle",
  conditions: [CONDITION.protocol, CONDITION.subscription],
  docs: docsFor("life"),
  steps: [
    { do: "seed", doc: "a", fields: { n: 1 } },
    ...openAndWait("s", [{ id: 1, doc: "a" }], "native/target-lifecycle/open"),
    { do: "write", doc: "a", fields: { n: 2 } },
    { do: "wait", stream: "s", until: { docChanges: 1 } },
    { do: "record", row: "native/target-lifecycle/update", stream: "s" },
    // The same data again: whether the backend raises a change or only moves its read time.
    { do: "write", doc: "a", fields: { n: 2 } },
    { do: "settle", ms: 4000 },
    { do: "record", row: "native/target-lifecycle/same-data", stream: "s" },
    { do: "remove", stream: "s", id: 1 },
    { do: "wait", stream: "s", until: { type: "REMOVE", id: 1 } },
    { do: "record", row: "native/target-lifecycle/remove", stream: "s" },
    { do: "add", stream: "s", target: { id: 2, doc: "a" } },
    { do: "wait", stream: "s", until: { current: 2 } },
    { do: "record", row: "native/target-lifecycle/readd", stream: "s" },
    { do: "delete", doc: "a" },
    { do: "wait", stream: "s", until: { frames: 1 } },
    { do: "record", row: "native/target-lifecycle/delete", stream: "s" },
    { do: "close", stream: "s" },
  ],
};

/** target-protocol: ids, once, read_time, a missing index, a collection group. */
const targetProtocol = {
  id: "native/target-protocol",
  conditions: [CONDITION.protocol],
  docs: {
    ...docsFor("proto"),
    c1: `${COLLECTION}/{run}-proto-g1/${CHILD_COLLECTION}/{run}-proto-c1`,
    c2: `${COLLECTION}/{run}-proto-g2/${CHILD_COLLECTION}/{run}-proto-c2`,
  },
  steps: [
    { do: "seed", doc: "a", fields: { n: 1, g: "proto" } },
    { do: "seed", doc: "b", fields: { n: 2, g: "proto" } },
    { do: "seed", doc: "c1", fields: { n: 1 } },
    { do: "seed", doc: "c2", fields: { n: 2 } },
    // A target id already active on the stream.
    ...openAndWait("dup", [{ id: 1, doc: "a" }]),
    { do: "add", stream: "dup", target: { id: 1, doc: "b" } },
    { do: "settle" },
    { do: "record", row: "native/target-protocol/duplicate-id", stream: "dup" },
    { do: "close", stream: "dup" },
    // Target id 0: the server assigns one; a later target with an explicit id is refused.
    { do: "open", stream: "zero", targets: [{ id: 0, doc: "a" }] },
    { do: "wait", stream: "zero", until: { frames: 3 }, settleMs: 2000, timeoutMs: 10_000 },
    { do: "record", row: "native/target-protocol/server-assigned-id", stream: "zero" },
    { do: "add", stream: "zero", target: { id: 7, doc: "b" } },
    { do: "settle" },
    { do: "record", row: "native/target-protocol/id-after-assigned", stream: "zero" },
    { do: "close", stream: "zero" },
    // A negative id.
    { do: "open", stream: "neg", targets: [{ id: -1, doc: "a" }] },
    { do: "settle", ms: 3000 },
    { do: "record", row: "native/target-protocol/negative-id", stream: "neg" },
    { do: "close", stream: "neg" },
    // once: the target is removed once it is current.
    { do: "open", stream: "once", targets: [{ id: 1, doc: "a", once: true }] },
    { do: "wait", stream: "once", until: { type: "REMOVE", id: 1 } },
    { do: "record", row: "native/target-protocol/once", stream: "once" },
    { do: "close", stream: "once" },
    // read_time: the time of one snapshot, then a write, then a target read at that time.
    ...openAndWait("t0", [{ id: 1, doc: "a" }]),
    { do: "save", stream: "t0", id: 1, time: "t0" },
    { do: "close", stream: "t0" },
    { do: "write", doc: "a", fields: { n: 5, g: "proto" } },
    { do: "open", stream: "past", targets: [{ id: 1, doc: "a", readTimeFrom: "t0" }] },
    { do: "wait", stream: "past", until: { current: 1 } },
    { do: "record", row: "native/target-protocol/read-time-before-write", stream: "past" },
    { do: "close", stream: "past" },
    ...openAndWait("t1", [{ id: 1, doc: "a" }]),
    { do: "save", stream: "t1", id: 1, time: "t1" },
    { do: "close", stream: "t1" },
    { do: "open", stream: "after", targets: [{ id: 1, doc: "a", readTimeFrom: "t1" }] },
    { do: "wait", stream: "after", until: { current: 1 } },
    { do: "record", row: "native/target-protocol/read-time-after-write", stream: "after" },
    { do: "close", stream: "after" },
    // A query that needs a composite index (an equality filter and an order on another field),
    // beside the same query shape that needs none.
    {
      do: "open",
      stream: "index",
      targets: [
        { id: 1, query: { collection: COLLECTION, where: [["g", "proto"]], orderBy: "n" } },
      ],
    },
    { do: "wait", stream: "index", until: { type: "REMOVE", id: 1 }, timeoutMs: 15_000 },
    { do: "record", row: "native/target-protocol/missing-index", stream: "index" },
    { do: "close", stream: "index" },
    ...openAndWait(
      "noindex",
      [{ id: 1, query: { collection: COLLECTION, where: [["g", "proto"]] } }],
      "native/target-protocol/equality-only-query",
    ),
    { do: "close", stream: "noindex" },
    // A collection-group target over two parents.
    ...openAndWait(
      "group",
      [{ id: 1, collectionGroup: CHILD_COLLECTION }],
      "native/target-protocol/collection-group",
    ),
    { do: "close", stream: "group" },
  ],
};

/** resume-token: current, older, unchanged, invalid and foreign tokens, and a fresh control. */
const resumeToken = {
  id: "native/resume-token",
  conditions: [CONDITION.resume],
  docs: docsFor("resume"),
  steps: [
    { do: "seed", doc: "a", fields: { n: 1, g: "resume" } },
    { do: "seed", doc: "b", fields: { n: 1, g: "resume" } },
    ...openAndWait("first", [{ id: 1, query: inGroup("resume") }], "native/resume-token/first"),
    { do: "save", stream: "first", id: 1, token: "old" },
    { do: "write", doc: "a", fields: { n: 2, g: "resume" } },
    { do: "wait", stream: "first", until: { docChanges: 1 } },
    { do: "save", stream: "first", id: 1, token: "mid" },
    { do: "close", stream: "first" },
    { do: "write", doc: "b", fields: { n: 2, g: "resume" } },
    // The token of the last snapshot: only what changed since arrives.
    {
      do: "open",
      stream: "current",
      targets: [{ id: 1, query: inGroup("resume"), resume: "mid" }],
    },
    { do: "wait", stream: "current", until: { current: 1 } },
    { do: "record", row: "native/resume-token/current", stream: "current" },
    { do: "save", stream: "current", id: 1, token: "latest" },
    { do: "close", stream: "current" },
    // An older token of the same target: every change since it.
    { do: "open", stream: "older", targets: [{ id: 1, query: inGroup("resume"), resume: "old" }] },
    { do: "wait", stream: "older", until: { current: 1 } },
    { do: "record", row: "native/resume-token/older", stream: "older" },
    { do: "close", stream: "older" },
    // Nothing changed since the latest token.
    {
      do: "open",
      stream: "unchanged",
      targets: [{ id: 1, query: inGroup("resume"), resume: "latest" }],
    },
    { do: "wait", stream: "unchanged", until: { current: 1 } },
    { do: "record", row: "native/resume-token/unchanged", stream: "unchanged" },
    { do: "close", stream: "unchanged" },
    // Bytes that are not a token.
    {
      do: "open",
      stream: "junk",
      targets: [{ id: 1, query: inGroup("resume"), rawToken: "not-a-token" }],
    },
    { do: "wait", stream: "junk", until: { current: 1 }, timeoutMs: 15_000 },
    { do: "record", row: "native/resume-token/invalid", stream: "junk" },
    { do: "close", stream: "junk" },
    // A token of one query on another query (unsupported, may fail).
    {
      do: "open",
      stream: "foreign",
      targets: [{ id: 1, query: inGroup("resume-other"), resume: "latest" }],
    },
    { do: "wait", stream: "foreign", until: { current: 1 }, timeoutMs: 15_000 },
    { do: "record", row: "native/resume-token/other-query", stream: "foreign" },
    { do: "close", stream: "foreign" },
    // The control: no token, the whole current state.
    ...openAndWait(
      "fresh",
      [{ id: 1, query: inGroup("resume") }],
      "native/resume-token/fresh-control",
    ),
    { do: "close", stream: "fresh" },
  ],
};

/** existence-filter: a document leaves the query while no stream is open, then the target resumes. */
const existenceFilter = {
  id: "native/existence-filter",
  conditions: [CONDITION.filter],
  docs: docsFor("filter"),
  steps: [
    { do: "seed", doc: "a", fields: { n: 1, g: "filter" } },
    { do: "seed", doc: "b", fields: { n: 1, g: "filter" } },
    { do: "seed", doc: "c", fields: { n: 1, g: "filter" } },
    ...openAndWait("first", [{ id: 1, query: inGroup("filter") }], "native/existence-filter/first"),
    { do: "save", stream: "first", id: 1, token: "t" },
    { do: "close", stream: "first" },
    // Control: nothing changed, the client still expects three.
    {
      do: "open",
      stream: "same",
      targets: [{ id: 1, query: inGroup("filter"), resume: "t", expectedCount: 3 }],
    },
    { do: "wait", stream: "same", until: { current: 1 } },
    { do: "record", row: "native/existence-filter/no-change", stream: "same" },
    { do: "close", stream: "same" },
    // A deleted document, and one that left the query by a field change.
    { do: "delete", doc: "b" },
    { do: "write", doc: "c", fields: { n: 2, g: "filter-other" } },
    {
      do: "open",
      stream: "counted",
      targets: [{ id: 1, query: inGroup("filter"), resume: "t", expectedCount: 3 }],
    },
    { do: "wait", stream: "counted", until: { current: 1 } },
    { do: "record", row: "native/existence-filter/with-expected-count", stream: "counted" },
    { do: "close", stream: "counted" },
    // The same resume without an expected count: no bloom filter is asked for.
    { do: "open", stream: "plain", targets: [{ id: 1, query: inGroup("filter"), resume: "t" }] },
    { do: "wait", stream: "plain", until: { current: 1 } },
    { do: "record", row: "native/existence-filter/without-expected-count", stream: "plain" },
    { do: "close", stream: "plain" },
  ],
};

/** commit-atomic-visibility: one transaction Commit of two documents beside separate Commits. */
const commitAtomicVisibility = {
  id: "native/commit-atomic-visibility",
  conditions: [CONDITION.atomic],
  docs: docsFor("atomic"),
  steps: [
    ...openAndWait(
      "s",
      [{ id: 1, query: inGroup("atomic") }],
      "native/commit-atomic-visibility/open",
    ),
    {
      do: "txn",
      writes: [
        { doc: "a", fields: { n: 1, g: "atomic" } },
        { doc: "b", fields: { n: 1, g: "atomic" } },
      ],
    },
    { do: "wait", stream: "s", until: { docChanges: 2 }, settleMs: 3000 },
    { do: "record", row: "native/commit-atomic-visibility/transaction", stream: "s", groups: true },
    {
      do: "commit",
      writes: [
        { doc: "c", fields: { n: 1, g: "atomic" } },
        { doc: "d", fields: { n: 1, g: "atomic" } },
      ],
    },
    { do: "wait", stream: "s", until: { docChanges: 2 }, settleMs: 3000 },
    {
      do: "record",
      row: "native/commit-atomic-visibility/single-commit",
      stream: "s",
      groups: true,
    },
    { do: "write", doc: "a", fields: { n: 2, g: "atomic" } },
    { do: "settle", ms: 1500 },
    { do: "write", doc: "b", fields: { n: 2, g: "atomic" } },
    { do: "wait", stream: "s", until: { docChanges: 2 }, settleMs: 3000 },
    {
      do: "record",
      row: "native/commit-atomic-visibility/separate-commits",
      stream: "s",
      groups: true,
    },
    { do: "close", stream: "s" },
  ],
};

export const NATIVE_PROGRAMS = [
  targetLifecycle,
  targetProtocol,
  resumeToken,
  existenceFilter,
  commitAtomicVisibility,
];

/** The collections whose run-prefixed documents the cleanup sweeps. */
export const SWEEP = (root) => [{ parent: root, collectionId: COLLECTION }];

/** Checks a program list is well formed; returns the problems (empty when it is). */
export function programProblems(programs) {
  const problems = [];
  const rowIds = new Set();
  for (const program of programs) {
    const where = (n, step) => `${program.id}#${n} (${step.do})`;
    if (!program.id.startsWith("native/"))
      problems.push(`${program.id}: id must start with native/`);
    const streams = new Set();
    const tokens = new Set();
    program.steps.forEach((step, n) => {
      const here = where(n, step);
      const usesDoc = (name) => {
        if (!Object.hasOwn(program.docs, name)) problems.push(`${here}: unknown doc ${name}`);
      };
      const usesStream = (name) => {
        if (!streams.has(name)) problems.push(`${here}: stream ${name} is not open`);
      };
      switch (step.do) {
        case "seed":
        case "write":
        case "delete":
          usesDoc(step.doc);
          break;
        case "commit":
        case "txn":
          for (const w of step.writes) usesDoc(w.doc ?? w.delete);
          break;
        case "open":
          if (streams.has(step.stream))
            problems.push(`${here}: stream ${step.stream} opened twice`);
          streams.add(step.stream);
          for (const t of step.targets) {
            if (t.doc !== undefined) usesDoc(t.doc);
            if (t.resume !== undefined && !tokens.has(t.resume))
              problems.push(`${here}: token ${t.resume} is not saved yet`);
            if (t.readTimeFrom !== undefined && !tokens.has(t.readTimeFrom))
              problems.push(`${here}: read time ${t.readTimeFrom} is not saved yet`);
          }
          break;
        case "add":
          usesStream(step.stream);
          if (step.target.doc !== undefined) usesDoc(step.target.doc);
          break;
        case "settle":
        case "sleep":
          break;
        case "remove":
        case "wait":
          usesStream(step.stream);
          break;
        case "save":
          usesStream(step.stream);
          tokens.add(step.token);
          tokens.add(step.time);
          break;
        case "record":
          usesStream(step.stream);
          if (!step.row.startsWith(`${program.id}/`))
            problems.push(`${here}: row ${step.row} must start with ${program.id}/`);
          if (rowIds.has(step.row)) problems.push(`${here}: row ${step.row} is recorded twice`);
          rowIds.add(step.row);
          break;
        case "close":
          usesStream(step.stream);
          streams.delete(step.stream);
          break;
        default:
          problems.push(`${here}: unknown step`);
      }
    });
    for (const name of streams) problems.push(`${program.id}: stream ${name} is never closed`);
    if (program.conditions.length === 0) problems.push(`${program.id}: names no condition`);
  }
  return problems;
}
