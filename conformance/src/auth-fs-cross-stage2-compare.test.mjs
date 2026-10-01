import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildFixture,
  classifyStage2,
  clientSummary,
  comparable,
  nativeSummary,
  sdkSummary,
} from "./auth-fs-cross/stage2-compare.mjs";

const change = (n, targetIds) => ({
  kind: "documentChange",
  doc: "afc2-owned/a",
  n,
  targetIds,
  removedTargetIds: [],
});
const snapshot = (n, { fromCache = false, pending = false } = {}) => ({
  kind: "snapshot",
  fromCache,
  pending,
  docs: [{ path: "afc2-owned/a", exists: n !== null, n }],
});

test("a native stream is compared by what each target delivered, not by how frames were cut", () => {
  const oneFrame = {
    events: [
      change("1", [1, 2]),
      { kind: "targetChange", type: "NO_CHANGE", targetIds: [1], cause: null },
    ],
  };
  const twoFrames = { events: [change("1", [1]), change("1", [2]), change("1", [2])] };
  assert.deepEqual(nativeSummary(oneFrame), nativeSummary(twoFrames));
  assert.deepEqual(nativeSummary(oneFrame), {
    targets: { 1: ["n:1"], 2: ["n:1"] },
    removed: {},
    end: null,
    endedBefore: false,
  });
  const removed = nativeSummary({
    events: [
      { kind: "targetChange", type: "CURRENT", targetIds: [1], cause: null },
      {
        kind: "targetChange",
        type: "REMOVE",
        targetIds: [1, 2],
        cause: { code: 16, message: "x" },
      },
      { kind: "documentRemove", doc: "afc2-owned/a", removedTargetIds: [2] },
    ],
    end: { reason: "error", code: 16 },
    endedBefore: false,
  });
  assert.deepEqual(removed, {
    targets: { 2: ["documentRemove"] },
    removed: { 1: 16, 2: 16 },
    end: 16,
    endedBefore: false,
  });
  assert.equal(nativeSummary({ events: [], endedBefore: true }).endedBefore, true);
});

test("an SDK listener is compared by its server states and its error", () => {
  assert.deepEqual(
    sdkSummary({
      events: [
        snapshot("1", { fromCache: true }),
        snapshot("1"),
        snapshot("1", { pending: true }),
        snapshot("1"),
        snapshot(null),
        { kind: "error", code: "permission-denied" },
      ],
    }),
    ["docs:1", "docs:absent", "error:permission-denied"],
  );
  assert.deepEqual(sdkSummary({ events: [] }), []);
  // A cached or pending state is not what the server said.
  assert.deepEqual(
    sdkSummary({
      events: [snapshot("0", { fromCache: true }), snapshot("5", { pending: true }), snapshot("1")],
    }),
    ["docs:1"],
  );
});

test("a client is compared by whose token each call carried and how its commands ended", () => {
  const events = [
    {
      kind: "wire",
      service: "firestore",
      method: "/google.firestore.v1.Firestore/Write",
      principal: "<uid:alice>",
    },
    {
      kind: "wire",
      service: "firestore",
      method: "/google.firestore.v1.Firestore/Write",
      principal: "<uid:alice>",
    },
    { kind: "wire", service: "identitytoolkit", method: "/v1/accounts:lookup", principal: null },
    { kind: "auth", uid: "<uid:alice>" },
    { kind: "auth", uid: "<uid:alice>" },
    { kind: "auth", uid: null },
    { kind: "result", op: "transaction", ok: false, code: "permission-denied", attempts: 1 },
    { kind: "result", op: "signOut", ok: true, code: null },
    { kind: "write-settled", writeId: "w", ok: true, code: null },
  ];
  assert.deepEqual(clientSummary(events), {
    wire: [
      "firestore /google.firestore.v1.Firestore/Write <uid:alice>",
      "identitytoolkit /v1/accounts:lookup null",
    ],
    results: ["transaction:permission-denied:1", "signOut:ok"],
    settled: ["w:ok"],
    auth: ["<uid:alice>", "null"],
  });
});

test("each kind of row reduces to its comparable form", () => {
  const probe = comparable({
    id: "p",
    listeners: { "grpc-a": { events: [change("2", [1])] }, "c/doc": { events: [snapshot("2")] } },
    clients: { c: [{ kind: "auth", uid: null }] },
  });
  assert.deepEqual(probe, {
    listeners: {
      "grpc-a": { targets: { 1: ["n:2"] }, removed: {}, end: null, endedBefore: false },
      "c/doc": ["docs:2"],
    },
    clients: { c: { wire: [], results: [], settled: [], auth: ["null"] } },
  });
  const awaited = comparable({
    result: { kind: "result", op: "transaction", ok: true, code: null, attempts: 1 },
    clients: {},
  });
  assert.deepEqual(awaited.result, ["transaction:ok:1"]);
  assert.deepEqual(comparable({ docs: { "afc2-tx/a": { exists: false, fields: null } } }), {
    docs: { "afc2-tx/a": { exists: false, fields: null } },
  });
  assert.deepEqual(comparable({ streams: { "grpc-a": { reason: "open" } }, listeners: {} }), {
    streams: { "grpc-a": { reason: "open" } },
    listeners: {},
  });
  const expiry = comparable({
    probes: [
      { doc: "afc2-owned/a-grpc", onTime: true, listeners: { "grpc-a": { events: [] } } },
      {
        doc: "afc2-owned/a-sdk",
        onTime: false,
        listeners: { "c/doc": { events: [snapshot("4")] } },
      },
    ],
  });
  assert.deepEqual(expiry.late, ["afc2-owned/a-sdk"]);
  assert.deepEqual(expiry.probes["afc2-owned/a-sdk"].listeners["c/doc"], ["docs:4"]);
});

test("a row matches only when both recordings agree with fireemu and every timer was on time", () => {
  const a = { listeners: { x: ["docs:1"] } };
  const b = { listeners: { x: ["error:permission-denied"] } };
  assert.equal(classifyStage2({ stale: true, production: a, fireemu: a }), "STALE_FIXTURE");
  assert.equal(classifyStage2({ production: undefined, fireemu: a }), "MISSING_FIXTURE");
  assert.equal(classifyStage2({ production: a, fireemu: undefined }), "MISSING");
  assert.equal(classifyStage2({ production: a, fireemu: a }), "MATCH");
  assert.equal(classifyStage2({ production: a, fireemu: b }), "MISMATCH");
  assert.equal(classifyStage2({ production: a, alternative: b, fireemu: a }), "INDETERMINATE");
  assert.equal(classifyStage2({ production: a, alternative: null, fireemu: a }), "INDETERMINATE");
  assert.equal(
    classifyStage2({ production: { ...a, late: ["d"] }, fireemu: { ...a, late: ["d"] } }),
    "INDETERMINATE",
  );
  assert.equal(
    classifyStage2({ production: { ...a, late: [] }, fireemu: { ...a, late: ["d"] } }),
    "INDETERMINATE",
  );
  assert.equal(
    classifyStage2({ production: { ...a, late: [] }, fireemu: { ...a, late: [] } }),
    "MATCH",
  );
});

test("a resume row is compared by its frames and how each resume ended", () => {
  const boundary = { kind: "boundary", resumeToken: true };
  const row = (frames) => ({
    id: "resume/open",
    conditions: ["C"],
    first: [boundary],
    resumes: {
      same: { frames, end: null },
      switch: { frames, end: { reason: "error", code: 16 } },
    },
  });
  assert.deepEqual(comparable(row([boundary])), {
    first: [boundary],
    resumes: {
      same: { frames: [boundary], end: null },
      switch: { frames: [boundary], end: { reason: "error", code: 16 } },
    },
  });
  assert.notDeepEqual(comparable(row([boundary])), comparable(row([])));
});

test("a fixture keeps each recording's stream ends, without their status texts", () => {
  const metas = [
    { recording: 1, programDigest: "p", harness: "h", startedAt: "t1", sha: "s" },
    { recording: 2, programDigest: "p", harness: "h", startedAt: "t2", sha: "s" },
  ];
  const end = (vsExpiryMs) => ({
    reason: "error",
    code: 13,
    details: "a text that may name the project",
    openedAtMs: 500,
    sinceOpenedMs: 3_540_000,
    vsExpiryMs,
  });
  const fixture = buildFixture({
    recordings: [
      { rows: {}, streamEnds: { "grpc-a": end(-40_000), "grpc-b": null } },
      { rows: {} },
    ],
    metas,
    programDigest: "p",
    harnessDigest: "h",
  });
  assert.deepEqual(
    fixture.recordings.map((r) => r.streamEnds),
    [
      {
        "grpc-a": {
          reason: "error",
          code: 13,
          openedAtMs: 500,
          sinceOpenedMs: 3_540_000,
          vsExpiryMs: -40_000,
        },
        "grpc-b": null,
      },
      {},
    ],
  );
  assert.equal(JSON.stringify(fixture).includes("may name the project"), false);
});

test("a fixture keeps recording 2 only where it differs, and refuses recordings of another program", () => {
  const row = (n) => ({
    conditions: ["C"],
    listeners: { "c/doc": { events: [snapshot(n)] } },
    clients: {},
  });
  const metas = [
    { recording: 1, programDigest: "p", harness: "h", startedAt: "t1", sha: "s" },
    { recording: 2, programDigest: "p", harness: "h", startedAt: "t2", sha: "s" },
  ];
  const fixture = buildFixture({
    recordings: [
      { rows: { same: row("1"), differs: row("1"), only: row("1") } },
      { rows: { same: row("1"), differs: row("2") } },
    ],
    metas,
    programDigest: "p",
    harnessDigest: "h",
  });
  assert.deepEqual(Object.keys(fixture.rows), ["differs", "only", "same"]);
  assert.equal("second" in fixture.rows.same, false);
  assert.deepEqual(fixture.rows.differs.second, {
    listeners: { "c/doc": ["docs:2"] },
    clients: {},
  });
  assert.equal(fixture.rows.only.second, null);
  assert.deepEqual(fixture.rows.same.conditions, ["C"]);
  assert.deepEqual(
    fixture.recordings.map((r) => r.recording),
    [1, 2],
  );
  assert.throws(
    () =>
      buildFixture({
        recordings: [{ rows: {} }, { rows: {} }],
        metas: [metas[0], { ...metas[1], harness: "other" }],
        programDigest: "p",
        harnessDigest: "h",
      }),
    /recording 2 is of another program or harness/,
  );
  assert.throws(
    () =>
      buildFixture({ recordings: [{ rows: {} }], metas, programDigest: "p", harnessDigest: "h" }),
    /two recordings/,
  );
});

test("a row whose client hit its request cap is kept apart from every comparison", () => {
  const form = comparable({ listeners: { "c/doc": { events: [] } }, clients: {}, capped: ["c"] });
  assert.deepEqual(form.capped, ["c"]);
  const plain = comparable({ listeners: { "c/doc": { events: [] } }, clients: {} });
  assert.equal("capped" in plain, false);
  assert.equal(classifyStage2({ production: plain, fireemu: form }), "CAPPED");
  assert.equal(classifyStage2({ production: form, fireemu: plain }), "CAPPED");
  assert.equal(classifyStage2({ production: plain, alternative: form, fireemu: plain }), "CAPPED");
  assert.equal(classifyStage2({ stale: true, production: form, fireemu: form }), "STALE_FIXTURE");
});

test("a row only recording 2 has is kept, with nothing to hold fireemu to", () => {
  const row = { conditions: ["C"], listeners: {}, clients: {} };
  const metas = [
    { recording: 1, programDigest: "p", harness: "h" },
    { recording: 2, programDigest: "p", harness: "h" },
  ];
  const fixture = buildFixture({
    recordings: [{ rows: {} }, { rows: { late: row } }],
    metas,
    programDigest: "p",
    harnessDigest: "h",
  });
  assert.equal(fixture.rows.late.production, null);
  assert.deepEqual(fixture.rows.late.second, { listeners: {}, clients: {} });
  assert.equal(
    classifyStage2({
      production: fixture.rows.late.production ?? undefined,
      alternative: fixture.rows.late.second,
      fireemu: {},
    }),
    "MISSING_FIXTURE",
  );
});

test("the deleted tenant's SDK row may vary only inside its allowed set", () => {
  const form = (t1, steady = ["docs:5"]) => ({
    probes: {
      "afc2-owned/steady-sdk": { listeners: { "sdk-steady/doc": steady } },
      "afc2-tenant/t1-sdk": { listeners: { "sdk-ten-t1/doc": t1, "sdk-ten-t1/query": t1 } },
    },
    late: [],
  });
  const row = "held/exp-plus-35-sdk";
  const error = ["error:unauthenticated"];
  // The set is `[]` only: production gave it in all four recordings, fireemu since the stream
  // close was fixed. An error, which local runs once gave, is now a mismatch on either side.
  assert.equal(
    classifyStage2({ row, production: form([]), alternative: form([]), fireemu: form([]) }),
    "MATCH_NONDETERMINISTIC",
  );
  assert.equal(classifyStage2({ row, production: form([]), fireemu: form(error) }), "MISMATCH");
  assert.equal(
    classifyStage2({ row, production: form(error), alternative: form([]), fireemu: form([]) }),
    "MISMATCH",
  );
  // A value outside the set, on either side, is a mismatch.
  assert.equal(
    classifyStage2({ row, production: form([]), fireemu: form(["docs:5"]) }),
    "MISMATCH",
  );
  assert.equal(
    classifyStage2({ row, production: form(["docs:5"]), fireemu: form([]) }),
    "MISMATCH",
  );
  // The rest of the row must still agree.
  assert.equal(
    classifyStage2({ row, production: form([]), fireemu: form([], ["error:x"]) }),
    "MISMATCH",
  );
  // Another row keeps the ordinary rules.
  assert.equal(
    classifyStage2({ row: "other", production: form([]), fireemu: form(error) }),
    "MISMATCH",
  );
  assert.equal(
    classifyStage2({
      row: "other",
      production: form([]),
      alternative: form(error),
      fireemu: form([]),
    }),
    "INDETERMINATE",
  );
  // A late timer or a cap still wins.
  assert.equal(
    classifyStage2({ row, production: { ...form([]), late: ["x"] }, fireemu: form([]) }),
    "INDETERMINATE",
  );
  assert.equal(
    classifyStage2({ row, production: { ...form([]), capped: ["c"] }, fireemu: form([]) }),
    "CAPPED",
  );
});

test("stage-2 comparison evidence binds the recording harness and the fireemu artifact apart", async () => {
  const { stage2Evidence } = await import("./auth-fs-cross/stage2-compare.mjs");
  const fixtureText = JSON.stringify({ harnessDigest: "h", programDigest: "p", rows: {} });
  const comparison = {
    summary: { MATCH: 1, MATCH_NONDETERMINISTIC: 1 },
    rows: [
      { row: "a", status: "MATCH", production: { x: 1 }, fireemu: { x: 1 } },
      { row: "b", status: "MATCH_NONDETERMINISTIC", production: {}, fireemu: {} },
    ],
  };
  const bindings = {
    artifactSha256: "f".repeat(64),
    harnessCommit: "a".repeat(40),
    harnessDigestAtCommit: "h",
    fireemuCommit: "b".repeat(40),
  };
  const evidence = stage2Evidence({ comparison, fixtureText, ...bindings });
  assert.equal(evidence.kind, "auth-fs-cross-stage2-comparison-v1");
  assert.deepEqual(evidence.harness, { commit: "a".repeat(40), digest: "h", programDigest: "p" });
  assert.deepEqual(evidence.fireemu, { commit: "b".repeat(40), artifactSha256: "f".repeat(64) });
  assert.match(evidence.fixtureSha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(evidence.summary, comparison.summary);
  assert.deepEqual(evidence.rows, [
    { row: "a", status: "MATCH" },
    { row: "b", status: "MATCH_NONDETERMINISTIC" },
  ]);
  // A summary that the rows do not add up to, or a non-passing row, is refused.
  assert.throws(
    () =>
      stage2Evidence({
        comparison: { ...comparison, summary: { MATCH: 2 } },
        fixtureText,
        ...bindings,
      }),
    /summary does not match the rows/,
  );
  assert.throws(
    () =>
      stage2Evidence({
        comparison: {
          summary: { MISMATCH: 1 },
          rows: [{ row: "a", status: "MISMATCH" }],
        },
        fixtureText,
        ...bindings,
      }),
    /not passing: a/,
  );
  assert.throws(
    () => stage2Evidence({ comparison, fixtureText, ...bindings, harnessCommit: "abc" }),
    /full commit/,
  );
  // The named commit's harness must be the one that recorded the fixture.
  assert.throws(
    () => stage2Evidence({ comparison, fixtureText, ...bindings, harnessDigestAtCommit: "x" }),
    /harness of a\{40\}|not the harness that recorded/,
  );
});
