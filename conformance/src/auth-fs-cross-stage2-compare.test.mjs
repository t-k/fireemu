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
