import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  assertCompleteRecording,
  BRACKET_OWNED_NAMES,
  BRACKET_REST_IDS,
  BRACKET_STREAM_IDS,
} from "./fs-data-write-sandbox.mjs";
import {
  isExactBracketProductionScope,
  productionScopeFromEnvironment,
} from "./firestore-probe/sandbox-session.mjs";
import {
  acquireSharedLedgerLock,
  bracketRequestBound,
  releaseSharedLedgerLock,
  requireBracketArguments,
  verifyBracketSendGates,
  ownedMutationNamesForPrograms,
  prepareSandboxCorpus,
  productionAdmissionPlan,
  productionRestEnvironment,
  selectBracketRecipes,
} from "./fs-data-write-sandbox-run.mjs";

const common = {
  input: "/private/corpus.json",
  output: "/private/rest.json",
  meta: "/private/meta.json",
  token: "not-used",
  journal: "/private/journal.json",
  runId: "a".repeat(32),
  corpusDigest: "b".repeat(64),
  sourceGitSha: "c".repeat(40),
};

test("the bracket corpus records exactly the fixed boundary pairs, twice with the same bytes", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const selection = selectBracketRecipes(corpus);
  const { recordingCorpus } = selection;
  assert.deepEqual(
    recordingCorpus.restPrograms.map((program) => program.id).toSorted(),
    [...BRACKET_REST_IDS].toSorted(),
  );
  assert.deepEqual(
    recordingCorpus.streamRecipes.map((recipe) => recipe.id),
    [...BRACKET_STREAM_IDS],
  );
  // Programs are the current corpus recipes byte for byte, so the supplement digests bind.
  for (const program of recordingCorpus.restPrograms) {
    assert.deepEqual(
      program,
      corpus.restPrograms.find((candidate) => candidate.id === program.id),
    );
  }
  assert.equal(recordingCorpus.restRequestCount, 38);
  assert.equal(recordingCorpus.sourceCorpusSha256, selection.sourceCorpusDigest);
  // No pass number or run marker appears in any name the corpus sends.
  assert.ok(!JSON.stringify(recordingCorpus).includes("DELETE_RUN_ID"));
  assert.throws(
    () =>
      selectBracketRecipes({
        ...corpus,
        restPrograms: corpus.restPrograms.filter((program) => program.id !== BRACKET_REST_IDS[0]),
        restRequestCount:
          corpus.restRequestCount -
          corpus.restPrograms.find((program) => program.id === BRACKET_REST_IDS[0]).steps.length,
      }),
    /bracket recipe/,
  );
});

test("bracket cleanup owns exactly the documents its recipes can create", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const { recordingCorpus } = selectBracketRecipes(corpus);
  assert.deepEqual(ownedMutationNamesForPrograms(recordingCorpus.restPrograms), [
    ...BRACKET_OWNED_NAMES,
  ]);
  assert.equal(BRACKET_OWNED_NAMES.length, 14);
  // Two preflight reads, one delete per owned name and one typed-missing read per attempt.
  assert.deepEqual(bracketRequestBound(recordingCorpus), {
    declaredHttp: 38,
    preflightHttp: 2,
    cleanupHttp: 15,
    maxHttpRequests: 55,
    maxStreamFrames: 2,
  });
  assert.throws(
    () =>
      bracketRequestBound({
        ...recordingCorpus,
        restPrograms: recordingCorpus.restPrograms.slice(1),
        restRequestCount:
          recordingCorpus.restRequestCount - recordingCorpus.restPrograms[0].steps.length,
      }),
    /bracket recipe/,
  );
});

test("the bracket admission plan pins recipes, owned names and bounds", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const selection = selectBracketRecipes(corpus);
  const plan = productionAdmissionPlan("bracket", selection);
  assert.equal(plan.mode, "bracket");
  assert.equal(plan.project, "fireemu-oracle-sbx");
  assert.deepEqual(plan.managedNames, [...BRACKET_OWNED_NAMES]);
  assert.deepEqual(plan.streamIds, [...BRACKET_STREAM_IDS]);
  assert.equal(plan.bounds.maxHttpRequests, 55);
  assert.equal(plan.attempts, 2);
  assert.equal(plan.attemptEstimateUsd, 0.5);
});

test("the child admits the bracket scope only as the parent sends it", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const bound = bracketRequestBound(selectBracketRecipes(corpus).recordingCorpus);
  const env = productionRestEnvironment({
    ...common,
    managedNames: [...BRACKET_OWNED_NAMES],
    bracket: { maxHttpRequests: bound.maxHttpRequests },
  });
  assert.equal(env.FIRESTORE_PROBE_BRACKET, "1");
  assert.equal(env.FIRESTORE_PROBE_BRACKET_LOCK_HELD, "1");
  assert.equal(env.FIRESTORE_PROBE_MAX_REQUESTS, "55");
  assert.equal(env.FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL, common.journal);
  assert.equal(env.FIRESTORE_PROBE_PARTIAL, undefined);
  assert.equal(env.FIRESTORE_PROBE_DELTA_V3, undefined);
  assert.deepEqual(productionScopeFromEnvironment(env), {
    delta: false,
    partial: false,
    bracket: true,
  });
  for (const change of [
    { FIRESTORE_PROBE_HOST: "attacker.example" },
    { FIRESTORE_PROBE_SCHEME: "http" },
    { FIRESTORE_PROBE_PROJECT: "fireemu-35fe6" },
    { FIRESTORE_PROBE_MAX_REQUESTS: "56" },
    { FIRESTORE_PROBE_BRACKET_LOCK_HELD: undefined },
    { FIRESTORE_PROBE_MANAGED_CLEAR_JOURNAL: undefined },
    { FIRESTORE_PROBE_PARTIAL: "1" },
    { FIRESTORE_PROBE_DELTA_V3: "1" },
    {
      FIRESTORE_PROBE_MANAGED_CLEAR_NAMES: JSON.stringify(BRACKET_OWNED_NAMES.slice(1)),
    },
  ]) {
    assert.equal(productionScopeFromEnvironment({ ...env, ...change }).bracket, false);
  }
  for (const [bracket, message] of [
    [{ maxHttpRequests: 0 }, /bracket HTTP cap/],
    [{ maxHttpRequests: 56 }, /bracket HTTP cap/],
  ]) {
    assert.throws(
      () =>
        productionRestEnvironment({ ...common, managedNames: [...BRACKET_OWNED_NAMES], bracket }),
      message,
    );
  }
  assert.throws(
    () =>
      productionRestEnvironment({
        ...common,
        managedNames: BRACKET_OWNED_NAMES.slice(1),
        bracket: { maxHttpRequests: 55 },
      }),
    /managed-clear names/,
  );
  assert.throws(
    () =>
      productionRestEnvironment({
        ...common,
        managedNames: [...BRACKET_OWNED_NAMES],
        bracket: { maxHttpRequests: 55 },
        partial: { maxHttpRequests: 55 },
      }),
    /one recording mode/,
  );
});

test("the exact bracket scope refuses every other target", () => {
  const scope = {
    mode: true,
    lockHeld: true,
    otherMode: false,
    host: "firestore.googleapis.com",
    scheme: "https",
    project: "fireemu-oracle-sbx",
    maxRequests: 55,
    managedClearJournal: "/private/journal.json",
    names: BRACKET_OWNED_NAMES.toReversed(),
  };
  assert.equal(isExactBracketProductionScope(scope), true);
  for (const change of [
    { mode: false },
    { lockHeld: false },
    { otherMode: true },
    { host: "firestore.googleapis.com.attacker.example" },
    { scheme: "http" },
    { project: "fireemu-oracle-idp" },
    { maxRequests: 0 },
    { maxRequests: 56 },
    { maxRequests: Number.NaN },
    { managedClearJournal: "" },
    { names: [...BRACKET_OWNED_NAMES, BRACKET_OWNED_NAMES[0]] },
    { names: BRACKET_OWNED_NAMES.map((name) => name.replace("rawQuery", "rawQueryX")) },
    { names: null },
  ]) {
    assert.equal(isExactBracketProductionScope({ ...scope, ...change }), false, change);
  }
});

const pins = {
  packetId: "fs-data-write-bracket-0123456789abcdef01234567",
  nonce: "0123456789abcdef01234567",
  packetSha256: "a".repeat(64),
  sourceCommit: "b".repeat(40),
  planSha256: "c".repeat(64),
  packetPath: "docs.local/runs/fs-data-write-bracket-20260927/PRESEND-PACKET.md",
};
const ownerRow = (overrides = {}) => {
  const value = { ...pins, ...overrides };
  return `- 2026-09-27 | FS-DATA-WRITE | bracket packet approved; packetSha256=${value.packetSha256}; sourceCommit=${value.sourceCommit}; planSha256=${value.planSha256}; nonce=${value.nonce} | オーナー（このセッションへの直接の返答） | ${value.packetPath}`;
};
const at = (minutes) => new Date(Date.UTC(2026, 8, 27, 12, 0) + minutes * 60_000).toISOString();
const sbx = (row) => ({ project: "fireemu-oracle-sbx", taskId: "FS-DATA-WRITE-SANDBOX", ...row });
const now = Date.parse(at(60));

test("a bracket send waits 30 minutes after the last sbx activity, ignoring notes and reservations", () => {
  const decisions = `# ledger\n${ownerRow()}\n`;
  // 29 minutes before now.
  const finished = sbx({ ts: at(31), outcome: "recorded", attemptId: "x" });
  const rows = [sbx({ ts: at(0), outcome: "reserved", attemptId: "x" }), finished];
  assert.throws(() => verifyBracketSendGates({ rows, now, decisions, pins }), /30 minutes/);
  const later = [
    sbx({ ts: at(0), outcome: "reserved", attemptId: "x" }),
    sbx({ ts: at(30), outcome: "recorded", attemptId: "x" }),
    sbx({ ts: at(59), event: "note", note: "text" }),
    sbx({ ts: at(59), outcome: "reserved-presend-admission", packetId: pins.packetId }),
    { ts: at(59), project: "fireemu-oracle-idp", outcome: "recorded" },
  ];
  assert.deepEqual(verifyBracketSendGates({ rows: later, now, decisions, pins }), {
    lastActivity: at(30),
  });
});

test("a bracket send refuses an open sbx attempt and a second run of the same packet", () => {
  const decisions = ownerRow();
  const open = [sbx({ ts: at(0), outcome: "reserved", attemptId: "y" })];
  assert.throws(() => verifyBracketSendGates({ rows: open, now, decisions, pins }), /open attempt/);
  const started = [sbx({ ts: at(0), event: "started", attemptId: "z" })];
  assert.throws(
    () => verifyBracketSendGates({ rows: started, now, decisions, pins }),
    /open attempt/,
  );
  const ran = [
    sbx({ ts: at(0), outcome: "reserved", attemptId: "w", packetId: pins.packetId }),
    sbx({ ts: at(1), outcome: "failed", attemptId: "w", packetId: pins.packetId }),
  ];
  assert.throws(() => verifyBracketSendGates({ rows: ran, now, decisions, pins }), /already ran/);
});

test("a bracket send needs one owner row pinning packet, commit, plan and nonce", () => {
  const rows = [];
  assert.equal(
    verifyBracketSendGates({ rows, now, decisions: ownerRow(), pins }).lastActivity,
    null,
  );
  for (const decisions of [
    "",
    ownerRow({ packetSha256: "d".repeat(64) }),
    ownerRow({ sourceCommit: "e".repeat(40) }),
    ownerRow({ planSha256: "f".repeat(64) }),
    ownerRow({ nonce: "fffffffffffffffffffffff0" }),
    ownerRow({ packetPath: "docs.local/other.md" }),
    ownerRow().replace("オーナー（このセッションへの直接の返答）", "Claude（委任）"),
    ownerRow().replace("| FS-DATA-WRITE |", "| FS-RULES |"),
    `${ownerRow()}\n${ownerRow()}`,
  ]) {
    assert.throws(
      () => verifyBracketSendGates({ rows, now, decisions, pins }),
      /owner approval/,
      decisions,
    );
  }
});

test("the shared ledger lock is taken exclusively and released only by its holder", async () => {
  const dir = await mkdtemp(join(tmpdir(), "bracket-lock-"));
  try {
    const path = join(dir, "sandbox-ledger.jsonl.lock");
    const held = await acquireSharedLedgerLock(path, pins.packetId);
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal(JSON.parse(await readFile(path, "utf8")).packetId, pins.packetId);
    await assert.rejects(acquireSharedLedgerLock(path, "other"), /shared ledger lock/);
    await releaseSharedLedgerLock(held);
    await assert.rejects(stat(path), { code: "ENOENT" });
    const again = await acquireSharedLedgerLock(path, pins.packetId);
    await releaseSharedLedgerLock(again);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("record-bracket takes the review and packet pins and nothing else", () => {
  const args = [
    "--nonce",
    pins.nonce,
    "--review",
    "/r.md",
    "--review-sha256",
    "1".repeat(64),
    "--packet",
    "/p.md",
    "--packet-sha256",
    pins.packetSha256,
  ];
  assert.deepEqual(requireBracketArguments(args), {
    nonce: pins.nonce,
    review: "/r.md",
    reviewSha256: "1".repeat(64),
    packet: "/p.md",
    packetSha256: pins.packetSha256,
  });
  assert.throws(() => requireBracketArguments(args.slice(0, 6)), /--packet/);
  assert.throws(() => requireBracketArguments([...args, "--extra", "x"]), /--packet/);
  assert.throws(
    () => requireBracketArguments(args.map((value) => (value === pins.packetSha256 ? "x" : value))),
    /--packet/,
  );
});

test("a failed or incomplete first attempt stops before the second is sent", async () => {
  const { corpus } = await prepareSandboxCorpus();
  const { recordingCorpus } = selectBracketRecipes(corpus);
  const rest = Object.fromEntries(
    recordingCorpus.restPrograms.map((program) => [
      program.id,
      {
        steps: Object.fromEntries(
          program.steps.map((step) => [step.id, { status: 200, code: "OK", body: {} }]),
        ),
      },
    ]),
  );
  const stream = Object.fromEntries(
    recordingCorpus.streamRecipes.map((recipe) => [
      recipe.id,
      { sentFrames: 1, wireBytes: recipe.wireBytes, status: { code: 3, details: "x" } },
    ]),
  );
  assertCompleteRecording(recordingCorpus, rest, stream);
  const webchannel = "writes/limits/webchannel-request-bytes/11534336";
  for (const failed of [
    { status: 0, code: "not-run", message: "the WebChannel control message was not acknowledged" },
    { status: 0, code: "probe-error", message: "fetch failed" },
    { status: 200, code: "OK" },
  ]) {
    const broken = structuredClone(rest);
    broken[webchannel].steps.boundary = failed;
    assert.throws(
      () => assertCompleteRecording(recordingCorpus, broken, stream),
      /failed observation/,
    );
  }
  const missing = structuredClone(rest);
  delete missing[webchannel];
  assert.throws(() => assertCompleteRecording(recordingCorpus, missing, stream), /incomplete/);
  const noStream = structuredClone(stream);
  delete noStream[BRACKET_STREAM_IDS[1]];
  assert.throws(
    () => assertCompleteRecording(recordingCorpus, rest, noStream),
    /incomplete stream/,
  );
});
