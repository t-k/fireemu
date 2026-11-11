// The recorder under FIREEMU_HOSTING_PROFILE=followup (packet v1): the profile's admission, budget,
// key bodies and refused finalizes, over the same fake world as record.test.mjs.
import assert from "node:assert/strict";
import test from "node:test";

import { compareFiles } from "./compare.mjs";
import { corpusManifest } from "./corpus.mjs";
import { buildFollowupCorpus, FOLLOWUP_PROFILE } from "./followup.mjs";
import { FOLLOWUP_CORPUS_SHA256 } from "./pins.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  admit,
  checkReport,
  PRODUCTION_PROFILE,
  productionDeps,
  profileOf,
  PROJECT,
  recordHosting,
  recoverHosting,
  TASK_ID,
} from "./record.mjs";
import { maskSecrets, shapeRow } from "./rows.mjs";
import { createWorld } from "./world.mjs";

const now = Date.parse("2026-11-12T12:00:00Z");
const fakeSecrets = { apiKey: "AIzaFAKEFAKEFAKEFAKEFAKEFAKE12345", projectNumber: "123456789012" };
const ENVELOPE = "HOSTING-FOLLOWUP-V1-20261112";
const closed = {
  ts: "2026-11-12T00:00:00Z",
  project: PROJECT,
  taskId: "other",
  event: "finished",
  outcome: "recorded",
};
const FOLLOW = "HOSTING-FOLLOWUP";
const reply = (status, value = {}) => ({ status, text: JSON.stringify(value) });
const edgeAnswer = (status, body = Buffer.alloc(0), headers = []) => ({
  outcome: "answered",
  status,
  headers,
  body,
});
const rowsOf = (r) => JSON.parse(r.files["rows.json"]).rows;
const deployOf = (r) => JSON.parse(r.files["deploy.json"]).versions;
const resultOf = (r) => JSON.parse(r.files["result.json"]);

async function run(options = {}) {
  const world = createWorld({
    run: "abc123",
    secrets: fakeSecrets,
    overrides: options.overrides ?? [],
  });
  const ledger = [JSON.stringify(closed)];
  const files = {};
  const sources = [];
  const deps = {
    now: () => now,
    assertCleanTree: async () => {},
    gitSha: async () => "a".repeat(40),
    readSources: async (profile) => {
      sources.push(profile);
      return { corpus: buildFollowupCorpus() };
    },
    readLedger: async () => ledger.join("\n"),
    appendLedger: async (text) => {
      ledger.push(text.trim());
    },
    ownerAdc: async () => ({}),
    webConfig: async () => ({
      projectId: PROJECT,
      ...fakeSecrets,
      messagingSenderId: fakeSecrets.projectNumber,
      appId: `1:${fakeSecrets.projectNumber}:web:deadbeef1234`,
    }),
    makeRunDir: async (name) => `/run/${name}`,
    writeRunFile: async (_dir, name, text) => {
      files[name] = text;
    },
    appendRunFile: async (_dir, name, text) => {
      files[name] = (files[name] ?? "") + text;
    },
    runTag: () => "abc123",
    token: async () => ({ value: "fake-bearer", expiresAt: now + 1e9 }),
    http: world.http,
    edge: world.edge,
    sleep: async () => {},
    installSignals: () => {},
    log() {},
    warn() {},
  };
  options.setup?.(world, deps, ledger);
  const env = {
    FIREEMU_HOSTING_PROFILE: "followup",
    FIREEMU_HOSTING_ENVELOPE: ENVELOPE,
    ...options.env,
  };
  const result = await recordHosting(env, deps);
  return { result, world, ledger, files, deps, env, sources };
}

test("a profile is named by FIREEMU_HOSTING_PROFILE; an unknown name is refused before any ledger read", async () => {
  await assert.rejects(
    () =>
      recordHosting({ FIREEMU_HOSTING_PROFILE: "other", FIREEMU_HOSTING_ENVELOPE: ENVELOPE }, {}),
    /unknown FIREEMU_HOSTING_PROFILE/,
  );
  assert.throws(
    () => admit({ ledgerText: JSON.stringify(closed), now, env: { FIREEMU_HOSTING_PROFILE: "x" } }),
    /unknown FIREEMU_HOSTING_PROFILE/,
  );
  // the recorder's default is the production profile, whose envelopes are HOSTING-PRODUCTION-...
  assert.throws(
    () =>
      admit({
        ledgerText: JSON.stringify(closed),
        now,
        env: { FIREEMU_HOSTING_ENVELOPE: ENVELOPE },
      }),
    /must name the envelope \(HOSTING-PRODUCTION-/,
  );
  assert.throws(
    () =>
      admit({
        ledgerText: JSON.stringify(closed),
        now,
        env: {
          FIREEMU_HOSTING_PROFILE: "followup",
          FIREEMU_HOSTING_ENVELOPE: "HOSTING-PRODUCTION-V5-20261111",
        },
      }),
    /must name the envelope \(HOSTING-FOLLOWUP-/,
  );
});

test("follow-up admission counts only its own task: attempts of the envelope and US$3.00 over all", () => {
  const started = (n, extra = {}) => ({
    ts: `2026-11-12T0${n}:00:00Z`,
    project: PROJECT,
    taskId: FOLLOW,
    event: "started",
    envelopeId: ENVELOPE,
    run: `a0000${n}`,
    ...extra,
  });
  const ended = (n, extra = {}) => ({
    ts: `2026-11-12T0${n}:30:00Z`,
    project: PROJECT,
    taskId: FOLLOW,
    event: "cleanup-verified",
    outcome: "recorded",
    envelopeId: ENVELOPE,
    run: `a0000${n}`,
    ...extra,
  });
  const text = (...rows) => rows.map((row) => JSON.stringify(row)).join("\n");
  const env = { FIREEMU_HOSTING_PROFILE: "followup", FIREEMU_HOSTING_ENVELOPE: ENVELOPE };
  const late = Date.parse("2026-11-13T00:00:00Z");
  // six production rows of the parent do not count: attempt 1 reserves US$1.00 of this envelope
  const production = Array.from({ length: 6 }, (_, i) => ({
    ts: `2026-11-10T0${i}:00:00Z`,
    project: PROJECT,
    taskId: TASK_ID,
    event: i % 2 ? "cleanup-verified" : "started",
    outcome: "recorded",
    envelopeId: "HOSTING-PRODUCTION-V5-20261111",
  }));
  assert.deepEqual(admit({ ledgerText: text(...production, closed), now: late, env }), {
    attempt: 1,
    cumulativeReservedUsd: 1,
  });
  assert.deepEqual(admit({ ledgerText: text(closed, started(1), ended(1)), now: late, env }), {
    attempt: 2,
    cumulativeReservedUsd: 2,
  });
  assert.deepEqual(
    admit({ ledgerText: text(started(1), ended(1), started(2), ended(2)), now: late, env }),
    { attempt: 3, cumulativeReservedUsd: 3 },
  );
  assert.throws(
    () =>
      admit({
        ledgerText: text(started(1), ended(1), started(2), ended(2), started(3), ended(3)),
        now: late,
        env,
      }),
    /attempt 4 exceeds 3 attempts/,
  );
  // another envelope's started rows do not count toward the attempts, but their money does
  const other = "HOSTING-FOLLOWUP-V2-20261114";
  assert.deepEqual(
    admit({
      ledgerText: text(started(1, { envelopeId: other }), ended(1, { envelopeId: other })),
      now: late,
      env,
    }),
    { attempt: 1, cumulativeReservedUsd: 2 },
  );
  assert.throws(
    () =>
      admit({
        ledgerText: text(
          started(1, { envelopeId: other }),
          ended(1),
          started(2, { envelopeId: other }),
          ended(2),
          started(3, { envelopeId: other }),
          ended(3),
        ),
        now: late,
        env,
      }),
    /cumulative reservation 4 passes US\$3\.00/,
  );
  // the attempt the launch names must be the recorder's count
  assert.throws(
    () =>
      admit({ ledgerText: text(closed), now: late, env: { ...env, FIREEMU_HOSTING_ATTEMPT: "2" } }),
    /is not attempt 1/,
  );
});

test("the check report names the follow-up corpus: five versions, 78 requests, its own caps", () => {
  const report = checkReport(FOLLOWUP_PROFILE);
  assert.equal(report.corpusSha256, FOLLOWUP_CORPUS_SHA256);
  assert.equal(report.pinned, FOLLOWUP_CORPUS_SHA256);
  assert.equal(report.versions, 5);
  assert.equal(report.requests, 78);
  assert.deepEqual(report.caps, FOLLOWUP_PROFILE.caps);
  assert.equal(report.worstCaseTotal, 263);
  assert.equal(corpusManifest(buildFollowupCorpus()).corpusSha256, FOLLOWUP_CORPUS_SHA256);
});

test("a full follow-up run records the 78 rows under its own task and digest, within its caps", async () => {
  const r = await run();
  assert.deepEqual(r.sources, [FOLLOWUP_PROFILE], "the recorder asks for the profile's corpus");
  const rows = rowsOf(r);
  assert.deepEqual(
    rows.map((row) => row.id),
    buildFollowupCorpus().versions.flatMap((v) => v.requests.map((spec) => spec.id)),
  );
  assert.equal(rows.length, 78);
  for (const line of r.ledger.slice(1).map((text) => JSON.parse(text))) {
    assert.equal(line.taskId, FOLLOW);
    assert.equal(line.corpusDigest, FOLLOWUP_CORPUS_SHA256);
    assert.equal(line.envelopeId, ENVELOPE);
  }
  const started = JSON.parse(r.ledger[1]);
  assert.equal(started.event, "started");
  assert.equal(started.reservedUsd, 1);
  assert.equal(started.cumulativeReservedUsd, 1);
  assert.equal(JSON.parse(r.files["rows.json"]).corpusSha256, FOLLOWUP_CORPUS_SHA256);
  assert.equal(r.world.state.versions.size, 5);
  assert.equal(r.world.state.channels.size, 5);
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  assert.ok([...r.world.state.versions.values()].every((version) => version.status === "DELETED"));
  assert.deepEqual(resultOf(r).caps, FOLLOWUP_PROFILE.caps);
  const requests = resultOf(r).requests;
  // the counted requests of a clean run: the budget table of the packet
  assert.deepEqual(requests, { token: 1, control: 35, cleanup: 13, upload: 16, edge: 83 });
  for (const kind of Object.keys(FOLLOWUP_PROFILE.caps)) {
    assert.ok(requests[kind] <= FOLLOWUP_PROFILE.caps[kind], `${kind} ${requests[kind]}`);
  }
  // no version lists its files: the reserved files were recorded in the closure
  assert.equal(
    r.world.log.filter((call) => call.method === "GET" && /\/files\?/.test(call.url ?? "")).length,
    0,
  );
  // the version cannot be told from a production-profile version except by its own task row
  assert.equal(TASK_ID, "HOSTING-PRODUCTION");
});

test("v11's default 404 page and auth handler bodies are kept; a body with a private value is withheld", async () => {
  const page = Buffer.from("<html>".padEnd(21_376, "x"));
  const r = await run({
    overrides: [
      {
        match: "GET /missing$/",
        answer: () => edgeAnswer(404, page, [["Content-Type", "text/html; charset=utf-8"]]),
      },
      {
        match: "GET /__/auth/handler$/",
        answer: () =>
          edgeAnswer(200, Buffer.from(`<html>${fakeSecrets.apiKey}</html>`), [
            ["Content-Type", "text/html"],
          ]),
      },
    ],
  });
  const by = Object.fromEntries(rowsOf(r).map((row) => [row.id, row]));
  assert.equal(by["v11.default-404"].bodyBytes, 21_376);
  assert.equal(Buffer.from(by["v11.default-404"].bodyBase64, "base64").equals(page), true);
  assert.equal("bodyText" in by["v11.default-404"], false);
  // the private value never reaches the file, not even base64-encoded
  assert.equal(by["v11.auth-handler"].bodyBase64, undefined);
  assert.equal(by["v11.auth-handler"].bodyWithheld, "private-value");
  assert.equal(r.files["rows.json"].includes(fakeSecrets.apiKey), false);
  assert.equal(
    r.files["rows.json"].includes(Buffer.from(fakeSecrets.apiKey).toString("base64")),
    false,
  );
  // a row without keepBody never carries a base64 body
  assert.equal(by["v11.default-404-json"].bodyBase64, undefined);
});

test("shapeRow keeps a body only for keepBody, only when it is not empty and holds no private value", () => {
  const ctx = { origin: "https://h", secrets: ["PRIVATEVALUE-1"], version: "v11" };
  const spec = (extra = {}) => ({
    id: "v11.x",
    condition: "default-404",
    method: "GET",
    target: "/x",
    ...extra,
  });
  const answered = (body) => ({ outcome: "answered", status: 404, headers: [], body });
  const kept = shapeRow(spec({ keepBody: true }), answered(Buffer.from("page\n")), ctx);
  assert.equal(kept.bodyBase64, Buffer.from("page\n").toString("base64"));
  assert.equal(kept.bodyWithheld, undefined);
  assert.equal(shapeRow(spec(), answered(Buffer.from("page\n")), ctx).bodyBase64, undefined);
  const empty = shapeRow(spec({ keepBody: true }), answered(Buffer.alloc(0)), ctx);
  assert.equal(empty.bodyBase64, undefined);
  assert.equal(empty.bodyWithheld, undefined);
  const secret = shapeRow(
    spec({ keepBody: true }),
    answered(Buffer.from("a PRIVATEVALUE-1 b")),
    ctx,
  );
  assert.equal(secret.bodyBase64, undefined);
  assert.equal(secret.bodyWithheld, "private-value");
  const unknown = shapeRow(
    spec({ keepBody: true }),
    { outcome: "unknown", reason: "timeout" },
    ctx,
  );
  assert.equal(unknown.bodyBase64, undefined);
  assert.equal(maskSecrets("a PRIVATEVALUE-1 b", ctx.secrets).includes("PRIVATEVALUE"), false);
});

test("a refused finalize of v13 or v14 is an observation: no halt, expected unknown rows, the run is recorded", async () => {
  const r = await run({
    overrides: [{ match: "PATCH /versions/0{15}3/", nth: 1, answer: reply(400) }],
  });
  const d = deployOf(r);
  assert.deepEqual(d.v13.configRefusal, { status: 400 });
  assert.equal(d.v13.failure, undefined);
  assert.equal(r.world.state.versions.size, 5);
  const rows = rowsOf(r);
  const v13 = rows.filter((row) => row.id.startsWith("v13."));
  assert.deepEqual(
    v13.map((row) => [row.outcome, row.reason]),
    [
      ["unknown", "config-refused"],
      ["unknown", "config-refused"],
      ["unknown", "config-refused"],
    ],
  );
  // the versions after it are still deployed and answered
  assert.equal(
    rows.filter((row) => row.id.startsWith("v15.") && row.outcome === "answered").length,
    32,
  );
  assert.equal(r.result.outcome, "recorded");
  assert.equal(r.result.closureReady, true);
  assert.ok([...r.world.state.channels.values()].every((channel) => channel.deleted));
  assert.ok([...r.world.state.versions.values()].every((version) => version.status === "DELETED"));
  const result = resultOf(r);
  assert.equal(result.unknownRows, 0, "an expected refusal is not an unexpected unknown row");
  assert.equal(result.refusedVersions.join(","), "v13");
});

test("a finalize failure of any other version, or an unknown one of v13, still halts the run", async () => {
  const other = await run({
    overrides: [{ match: "PATCH /versions/", nth: 1, answer: reply(400) }],
  });
  assert.equal(other.result.outcome, "failed-cleaned");
  assert.equal(deployOf(other).v11.failure, "finalize failed (400)");
  assert.equal(other.world.state.versions.size, 1);
  const unknown = await run({
    overrides: [{ match: "PATCH /versions/0{15}3/", nth: 1, answer: reply(500) }],
  });
  assert.equal(unknown.result.outcome, "failed-cleaned");
  assert.equal(deployOf(unknown).v13.failure, "finalize failed (500)");
  assert.equal(deployOf(unknown).v13.configRefusal, undefined);
  // a 403 is a definite refusal as well, but only a 400 or 422 names the config
  const forbidden = await run({
    overrides: [{ match: "PATCH /versions/0{15}3/", nth: 1, answer: reply(403) }],
  });
  assert.equal(forbidden.result.outcome, "failed-cleaned");
});

test("recovery under the follow-up profile reads its own task's last run and writes under its own task", async () => {
  const r = await run();
  const channel = [...r.world.state.channels.values()][0];
  channel.deleted = false;
  const version = [...r.world.state.versions.values()][0];
  version.deleted = false;
  version.status = "CREATED";
  r.ledger.push(
    JSON.stringify({
      ts: new Date(now - 10_000).toISOString(),
      project: PROJECT,
      taskId: FOLLOW,
      event: "started",
      run: "abc123",
      authorizedDomainsBefore: ["localhost"],
      envelopeId: ENVELOPE,
    }),
    JSON.stringify({
      ts: new Date(now - 5_000).toISOString(),
      project: PROJECT,
      taskId: FOLLOW,
      event: "needs-recovery",
      outcome: "needs-recovery",
      run: "abc123",
      openUnknownCreates: [],
      residualEntries: [],
    }),
  );
  // the production profile finds no run of its task to recover
  await assert.rejects(() => recoverHosting({}, r.deps), /no run of this task/);
  const recovered = await recoverHosting({ FIREEMU_HOSTING_PROFILE: "followup" }, r.deps);
  assert.equal(recovered.outcome, "recovery-read-clean");
  assert.equal(channel.deleted, true);
  const row = JSON.parse(r.ledger.at(-1));
  assert.equal(row.taskId, FOLLOW);
  assert.equal(row.event, "recovery-read");
});

test("profileOf: the default and `production` are the parent's recording, `followup` is the packet's", () => {
  assert.equal(profileOf({}), PRODUCTION_PROFILE);
  assert.equal(profileOf({ FIREEMU_HOSTING_PROFILE: "production" }), PRODUCTION_PROFILE);
  assert.equal(profileOf({ FIREEMU_HOSTING_PROFILE: "followup" }), FOLLOWUP_PROFILE);
  assert.throws(
    () => profileOf({ FIREEMU_HOSTING_PROFILE: "Followup" }),
    /unknown FIREEMU_HOSTING_PROFILE/,
  );
  assert.throws(
    () => profileOf({ FIREEMU_HOSTING_PROFILE: "" }),
    /unknown FIREEMU_HOSTING_PROFILE/,
  );
  assert.equal(PRODUCTION_PROFILE.taskId, "HOSTING-PRODUCTION");
  assert.equal(PRODUCTION_PROFILE.maxCumulativeUsd, 6);
  assert.equal(PRODUCTION_PROFILE.listFilesVersion, "v01");
});

test("a 422 is a refusal of the config as well; the sources check names the corpus the profile pins", async () => {
  const r = await run({
    overrides: [{ match: "PATCH /versions/0{15}4/", nth: 1, answer: reply(422) }],
  });
  assert.deepEqual(deployOf(r).v14.configRefusal, { status: 422 });
  assert.equal(r.result.outcome, "recorded");
  assert.equal(resultOf(r).refusedVersions.join(","), "v14");
  const deps = await productionDeps();
  const { corpus } = await deps.readSources(FOLLOWUP_PROFILE);
  assert.equal(corpusManifest(corpus).corpusSha256, FOLLOWUP_CORPUS_SHA256);
  await assert.rejects(
    () => deps.readSources({ ...FOLLOWUP_PROFILE, corpusSha256: "0".repeat(64) }),
    /the corpus is not the pinned one/,
  );
  const production = await deps.readSources();
  assert.equal(production.corpus.versions.length, 10);
});

test("the command line prints the digest and the check of the profile the environment names", () => {
  const record = new URL("./record.mjs", import.meta.url).pathname;
  const output = (mode, profile) =>
    execFileSync(process.execPath, [record, mode], {
      env: { PATH: process.env.PATH, ...(profile ? { FIREEMU_HOSTING_PROFILE: profile } : {}) },
    }).toString();
  assert.equal(output("digest", "followup").trim(), FOLLOWUP_CORPUS_SHA256);
  assert.equal(output("digest").trim(), PRODUCTION_PROFILE.corpusSha256);
  assert.equal(JSON.parse(output("check", "followup")).requests, 78);
  assert.equal(JSON.parse(output("check")).requests, 201);
});

test("recovery under the follow-up profile has the follow-up cleanup budget of 30 requests", async () => {
  const r = await run();
  // 32 live channels of the run: one list and 32 deletes are 33 cleanup requests
  const base = "https://firebasehosting.googleapis.com/v1beta1";
  for (let n = 20; n < 52; n += 1) {
    await r.world.http({
      method: "POST",
      url: `${base}/projects/${PROJECT}/sites/${PROJECT}/channels?channelId=hst-abc123-v${n}`,
      body: JSON.stringify({ labels: { "fireemu-run": "abc123" } }),
    });
  }
  r.ledger.push(
    JSON.stringify({
      ts: new Date(now - 10_000).toISOString(),
      project: PROJECT,
      taskId: FOLLOW,
      event: "started",
      run: "abc123",
      authorizedDomainsBefore: ["localhost"],
    }),
  );
  await assert.rejects(
    () => recoverHosting({ FIREEMU_HOSTING_PROFILE: "followup" }, r.deps),
    /the cleanup budget is exhausted/,
  );
});

test("two follow-up runs compare row by row under the follow-up corpus, with no known differences", async () => {
  const left = await run();
  const right = await run();
  const file = (r, name) => ({ name, sha256: "", value: JSON.parse(r.files["rows.json"]) });
  const result = compareFiles({
    kind: "run-vs-run",
    left: file(left, "a"),
    right: file(right, "b"),
    corpus: buildFollowupCorpus(),
    known: [],
  });
  assert.equal(result.corpusSha256, FOLLOWUP_CORPUS_SHA256);
  assert.equal(result.rows.length, 78);
  assert.deepEqual(result.knownDifferences, []);
  assert.equal(result.summary.MISMATCH, 0);
  // the fake edge cannot answer one dependency, on both sides alike
  assert.deepEqual(
    result.rows.filter((row) => row.status === "UNKNOWN").map((row) => row.id),
    [],
  );
  // a row file of another corpus is refused
  const other = {
    name: "c",
    sha256: "",
    value: { ...file(left, "c").value, corpusSha256: "0".repeat(64) },
  };
  assert.throws(
    () =>
      compareFiles({
        kind: "run-vs-run",
        left: other,
        right: file(right, "b"),
        corpus: buildFollowupCorpus(),
        known: [],
      }),
    /not a row file of the pinned corpus/,
  );
});

test("the compare command line reads follow-up rows only when it is told to", async () => {
  const r = await run();
  const dir = mkdtempSync(join(tmpdir(), "followup-compare-"));
  const rows = join(dir, "rows.json");
  writeFileSync(rows, r.files["rows.json"]);
  const compare = new URL("./compare.mjs", import.meta.url).pathname;
  const node = (...args) =>
    execFileSync(process.execPath, [compare, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
    }).toString();
  const done = JSON.parse(node("run-vs-run", rows, rows, join(dir, "out.json"), "followup"));
  assert.equal(done.summary.MISMATCH, 0);
  assert.equal(
    Object.values(done.summary).reduce((a, b) => a + b, 0),
    78,
  );
  // without the word, the rows are checked against the parent's corpus and refused
  assert.throws(() => node("run-vs-run", rows, rows, join(dir, "out2.json")), /pinned corpus/);
  assert.throws(() => node("run-vs-run", rows, rows, join(dir, "out3.json"), "other"), /usage/);
});

// A small deterministic generator for the property test.
function prng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

test("property: over any closed ledger, the attempt counts this envelope's started rows and the money this task's", () => {
  const random = prng(20261111);
  const pick = (items) => items[Math.floor(random() * items.length)];
  const tasks = [FOLLOW, FOLLOW, TASK_ID, `${TASK_ID}-RECOVERY`, "OTHER-TASK"];
  const envelopes = [
    ENVELOPE,
    ENVELOPE,
    "HOSTING-FOLLOWUP-V2-20261114",
    "HOSTING-PRODUCTION-V5-20261111",
  ];
  const late = Date.parse("2026-11-20T00:00:00Z");
  const seen = { attempts: 0, money: 0, admitted: 0 };
  for (let round = 0; round < 400; round += 1) {
    const rows = [];
    let attemptsHere = 0;
    let startedOfTask = 0;
    const runs = Math.floor(random() * 9);
    for (let n = 0; n < runs; n += 1) {
      const taskId = pick(tasks);
      const envelopeId = pick(envelopes);
      const day = String(n + 1).padStart(2, "0");
      const base = { project: PROJECT, taskId, envelopeId, run: `a000${n}${n}` };
      rows.push({ ts: `2026-11-${day}T01:00:00Z`, ...base, event: "started" });
      rows.push({
        ts: `2026-11-${day}T02:00:00Z`,
        ...base,
        event: "cleanup-verified",
        outcome: "recorded",
      });
      if (taskId === FOLLOW) {
        startedOfTask += 1;
        if (envelopeId === ENVELOPE) attemptsHere += 1;
      }
    }
    rows.push(closed);
    const ledgerText = rows.map((row) => JSON.stringify(row)).join("\n");
    const env = { FIREEMU_HOSTING_PROFILE: "followup", FIREEMU_HOSTING_ENVELOPE: ENVELOPE };
    const attempt = attemptsHere + 1;
    const cumulative = startedOfTask + 1;
    if (attempt > 3) {
      seen.attempts += 1;
      assert.throws(
        () => admit({ ledgerText, now: late, env }),
        /exceeds 3 attempts/,
        `round ${round}`,
      );
    } else if (cumulative > 3) {
      seen.money += 1;
      assert.throws(
        () => admit({ ledgerText, now: late, env }),
        /cumulative reservation/,
        `round ${round}`,
      );
    } else {
      seen.admitted += 1;
      assert.deepEqual(
        admit({ ledgerText, now: late, env }),
        { attempt, cumulativeReservedUsd: cumulative },
        `round ${round}`,
      );
    }
  }
  // the generator reaches every outcome
  assert.ok(seen.attempts > 5 && seen.money > 5 && seen.admitted > 50, JSON.stringify(seen));
});
