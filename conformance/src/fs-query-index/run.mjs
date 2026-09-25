// Sandbox runner of FS-QUERY-INDEX and, with FIREEMU_SANDBOX_LANE=fs-data-write-list, of the
// FS-DATA-WRITE-LIST observation (lanes.mjs). File names below are the FS-QUERY-INDEX lane's.
//
//   node src/fs-query-index/run.mjs verify-indexes      read-only: the sandbox's composite
//                                                       indexes and field overrides must equal
//                                                       fs-query-index.indexes.json, all READY
//   node src/fs-query-index/run.mjs preflight           read-only: verify-indexes, the lane file
//                                                       holds the shared indexes, and (default)
//                                                       is empty (record-production runs it first)
//   node src/fs-query-index/run.mjs record-production   record the corpus twice against
//                                                       fireemu-oracle-query/(default) and update
//                                                       fs-query-index-production.json
//   node src/fs-query-index/run.mjs rebuild-fixture <runDir> [--skip-changed]
//   node src/fs-query-index/run.mjs check               run the corpus against fireemu and
//                                                       compare with the saved production rows
//   node src/fs-query-index/run.mjs export-comparison <out.json>
//
// `record-production` needs owner ADC (`gcloud auth application-default`),
// FIREEMU_SANDBOX_LEDGER (the private append-only run ledger) and FIREEMU_FS_QUERY_PRIVATE_DIR
// (a git-ignored directory for the raw recordings). FS_QUERY_INDEX_PROGRAMS limits a run to
// programs whose id starts with one of its comma-separated prefixes (FS_QUERY_INDEX_PROGRAMS_EXACT=1
// for exact ids); recorded programs replace their previous entries and the others are kept.
// `check` uses FIREEMU_BIN (or the workspace build) and writes .runs/fs-query-index/comparison.json.
//
// With FIREEMU_SANDBOX_LANE=fs-data-write-list the same commands run the listDocuments /
// listCollectionIds lane: corpus src/fs-list/corpus.mjs, fixture fs-data-write-list-production.json,
// run directory .runs/fs-data-write-list, ledger task FS-DATA-WRITE-LIST. The environment names
// above (FS_QUERY_INDEX_PROGRAMS, FIREEMU_FS_QUERY_PRIVATE_DIR) serve both lanes. Both lanes wipe
// the whole sandbox `(default)` database, so a recording holds a lock file next to the ledger and
// the other lane cannot record at the same time.

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, open, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR, REPO_ROOT } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { scanFixture } from "./fixture-scan.mjs";
import {
  DATABASE,
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  createContext,
  diffRecordings,
  isTransient,
  normalizeStep,
  sameRecording,
  validateCorpus,
} from "./harness.mjs";
import { selectLane } from "./lanes.mjs";
import { runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const LANE = selectLane();
const { PROGRAMS } = await import(LANE.corpus);
// A lane without approved divergences compares every row strictly.
const { approvedDivergence, crossRowChecks } = LANE.divergences
  ? await import(LANE.divergences)
  : { approvedDivergence: () => undefined, crossRowChecks: () => ({ demote: new Set() }) };
const FIXTURE = join(CONFORMANCE_DIR, LANE.fixture);
const INDEXES = join(CONFORMANCE_DIR, LANE.indexes);
const LOCAL_CONFIG = join(CONFORMANCE_DIR, LANE.localConfig);
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", LANE.id);
const TASK_ID = LANE.taskId;
const ADMIN_ORIGIN = "https://firestore.googleapis.com/v1";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

export function selectPrograms(
  programs,
  selection = process.env.FS_QUERY_INDEX_PROGRAMS ?? "",
  exact = process.env.FS_QUERY_INDEX_PROGRAMS_EXACT === "1",
) {
  const prefixes = selection.split(",").filter(Boolean);
  const selected = prefixes.length
    ? programs.filter((p) =>
        prefixes.some((prefix) => (exact ? p.id === prefix : p.id.startsWith(prefix))),
      )
    : programs;
  if (selected.length === 0) throw new Error("no program matches FS_QUERY_INDEX_PROGRAMS");
  return selected;
}

export const programDigest = (program) => sha256(JSON.stringify(program));

/** Normalization and request semantics a saved row depends on; a change makes it stale. */
export async function harnessDigest() {
  const sources = await Promise.all(
    ["harness.mjs", "session.mjs"].map((file) =>
      readFile(join(CONFORMANCE_DIR, "src/fs-query-index", file), "utf8"),
    ),
  );
  const indexes = await readFile(INDEXES, "utf8");
  return sha256(`${sources.join("\n")}\n${indexes}`);
}

/** Per recording: every step once; the harness gets its own budget for wipes and seeds. */
const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.length, 0),
  maxHarnessRequests: programs.reduce(
    (total, p) => total + 8 + 2 * Math.ceil((p.seed?.length ?? 0) / 500),
    20,
  ),
});

/** Private recordings must never be committable. */
async function assertIgnored(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  try {
    // Asked of the repository that contains the path (docs.local lives in the main checkout,
    // not in this worktree); a path in no repository cannot be committed at all.
    await execFileAsync("git", ["-C", path, "rev-parse", "--show-toplevel"]);
  } catch {
    return;
  }
  try {
    await execFileAsync("git", ["-C", path, "check-ignore", "-q", path]);
  } catch {
    throw new Error(`${path} is not ignored by git; private recordings must not be committable`);
  }
}

async function assertCleanTree() {
  const { stdout } = await execFileAsync(
    "git",
    ["status", "--porcelain", "--", ...LANE.sources, LANE.fixture, LANE.localConfig, LANE.indexes],
    { cwd: CONFORMANCE_DIR },
  );
  if (stdout.trim()) throw new Error(`record-production needs a clean tree:\n${stdout}`);
}

async function gitSha() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
    cwd: CONFORMANCE_DIR,
  });
  return stdout.trim();
}

/**
 * The private values the committed fixture must never contain: the sandbox project number
 * (FIREEMU_SANDBOX_PROJECT_NUMBER, kept outside the repository) and the ADC account.
 */
export async function privateValues() {
  const number = process.env.FIREEMU_SANDBOX_PROJECT_NUMBER ?? "";
  if (!/^[1-9]\d{5,}$/.test(number))
    throw new Error("FIREEMU_SANDBOX_PROJECT_NUMBER (the sandbox project number) is required");
  const described = await execFileAsync("gcloud", [
    "projects",
    "describe",
    SANDBOX_PROJECT,
    "--format=value(projectNumber)",
  ]);
  if (described.stdout.trim() !== number)
    throw new Error("FIREEMU_SANDBOX_PROJECT_NUMBER is not the sandbox project's number");
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "list",
    "--filter=status:ACTIVE",
    "--format=value(account)",
  ]);
  return [
    SANDBOX_PROJECT,
    number,
    ...stdout
      .split("\n")
      .map((a) => a.trim())
      .filter(Boolean),
  ];
}

async function accessToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

async function adminGet(path, token) {
  const response = await fetch(`${ADMIN_ORIGIN}/${path}`, {
    headers: {
      authorization: `Bearer ${token}`,
      "x-goog-user-project": SANDBOX_PROJECT,
    },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(`GET ${path}: HTTP ${response.status}`);
  return body;
}

const fieldKey = (field) =>
  `${field.fieldPath}:${field.order ?? ""}${field.arrayConfig ?? ""}${field.vectorConfig ? `vector${field.vectorConfig.dimension}` : ""}`;

/** The configured indexes of the sandbox database, in the file's canonical form. */
export async function productionIndexes(token) {
  const group = `projects/${SANDBOX_PROJECT}/databases/${DATABASE}/collectionGroups/-`;
  const composites = [];
  let pageToken = "";
  do {
    const page = await adminGet(
      `${group}/indexes${pageToken ? `?pageToken=${encodeURIComponent(pageToken)}` : ""}`,
      token,
    );
    composites.push(...(page.indexes ?? []));
    pageToken = page.nextPageToken ?? "";
  } while (pageToken);
  const overrides = [];
  pageToken = "";
  do {
    const page = await adminGet(
      `${group}/fields?filter=${encodeURIComponent("indexConfig.usesAncestorConfig:false")}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`,
      token,
    );
    overrides.push(...(page.fields ?? []));
    pageToken = page.nextPageToken ?? "";
  } while (pageToken);
  return { composites, overrides };
}

/**
 * An index in canonical text form. Production appends `__name__` in the direction of the last
 * field; the file may list it explicitly. Both forms are dropped when implied.
 */
export function indexKey(groupId, queryScope, fields) {
  const vector = fields.at(-1)?.vectorConfig ? fields.slice(-1) : [];
  let ordered = vector.length ? fields.slice(0, -1) : fields;
  const last = ordered.at(-1);
  if (last?.fieldPath === "__name__" && (ordered.length > 1 || vector.length)) {
    const implied = ordered.at(-2)?.order ?? "ASCENDING";
    if ((last.order ?? "ASCENDING") === implied) ordered = ordered.slice(0, -1);
  }
  return `${groupId}|${queryScope}|${[...ordered, ...vector].map(fieldKey).join(",")}`;
}

async function verifyIndexes() {
  const token = await accessToken();
  const expected = JSON.parse(await readFile(INDEXES, "utf8"));
  const { composites, overrides } = await productionIndexes(token);
  const wanted = expected.indexes
    .map((i) => indexKey(i.collectionGroup, i.queryScope, i.fields))
    .toSorted();
  const actual = composites
    .map((i) =>
      indexKey(i.name.split("/collectionGroups/")[1].split("/")[0], i.queryScope, i.fields),
    )
    .toSorted();
  const notReady = composites.filter((i) => i.state !== "READY").map((i) => i.name);
  const missing = wanted.filter((w) => !actual.includes(w));
  const extra = actual.filter((a) => !wanted.includes(a));
  // Field overrides compare by their full index list, in canonical form, and every one of their
  // indexes must be READY.
  const overrideKey = (group, path, indexes) =>
    `${group}:${path}=[${(indexes ?? [])
      .map((i) => `${i.queryScope}/${i.order ?? i.arrayConfig}`)
      .toSorted()
      .join(",")}]`;
  const actualOverrides = overrides
    .filter((o) => !o.name.includes("/collectionGroups/__default__/"))
    .map((o) => {
      const [group, path] = o.name.split("/collectionGroups/")[1].split("/fields/");
      const indexes = (o.indexConfig?.indexes ?? []).map((i) => ({
        queryScope: i.queryScope,
        order: i.fields?.[0]?.order,
        arrayConfig: i.fields?.[0]?.arrayConfig,
      }));
      notReady.push(
        ...(o.indexConfig?.indexes ?? []).filter((i) => i.state !== "READY").map(() => o.name),
      );
      return overrideKey(group, path, indexes);
    })
    .toSorted();
  const wantedOverrides = (expected.fieldOverrides ?? [])
    .map((o) => overrideKey(o.collectionGroup, o.fieldPath, o.indexes))
    .toSorted();
  const result = {
    composites: composites.length,
    notReady,
    missing,
    extra,
    actualOverrides,
    wantedOverrides,
  };
  console.log(JSON.stringify(result, null, 2));
  if (
    notReady.length ||
    missing.length ||
    extra.length ||
    !sameRecording(actualOverrides, wantedOverrides)
  )
    throw new Error(`sandbox indexes do not equal ${LANE.indexes}`);
}

/**
 * Whether the sandbox `(default)` database holds any document. The corpus wipes the whole
 * database around every program, so it records only into an empty one: a document there is
 * another lane's, or a failed run's, and must not be deleted unseen.
 */
async function databaseDocuments(token) {
  const response = await fetch(
    `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/${DATABASE}/documents:runQuery`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "x-goog-user-project": SANDBOX_PROJECT,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ allDescendants: true }],
          select: { fields: [{ fieldPath: "__name__" }] },
          limit: 1,
        },
      }),
    },
  );
  const body = await response.json();
  if (!response.ok) throw new Error(`runQuery: HTTP ${response.status}`);
  return body.filter((entry) => entry.document).map((entry) => entry.document.name);
}

/**
 * The checks before any production recording (owner directive 2026-09-24, oracle-query
 * shared rules): the `(default)` indexes equal the lane file, which holds every index of the
 * shared `conformance/firestore.indexes.json`, and are all READY; and the database is empty.
 * Read-only.
 */
async function preflight(token) {
  const shared = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "firestore.indexes.json"), "utf8"),
  );
  const lane = JSON.parse(await readFile(INDEXES, "utf8"));
  const key = (i) => indexKey(i.collectionGroup, i.queryScope, i.fields);
  const laneKeys = new Set(lane.indexes.map(key));
  const notInLane = shared.indexes.map(key).filter((k) => !laneKeys.has(k));
  if (notInLane.length) {
    throw new Error(`the lane index file lacks shared indexes: ${notInLane.join(", ")}`);
  }
  await verifyIndexes();
  const documents = await databaseDocuments(token);
  if (documents.length) {
    throw new Error(
      `the sandbox (default) database is not empty (${documents[0]}); record only into an empty database`,
    );
  }
  console.log(JSON.stringify({ preflight: "ok", database: DATABASE }, null, 2));
}

async function recordOnce(programs, run, token, projectNumber) {
  const ctx = createContext({
    run,
    target: {
      kind: "production",
      token,
      quotaProject: SANDBOX_PROJECT,
      projectNumber,
    },
  });
  return runCorpus(programs, ctx, {
    ...ceilings(programs),
    log: (line) => console.log(line),
  });
}

/**
 * Writes the committed fixture from two recordings. Kept separate from recording so that a
 * refusal here (for example by the secret scan) never loses a production run: the recordings
 * are saved privately first and `rebuild-fixture` can retry from them.
 */
async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Firestore REST v1 and gRPC google.firestore.v1, Standard edition, us-central1, database (default)",
    project: RECORDED_PROJECT,
    indexes: `conformance/${LANE.indexes}`,
    note: `Two recordings per program. Run-window times, execution durations, page and transaction tokens (also where an answer echoes a token the request carried) and the project id are placeholders; the project id is recorded as ${RECORDED_PROJECT} in every lane. Missing-index links keep their encoded index with the project id replaced. \`second\` holds the other recording of rows that differed.`,
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => !sameRecording(rec, one.steps[id])),
    );
    fixture.programs[program.id] = {
      corpusDigest: programDigest(program),
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      gitSha: meta.sha,
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  scanFixture(text, secrets);
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

/**
 * Runs `record` while holding `<ledger>.lock`, created exclusively: the lanes sharing the
 * sandbox `(default)` database each wipe all of it, so two recordings must never overlap. A
 * lock left by a crashed run names its lane and process and must be removed by hand.
 */
export async function withRecordingLock(ledger, lane, record) {
  const lock = `${ledger}.lock`;
  let handle;
  try {
    handle = await open(lock, "wx", 0o600);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const holder = await readFile(lock, "utf8").catch(() => "unknown");
    throw new Error(
      `another recording holds ${lock} (${holder.trim()}); both lanes wipe (default)`,
      { cause: error },
    );
  }
  try {
    await handle.writeFile(`${lane} pid ${process.pid} since ${new Date().toISOString()}\n`);
    await handle.close();
    return await record();
  } finally {
    await rm(lock, { force: true });
  }
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  if (!ledger) throw new Error("FIREEMU_SANDBOX_LEDGER is required");
  return withRecordingLock(ledger, LANE.id, recordProductionLocked);
}

async function recordProductionLocked() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_FS_QUERY_PRIVATE_DIR;
  if (!ledger || !privateRoot) {
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_FS_QUERY_PRIVATE_DIR are required");
  }
  await assertCleanTree();
  const programs = selectPrograms(PROGRAMS);
  const corpusRequests = validateCorpus(programs, LANE.id);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  const secrets = await privateValues();
  await assertIgnored(privateRoot);
  await assertIgnored(dirname(ledger));
  const runDir = join(privateRoot, `${LANE.id}-production-${meta.startedAt.replaceAll(":", "")}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const recordings = [];
  let outcome = "recorded";
  let error;
  const tokens = [];
  try {
    await preflight(await accessToken());
    for (const offset of [0, 1]) {
      const token = await accessToken();
      tokens.push(token);
      const recording = await recordOnce(
        programs,
        String(Date.now() + offset),
        token,
        process.env.FIREEMU_SANDBOX_PROJECT_NUMBER,
      );
      recordings.push(recording);
      await writeFile(join(runDir, `recording-${offset + 1}.json`), JSON.stringify(recording), {
        mode: 0o600,
      });
    }
  } catch (caught) {
    outcome = caught.fatal ? "aborted-fatal" : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) recordings.push(caught.partial);
  }
  await writeFile(join(runDir, "meta.json"), JSON.stringify({ ...meta, outcome, error }, null, 2), {
    mode: 0o600,
  });
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const failures = recordings.flatMap((r) => r.failures);
  try {
    if (!error) {
      const nondeterministic = await writeFixture({
        programs,
        recordings,
        meta,
        secrets: [...tokens, ...secrets],
      });
      if (failures.length) outcome = "recorded-with-program-failures";
      console.log(
        JSON.stringify(
          {
            programs: programs.length,
            corpusRequests,
            requests,
            nondeterministic,
            failures,
          },
          null,
          2,
        ),
      );
    }
  } catch (caught) {
    outcome = "not-written";
    error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
  } finally {
    await appendFile(
      ledger,
      `${JSON.stringify({
        ts: new Date().toISOString(),
        project: SANDBOX_PROJECT,
        database: DATABASE,
        gitSha: meta.sha,
        corpusDigest: sha256(JSON.stringify(programs)),
        requests,
        estimatedUsd: estimatedUsd(programs, recordings.length),
        outcome,
        taskId: TASK_ID,
        programs: meta.programs.length,
        runDir,
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

/**
 * A deliberate overestimate of one run's cost at Standard us-central1 list prices (reads
 * US$0.03, writes US$0.09, deletes US$0.01 per 100,000): every recorded step as 100 reads,
 * every seeded document written and deleted, per recording.
 */
export function estimatedUsd(programs, recordings) {
  const seeded = programs.reduce((n, p) => n + (p.seed?.length ?? 0), 0);
  const steps = programs.reduce((n, p) => n + p.steps.length, 0);
  const perRecording = (steps * 100 * 0.03 + seeded * 0.09 + seeded * 0.01) / 100_000;
  return Math.ceil(perRecording * Math.max(recordings, 1) * 10_000) / 10_000;
}

/**
 * Normalizes a saved raw recording again with the current harness. The raw request and
 * response of every step were saved privately, so a normalization change never needs a new
 * production observation. Steps without a raw answer (an unresolved dependency) keep their row.
 */
export function renormalize(recording, programs) {
  const ctx = createContext({
    run: recording.context.run,
    startedMs: recording.context.startedMs,
    target: {
      kind: "production",
      token: "renormalize",
      quotaProject: SANDBOX_PROJECT,
      projectNumber: process.env.FIREEMU_SANDBOX_PROJECT_NUMBER,
    },
  });
  const results = {};
  for (const program of programs) {
    const saved = recording.results[program.id];
    if (!saved) continue;
    const anchors = new Map();
    const steps = {};
    for (const step of program.steps) {
      const raw = saved.raw?.[step.id];
      steps[step.id] = raw ? normalizeStep(raw, ctx, anchors) : saved.steps[step.id];
    }
    results[program.id] = { steps };
  }
  return { ...recording, results };
}

/** Retries the fixture from a saved run directory; sends nothing to production. */
async function rebuildFixture(runDir, skipChanged) {
  const meta = JSON.parse(await readFile(join(runDir, "meta.json"), "utf8"));
  const recordings = await Promise.all(
    [1, 2].map(async (n) =>
      JSON.parse(await readFile(join(runDir, `recording-${n}.json`), "utf8")),
    ),
  );
  const recorded = PROGRAMS.filter((p) => meta.programs.includes(p.id));
  const changed = recorded.filter((p) => meta.corpusDigests?.[p.id] !== programDigest(p));
  if (recorded.length !== meta.programs.length || (changed.length && !skipChanged)) {
    throw new Error(`corpus changed since the recording: ${changed.map((p) => p.id).join(", ")}`);
  }
  // With --skip-changed, programs edited after this recording keep the rows a later recording
  // gave them; rebuild that later recording next.
  const programs = recorded.filter((p) => !changed.includes(p));
  const harness = await harnessDigest();
  const rebuilt =
    meta.harness === harness ? recordings : recordings.map((r) => renormalize(r, programs));
  const nondeterministic = await writeFixture({
    programs,
    recordings: rebuilt,
    meta: { ...meta, harness },
    secrets: await privateValues(),
  });
  console.log(
    JSON.stringify(
      {
        programs: programs.length,
        skipped: changed.map((p) => p.id),
        renormalized: meta.harness !== harness,
        nondeterministic,
      },
      null,
      2,
    ),
  );
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.FS_QUERY_INDEX_IN, "utf8"));
  const host = process.env.FIRESTORE_EMULATOR_HOST;
  if (!host) throw new Error("FIRESTORE_EMULATOR_HOST is not set");
  const url = new URL(`http://${host}`);
  const ctx = createContext({
    run: process.env.FS_QUERY_INDEX_RUN,
    target: {
      kind: "local",
      origin: url.origin,
      grpcHost: url.hostname,
      grpcPort: Number(url.port),
    },
  });
  const out = await runCorpus(programs, ctx, ceilings(programs));
  await writeFile(process.env.FS_QUERY_INDEX_OUT, JSON.stringify(out));
}

async function runLocal(programs) {
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, "programs.json");
  const outPath = join(RUN_DIR, "fireemu.json");
  await writeFile(inPath, JSON.stringify(programs));
  const binary = resolveFireemuBinary();
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      LOCAL_CONFIG,
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "firestore",
      "--firestore-port",
      "0",
      "--http-port",
      "0",
      "--storage-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      process.execPath,
      join(CONFORMANCE_DIR, "src/fs-query-index/run.mjs"),
      "session-local",
    ],
    {
      // The config's paths are relative to the repository root.
      cwd: REPO_ROOT,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        FS_QUERY_INDEX_IN: inPath,
        FS_QUERY_INDEX_OUT: outPath,
        FS_QUERY_INDEX_RUN: String(Date.now()),
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

export function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  // A server error production returned identically in both recordings (no `second` row) is
  // behavior, not noise: compare it, and fireemu's own 5xx with it.
  const repeatedServerError =
    alternative === undefined &&
    (production.status >= 500 || (production.transport === "grpc" && production.code === 13));
  const transient = (recorded) => isTransient(recorded) && !repeatedServerError;
  // Only production can be transient: fireemu is local, so its 5xx is a defect (MISMATCH).
  if ([production, alternative].some(transient)) return "INDETERMINATE";
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

async function check() {
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { programs: {} };
  const selected = selectPrograms(PROGRAMS);
  const harness = await harnessDigest();
  const local = await runLocal(selected);
  const rows = [];
  for (const program of selected) {
    const saved = fixture.programs[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) || saved.harnessDigest !== harness);
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      const row = `${program.id}#${step.id}`;
      let status = classify({ stale, production, alternative, fireemu });
      const decision =
        status === "MISMATCH" ? approvedDivergence(row, production, fireemu) : undefined;
      if (decision) status = "DIVERGENCE_APPROVED";
      rows.push({
        row,
        status,
        ...(decision ? { decision } : {}),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  // What S5 still requires across rows: the ranges add up on both sides, and fireemu's
  // partition cursors are in key order and nest from one count to the next.
  const { demote, rangeTotals } = crossRowChecks(rows);
  for (const row of rows) {
    if (demote.has(row.row) && row.status === "DIVERGENCE_APPROVED") {
      row.status = "MISMATCH";
      delete row.decision;
    }
  }
  const known = new Set(PROGRAMS.map((p) => p.id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, rangeTotals, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC", "DIVERGENCE_APPROVED"]);
  for (const row of rows.filter((r) => !passing.has(r.status))) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${String(JSON.stringify(row.production)).slice(0, 600)}`);
    console.log(`  fireemu    ${String(JSON.stringify(row.fireemu)).slice(0, 600)}`);
  }
  console.log(JSON.stringify({ summary, orphans, failures: local.failures }, null, 2));
  if (!rows.every((r) => passing.has(r.status)) || orphans.length || local.failures.length) {
    process.exitCode = 1;
  }
}

/** The paths where two recordings differ. */
export function differencePaths(production, fireemu) {
  const differences = [];
  const walk = (a, b, path) => {
    if (JSON.stringify(a) === JSON.stringify(b)) return;
    if (
      a &&
      b &&
      typeof a === "object" &&
      typeof b === "object" &&
      Array.isArray(a) === Array.isArray(b)
    ) {
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
        walk(a[key], b[key], `${path}.${key}`);
      return;
    }
    differences.push(path.slice(1));
  };
  walk(production, fireemu, "");
  return differences;
}

/**
 * Writes the committed closure evidence from the last `check`: the artifact, the fixture it
 * was compared with, and every row's classification (no response bodies).
 */
async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const fixtureSha256 = sha256(await readFile(FIXTURE, "utf8"));
  const evidence = {
    kind: `${LANE.id}-comparison-v1`,
    artifactSha256: comparison.artifactSha256,
    fixtureSha256,
    summary: comparison.summary,
    rangeTotals: comparison.rangeTotals,
    rows: comparison.rows.map(({ row, status, decision, production, fireemu }) =>
      status === "MISMATCH" || status === "DIVERGENCE_APPROVED"
        ? {
            row,
            status,
            ...(decision ? { decision } : {}),
            differences: differencePaths(production, fireemu),
          }
        : { row, status },
    ),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ out, summary: evidence.summary, fixtureSha256 }, null, 2));
}

const mode = process.argv[2];
if (import.meta.url === `file://${process.argv[1]}`) {
  if (mode === "verify-indexes") await verifyIndexes();
  else if (mode === "preflight") await preflight(await accessToken());
  else if (mode === "record-production") await recordProduction();
  else if (mode === "rebuild-fixture")
    await rebuildFixture(process.argv[3], process.argv[4] === "--skip-changed");
  else if (mode === "check") await check();
  else if (mode === "export-comparison") await exportComparison(process.argv[3]);
  else if (mode === "session-local") await sessionLocal();
  else if (mode === "local") {
    const local = await runLocal(selectPrograms(PROGRAMS));
    await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
    console.log(JSON.stringify({ requests: local.requests, failures: local.failures }, null, 2));
  } else {
    console.error(
      "usage: run.mjs verify-indexes|preflight|record-production|rebuild-fixture|check|export-comparison|local",
    );
    process.exitCode = 2;
  }
}
