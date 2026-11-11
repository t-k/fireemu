// Builds the evidence of the TASK-QUEUE-FUNCTIONS closure record from the committed recordings and comparisons, so that the
// record is derived and a test can require that it equals what the files say.
//
//   node closure-evidence.mjs --check    the record in spec/ equals the derived one
//   node closure-evidence.mjs --write    rewrites the record's evidence (the rest of the record is kept)
//
// A condition is VERIFIED when none of its cases is a mismatch, unknown or outside its timing in the run-versus-run comparison and
// in both strict-versus-recording comparisons, and it is not named in NOT_COMPARED below. Nothing here promotes the parent.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const RECORD = "spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json";
export const FILES = Object.freeze({
  pass1: "conformance/task-queue-production-pass-1.json",
  pass2: "conformance/task-queue-production-pass-2.json",
  local: "conformance/task-queue-production-local-strict.json",
  runs: "conformance/task-queue-production-run-comparison.json",
  strict1: "conformance/task-queue-production-strict-vs-pass-1.json",
  strict2: "conformance/task-queue-production-strict-vs-pass-2.json",
  knownDifferences: "conformance/src/task-queue-production/known-differences.mjs",
});

/** Conditions that no comparison can claim, with the reason (a ruling or a limit of the evidence). */
export const NOT_COMPARED = Object.freeze({
  "TASK-QUEUE-FUNCTIONS/queue-config-mapping":
    "The queue settings are read back with getQueue, which is the Cloud Tasks queue management API: neither fireemu nor the official emulator serves it (coordinator ruling 3). The settings read from production are recorded in both recordings (the queue-* cases) and their effects are compared by retry-backoff-schedule, retry-limits and max-concurrent-dispatches.",
  "TASK-QUEUE-FUNCTIONS/max-dispatches-per-second":
    "The program sent the eight tasks of the rate queue about 1.4 seconds apart in both production runs, so the limit never held a task back and no spacing or burst was observed; the local limiter spaces them one second apart. Rate and burst are not claimed (the rate cases carry no timing claim).",
  "TASK-QUEUE-FUNCTIONS/dedup-window-expiry":
    "The end of the reuse window was not observed: the window is documented as about one hour and strict under productionExact refuses a name for 3600 seconds after it finished or was deleted. A stage 2 packet of about 70 minutes would record the expiry; stage 1 leaves the refusal inside the window recorded, so the packet is recommended against unless the coordinator wants the length measured (ruling 4).",
});

const read = (path) => readFileSync(root + path);
const json = (path) => JSON.parse(read(path));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

export const countsOf = (rows) => {
  const counts = { MATCH: 0, MATCH_LAYOUT: 0, KNOWN_DIFFERENCE: 0, MISMATCH: 0, UNKNOWN: 0 };
  for (const row of rows) counts[row.structure] += 1;
  return counts;
};

const comparison = (path) => {
  const bytes = read(path);
  const document = JSON.parse(bytes);
  return {
    path,
    sha256: sha(bytes),
    rows: document.rows.length,
    summary: countsOf(document.rows),
    document,
  };
};

/**
 * One condition's evidence from the three comparison documents (`{ document: { rows } }` each): VERIFIED when every case of the
 * condition is found in the strict comparison and none of its rows, in any of the three, is a mismatch, an unknown or outside
 * its timing. A condition named in NOT_COMPARED is never verified.
 */
export function conditionEvidence(condition, { runs, strict1, strict2 }, productionEvidence) {
  const id = condition.conditionId;
  const base = { ...condition };
  for (const key of [
    "observedPasses",
    "passComparison",
    "comparisons",
    "knownDifferences",
    "profiles",
    "reason",
  ])
    delete base[key];
  if (condition.evidenceType !== "production-parity")
    return { ...base, status: "PLANNED", productionEvidence: [] };
  if (NOT_COMPARED[id])
    return { ...base, status: "NOT_COMPARED", productionEvidence, reason: NOT_COMPARED[id] };
  const keys = new Set(condition.corpusSteps ?? []);
  const rowsOf = (c) => c.document.rows.filter((row) => keys.has(row.case));
  const bad = [runs, strict1, strict2]
    .flatMap(rowsOf)
    .filter(
      (row) => ["MISMATCH", "UNKNOWN"].includes(row.structure) || row.timing.verdict === "OUTSIDE",
    );
  if (bad.length > 0 || rowsOf(strict1).length !== keys.size)
    return { ...base, status: "PLANNED", productionEvidence };
  const used = new Set();
  for (const row of [...rowsOf(strict1), ...rowsOf(strict2)])
    for (const part of Object.values(row.parts))
      for (const kd of part.knownDifferences ?? []) used.add(kd);
  for (const row of [...rowsOf(strict1), ...rowsOf(strict2)])
    if (row.timingKnownDifference) used.add(row.timingKnownDifference);
  return {
    ...base,
    status: "VERIFIED",
    productionEvidence,
    observedPasses: 2,
    passComparison: "MATCH",
    comparisons: {
      runVsRun: { rows: rowsOf(runs).length, counts: countsOf(rowsOf(runs)) },
      strictVsPass1: { rows: rowsOf(strict1).length, counts: countsOf(rowsOf(strict1)) },
      strictVsPass2: { rows: rowsOf(strict2).length, counts: countsOf(rowsOf(strict2)) },
    },
    knownDifferences: [...used].toSorted(),
    profiles: {
      strict: "MATCHES_RECORDED_CASES_WITH_PRODUCTION_EXACT",
      emulator: "NO_PRODUCTION_CLAIM",
    },
  };
}

/** The evidence derived from the committed files. */
export function derive(record) {
  const recordings = [
    { alias: "pass-1", file: FILES.pass1 },
    { alias: "pass-2", file: FILES.pass2 },
  ].map(({ alias, file }) => {
    const bytes = read(file);
    const recording = JSON.parse(bytes);
    return {
      alias,
      run: recording.run,
      envelope: recording.envelope,
      fixturePath: file,
      fixtureSha256: sha(bytes),
      corpusSha256: recording.corpusSha256,
      recorderRequests: recording.recorderRequests,
      observationComplete: recording.observationComplete,
      findings: recording.findings,
    };
  });
  const runs = comparison(FILES.runs);
  const strict1 = comparison(FILES.strict1);
  const strict2 = comparison(FILES.strict2);
  const local = { path: FILES.local, sha256: sha(read(FILES.local)) };
  const comparisons = {
    runVsRun: { path: runs.path, sha256: runs.sha256, rows: runs.rows, summary: runs.summary },
    strictVsPass1: {
      path: strict1.path,
      sha256: strict1.sha256,
      rows: strict1.rows,
      summary: strict1.summary,
    },
    strictVsPass2: {
      path: strict2.path,
      sha256: strict2.sha256,
      rows: strict2.rows,
      summary: strict2.summary,
    },
    localStrictReplay: local,
  };
  const knownDifferences = {
    path: FILES.knownDifferences,
    sha256: sha(read(FILES.knownDifferences)),
    entries: strict1.document.knownDifferences.map((kd) => kd.id),
  };
  const productionEvidence = recordings.map(({ alias, fixturePath, fixtureSha256 }) => ({
    alias,
    fixturePath,
    fixtureSha256,
  }));
  const conditions = record.conditions.map((condition) =>
    conditionEvidence(condition, { runs, strict1, strict2 }, productionEvidence),
  );
  return {
    recordings,
    comparisons,
    knownDifferences,
    conditions,
    recordingPolicy: { observedPasses: 2, requiredPasses: 2, waiver: null },
  };
}

const ADDED_LIMITATIONS = Object.freeze([
  "Two production recordings (stage 1) back the verified conditions; the parent stays IMPLEMENTING until an independent review approves the record.",
  "The reuse window of a task id is refused for 3600 seconds under strict productionExact (documented as about one hour); its expiry was not observed.",
  "The production default queue retries 100 times; fireemu's strict profile keeps the retry configuration the function declares and the official emulator's default for one that declares none (a known difference, not a claim).",
]);

export const applyEvidence = (record) => {
  const evidence = derive(record);
  const kept = record.limitations.filter(
    (text) =>
      !ADDED_LIMITATIONS.includes(text) &&
      !/No production observation exists yet|task reuse window is documented/.test(text),
  );
  return {
    ...record,
    conditions: evidence.conditions,
    recordings: evidence.recordings,
    recordingPolicy: evidence.recordingPolicy,
    comparisons: evidence.comparisons,
    knownDifferences: evidence.knownDifferences,
    limitations: [ADDED_LIMITATIONS[0], ...kept, ...ADDED_LIMITATIONS.slice(1)],
  };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const record = json(RECORD);
  const next = applyEvidence(record);
  if (process.argv[2] === "--write")
    writeFileSync(root + RECORD, JSON.stringify(next, null, 2) + "\n");
  else if (process.argv[2] === "--check") {
    if (JSON.stringify(next) !== JSON.stringify(record))
      throw new Error(`${RECORD} is not what the committed evidence derives`);
  } else throw new Error("--check | --write");
}
