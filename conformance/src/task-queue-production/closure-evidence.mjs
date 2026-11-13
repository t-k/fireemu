// Builds the evidence of the TASK-QUEUE-FUNCTIONS closure record from the committed recordings and comparisons, so that the
// record is derived and a test can require that it equals what the files say.
//
//   node closure-evidence.mjs --check    the record in spec/ equals the derived one
//   node closure-evidence.mjs --write    rewrites the record's evidence (the rest of the record is kept)
//
// A condition is VERIFIED when none of its cases is a mismatch, unknown or outside its timing in the run-versus-run comparison and
// in both strict-versus-recording comparisons, and it is not named in NOT_COMPARED below. The coordinator decides the parent status.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { compareBurst } from "./burst-compare.mjs";

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
  burstProduction: "conformance/task-queue-production-burst-pass-1.json",
  burstLocal: "conformance/task-queue-production-burst-local-strict.json",
  burstComparison: "conformance/task-queue-production-burst-strict-vs-pass-1.json",
  burstProduction2: "conformance/task-queue-production-burst-pass-2.json",
  burstComparison2: "conformance/task-queue-production-burst-strict-vs-pass-2.json",
  burstRuns: "conformance/task-queue-production-burst-run-comparison.json",
});

/**
 * The tests that verify the fireemu-only condition `local-controls`: each local control of the task queue and the named test of
 * the repository that exercises it. `closure-evidence --check` requires every named test to exist.
 */
export const LOCAL_CONTROLS = Object.freeze([
  {
    control: "virtual clock",
    file: "crates/fireemu-adapter-functions/tests/runtime.rs",
    test: "virtual_task_exact_retry_expiry_retires_rate_wait_and_long_backoff",
  },
  {
    control: "virtual clock",
    file: "crates/fireemu-adapter-functions/tests/task_strict_admission.rs",
    test: "a_finished_name_is_held_for_exactly_the_window_on_the_virtual_clock",
  },
  {
    control: "virtual clock",
    file: "crates/fireemu-adapter-functions/tests/task_strict_admission.rs",
    test: "the_retry_gaps_of_a_failing_task_follow_production_after_a_dozen_failures_in_strict",
  },
  {
    control: "Run now",
    file: "crates/fireemu-adapter-functions/tests/task_schedule_time.rs",
    test: "run_now_releases_a_waiting_task_and_only_the_named_one",
  },
  {
    control: "Run now",
    file: "crates/fireemu-adapter-functions/src/task_scheduler.rs",
    test: "run_now_releases_a_task_before_its_schedule_time_and_only_that_task",
  },
  {
    control: "queue statistics",
    file: "crates/fireemu-adapter-functions/src/task_scheduler.rs",
    test: "queue_statistics_report_pending_work_and_rate_limits",
  },
  {
    control: "queue statistics",
    file: "crates/fireemu-adapter-functions/src/task_scheduler.rs",
    test: "queue_statistics_history_is_bounded_when_queue_stats_is_never_read",
  },
  {
    control: "await-idle scope",
    file: "crates/fireemu-adapter-functions/tests/task_schedule_time.rs",
    test: "runnable_idle_retains_future_tasks_without_dispatch_or_schedule_mutation",
  },
  {
    control: "memory limits",
    file: "crates/fireemu-adapter-functions/src/task_scheduler.rs",
    test: "completed_name_history_is_bounded_by_bytes_as_well_as_count",
  },
  {
    control: "memory limits",
    file: "crates/fireemu-adapter-functions/src/task_scheduler.rs",
    test: "the_history_of_finished_names_holds_exactly_the_count_and_the_bytes_it_is_bounded_by",
  },
  {
    control: "memory limits",
    file: "crates/fireemu-adapter-functions/tests/task_strict_admission.rs",
    test: "the_task_size_counts_the_decoded_body_and_the_headers_against_one_mebibyte",
  },
  {
    control: "Host guard",
    file: "crates/fireemu-adapter-functions/tests/app_check_callable.rs",
    test: "the_functions_and_support_listeners_refuse_a_rebound_host",
  },
  {
    control: "bearer refusal",
    file: "crates/fireemu-adapter-functions/tests/strict_task_bearer.rs",
    test: "a_task_to_a_callable_in_code_needs_a_bearer_a_callable_request_would_accept",
  },
  {
    control: "name lifecycle",
    file: "crates/fireemu-adapter-functions/src/task_scheduler.rs",
    test: "a_name_is_free_live_or_finished_and_a_finished_one_is_released_by_the_reuse_rule",
  },
  {
    control: "listener",
    file: "crates/fireemu-adapter-functions/tests/task_strict_admission.rs",
    test: "the_strict_listener_deletes_with_json_and_refuses_other_methods",
  },
]);

/** What `final-artifact-regression` rests on: the release run that reproduces the three comparisons on the packed binary. */
export const REGRESSION = Object.freeze({
  run: "R38",
  runner: "conformance/src/release-strict-regression.mjs",
  replay: "conformance/src/task-queue-production/release-replay.mjs",
  judge: "conformance/src/task-queue-production/release-judge.mjs",
  tests: [
    "conformance/src/task-queue-production/release-judge.test.mjs",
    "conformance/src/release-strict-regression.test.mjs",
    "conformance/src/task-queue-production/strict-replay.test.mjs",
  ],
  workflow: ".github/workflows/conformance.yml",
  workflowStep: "strict replay of the task queue recordings",
  releaseWorkflow: ".github/workflows/release.yml",
  releaseDependencies: "npm ci --prefix conformance/task-queue-functions/functions",
});

/** Conditions that no comparison can claim, with the reason (a ruling or a limit of the evidence). */
export const NOT_COMPARED = Object.freeze({
  "TASK-QUEUE-FUNCTIONS/queue-config-mapping":
    "The queue settings are read back with getQueue, which is the Cloud Tasks queue management API: neither fireemu nor the official emulator serves it (coordinator ruling 3). The settings read from production are recorded in both recordings (the queue-* cases) and their effects are compared by retry-backoff-schedule, retry-limits and max-concurrent-dispatches.",
  "TASK-QUEUE-FUNCTIONS/dedup-window-expiry":
    "The end of the reuse window was not observed: the window is documented as about one hour and strict under productionExact refuses a name for 3600 seconds after it finished or was deleted. A stage 2 packet of about 70 minutes would record the expiry; stage 1 leaves the refusal inside the window recorded, so the packet is recommended against unless the coordinator wants the length measured (ruling 4).",
});

const read = (path) => readFileSync(root + path);
const json = (path) => JSON.parse(read(path));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The burst projections must be complete recordings (production) or a strict replay (local) of the burst program. */
function checkedProjection(bytes, local = false) {
  const p = JSON.parse(bytes);
  if (
    p.kind !== "task-queue-burst-projection-v1" ||
    p.program !== "burst" ||
    p.tasks !== 120 ||
    p.observationComplete !== true ||
    (local && p.profile !== "strict")
  )
    throw new Error("invalid burst projection");
  return p;
}

/** A committed comparison must rebuild from its projections and match. */
function checkedComparison(bytes, a, b) {
  const comparison = JSON.parse(bytes);
  if (!isDeepStrictEqual(comparison, compareBurst(a, b)) || comparison.verdict !== "MATCH")
    throw new Error("burst comparison differs from its projections or does not match");
  return comparison;
}

/**
 * max-dispatches-per-second from the burst program: VERIFIED only with two production recordings that agree with each other
 * (run against run) and each agree with the strict replay. Each comparison's cadence tolerance is the production side's own
 * spread plus 250 ms (burst-compare.mjs). One recording that matches is reported as one pass, never verified.
 */
export function burstEvidence(readFile = read) {
  const evidence = [];
  const comparisons = [];
  try {
    const p1Bytes = readFile(FILES.burstProduction);
    evidence.push({ path: FILES.burstProduction, sha256: sha(p1Bytes) });
    const local = checkedProjection(readFile(FILES.burstLocal), true);
    const p1 = checkedProjection(p1Bytes);
    const c1Bytes = readFile(FILES.burstComparison);
    checkedComparison(c1Bytes, p1, local);
    comparisons.push({ path: FILES.burstComparison, sha256: sha(c1Bytes), verdict: "MATCH" });
    let p2Bytes;
    try {
      p2Bytes = readFile(FILES.burstProduction2);
    } catch {
      return {
        status: "NOT_COMPARED",
        productionEvidence: evidence,
        reason:
          "One pass: the strict replay matches the 2026-11-13 burst recording (burst, cadence, count); the second recording is pending.",
      };
    }
    evidence.push({ path: FILES.burstProduction2, sha256: sha(p2Bytes) });
    const p2 = checkedProjection(p2Bytes);
    const runsBytes = readFile(FILES.burstRuns);
    checkedComparison(runsBytes, p1, p2);
    const c2Bytes = readFile(FILES.burstComparison2);
    checkedComparison(c2Bytes, p2, local);
    comparisons.unshift({ path: FILES.burstRuns, sha256: sha(runsBytes), verdict: "MATCH" });
    comparisons.push({ path: FILES.burstComparison2, sha256: sha(c2Bytes), verdict: "MATCH" });
    return {
      status: "VERIFIED",
      productionEvidence: evidence,
      observedPasses: 2,
      comparisons,
      knownDifferences: [
        {
          id: "KD-BURST-LOCAL-START",
          what: "The strict replay starts the burst earlier after the due time than production did (local 24-56 ms; production 153-214 and 128-170 ms), inside each comparison's cadence tolerance (the production pass's own spread plus 250 ms).",
          bound: "the cadence tolerance of each strict comparison",
          ruling: 21,
        },
      ],
    };
  } catch {
    return {
      status: "NOT_COMPARED",
      productionEvidence: evidence,
      reason:
        "The burst comparisons are missing, invalid, do not rebuild from their projections, or do not match.",
    };
  }
}

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
export function conditionEvidence(
  condition,
  { runs, strict1, strict2 },
  productionEvidence,
  {
    localTests = LOCAL_CONTROLS,
    testExists = repositoryTestExists,
    regressionHolds = repositoryRegressionHolds,
    closureReview,
    burst = burstEvidence,
  } = {},
) {
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
  for (const key of ["localEvidence", "regressionEvidence", "reviewEvidence"]) delete base[key];
  if (condition.evidenceType === "fireemu-only") {
    // A control is verified by the tests that exercise it, all of which must exist; it makes no claim about production.
    if (localTests.length > 0 && localTests.every(({ file, test }) => testExists(file, test)))
      return { ...base, status: "VERIFIED", productionEvidence: [], localEvidence: localTests };
    return { ...base, status: "PLANNED", productionEvidence: [] };
  }
  if (condition.evidenceType === "closure-gate") {
    // The release regression is verified once its run, replay, judge, tests and workflow steps exist; the review is the coordinator's.
    if (
      id.endsWith("/closure-review") &&
      closureReview?.decision === "APPROVED" &&
      closureReview.reviews?.length > 0
    )
      return {
        ...base,
        status: "VERIFIED",
        productionEvidence: [],
        reviewEvidence: closureReview.reviews.map(
          ({ reportPath, reportSha256, reviewedCommit, outcome }) => ({
            ...(reportPath === undefined ? {} : { reportPath }),
            ...(reportSha256 === undefined ? {} : { reportSha256 }),
            reviewedCommit,
            outcome,
          }),
        ),
      };
    if (id.endsWith("/final-artifact-regression") && regressionHolds(REGRESSION))
      return {
        ...base,
        status: "VERIFIED",
        productionEvidence: [],
        regressionEvidence: REGRESSION,
      };
    return { ...base, status: "PLANNED", productionEvidence: [] };
  }
  if (id === "TASK-QUEUE-FUNCTIONS/max-dispatches-per-second") return { ...base, ...burst() };
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
const repositoryText = (file) => {
  try {
    return readFileSync(root + file, "utf8");
  } catch {
    return null;
  }
};

/** Whether a Rust test function of that name is defined in that file. */
export const repositoryTestExists = (file, test) =>
  new RegExp(`\\bfn ${test}\\b`).test(repositoryText(file) ?? "");

/** Whether every file the regression names exists and the run and the workflow steps are wired. */
export function repositoryRegressionHolds(regression) {
  const files = [regression.runner, regression.replay, regression.judge, ...regression.tests];
  if (files.some((file) => repositoryText(file) === null)) return false;
  return (
    repositoryText(regression.runner).includes(`taskQueueRun("${regression.run}")`) &&
    (repositoryText(regression.workflow) ?? "").includes(regression.workflowStep) &&
    (repositoryText(regression.releaseWorkflow) ?? "").includes(regression.releaseDependencies)
  );
}

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
  const localBytes = read(FILES.local);
  const local = {
    path: FILES.local,
    sha256: sha(localBytes),
    binarySha256: JSON.parse(localBytes).binarySha256 ?? null,
  };
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
    conditionEvidence(condition, { runs, strict1, strict2 }, productionEvidence, {
      closureReview: record.closureReview,
    }),
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
  "Two production recordings (stage 1) back the verified conditions; the parent is COMPAT_VERIFIED for the recorded cases after an independent closure review and a delta review (closureReview).",
  "The reuse window of a task id is refused for 3600 seconds under strict productionExact (`functions.taskNameReuse` `production`, documented as about one hour); its expiry was not observed. The default profile frees a finished name at once, and an explicit key wins over productionExact.",
  "Production's default queue retry config comes from a recording: the default queue of a function that declared no retry options read back (getQueue, both runs) with maxAttempts 100, minBackoff 0.100 s, maxBackoff 3600 s and maxDoublings 16 and no maxRetryDuration, the Cloud Tasks documentation's defaults. `functions.taskRetryDefaults` `production` (selected by productionExact) fills maxAttempts 100 for a field the function does not declare; the default profile keeps the official emulator's 3 attempts, and a declared value is always kept.",
  "Production's retry gaps grew past the declared maxBackoff in both runs (queue tqwindow, maxBackoff 2 s, 100 attempts: 1 s, then ten gaps of 2 s, then 4 s three times, 8 s twice and 10 s from the seventeenth gap on). `functions.taskRetryBackoff` `production` (selected by productionExact) follows that schedule as a floor under the declared gap, and the comparison claims every gap of the shorter side. Not recorded: how the growth depends on the declared maxBackoff (no other queue of the program failed twelve times), whether it depends on the elapsed time, and the gaps after the observation ended; the length of the observation differs between runs, which is the observation-window known difference (ruling 16).",
  "Strict delivers an `Authorization: Bearer` identity token of three segments to a task that named an `oidcToken`, so that `request.auth` is present in an `onTaskDispatched` handler as in production. The emulator issues it unsigned (`alg: none`, an empty third segment) with Google's claim names: only the scheme, the segment count and the presence of `request.auth` are production's, not the signature or the values (rulings 17 and 23). The handler and its timers see `FUNCTIONS_EMULATOR=\"true\"` (ruling 22).",
  "The strict FUNCTIONS_EMULATOR hide covers the next read inside a dispatch scope, which is the SDK's request.auth check; an onInit callback that reads FUNCTIONS_EMULATOR during the first dispatch would take that read (coordinator re-check of ruling 22, 2026-11-12).",
  "The answers of createTask, deleteTask and the refusals are printed as production printed them (two-space JSON in proto field order with a newline at the end, `<`, `>` and `&` escaped, `application/json; charset=UTF-8`), including the `details` of an argument error; the order of the members of `headers` varied between production's runs and is not compared. The byte length is not compared because the task's URL differs (rulings 18 and 24). getTask stays 405 in strict under KD-QUEUE-READS (rulings 3 and 24).",
  "A strict createTask whose body is not JSON is refused with 400, which production does not do (a task body is any bytes); the daemon needs a JSON body to deliver to an `onTaskDispatched` function. A refusal of that kind is not a recorded production answer.",
  "The emulator profile is unchanged by this closure: it keeps the official emulator's answers, plain-text refusals, header shape, 100 KiB request limit, forever-kept names and retry defaults (ruling 20).",
]);

/** The scope decision TQ-TIMING as answered by the comparison. */
const TIMING_DECISION =
  "A time-dependent condition is compared by bounds that two recordings support (a lower bound, an upper bound, an order, a count), never by exact equality. The first delivery is compared by how late it started after the time the task was due (the ETA header), which removes the service's rounding of the create time to whole seconds and the latency of the create call; each retry gap is compared within 1.5 s up to the shorter side of a queue observed for as long as the run lasted. A timing known difference must carry a bound (ruling 21).";

const AUTHORITY =
  "owner ledger 2417 (closure parent approved), 2459 (start); coordinator rulings of 2026-11-11 (1 to 11) and 2026-11-12 (12 to 21: per-key development defaults, the retry defaults and gaps, the identity token, the answer layout, the emulator profile unchanged)";

const FOLLOW_UPS = Object.freeze([
  "Rate and burst: a burst-send probe of a queue limited to one dispatch per second (ruling 14), tracked in docs.local/issues/open/task-queue-rate-burst-probe.md.",
  "Recorder follow-ups S1 to S6 of the presend review and the CLI write parser fix, to be made before any further packet (ruling 15), tracked in docs.local/issues/open/task-queue-recorder-follow-ups.md.",
]);

/** The release regression block of the record; parentStatus and closureReview are the coordinator's. */
function integratedRegression(comparisons) {
  const entry = (c) => ({ path: c.path, sha256: c.sha256, rows: c.rows, summary: c.summary });
  return {
    status: "OFFLINE_PASS",
    suite: "conformance/src/task-queue-production/strict-replay.test.mjs",
    matrix: "conformance/TASK-QUEUE-MATRIX.md",
    scope:
      "the 122-step program served by the strict profile under productionExact against the two production recordings (comparisons)",
    comparisons: [comparisons.runVsRun, comparisons.strictVsPass1, comparisons.strictVsPass2].map(
      entry,
    ),
    productionRequests: 0,
    result: "COMPARED_ON_RECORDED_CORPUS_WITH_KNOWN_DIFFERENCES",
    strictReplay: {
      test: "conformance/src/task-queue-production/strict-replay.test.mjs",
      command:
        "FIREEMU_BIN=<fireemu> node --test conformance/src/task-queue-production/strict-replay.test.mjs",
      requires:
        "the structure verdicts of every row equal the committed ones, with productionExact set (local.mjs does)",
    },
    releaseBindingNote: `Run ${REGRESSION.run} of ${REGRESSION.runner} reproduces the three comparisons on the packed binary (strict profile, productionExact, loopback only), judged by ${REGRESSION.judge}: the same cases with the same structure and parts, no mismatch, no unknown, no timing outside twice the committed tolerance, both concurrency properties MATCH, and the comparison of the two recordings equal to the committed one. The conformance workflow runs the same replay on a fresh build (conformance.yml, step "${REGRESSION.workflowStep}").`,
  };
}

export const applyEvidence = (record) => {
  const evidence = derive(record);
  const owned = (text) =>
    ADDED_LIMITATIONS.includes(text) ||
    /No production observation exists yet|^Two production recordings \(stage 1\) back the verified conditions|task reuse window is documented|^The reuse window of a task id is refused|^The production default queue retries 100 times|^Production's default queue retry config|^Production's retry gaps grew|^Strict delivers an `Authorization|^The answers of createTask|^A strict createTask whose body|^The emulator profile is unchanged/.test(
      text,
    );
  const kept = record.limitations.filter((text) => !owned(text));
  return {
    ...record,
    authority: AUTHORITY,
    scopeDecisions: record.scopeDecisions.map((decision) =>
      decision.id === "TQ-TIMING"
        ? { ...decision, status: "ANSWERED", decision: TIMING_DECISION }
        : decision,
    ),
    conditions: evidence.conditions,
    recordings: evidence.recordings,
    recordingPolicy: evidence.recordingPolicy,
    comparisons: evidence.comparisons,
    knownDifferences: evidence.knownDifferences,
    integratedRegression: integratedRegression(evidence.comparisons),
    followUps: [...FOLLOW_UPS],
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
