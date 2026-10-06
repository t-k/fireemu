// The release comparison of the strict profile with the committed production recordings.
//
//   FIREEMU_BIN=<installed fireemu> FIREEMU_NODE=<Node 22.22.1> \
//     node conformance/src/release-strict-regression.mjs --out <dir> [--dist <npm dist dir>]
//
// Every parent whose closure is COMPAT_VERIFIED names, in `integratedRegression`, the
// comparison files one release binary produced against its saved production recordings. This
// script reruns those local comparisons on the binary under test, from the repository root,
// and requires each result to equal the committed file: the same rows, each with the same
// status and the same row summary (differences, decisions, relabels), the same fixture and the
// same totals. R11 additionally reclassifies its retained raw replay using the pinned original
// corpus: a removed legacy mismatch requires a complete canonical match, and the original
// indeterminate set must remain exact. Its supplied summary must agree with that recomputation.
// Nothing is sent to production: the recording modes are not in the command table,
// production and sandbox credentials refuse the run, and the run refuses to start while a
// production endpoint answers (the release job runs it in a network namespace with loopback
// only). The comparisons that need private inputs are listed in EXCLUDED_PARTS with the issue
// that tracks them.
//
// The runs are sequential: several harnesses listen on fixed loopback ports (32291-32298,
// 32320-32322).
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { copyFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

import {
  historicalProductionSummary,
  historicalProductionBaseline,
  probeProfileBindingProblems,
  pinnedProductionIndexAuthority,
} from "./firestore-probe/run.mjs";
import { federationEnvironment } from "./release-openssl.mjs";
import { bindingProblems } from "./harness-registry.mjs";
import { EXPECTED_ACTIONS, localSetupDigest } from "./harness-target/local-tenancy.mjs";
import { findPackagedRunner, packagedRunnerCandidates } from "./packaged-runner.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const CONFORMANCE = join(ROOT, "conformance");
const RUNS_DIR = join(CONFORMANCE, ".runs");
const CLOSURE_DIR = "spec/compatibility/closure";
const COMMAND_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_ANNOTATIONS = 50;

/** The only harness modes this script may invoke: all of them local. */
export const ALLOWED_MODES = new Set([
  "check",
  "export-comparison",
  "local-child",
  "compare-local",
  "check-production",
  "check-local",
]);

/** Environment that belongs to production or sandbox recording; its presence refuses the run. */
const FORBIDDEN_ENV_NAMES = new Set([
  "FIREEMU_SANDBOX_LEDGER",
  "FIREEMU_AUTH_SANDBOX_WEB_CONFIG",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "FIREEMU_PRODUCTION_TOKEN",
  "FIREEMU_PRODUCTION_PROJECT",
  // Names a runner of its own: the gate runs the runner the package ships.
  "FIREEMU_RUNNER_NODE",
]);
const FORBIDDEN_ENV_PATTERNS = [/^FIREEMU_.*_PRIVATE_DIR$/, /^CLOUDSDK_/];

/** Production endpoints the harnesses' SDKs would reach if a local target were missed. */
export const PRODUCTION_ORIGINS = [
  "https://firestore.googleapis.com/",
  "https://identitytoolkit.googleapis.com/",
];

/**
 * A lane run: the harness's `check`, then its `export-comparison`. `rowPrefix` names the rows of
 * the comparison files this run serves when one kind has several runs (see planComparisons);
 * `extraArgs` (a corpus packet) follow the mode in both commands.
 */
const laneRun = (
  id,
  kind,
  script,
  runDir,
  expectedCheckExit,
  env = {},
  { rowPrefix, extraArgs = [] } = {},
) => ({
  id,
  kind,
  ...(rowPrefix === undefined ? {} : { rowPrefix }),
  clear: [runDir],
  commands: [
    {
      mode: "check",
      argv: ["node", script, "check", ...extraArgs],
      env,
      expectedExitCodes: [expectedCheckExit],
    },
    {
      mode: "export-comparison",
      argv: ["node", script, "export-comparison", ...extraArgs, "{export}"],
      env,
      expectedExitCodes: [0],
    },
  ],
});

/**
 * The comparisons the closures name, each rerun by one entry. `{bin}`, `{export}` and `{runDir}`
 * are filled in when the entry runs; `{functionsNode}` is FIREEMU_NODE.
 */
export const RUNS = [
  laneRun(
    "R1",
    "fs-query-index-comparison-v1",
    "conformance/src/fs-query-index/run.mjs",
    "fs-query-index",
    0,
  ),
  laneRun(
    "R2",
    "fs-data-write-list-comparison-v1",
    "conformance/src/fs-query-index/run.mjs",
    "fs-data-write-list",
    0,
    { FIREEMU_SANDBOX_LANE: "fs-data-write-list" },
  ),
  laneRun(
    "R3",
    "fs-config-lifecycle-comparison-v1",
    "conformance/src/fs-config-lifecycle/run.mjs",
    "fs-config-lifecycle",
    0,
  ),
  {
    // The local tenant setup runs outside the recorded harness (harness-target/local-tenancy.mjs),
    // so the export must say what it did.
    ...laneRun("R4", "fs-rules-comparison-v1", "conformance/src/fs-rules/run.mjs", "fs-rules", 0),
    localSetup: true,
  },
  laneRun(
    "R5",
    "auth-account-comparison-v1",
    "conformance/src/auth-account/run.mjs",
    "auth-account",
    0,
  ),
  laneRun(
    "R6",
    "auth-credential-comparison-v1",
    "conformance/src/auth-credential/run.mjs",
    "auth-credential",
    0,
  ),
  laneRun(
    "R7",
    "auth-action-comparison-v1",
    "conformance/src/auth-action/run.mjs",
    "auth-action",
    0,
  ),
  laneRun("R8", "auth-mfa-comparison-v1", "conformance/src/auth-mfa/run.mjs", "auth-mfa", 0),
  // The eight MISMATCH rows of AUTH-CONFIG-SDK are owner-approved, so its check exits 1.
  laneRun(
    "R9",
    "auth-config-sdk-comparison-v1",
    "conformance/src/auth-config-sdk/run.mjs",
    "auth-config-sdk",
    1,
  ),
  // AUTH-TENANT-BLOCKING: one kind, two suites, each its own run (AUTH_TENANT_SUITE). The blocking
  // suite serves the Functions fixture from the checkout (its dependencies are installed by the
  // job). Both suites run the packaged runner beside the binary under test and refuse to run
  // without it (AUTH_TENANT_PACKAGED_RUNNER): the checkout's runner would not show a module
  // missing from the package.
  laneRun(
    "R13",
    "auth-tenant-blocking-comparison-v1",
    "conformance/src/auth-tenant-blocking/run.mjs",
    "auth-tenant-blocking",
    0,
    { AUTH_TENANT_SUITE: "tenant", AUTH_TENANT_PACKAGED_RUNNER: "1" },
    { rowPrefix: "atb/tenant/" },
  ),
  laneRun(
    "R14",
    "auth-tenant-blocking-comparison-v1",
    "conformance/src/auth-tenant-blocking/run.mjs",
    "auth-tenant-blocking",
    0,
    { AUTH_TENANT_SUITE: "blocking", AUTH_TENANT_PACKAGED_RUNNER: "1" },
    { rowPrefix: "atb/blocking/" },
  ),
  // AUTH-FEDERATION: the comparison script (not the recording harness) runs each corpus packet.
  laneRun(
    "R15",
    "auth-federation-comparison-v1",
    "conformance/src/auth-federation/compare.mjs",
    "auth-federation",
    0,
    {},
    { extraArgs: ["record-oidc"] },
  ),
  laneRun(
    "R16",
    "auth-federation-saml-comparison-v1",
    "conformance/src/auth-federation/compare.mjs",
    "auth-federation",
    0,
    {},
    { extraArgs: ["record-saml"] },
  ),
  laneRun(
    "R17",
    "auth-federation-followup-comparison-v1",
    "conformance/src/auth-federation/compare.mjs",
    "auth-federation",
    0,
    {},
    { extraArgs: ["record-followup"] },
  ),
  {
    // FS-DATA-WRITE's sandbox corpus against the binary under test, called directly: the lane's
    // local checker builds target/debug/fireemu, and the runner is bound to the lane evidence.
    id: "R10",
    kind: "fs-data-write-integrated-regression",
    part: "current",
    clear: ["fs-data-write-local-*"],
    commands: [
      {
        mode: "local-child",
        argv: [
          "{bin}",
          "exec",
          "--config",
          "conformance/fs-data-write-sandbox.fireemu.json",
          "--project",
          "fireemu-oracle-sbx",
          "--only",
          "firestore",
          "--firestore-port",
          "0",
          "--http-port",
          "0",
          "--storage-port",
          "0",
          "--hub-port",
          "0",
          "--logging-port",
          "0",
          "--",
          "node",
          "conformance/src/fs-data-write-sandbox-run.mjs",
          "local-child",
        ],
        env: {},
        expectedExitCodes: [0],
      },
      {
        mode: "compare-local",
        argv: [
          "node",
          "conformance/src/fs-data-write-sandbox-run.mjs",
          "compare-local",
          "{runDir}",
        ],
        env: {},
        expectedExitCodes: [0],
      },
    ],
  },
  {
    // The pinned historical production corpus of FS-DATA-WRITE, replayed without production.
    id: "R11",
    kind: "fs-data-write-integrated-regression",
    part: "historical",
    clear: ["firestore-probe"],
    commands: [
      {
        mode: "check-production",
        argv: [
          "node",
          "conformance/src/firestore-probe/run.mjs",
          "check-production",
          "--profile",
          "strict",
        ],
        // The request timeout of the production recording (run.mjs): the replay must outwait the
        // strict contention wait, or a held writer's answer is cut to "no-response".
        env: { FIRESTORE_PROBE_TIMEOUT_MS: "60000" },
        expectedExitCodes: [0],
      },
    ],
  },
  {
    // FUNCTIONS-HTTP's production recordings are private; the local recording must be the same
    // bytes the lane compared with them, which fixes every row's result.
    id: "R12",
    kind: "functions-http-integrated-regression",
    clear: ["functions-http"],
    commands: [
      {
        mode: "check-local",
        argv: ["{functionsNode}", "conformance/functions-http/run.mjs", "check-local"],
        env: {},
        functionsNodeOnPath: true,
        expectedExitCodes: [0],
      },
    ],
  },
  {
    // AUTH-FS-CROSS stage 1, the unary conditions; stage 2 is a 61-minute real-time window.
    ...laneRun(
      "R18",
      "auth-fs-cross-comparison-v1",
      "conformance/src/auth-fs-cross/run.mjs",
      "auth-fs-cross",
      0,
    ),
    localSetup: true,
  },
];

/** Composite comparison files: which part each run covers. Other keys are metadata. */
const COMPOSITE_KINDS = {
  "fs-data-write-integrated-regression": ["schemaVersion", "kind", "binarySha256"],
};

/** Parts of a comparison file the release does not rerun, with why and where it is tracked. */
export const EXCLUDED_PARTS = [
  {
    kind: "fs-data-write-integrated-regression",
    part: "savedStreamTransaction",
    condition: "FS-DATA-WRITE/stream-transaction-precedence",
    reason:
      "the saved 23-row stream transaction replay reads a production receipt that is not published; the condition stays on the lane evidence",
    issue: "fs-data-write-saved-stream-comparison-needs-private-receipt.md",
  },
  {
    kind: "fs-data-write-integrated-regression",
    part: "emulatorProfile",
    scope: "emulator-profile",
    reason:
      "the emulator profile rows are not a strict production comparison; the emulator profile is gated by verify-artifact",
  },
];

/**
 * Comparison kinds a COMPAT_VERIFIED closure names that no run reproduces yet, with why and where
 * the missing run is tracked (owner decision 2026-09-29: v0.9.0 is released with these disclosed).
 * Every other comparison a verified closure names is rerun. A kind here must not also have a run,
 * and must be named by a verified closure.
 */
export const EXCLUDED_KINDS = [
  {
    kind: "scheduled-functions-calendar-comparison-v1",
    reason:
      "The calendar rows were compared on the v0.13.0 closure-base release binary against two private v6 journals; publishing the recordings and adding installed-binary release check/export modes is required before the release job can replay them",
    issue: "scheduled-functions-calendar-comparison-needs-release-replay.md",
  },
  {
    kind: "scheduled-functions-comparison-v1",
    reason:
      "The delivery table was rerun on the v0.13.0 closure-base release binary and bound to its SHA-256 and runner manifest; the producer still needs installed-binary release check/export modes before the release job can replay it",
    issue: "scheduled-functions-delivery-comparison-needs-release-replay.md",
  },
  {
    kind: "functions-events-comparison",
    reason:
      "the comparison pairs the local answers of the Functions runner with frames of the two passes of one private production recording (FE v7) that is not published, made by a harness that drives a deployed Functions codebase through the Node runner and the Admin SDKs; the recordings must be published and the harness given a check and an export-comparison mode before the release job can rerun it; the rows were compared on the release binary of the integration commit named by the closure",
    issue: "functions-events-comparison-needs-the-recordings-in-the-release-job.md",
  },
  {
    kind: "auth-fs-cross-stage2-comparison-v1",
    reason:
      "the stage-2 local window keeps production's timeline in real time (about 61 minutes on the v0.9.0 final artifact) and drives a browser client, which the 45-minute release job and its runner do not allow; the local tenant setup is no longer a reason (it runs outside the recorded harness), and the rows were compared on the final artifact",
    issue: "auth-fs-cross-stage2-needs-a-long-release-job.md",
  },
  {
    kind: "storage-rules-comparison-v2",
    reason:
      "the 3,641 strict rows are the local answers to two private production recordings (stage3 runs c and d) that are not published, collected by a comparison tool kept outside this tree; the recordings and the tool must be published before the release job can rerun them; the rows were compared on the closure-base binary named by the closure",
    issue: "storage-rules-strict-comparison-needs-the-recordings-in-the-release-job.md",
  },
  {
    kind: "storage-rules-management-comparison-v1",
    reason:
      "the management comparison pairs the local answers with frozen projections of the same private production recordings and runs the management programs under a local setup of the recorded sandbox; the projections are not published and the runner has no check and export-comparison mode; the rows were compared on the closure-base binary named by the closure",
    issue: "storage-rules-management-comparison-needs-the-projections-in-the-release-job.md",
  },
  {
    kind: "storage-object-comparison-v1",
    reason:
      "the comparison is made from a rehearsal of the STORAGE-OBJECT recorder (26 recipes, 2,436 exchanges) that lives on its own branch and not in this tree, and it runs under a Rules file kept outside the repository; both must be published and the tool given a check and an export-comparison mode before the release job can rerun it; the rows were compared on the closure-base binary named by the closure",
    issue: "storage-object-comparison-needs-the-recorder-in-the-release-job.md",
  },
];

/**
 * The runs that serve one comparison file. A kind whose runs declare a `rowPrefix` has several
 * files, each served by the one run whose prefix begins every row of the file; a file with none,
 * or with more than one, is an error and yields `undefined`. The other kinds are served by all
 * their runs (a composite file has several parts).
 */
function runsForComparison(allRuns, kind, document, path, errors) {
  const ofKind = allRuns.filter((run) => run.kind === kind);
  if (!ofKind.some((run) => run.rowPrefix !== undefined)) return ofKind;
  const ids = (document?.rows ?? []).map(rowKey);
  const covering =
    ids.length === 0
      ? []
      : ofKind.filter((run) => ids.every((id) => String(id).startsWith(run.rowPrefix ?? "")));
  if (covering.length === 0) {
    errors.push(`${path}: no run of kind ${kind} has a row prefix covering every row of the file`);
    return undefined;
  }
  if (covering.length > 1) {
    errors.push(
      `${path}: more than one run of kind ${kind} covers it (${covering.map((run) => run.id).join(", ")})`,
    );
    return undefined;
  }
  return covering;
}

/** Errors in a list of kind exclusions: a missing reason or issue, or a kind a run reproduces. */
function exclusionErrors(excludedKinds, runs) {
  const errors = [];
  for (const exclusion of excludedKinds) {
    const kind = exclusion.kind;
    if (typeof exclusion.reason !== "string" || exclusion.reason.length <= 20) {
      errors.push(`excluded kind ${kind}: no reason`);
    }
    if (typeof exclusion.issue !== "string" || !/^[a-z0-9-]+\.md$/.test(exclusion.issue)) {
      errors.push(`excluded kind ${kind}: no issue named by file name`);
    }
    if (runs.some((run) => run.kind === kind)) {
      errors.push(`excluded kind ${kind}: a run reproduces it`);
    }
  }
  return errors;
}

/**
 * Why the binary under test is not an installed package, or undefined: the gate runs the runner
 * the package ships beside the binary, and a build under target/ has none.
 */
export function packagedRunnerError(binary, lookup) {
  if (findPackagedRunner(binary, lookup) !== undefined) return undefined;
  return `no packaged runner beside ${binary} (${packagedRunnerCandidates(binary, lookup?.realpath).join(", ")}); run the installed package, not a build`;
}

/** The environment variables that refuse the run. */
export function forbiddenEnvironment(env) {
  return Object.keys(env)
    .filter(
      (name) => FORBIDDEN_ENV_NAMES.has(name) || FORBIDDEN_ENV_PATTERNS.some((re) => re.test(name)),
    )
    .toSorted();
}

/** Fails when any production endpoint answers: the run needs a network with loopback only. */
export async function assertNoOutboundNetwork(fetchImpl, origins = PRODUCTION_ORIGINS) {
  const reached = [];
  for (const origin of origins) {
    try {
      await fetchImpl(origin, { signal: AbortSignal.timeout(5000), redirect: "manual" });
      reached.push(origin);
    } catch {
      // Refused, unresolvable or timed out: not reachable, as required.
    }
  }
  if (reached.length > 0) {
    throw new Error(
      `production reached (${reached.join(", ")}); run inside a loopback-only network namespace`,
    );
  }
}

/** Every harness mode the command table uses. */
export function commandModes(runs) {
  return [...new Set(runs.flatMap((run) => run.commands.map((command) => command.mode)))];
}

export function parseArguments(args) {
  const parsed = { out: undefined, dist: undefined };
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    const value = args[index + 1];
    if (name !== "--out" && name !== "--dist") throw new Error(`unknown argument ${name}`);
    if (!value || value.startsWith("--")) throw new Error(`${name} needs a value`);
    parsed[name.slice(2)] = value;
    index += 1;
  }
  if (!parsed.out)
    throw new Error("usage: release-strict-regression.mjs --out <dir> [--dist <dir>]");
  return parsed;
}

const parentName = ({ name, closure }) => closure.parent ?? name.replace(/\.json$/, "");

/**
 * The comparison files every COMPAT_VERIFIED closure names, each with the runs that reproduce
 * it, and the ones of an excluded kind. A closure without an integrated regression, a
 * comparison of a kind no run produces and no exclusion names, a part of a composite file that
 * is neither run nor excluded, and a malformed or unused exclusion are errors.
 */
export function planComparisons(
  closures,
  readJson,
  { excludedKinds = EXCLUDED_KINDS, runs: allRuns = RUNS } = {},
) {
  const errors = exclusionErrors(excludedKinds, allRuns);
  const byPath = new Map();
  for (const entry of closures) {
    if (entry.closure.parentStatus !== "COMPAT_VERIFIED") continue;
    const parent = parentName(entry);
    const comparisons = entry.closure.integratedRegression?.comparisons;
    if (!Array.isArray(comparisons) || comparisons.length === 0) {
      errors.push(`${parent}: COMPAT_VERIFIED without integratedRegression comparisons`);
      continue;
    }
    for (const { path } of comparisons) {
      if (!byPath.has(path)) byPath.set(path, new Set());
      byPath.get(path).add(parent);
    }
  }
  const planned = [];
  const excluded = [];
  const usedExclusions = new Set();
  for (const [path, parents] of byPath) {
    const document = readJson(path);
    const kind = document?.kind;
    const runs = runsForComparison(allRuns, kind, document, path, errors);
    if (runs === undefined) continue;
    if (runs.length === 0) {
      const exclusion = excludedKinds.find((ex) => ex.kind === kind);
      if (exclusion) {
        usedExclusions.add(kind);
        excluded.push({
          path,
          kind,
          parents: [...parents].toSorted(),
          reason: exclusion.reason,
          issue: exclusion.issue,
        });
      } else {
        errors.push(`${path}: no run produces comparisons of kind ${kind}`);
      }
      continue;
    }
    if (COMPOSITE_KINDS[kind]) {
      const metadata = new Set(COMPOSITE_KINDS[kind]);
      for (const part of Object.keys(document)) {
        if (metadata.has(part)) continue;
        const covered = runs.some((run) => run.part === part);
        const excluded = EXCLUDED_PARTS.some((ex) => ex.kind === kind && ex.part === part);
        if (!covered && !excluded) errors.push(`${path}: part ${part} is neither run nor excluded`);
      }
    }
    planned.push({ path, kind, parents: [...parents].toSorted(), runIds: runs.map((r) => r.id) });
  }
  for (const exclusion of excludedKinds) {
    if (!usedExclusions.has(exclusion.kind)) {
      errors.push(`excluded kind ${exclusion.kind}: no verified closure names it`);
    }
  }
  return { comparisons: planned, excluded, errors };
}

/**
 * The plan of the release comparison, and the errors of the harness binding: the recorded rows
 * are only comparable if their harness digests are still bound, and a shallow clone cannot
 * verify the lineage, so it stops here (the release job checks out the whole history).
 */
export function planRelease(closures, readJson, { binding = bindingProblems } = {}) {
  const plan = planComparisons(closures, readJson);
  plan.errors.push(...binding().map((problem) => `harness binding: ${problem}`));
  return plan;
}

const brief = (value) => {
  const text = JSON.stringify(value);
  return text === undefined ? "undefined" : text.length > 300 ? `${text.slice(0, 300)}...` : text;
};

const rowKey = (row) => row?.row ?? row?.id;

/**
 * A run that prepared the local target outside the recorded harness must say so: the export names
 * the digest of the helper that did it and exactly the changes it made and read back.
 */
export function localSetupDifferences(actual) {
  const setup = actual?.localSetup;
  if (!setup || typeof setup !== "object") return ["localSetup: the export names no local setup"];
  const differences = [];
  if (setup.digest !== localSetupDigest())
    differences.push(
      `localSetup.digest: expected ${localSetupDigest()} got ${brief(setup.digest)}`,
    );
  if (!isDeepStrictEqual(setup.actions, EXPECTED_ACTIONS))
    differences.push(
      `localSetup.actions: expected ${brief(EXPECTED_ACTIONS)} got ${brief(setup.actions)}`,
    );
  const extra = Object.keys(setup).filter((key) => key !== "digest" && key !== "actions");
  if (extra.length) differences.push(`localSetup: unexpected ${extra.join(", ")}`);
  return differences;
}

/** Differences between a lane export and the committed comparison file. */
export function compareLaneExport(expected, actual, binarySha256) {
  if (!actual || typeof actual !== "object" || !Array.isArray(actual.rows)) {
    return ["no comparison was exported"];
  }
  const differences = [];
  for (const field of ["kind", "fixtureSha256", "summary"]) {
    if (!isDeepStrictEqual(expected[field], actual[field])) {
      differences.push(`${field}: expected ${brief(expected[field])} got ${brief(actual[field])}`);
    }
  }
  if ("rangeTotals" in expected && !isDeepStrictEqual(expected.rangeTotals, actual.rangeTotals)) {
    differences.push(
      `rangeTotals: expected ${brief(expected.rangeTotals)} got ${brief(actual.rangeTotals)}`,
    );
  }
  if (actual.artifactSha256 !== binarySha256) {
    differences.push(`artifactSha256 ${actual.artifactSha256} is not the binary under test`);
  }
  const committed = new Map(expected.rows.map((row) => [rowKey(row), row]));
  const seen = new Set();
  for (const row of actual.rows) {
    const key = rowKey(row);
    if (seen.has(key)) {
      differences.push(`${key}: exported twice`);
      continue;
    }
    seen.add(key);
    if (!committed.has(key)) differences.push(`${key}: not in the committed comparison`);
    else if (!isDeepStrictEqual(committed.get(key), row)) {
      differences.push(`${key}: expected ${brief(committed.get(key))} got ${brief(row)}`);
    }
  }
  for (const key of committed.keys()) {
    if (!seen.has(key)) differences.push(`${key}: missing from the export`);
  }
  return differences;
}

const sameSet = (a, b) =>
  Array.isArray(a) &&
  Array.isArray(b) &&
  a.length === b.length &&
  a.every((item) => b.includes(item));

const expectEqual = (differences, label, expected, actual) => {
  if (!isDeepStrictEqual(expected, actual)) {
    differences.push(`${label}: expected ${brief(expected)} got ${brief(actual)}`);
  }
};

const RUNNER_INPUTS = [
  "conformance/src/fs-data-write-sandbox-run.mjs",
  "conformance/src/firestore-probe/sandbox-session.mjs",
];

/** FS-DATA-WRITE's local sandbox comparison against `current` of the regression file. */
export function judgeFsDataWriteCurrent(expected, observed, laneRuntimeInputs) {
  const differences = [];
  expectEqual(differences, "compare-local exit code", 0, observed.exitCode);
  const result = observed.result;
  if (!result || typeof result !== "object") return [...differences, "no compare-local result"];
  expectEqual(differences, "corpusDigest", expected.corpusSha256, result.corpusDigest);
  expectEqual(
    differences,
    "recordedCorpusDigest",
    expected.recordedCorpusSha256,
    result.recordedCorpusDigest,
  );
  expectEqual(
    differences,
    "comparedPrograms",
    expected.comparedRestPrograms,
    result.comparedPrograms,
  );
  expectEqual(differences, "comparedStreams", expected.comparedGrpcStreams, result.comparedStreams);
  expectEqual(differences, "pendingRestIds", [], result.pendingRestIds);
  expectEqual(differences, "pendingStreamIds", [], result.pendingStreamIds);
  if (!sameSet(expected.retiredRestIds, result.retiredRestIds)) {
    differences.push(`retiredRestIds: got ${brief(result.retiredRestIds)}`);
  }
  expectEqual(
    differences,
    "retiredStreamIds",
    expected.retiredStreamIds ?? [],
    result.retiredStreamIds,
  );
  expectEqual(differences, "mismatches", 0, result.mismatches);
  for (const path of RUNNER_INPUTS) {
    expectEqual(
      differences,
      `runner input ${path}`,
      laneRuntimeInputs[path],
      observed.runtimeInputs?.[path],
    );
  }
  return differences;
}

/** FS-DATA-WRITE's historical production replay against `historical` of the regression file. */
export function judgeFsDataWriteHistorical(expected, observed, binarySha256) {
  const differences = [];
  expectEqual(differences, "check-production exit code", 0, observed.exitCode);
  const result = observed.result;
  if (!result || typeof result !== "object") return [...differences, "no historical comparison"];
  expectEqual(differences, "probe cwd", CONFORMANCE, result.profileBinding?.cwd);
  expectEqual(
    differences,
    "probe source config",
    join(CONFORMANCE, "firestore-probe.fireemu.json"),
    result.profileBinding?.config?.sourcePath,
  );
  differences.push(
    ...probeProfileBindingProblems(
      result.profileBinding,
      "strict",
      binarySha256,
      sha256Bytes(readFileSync(join(CONFORMANCE, "firestore-probe.fireemu.json"))),
      pinnedProductionIndexAuthority(
        readFileSync(join(CONFORMANCE, "firestore-production-matrix.json")),
      ),
    ),
  );
  expectEqual(
    differences,
    "recorded index fixture",
    join(CONFORMANCE, "firestore-production.indexes.json"),
    result.profileBinding?.indexes?.sourcePath,
  );
  expectEqual(differences, "binary before", binarySha256, result.artifact?.sha256Before);
  expectEqual(differences, "binary after", binarySha256, result.artifact?.sha256After);
  try {
    if (!observed.raw || typeof observed.raw.bytesBase64 !== "string")
      throw new Error("no retained historical raw comparands");
    const bytes = Buffer.from(observed.raw.bytesBase64, "base64");
    if (
      bytes.toString("base64") !== observed.raw.bytesBase64 ||
      sha256Bytes(bytes) !== observed.raw.sha256 ||
      result.localRawSha256 !== observed.raw.sha256
    )
      throw new Error("historical raw digest mismatch");
    if (!observed.comparison || typeof observed.comparison.bytesBase64 !== "string")
      throw new Error("no collected historical comparison snapshot");
    const comparisonBytes = Buffer.from(observed.comparison.bytesBase64, "base64");
    if (
      comparisonBytes.toString("base64") !== observed.comparison.bytesBase64 ||
      sha256Bytes(comparisonBytes) !== observed.comparison.sha256 ||
      !isDeepStrictEqual(parseUniqueJson(comparisonBytes.toString("utf8")), result)
    )
      throw new Error("historical comparison snapshot mismatch");
    const live = parseUniqueJson(bytes.toString("utf8"));
    const summary = historicalProductionSummary(live);
    for (const [key, value] of Object.entries(summary))
      expectEqual(differences, `recomputed ${key}`, value, result[key]);
    expectEqual(differences, "comparable", expected.comparable, summary.comparable);
    const committed = JSON.parse(
      readFileSync(
        join(
          ROOT,
          "spec/compatibility/closure/evidence/integration-v0.8.0/FS-DATA-WRITE-regression.json",
        ),
      ),
    ).historical;
    expectEqual(differences, "historical expected authority", committed, expected);
    expectEqual(
      differences,
      "legacy known count",
      expected.knownMismatches,
      expected.rows.length - expected.indeterminate,
    );
    // Replaying the recorded baseline through the same classifier establishes its exact debt partition.
    const original = historicalProductionBaseline();
    expectEqual(
      differences,
      "indeterminate",
      expected.indeterminate,
      original.indeterminate.length,
    );
    if (
      new Set(expected.rows).size !== expected.rows.length ||
      !expected.rows.every((key) =>
        [...original.baselineMismatches, ...original.indeterminate].includes(key),
      )
    )
      differences.push("original historical row partition mismatch");
    expectEqual(
      differences,
      "retained indeterminate",
      original.indeterminate,
      summary.indeterminate,
    );
    if (!summary.currentMismatches.every((key) => expected.rows.includes(key)))
      differences.push("unlisted current historical mismatch");
    expectEqual(differences, "newMismatches", [], summary.newMismatches);
    expectEqual(differences, "newIndeterminate", [], summary.newIndeterminate);
  } catch (error) {
    differences.push(`historical raw proof: ${error.message}`);
  }
  return differences;
}

// JSON.parse alone silently overwrites duplicate keys; inspect every object before accepting bytes.
function parseUniqueJson(text) {
  const value = JSON.parse(text);
  const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}[\]:,]|[^\s{}[\]:,]+/g);
  let at = 0;
  function visit() {
    const token = tokens[at++];
    if (token === "{") {
      const keys = new Set();
      while (tokens[at] !== "}") {
        const key = JSON.parse(tokens[at++]);
        if (keys.has(key)) throw new Error("duplicate historical JSON key");
        keys.add(key);
        if (tokens[at++] !== ":") throw new Error("invalid historical object");
        visit();
        if (tokens[at] !== ",") break;
        at++;
      }
      at++;
    } else if (token === "[") {
      while (tokens[at] !== "]") {
        visit();
        if (tokens[at] !== ",") break;
        at++;
      }
      at++;
    }
  }
  visit();
  return value;
}

export async function collectHistoricalReplay(runDir, outDir) {
  const summaryPath = join(runDir, "historical-production-comparison.json");
  const rawPath = join(runDir, "fireemu-historical-production.json");
  const comparisonBytes = existsSync(summaryPath) ? await readFile(summaryPath) : undefined;
  const rawBytes = existsSync(rawPath) ? await readFile(rawPath) : undefined;
  if (comparisonBytes)
    await writeFile(join(outDir, "R11-historical-production-comparison.json"), comparisonBytes);
  if (rawBytes) await writeFile(join(outDir, "R11-fireemu-historical-production.json"), rawBytes);
  return {
    result: comparisonBytes ? parseUniqueJson(comparisonBytes.toString("utf8")) : undefined,
    comparison: comparisonBytes ? historicalRawObservation(comparisonBytes) : undefined,
    raw: rawBytes ? historicalRawObservation(rawBytes) : undefined,
  };
}

export function historicalRawObservation(bytes) {
  return { bytesBase64: bytes.toString("base64"), sha256: sha256Bytes(bytes) };
}

const caseCount = (recording) =>
  Object.values(recording ?? {}).reduce(
    (total, cases) => total + Object.keys(cases ?? {}).length,
    0,
  );

/** The FUNCTIONS-HTTP stand-in: the local strict recording is the lane's bytes. */
export function judgeFunctionsHttp(expected, observed) {
  const differences = [];
  expectEqual(differences, "check-local exit code", 0, observed.exitCode);
  const strict = expected.runs.find((run) => run.profile === "strict");
  expectEqual(
    differences,
    "strict recording sha256",
    strict?.recordingSha256,
    observed.outputSha256,
  );
  expectEqual(differences, "Functions runtime Node", expected.nodeVersion, observed.nodeVersion);
  expectEqual(
    differences,
    "fixture index.js",
    expected.fixtureIndexSha256,
    observed.fixtureIndexSha256,
  );
  expectEqual(
    differences,
    "fixture package-lock.json",
    expected.fixturePackageLockSha256,
    observed.fixturePackageLockSha256,
  );
  if (!/^\s*profile: strict\b/m.test(observed.log ?? "")) {
    differences.push("the daemon did not report the strict profile");
  }
  const recordings = observed.output?.recordings;
  if (!Array.isArray(recordings) || recordings.length !== 2) {
    return [...differences, "the local run did not record the corpus twice"];
  }
  if (!isDeepStrictEqual(recordings[0], recordings[1])) {
    differences.push("the two local recordings differ");
  }
  expectEqual(differences, "recorded cases", expected.totalCases, caseCount(recordings[0]));
  return differences;
}

// --- execution --------------------------------------------------------------------------------

const sha256Bytes = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sha256File = async (path) => sha256Bytes(await readFile(path));

const fill = (argv, values) =>
  argv.map((arg) => arg.replace(/\{(\w+)\}/g, (match, name) => values[name] ?? match));

async function clearRunDirs(patterns) {
  let names = [];
  try {
    names = await readdir(RUNS_DIR);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  for (const pattern of patterns) {
    const matches = pattern.endsWith("*")
      ? names.filter((name) => name.startsWith(pattern.slice(0, -1)))
      : names.filter((name) => name === pattern);
    for (const name of matches) await rm(join(RUNS_DIR, name), { recursive: true, force: true });
  }
}

/** Processes still running the binary under test. */
function leftoverProcesses(binary) {
  const pids = [];
  if (process.platform === "linux") {
    for (const entry of readdirSync("/proc")) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        if (realpathSync(`/proc/${entry}/exe`) === binary) pids.push(Number(entry));
      } catch {
        // Gone, or not ours to read.
      }
    }
  }
  return pids;
}

function killGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch {
    // The group has already exited.
  }
}

/** Runs one command in its own process group, with a deadline, logging to `logPath`. */
async function runCommand(argv, env, cwd, logPath) {
  const started = Date.now();
  const child = spawn(argv[0], argv.slice(1), {
    cwd,
    env,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const append = (chunk) => {
    output += chunk;
  };
  child.stdout.setEncoding("utf8").on("data", append);
  child.stderr.setEncoding("utf8").on("data", append);
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    killGroup(child.pid, "SIGKILL");
  }, COMMAND_TIMEOUT_MS);
  const exitCode = await new Promise((done) => {
    child.once("error", (error) => {
      append(`${error.stack}\n`);
      done(-1);
    });
    child.once("close", (code, signal) => done(code ?? (signal ? 128 : -1)));
  });
  clearTimeout(timer);
  killGroup(child.pid, "SIGKILL");
  await writeFile(logPath, output);
  return { exitCode: timedOut ? "timeout" : exitCode, ms: Date.now() - started, output };
}

const lastJsonLine = (text) => {
  const lines = text.trim().split("\n");
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      return JSON.parse(lines[index]);
    } catch {
      // Not the result line.
    }
  }
  return undefined;
};

const readJsonFile = async (path) => JSON.parse(await readFile(path, "utf8"));

export async function runEntry(run, context) {
  const record = { id: run.id, kind: run.kind, part: run.part, commands: [], errors: [] };
  const values = {
    bin: context.binary,
    functionsNode: context.functionsNode,
    export: join(context.out, `${run.id}-export.json`),
    runDir: "",
  };
  const outputs = [];
  let runEnv;
  try {
    runEnv = federationEnvironment(run.id, context.env);
  } catch (error) {
    record.errors.push(error.message);
    return { record, outputs, values };
  }
  await clearRunDirs(run.clear);
  for (const [index, command] of run.commands.entries()) {
    if (!ALLOWED_MODES.has(command.mode) || !command.argv.includes(command.mode)) {
      throw new Error(`${run.id}: mode ${command.mode} is not allowed`);
    }
    const argv = fill(command.argv, values);
    const env = { ...runEnv, ...command.env };
    if (command.functionsNodeOnPath) {
      env.PATH = `${dirname(context.functionsNode)}:${env.PATH}`;
    }
    const logPath = join(context.out, "logs", `${run.id}-${index + 1}-${command.mode}.log`);
    const result = await runCommand(argv, env, ROOT, logPath);
    outputs.push(result.output);
    record.commands.push({ mode: command.mode, argv, exitCode: result.exitCode, ms: result.ms });
    if (!command.expectedExitCodes.includes(result.exitCode)) {
      record.errors.push(
        `${command.mode} exited ${result.exitCode}, expected ${command.expectedExitCodes.join(" or ")}`,
      );
    }
    if (command.mode === "local-child") {
      const runDir = lastJsonLine(result.output)?.runDir;
      if (
        typeof runDir !== "string" ||
        !resolve(runDir).startsWith(join(RUNS_DIR, "fs-data-write-local-"))
      ) {
        record.errors.push("local-child did not name a run directory under conformance/.runs");
        break;
      }
      values.runDir = resolve(runDir);
    }
  }
  const leftovers = leftoverProcesses(context.binary);
  for (const pid of leftovers) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  if (leftovers.length > 0) record.errors.push(`fireemu processes were left running: ${leftovers}`);
  return { record, outputs, values };
}

async function observe(run, entry, context) {
  const { record, outputs, values } = entry;
  const lastExit = record.commands.at(-1)?.exitCode;
  if (run.id === "R10") {
    const inputs = {};
    for (const path of RUNNER_INPUTS) inputs[path] = await sha256File(join(ROOT, path));
    const result = lastJsonLine(outputs.at(-1) ?? "");
    const raw = {};
    if (values.runDir) {
      for (const name of ["rest-results.json", "stream-results.json"]) {
        const path = join(values.runDir, name);
        if (existsSync(path)) raw[name] = await sha256File(path);
      }
    }
    if (result) {
      await writeFile(
        join(context.out, "R10-compare-local.json"),
        `${JSON.stringify(result, null, 2)}\n`,
      );
    }
    return {
      exitCode: record.commands.length === 2 ? lastExit : "not run",
      result,
      runtimeInputs: inputs,
      raw,
    };
  }
  if (run.id === "R11") {
    return {
      exitCode: lastExit,
      ...(await collectHistoricalReplay(join(RUNS_DIR, "firestore-probe"), context.out)),
    };
  }
  if (run.id === "R12") {
    const line = lastJsonLine(outputs.at(-1) ?? "");
    const outputPath = line?.output;
    const bytes = outputPath && existsSync(outputPath) ? await readFile(outputPath) : undefined;
    const fixture = join(CONFORMANCE, "functions-http", "fixtures");
    const version = await runCommand(
      [context.functionsNode, "--version"],
      context.env,
      ROOT,
      join(context.out, "logs", "R12-node-version.log"),
    );
    return {
      exitCode: lastExit,
      outputSha256: bytes ? sha256Bytes(bytes) : undefined,
      output: bytes ? JSON.parse(bytes.toString("utf8")) : undefined,
      nodeVersion: version.output.trim(),
      fixtureIndexSha256: await sha256File(join(fixture, "index.js")),
      fixturePackageLockSha256: await sha256File(join(fixture, "package-lock.json")),
      log: outputs.at(-1),
    };
  }
  const path = values.export;
  return existsSync(path) ? await readJsonFile(path) : undefined;
}

export function judge(comparison, observations, context) {
  const expected = context.readJson(comparison.path);
  if (comparison.kind === "fs-data-write-integrated-regression") {
    const lane = context.readJson(expected.current.laneComparisonPath);
    return [
      ...judgeFsDataWriteCurrent(expected.current, observations.R10, lane.runtimeInputs).map(
        (d) => `current: ${d}`,
      ),
      ...judgeFsDataWriteHistorical(
        expected.historical,
        observations.R11,
        context.binarySha256,
      ).map((d) => `historical: ${d}`),
    ];
  }
  if (comparison.kind === "functions-http-integrated-regression") {
    return judgeFunctionsHttp(expected, observations.R12);
  }
  const observed = observations[comparison.runIds[0]];
  const run = RUNS.find((r) => r.id === comparison.runIds[0]);
  return [
    ...compareLaneExport(expected, observed, context.binarySha256),
    ...(run?.localSetup ? localSetupDifferences(observed) : []),
  ];
}

/**
 * The exports to keep under the comparison files' names: one copy per comparison file served by
 * a run that exports a comparison. Several files of one kind share a run's export, so a file
 * name maps to its own copy rather than one per run.
 */
export function exportCopies(comparisons, runs) {
  const exporting = new Set(
    runs
      .filter((run) => run.commands.some((command) => command.mode === "export-comparison"))
      .map((run) => run.id),
  );
  return comparisons
    .filter((comparison) => exporting.has(comparison.runIds[0]))
    .map((comparison) => ({
      from: `${comparison.runIds[0]}-export.json`,
      to: comparison.path.split("/").at(-1),
    }));
}

const annotate = (title, message) => {
  const clean = (text) =>
    String(text).replaceAll("%", "%25").replaceAll("\r", "").replaceAll("\n", " ");
  console.log(`::error title=${clean(title)}::${clean(message)}`);
};

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const forbidden = forbiddenEnvironment(process.env);
  if (forbidden.length > 0) throw new Error(`refusing to run with ${forbidden.join(", ")} set`);
  const binaryPath = process.env.FIREEMU_BIN;
  const functionsNode = process.env.FIREEMU_NODE;
  if (!binaryPath || !functionsNode) throw new Error("FIREEMU_BIN and FIREEMU_NODE are required");
  const binary = realpathSync(resolve(binaryPath));
  const notPackaged = packagedRunnerError(binary);
  if (notPackaged) throw new Error(notPackaged);
  await assertNoOutboundNetwork(fetch);
  const out = resolve(args.out);
  await rm(out, { recursive: true, force: true });
  await mkdir(join(out, "logs"), { recursive: true });
  const readJson = (path) => JSON.parse(readFileSync(join(ROOT, path), "utf8"));
  const closures = readdirSync(join(ROOT, CLOSURE_DIR))
    .filter((name) => name.endsWith(".json") && name !== "record-digests.json")
    .map((name) => ({ name, closure: readJson(`${CLOSURE_DIR}/${name}`) }));
  const plan = planRelease(closures, readJson);
  const binarySha256 = await sha256File(binary);
  const tarballs = {};
  if (args.dist) {
    for (const name of (await readdir(args.dist)).filter((n) => n.endsWith(".tgz")).toSorted()) {
      tarballs[name] = await sha256File(join(args.dist, name));
    }
  }
  const context = {
    binary,
    binarySha256,
    functionsNode,
    out,
    readJson,
    env: { ...process.env, FIREEMU_BIN: binary, FIREEMU_NODE: functionsNode },
  };
  const summary = {
    binary: { path: binary, sha256: binarySha256 },
    tarballs,
    node: process.version,
    exclusions: EXCLUDED_PARTS,
    excludedComparisons: plan.excluded,
    planErrors: plan.errors,
    runs: [],
    comparisons: [],
  };
  const observations = {};
  if (plan.errors.length === 0) {
    for (const run of RUNS) {
      console.log(`== ${run.id} ${run.kind}${run.part ? ` (${run.part})` : ""}`);
      const entry = await runEntry(run, context);
      observations[run.id] = await observe(run, entry, context);
      if (run.id === "R10") entry.record.rawLocalResultDigests = observations.R10.raw;
      summary.runs.push(entry.record);
      console.log(
        `   ${entry.record.commands.map((c) => `${c.mode}=${c.exitCode} (${Math.round(c.ms / 1000)} s)`).join(", ")}`,
      );
    }
    for (const comparison of plan.comparisons) {
      const differences = judge(comparison, observations, context);
      summary.comparisons.push({ ...comparison, differences });
    }
    for (const { from, to } of exportCopies(plan.comparisons, RUNS)) {
      if (existsSync(join(out, from))) await copyFile(join(out, from), join(out, to));
    }
  }
  const expectedRaw = context.readJson(
    "spec/compatibility/closure/evidence/integration-v0.8.0/FS-DATA-WRITE-regression.json",
  ).current.rawLocalResultDigests.strict;
  summary.reportOnly = {
    fsDataWriteRawResultsEqualLane:
      observations.R10 && isDeepStrictEqual(observations.R10.raw, expectedRaw.lane ?? expectedRaw),
  };
  const failures = [
    ...plan.errors.map((error) => ["coverage", error]),
    ...summary.runs.flatMap((run) => run.errors.map((error) => [run.id, error])),
    ...summary.comparisons.flatMap((c) =>
      c.differences.map((d) => [c.parents.join(","), `${c.path.split("/").at(-1)}: ${d}`]),
    ),
  ];
  summary.result = failures.length === 0 ? "PASS" : "FAIL";
  await writeFile(join(out, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  for (const [title, message] of failures.slice(0, MAX_ANNOTATIONS)) annotate(title, message);
  for (const comparison of summary.comparisons) {
    console.log(
      `${comparison.differences.length === 0 ? "ok  " : "FAIL"} ${comparison.path.split("/").at(-1)} (${comparison.parents.join(", ")}; ${comparison.runIds.join(", ")})`,
    );
  }
  console.log(`strict production comparison: ${summary.result} (${failures.length} findings)`);
  return failures.length === 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
