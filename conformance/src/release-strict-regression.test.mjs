// The release comparison of the strict profile with the committed production recordings: its
// judgements (rows, coverage, the FS-DATA-WRITE and FUNCTIONS-HTTP parts) and its safety
// checks (no recording mode, no production credential, no route out) are tested here on inputs
// built from the committed evidence, each broken in one place.
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { EXPECTED_ACTIONS, localSetupDigest } from "./harness-target/local-tenancy.mjs";

import {
  ALLOWED_MODES,
  EXCLUDED_KINDS,
  EXCLUDED_PARTS,
  RUNS,
  runEntry,
  assertNoOutboundNetwork,
  commandModes,
  compareLaneExport,
  exportCopies,
  forbiddenEnvironment,
  judge,
  judgeFsDataWriteCurrent,
  judgeFsDataWriteHistorical as judgeHistorical,
  historicalRawObservation,
  collectHistoricalReplay,
  judgeFunctionsHttp,
  localSetupDifferences,
  packagedRunnerError,
  parseArguments,
  planComparisons,
  planRelease,
  readReleaseJson,
} from "./release-strict-regression.mjs";
import { PROGRAMS } from "./firestore-probe/programs.mjs";
import { historicalProductionSummary } from "./firestore-probe/run.mjs";
import { COMPARISONS } from "./auth-federation/compare.mjs";

const judgeFsDataWriteHistorical = (expected, observed, binary) =>
  judgeHistorical(
    expected,
    {
      ...observed,
      comparison:
        observed.comparison ??
        (observed.result
          ? historicalRawObservation(Buffer.from(JSON.stringify(observed.result)))
          : undefined),
    },
    binary,
  );

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const readJson = (path) => readReleaseJson(repo(""), path);
const clone = (value) => structuredClone(value);
const sha256 = (path) =>
  createHash("sha256")
    .update(readFileSync(repo(path)))
    .digest("hex");

const EVIDENCE = "spec/compatibility/closure/evidence/integration-v0.8.0";
const BINARY = "a".repeat(64);

const committedClosures = () =>
  readdirSync(repo("spec/compatibility/closure"))
    .filter((name) => name.endsWith(".json") && name !== "record-digests.json")
    .map((name) => ({ name, closure: readJson(`spec/compatibility/closure/${name}`) }));

/** A lane export as the harness writes it: the committed file with this run's binary. */
const exportOf = (path) => ({ ...readJson(path), artifactSha256: BINARY });

// --- lane exports ---------------------------------------------------------------------------

test("a lane export equal to the committed comparison passes", () => {
  for (const name of ["AUTH-CONFIG-SDK", "FS-QUERY-INDEX", "FS-CONFIG-LIFECYCLE", "AUTH-MFA"]) {
    const path = `${EVIDENCE}/${name}-comparison.json`;
    assert.deepEqual(compareLaneExport(readJson(path), exportOf(path), BINARY), [], name);
  }
});

test("a row order change alone is not a difference", () => {
  const path = `${EVIDENCE}/AUTH-ACCOUNT-comparison.json`;
  const actual = exportOf(path);
  actual.rows = actual.rows.toReversed();
  assert.deepEqual(compareLaneExport(readJson(path), actual, BINARY), []);
});

test("every departure of a lane export from the committed comparison is a difference", () => {
  const path = `${EVIDENCE}/AUTH-CONFIG-SDK-comparison.json`;
  const expected = readJson(path);
  const mismatchIndex = expected.rows.findIndex((row) => row.status === "MISMATCH");
  const breakers = {
    "a missing row": (a) => a.rows.pop(),
    "an extra row": (a) => a.rows.push({ row: "auth-config-sdk/extra#row", status: "MATCH" }),
    "a changed status": (a) => {
      a.rows[0].status = "MISMATCH";
    },
    "changed MISMATCH differences": (a) => {
      a.rows[mismatchIndex].differences = ["body"];
    },
    "a changed sameErrorCode": (a) => {
      a.rows[mismatchIndex].sameErrorCode = true;
    },
    "a changed fixture digest": (a) => {
      a.fixtureSha256 = "b".repeat(64);
    },
    "a changed summary": (a) => {
      a.summary = { MATCH: 359 };
    },
    "a changed kind": (a) => {
      a.kind = "auth-account-comparison-v1";
    },
    "another binary": (a) => {
      a.artifactSha256 = "c".repeat(64);
    },
    "a duplicated row": (a) => a.rows.push(clone(a.rows[0])),
  };
  for (const [name, breakIt] of Object.entries(breakers)) {
    const actual = exportOf(path);
    breakIt(actual);
    assert.notDeepEqual(compareLaneExport(expected, actual, BINARY), [], name);
  }
});

test("FS-QUERY-INDEX range totals are compared", () => {
  const path = `${EVIDENCE}/FS-QUERY-INDEX-comparison.json`;
  const actual = exportOf(path);
  actual.rangeTotals = {};
  assert.notDeepEqual(compareLaneExport(readJson(path), actual, BINARY), []);
  const missing = exportOf(path);
  delete missing.rangeTotals;
  assert.notDeepEqual(compareLaneExport(readJson(path), missing, BINARY), []);
});

test("a changed decision or relabel of a row is a difference", () => {
  const index = `${EVIDENCE}/FS-QUERY-INDEX-comparison.json`;
  const approved = exportOf(index);
  const row = approved.rows.find((r) => r.status === "DIVERGENCE_APPROVED");
  row.decision = "another decision";
  assert.notDeepEqual(compareLaneExport(readJson(index), approved, BINARY), []);
  const lifecycle = `${EVIDENCE}/FS-CONFIG-LIFECYCLE-comparison.json`;
  const relabeled = exportOf(lifecycle);
  const moved = relabeled.rows.find((r) => r.status === "MATCH_RELABELED");
  moved.matched = "another/row";
  assert.notDeepEqual(compareLaneExport(readJson(lifecycle), relabeled, BINARY), []);
});

test("a missing export is a difference, not a crash", () => {
  const path = `${EVIDENCE}/AUTH-ACTION-comparison.json`;
  assert.notDeepEqual(compareLaneExport(readJson(path), undefined, BINARY), []);
  assert.notDeepEqual(compareLaneExport(readJson(path), { rows: "x" }, BINARY), []);
  assert.notDeepEqual(compareLaneExport(readJson(path), {}, BINARY), []);
});

test("each kind of row difference names the row and what is wrong with it", () => {
  const path = `${EVIDENCE}/AUTH-ACTION-comparison.json`;
  const extra = exportOf(path);
  extra.rows.push({ row: "auth-action/extra#row", status: "MATCH" });
  assert.deepEqual(compareLaneExport(readJson(path), extra, BINARY), [
    "auth-action/extra#row: not in the committed comparison",
  ]);
  const missing = exportOf(path);
  const gone = missing.rows.pop();
  assert.deepEqual(compareLaneExport(readJson(path), missing, BINARY), [
    `${gone.row}: missing from the export`,
  ]);
  const twice = exportOf(path);
  twice.rows.push(clone(twice.rows[0]));
  assert.deepEqual(compareLaneExport(readJson(path), twice, BINARY), [
    `${twice.rows[0].row}: exported twice`,
  ]);
});

// --- coverage -------------------------------------------------------------------------------

test("every comparison a verified closure names is run or excluded with a reason", () => {
  const plan = planComparisons(committedClosures(), readJson);
  assert.deepEqual(plan.errors, []);
  const paths = new Set([...plan.comparisons, ...plan.excluded].map((c) => c.path));
  for (const { closure } of committedClosures()) {
    if (closure.parentStatus !== "COMPAT_VERIFIED") continue;
    for (const { path } of closure.integratedRegression.comparisons) assert.ok(paths.has(path));
  }
  const runIds = new Set(RUNS.map((run) => run.id));
  for (const comparison of plan.comparisons) {
    assert.ok(comparison.runIds.length > 0, comparison.path);
    for (const id of comparison.runIds) assert.ok(runIds.has(id), `${comparison.path}: ${id}`);
  }
  // Every executed run serves a committed comparison, including parents awaiting formal closure.
  const executionPlan = planComparisons(
    committedClosures().map((entry) => {
      const copy = clone(entry);
      copy.closure.parentStatus = "COMPAT_VERIFIED";
      return copy;
    }),
    readJson,
    { excludedKinds: [] },
  );
  const used = new Set(executionPlan.comparisons.flatMap((c) => c.runIds));
  for (const run of RUNS) assert.ok(used.has(run.id), run.id);
});

test("a verified closure with a comparison of an unknown kind stops the release", () => {
  const closures = committedClosures();
  const fake = {
    name: "NEW-PARENT.json",
    closure: {
      parent: "NEW-PARENT",
      parentStatus: "COMPAT_VERIFIED",
      integratedRegression: { comparisons: [{ path: "new/comparison.json" }] },
    },
  };
  const read = (path) =>
    path === "new/comparison.json" ? { kind: "new-kind-v1" } : readJson(path);
  const plan = planComparisons([...closures, fake], read);
  assert.ok(plan.errors.some((error) => error.includes("new-kind-v1")));
});

// --- several comparison files of one kind -----------------------------------------------------

const SYNTHETIC_KIND = "synthetic-two-suites-v1";
const suiteRun = (id, rowPrefix) => ({
  id,
  kind: SYNTHETIC_KIND,
  rowPrefix,
  clear: [],
  commands: [],
});
const suiteRuns = [suiteRun("S1", "one/"), suiteRun("S2", "two/")];
const noRunError = (path) =>
  `${path}: no run of kind ${SYNTHETIC_KIND} has a row prefix covering every row of the file`;
const suiteFile = (path, rowIds) => ({
  path,
  document: { kind: SYNTHETIC_KIND, rows: rowIds.map((row) => ({ row, status: "MATCH" })) },
});
const planSuites = (...files) => {
  const byPath = new Map(files.map((file) => [file.path, file.document]));
  const fake = {
    name: "SUITES.json",
    closure: {
      parent: "SUITES",
      parentStatus: "COMPAT_VERIFIED",
      integratedRegression: { comparisons: files.map(({ path }) => ({ path })) },
    },
  };
  return planComparisons([fake], (path) => byPath.get(path), {
    excludedKinds: [],
    runs: suiteRuns,
  });
};

test("comparison files of one kind are each served by the run whose row prefix covers them", () => {
  const plan = planSuites(
    suiteFile("a.json", ["one/a#1", "one/b#1"]),
    suiteFile("b.json", ["two/a#1"]),
  );
  assert.deepEqual(plan.errors, []);
  assert.deepEqual(
    plan.comparisons.map((c) => [c.path, c.runIds]),
    [
      ["a.json", ["S1"]],
      ["b.json", ["S2"]],
    ],
  );
});

test("a file that no run's row prefix covers stops the release", () => {
  const plan = planSuites(suiteFile("a.json", ["three/a#1"]));
  assert.deepEqual(plan.errors, [noRunError("a.json")]);
});

test("a file whose rows are split across two runs' prefixes stops the release", () => {
  const plan = planSuites(suiteFile("a.json", ["one/a#1", "two/a#1"]));
  assert.deepEqual(plan.errors, [noRunError("a.json")]);
});

test("a row that contains a run's prefix without starting with it is not covered", () => {
  const plan = planSuites(suiteFile("a.json", ["one/a#1", "x/one/a#1"]));
  assert.deepEqual(plan.errors, [noRunError("a.json")]);
});

test("an empty file is refused even when a single run has a prefix", () => {
  const document = { kind: SYNTHETIC_KIND, rows: [] };
  const plan = planComparisons([verifiedWith("SUITES", "a.json")], () => document, {
    excludedKinds: [],
    runs: [suiteRun("S1", "")],
  });
  assert.deepEqual(plan.errors, [noRunError("a.json")]);
});

test("a file two runs' prefixes both cover stops the release", () => {
  const overlapping = [suiteRun("S1", "one/"), suiteRun("S3", "one/x")];
  const file = suiteFile("a.json", ["one/x#1"]);
  const fake = verifiedWith("SUITES", "a.json");
  const plan = planComparisons([fake], () => file.document, {
    excludedKinds: [],
    runs: overlapping,
  });
  assert.ok(
    plan.errors.some((error) => error.includes("a.json") && error.includes("more than one")),
  );
});

test("a file without rows cannot be assigned to a run and stops the release", () => {
  const plan = planSuites({ path: "a.json", document: { kind: SYNTHETIC_KIND, rows: [] } });
  assert.deepEqual(plan.errors, [noRunError("a.json")]);
});

test("every export is copied once per comparison file, under that file's name", () => {
  const comparisons = [
    { path: "e/tenant.json", runIds: ["S1"] },
    { path: "e/other.json", runIds: ["S1"] },
    { path: "e/blocking.json", runIds: ["S2"] },
  ];
  assert.deepEqual(exportCopies(comparisons, suiteRunsWithExport()), [
    { from: "S1-export.json", to: "tenant.json" },
    { from: "S1-export.json", to: "other.json" },
    { from: "S2-export.json", to: "blocking.json" },
  ]);
  // A comparison served by a run that exports nothing (a composite file) has no copy.
  assert.deepEqual(exportCopies([{ path: "e/x.json", runIds: ["C1"] }], suiteRunsWithExport()), []);
});

function suiteRunsWithExport() {
  const exporting = (run) => ({ ...run, commands: [{ mode: "export-comparison" }] });
  return [
    ...suiteRuns.map(exporting),
    { id: "C1", kind: "c", clear: [], commands: [{ mode: "check-local" }] },
  ];
}

test("the committed ATB tenant, blocking and federation copies are served by the right runs", () => {
  const plan = planComparisons(committedClosures(), readJson);
  const runsOf = (name) => plan.comparisons.find((c) => c.path.endsWith(name))?.runIds;
  assert.deepEqual(runsOf("AUTH-TENANT-BLOCKING-tenant-comparison.json"), ["R13"]);
  assert.deepEqual(runsOf("AUTH-FEDERATION-tenant-blocking-regression.json"), ["R13"]);
  assert.deepEqual(runsOf("AUTH-TENANT-BLOCKING-blocking-comparison.json"), ["R14"]);
  assert.deepEqual(runsOf("AUTH-FEDERATION-comparison.json"), ["R15"]);
  assert.deepEqual(runsOf("AUTH-FEDERATION-saml-comparison.json"), ["R16"]);
  assert.deepEqual(runsOf("AUTH-FEDERATION-followup-comparison.json"), ["R17"]);
});

const verifiedWith = (name, path) => ({
  name: `${name}.json`,
  closure: {
    parent: name,
    parentStatus: "COMPAT_VERIFIED",
    integratedRegression: { comparisons: [{ path }] },
  },
});

test("a comparison of an excluded kind is planned as excluded, with its reason and issue", () => {
  const exclusion = {
    kind: "synthetic-excluded-v1",
    reason: "a reason long enough to be a real one",
    issue: "synthetic.md",
  };
  const read = (path) => (path === "new/excluded.json" ? { kind: exclusion.kind } : readJson(path));
  const plan = planComparisons(
    [...committedClosures(), verifiedWith("NEW", "new/excluded.json")],
    read,
    {
      excludedKinds: [...EXCLUDED_KINDS, exclusion],
    },
  );
  assert.deepEqual(plan.errors, []);
  assert.ok(!plan.comparisons.some((c) => c.path === "new/excluded.json"));
  const excluded = plan.excluded.find((c) => c.path === "new/excluded.json");
  assert.deepEqual(excluded, {
    path: "new/excluded.json",
    kind: exclusion.kind,
    parents: ["NEW"],
    reason: exclusion.reason,
    issue: exclusion.issue,
  });
});

test("an unlisted kind with no run still stops the release", () => {
  const read = (path) =>
    path === "new/unlisted.json" ? { kind: "unlisted-kind-v1" } : readJson(path);
  const plan = planComparisons(
    [...committedClosures(), verifiedWith("NEW", "new/unlisted.json")],
    read,
  );
  assert.ok(plan.errors.some((error) => error.includes("unlisted-kind-v1")));
  assert.ok(!plan.excluded.some((c) => c.kind === "unlisted-kind-v1"));
});

test("an exclusion without a reason or an issue stops the release", () => {
  const kinds = (entry) => [...EXCLUDED_KINDS, entry];
  const withReason = planComparisons(committedClosures(), readJson, {
    excludedKinds: kinds({ kind: "x-v1", reason: "", issue: "x.md" }),
  });
  assert.ok(withReason.errors.some((error) => error.includes("x-v1") && error.includes("reason")));
  const withIssue = planComparisons(committedClosures(), readJson, {
    excludedKinds: kinds({
      kind: "y-v1",
      reason: "a reason long enough to be a real one",
      issue: "",
    }),
  });
  assert.ok(withIssue.errors.some((error) => error.includes("y-v1") && error.includes("issue")));
  const withPath = planComparisons(committedClosures(), readJson, {
    excludedKinds: kinds({
      kind: "z-v1",
      reason: "a reason long enough to be a real one",
      issue: "docs.local/issues/open/z.md",
    }),
  });
  assert.ok(withPath.errors.some((error) => error.includes("z-v1") && error.includes("issue")));
});

test("an exclusion of a kind a run reproduces stops the release", () => {
  const plan = planComparisons(committedClosures(), readJson, {
    excludedKinds: [
      ...EXCLUDED_KINDS,
      { kind: RUNS[0].kind, reason: "a reason long enough to be a real one", issue: "r.md" },
    ],
  });
  assert.ok(plan.errors.some((error) => error.includes(RUNS[0].kind) && error.includes("run")));
});

test("an exclusion no verified closure needs stops the release", () => {
  const plan = planComparisons(committedClosures(), readJson, {
    excludedKinds: [
      ...EXCLUDED_KINDS,
      { kind: "unused-v1", reason: "a reason long enough to be a real one", issue: "u.md" },
    ],
  });
  assert.ok(plan.errors.some((error) => error.includes("unused-v1")));
});

test("the excluded kinds are exactly the ones the release discloses", () => {
  // Removing an exclusion means adding its run; adding one means a disclosure of its own.
  assert.deepEqual(EXCLUDED_KINDS.map((exclusion) => exclusion.kind).toSorted(), [
    "auth-fs-cross-stage2-comparison-v1",
    "fs-listen-sdk-comparison-v1",
    "functions-events-comparison",
    "scheduled-functions-calendar-comparison-v1",
    "scheduled-functions-comparison-v1",
    "storage-object-comparison-v1",
    "storage-rules-comparison-v2",
    "storage-rules-management-comparison-v1",
  ]);
});

test("scheduled exclusions are used by a verified closure", () => {
  const scheduledKinds = EXCLUDED_KINDS.filter(({ kind }) =>
    kind.startsWith("scheduled-functions-"),
  );
  assert.equal(scheduledKinds.length, 2);
  const closures = committedClosures();
  const scheduled = closures.find(({ closure }) => closure.parent === "SCHEDULED-FUNCTIONS");
  assert.equal(scheduled.closure.parentStatus, "COMPAT_VERIFIED");
  const plan = planComparisons(closures, readJson);
  assert.deepEqual(plan.errors, []);
  const excluded = plan.excluded.filter(({ parents }) => parents.includes("SCHEDULED-FUNCTIONS"));
  assert.deepEqual(
    excluded.map(({ kind }) => kind).toSorted(),
    scheduledKinds.map(({ kind }) => kind).toSorted(),
  );
  assert.ok(excluded.every(({ parents }) => parents.length === 1));
  scheduled.closure.integratedRegression.comparisons.pop();
  assert.ok(
    planComparisons(closures, readJson).errors.some((error) =>
      error.includes("no verified closure names it"),
    ),
  );
  assert.ok(
    planComparisons(
      closures.filter((entry) => entry !== scheduled),
      readJson,
    ).errors.some((error) => error.includes("scheduled-functions")),
  );
});

test("every kind exclusion names its reason and an issue by file name only", () => {
  for (const exclusion of EXCLUDED_KINDS) {
    assert.ok(exclusion.reason.length > 20, exclusion.kind);
    assert.match(exclusion.issue, /^[a-z0-9-]+\.md$/, exclusion.kind);
    assert.ok(!RUNS.some((run) => run.kind === exclusion.kind), exclusion.kind);
  }
});

test("a verified closure without an integrated regression stops the release", () => {
  const fake = { name: "NEW.json", closure: { parent: "NEW", parentStatus: "COMPAT_VERIFIED" } };
  const plan = planComparisons([...committedClosures(), fake], readJson);
  assert.ok(plan.errors.some((error) => error.includes("NEW")));
});

test("a verified closure with an empty integrated regression stops the release", () => {
  const fake = {
    name: "EMPTY.json",
    closure: {
      parent: "EMPTY",
      parentStatus: "COMPAT_VERIFIED",
      integratedRegression: { comparisons: [] },
    },
  };
  const plan = planComparisons([...committedClosures(), fake], readJson);
  assert.ok(plan.errors.some((error) => error.includes("EMPTY")));
});

test("a closure that is not verified is not required", () => {
  const fake = { name: "OPEN.json", closure: { parent: "OPEN", parentStatus: "IN_PROGRESS" } };
  assert.deepEqual(planComparisons([...committedClosures(), fake], readJson).errors, []);
});

test("an FS-DATA-WRITE regression part that is neither run nor excluded stops the release", () => {
  const path = `${EVIDENCE}/FS-DATA-WRITE-regression.json`;
  const read = (p) => (p === path ? { ...readJson(path), newPart: {} } : readJson(p));
  const plan = planComparisons(committedClosures(), read);
  assert.ok(plan.errors.some((error) => error.includes("newPart")));
});

test("every exclusion names its reason and an issue by file name only", () => {
  assert.ok(EXCLUDED_PARTS.length > 0);
  for (const exclusion of EXCLUDED_PARTS) {
    assert.ok(exclusion.reason.length > 20, exclusion.part);
    if (exclusion.scope === "emulator-profile") continue;
    assert.match(exclusion.issue, /^[a-z0-9-]+\.md$/, exclusion.part);
    assert.ok(!exclusion.issue.includes("docs.local"), exclusion.part);
  }
});

// --- safety ---------------------------------------------------------------------------------

test("no run can record against production or recover a sandbox", () => {
  const modes = commandModes(RUNS);
  assert.ok(modes.length > 0);
  for (const mode of modes) {
    assert.ok(ALLOWED_MODES.has(mode), mode);
    assert.doesNotMatch(mode, /record|preflight|recover|restore|rebuild|reserve/);
  }
  for (const mode of ALLOWED_MODES) assert.doesNotMatch(mode, /record|preflight|recover/);
});

test("a production or sandbox credential in the environment refuses the run", () => {
  assert.deepEqual(forbiddenEnvironment({ PATH: "/bin", FIREEMU_BIN: "x", HOME: "/h" }), []);
  for (const name of [
    "FIREEMU_SANDBOX_LEDGER",
    "FIREEMU_AUTH_SANDBOX_WEB_CONFIG",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "FIREEMU_PRODUCTION_TOKEN",
    "FIREEMU_PRODUCTION_PROJECT",
    "FIREEMU_RUNNER_NODE",
    "FIREEMU_FS_RULES_PRIVATE_DIR",
    "CLOUDSDK_CONFIG",
  ]) {
    assert.deepEqual(forbiddenEnvironment({ PATH: "/bin", [name]: "1" }), [name], name);
  }
});

test("a route out refuses the run; refused connections let it start", async () => {
  const refused = async () => {
    throw new TypeError("fetch failed");
  };
  await assertNoOutboundNetwork(refused);
  const open = async () => new Response("", { status: 404 });
  await assert.rejects(assertNoOutboundNetwork(open), /reached/);
  let calls = 0;
  const partlyOpen = async (url) => {
    calls += 1;
    if (String(url).includes("identitytoolkit")) return new Response("", { status: 404 });
    throw new TypeError("fetch failed");
  };
  await assert.rejects(assertNoOutboundNetwork(partlyOpen), /identitytoolkit/);
  assert.equal(calls, 2);
});

test("the arguments name an output directory and accept nothing else", () => {
  assert.deepEqual(parseArguments(["--out", "dir"]), { out: "dir", dist: undefined });
  assert.deepEqual(parseArguments(["--out", "dir", "--dist", "npm/dist"]), {
    out: "dir",
    dist: "npm/dist",
  });
  assert.throws(() => parseArguments([]), /--out/);
  assert.throws(() => parseArguments(["--out"]), /--out/);
  assert.throws(() => parseArguments(["--out", "dir", "--record"]), /unknown/);
});

// --- FS-DATA-WRITE ----------------------------------------------------------------------------

const regression = () => readJson(`${EVIDENCE}/FS-DATA-WRITE-regression.json`);
const laneCurrent = () =>
  readJson("spec/compatibility/closure/evidence/FS-DATA-WRITE-current-comparison.json");
const runtimeInputs = () => ({
  "conformance/src/fs-data-write-sandbox-run.mjs": sha256(
    "conformance/src/fs-data-write-sandbox-run.mjs",
  ),
  "conformance/src/firestore-probe/sandbox-session.mjs": sha256(
    "conformance/src/firestore-probe/sandbox-session.mjs",
  ),
});
const passingCompareLocal = () => {
  const current = regression().current;
  return {
    corpusDigest: current.corpusSha256,
    recordedCorpusDigest: current.recordedCorpusSha256,
    comparedPrograms: current.comparedRestPrograms,
    comparedStreams: current.comparedGrpcStreams,
    pendingRestIds: [],
    pendingStreamIds: [],
    retiredRestIds: current.retiredRestIds.toReversed(),
    retiredStreamIds: [],
    mismatches: 0,
    differences: [],
  };
};

test("the FS-DATA-WRITE local comparison passes on the committed figures", () => {
  assert.deepEqual(
    judgeFsDataWriteCurrent(
      regression().current,
      { exitCode: 0, result: passingCompareLocal(), runtimeInputs: runtimeInputs() },
      laneCurrent().runtimeInputs,
    ),
    [],
  );
});

test("every departure of the FS-DATA-WRITE local comparison fails it", () => {
  const breakers = {
    "a nonzero exit": (o) => {
      o.exitCode = 1;
    },
    "another corpus": (o) => {
      o.result.corpusDigest = "d".repeat(64);
    },
    "another recorded corpus": (o) => {
      o.result.recordedCorpusDigest = "d".repeat(64);
    },
    "fewer programs": (o) => {
      o.result.comparedPrograms -= 1;
    },
    "fewer streams": (o) => {
      o.result.comparedStreams -= 1;
    },
    "a pending program": (o) => {
      o.result.pendingRestIds = ["writes/x"];
    },
    "a pending stream": (o) => {
      o.result.pendingStreamIds = ["streams/x"];
    },
    "another retired set": (o) => {
      o.result.retiredRestIds.pop();
    },
    "an extra retired program": (o) => {
      o.result.retiredRestIds.push("writes/extra");
    },
    "a retired program replaced by another": (o) => {
      o.result.retiredRestIds[0] = "writes/other";
    },
    "a retired stream": (o) => {
      o.result.retiredStreamIds = ["streams/x"];
    },
    "a mismatch": (o) => {
      o.result.mismatches = 1;
    },
    "another runner": (o) => {
      o.runtimeInputs["conformance/src/fs-data-write-sandbox-run.mjs"] = "e".repeat(64);
    },
    "another session": (o) => {
      o.runtimeInputs["conformance/src/firestore-probe/sandbox-session.mjs"] = "e".repeat(64);
    },
    "no result": (o) => {
      o.result = undefined;
    },
  };
  for (const [name, breakIt] of Object.entries(breakers)) {
    const observed = { exitCode: 0, result: passingCompareLocal(), runtimeInputs: runtimeInputs() };
    breakIt(observed);
    assert.notDeepEqual(
      judgeFsDataWriteCurrent(regression().current, observed, laneCurrent().runtimeInputs),
      [],
      name,
    );
  }
});

const passingProfileBinding = () => {
  const sourceBytes = readFileSync(repo("conformance/firestore-probe.fireemu.json"));
  const config = JSON.parse(sourceBytes);
  config.profile = "strict";
  config.firestore.rules = repo("conformance/firestore-probe.rules");
  config.firestore.indexFile = "/private/run/strict-indexes.json";
  const indexBytes = readFileSync(repo("conformance/firestore-production.indexes.json"));
  const bytes = Buffer.from(JSON.stringify(config, null, 2) + "\n");
  const digest = (value) => createHash("sha256").update(value).digest("hex");
  const daemonLog =
    "  profile: strict (behaves like production Firebase where the official emulators do not)\n";
  return {
    requestedProfile: "strict",
    effectiveProfile: "strict",
    daemonLog,
    daemonLogSha256: digest(daemonLog),
    cwd: repo("conformance"),
    argv: ["exec", "--config", "/private/run/strict-config.json"],
    binary: { sha256Before: BINARY, sha256After: BINARY },
    indexes: {
      authority: {
        sourceGit: "2526c61eda5fc53ac91250307786127ae3c601be",
        file: "conformance/firestore.indexes.json",
        bytes: 2484,
        sha256: "sha256-8a4d4bd7a72c3ce2bed4e0f8c4adc0cdb3a7c428477578295e44a11ae063d01c",
      },
      sourcePath: repo("conformance/firestore-production.indexes.json"),
      sourceBytesBase64: indexBytes.toString("base64"),
      sourceBytesBefore: 2484,
      sourceBytesAfter: 2484,
      sourceSha256Before: digest(indexBytes),
      sourceSha256After: digest(indexBytes),
      path: "/private/run/strict-indexes.json",
      bytesBase64: indexBytes.toString("base64"),
      bytesBefore: 2484,
      bytesAfter: 2484,
      sha256Before: digest(indexBytes),
      sha256After: digest(indexBytes),
    },
    config: {
      sourcePath: repo("conformance/firestore-probe.fireemu.json"),
      sourceBytesBase64: sourceBytes.toString("base64"),
      sourceSha256Before: digest(sourceBytes),
      sourceSha256After: digest(sourceBytes),
      path: "/private/run/strict-config.json",
      bytesBase64: bytes.toString("base64"),
      sha256Before: digest(bytes),
      sha256After: digest(bytes),
    },
  };
};

const baselineRaw = () => {
  const saved = readJson("conformance/firestore-production-matrix.json");
  const live = Object.fromEntries(
    PROGRAMS.map((program) => [
      program.id,
      {
        steps: Object.fromEntries(
          program.steps.map((step) => [
            step.id,
            saved.programs.find((old) => old.id === program.id)?.steps[step.id]?.fireemu ?? {
              missing: true,
            },
          ]),
        ),
      },
    ]),
  );
  live["queries/collection-group"].steps["partition-query"] = saved.programs.find(
    (p) => p.id === "queries/collection-group",
  ).steps["partition-query"].production;
  return live;
};
const passingRaw = () => historicalRawObservation(Buffer.from(JSON.stringify(baselineRaw())));
const passingHistorical = () => ({
  artifact: { sha256Before: BINARY, sha256After: BINARY },
  profileBinding: passingProfileBinding(),
  localRawSha256: passingRaw().sha256,
  ...historicalProductionSummary(baselineRaw()),
});

test("the historical production replay passes on the committed figures", () => {
  assert.deepEqual(
    judgeFsDataWriteHistorical(
      regression().historical,
      { exitCode: 0, result: passingHistorical(), raw: passingRaw() },
      BINARY,
    ),
    [],
  );
});

test("every departure of the historical production replay fails it", () => {
  const breakers = {
    "a nonzero exit": (o) => {
      o.exitCode = 1;
    },
    "fewer comparable rows": (o) => {
      o.result.comparable -= 1;
    },
    "one known mismatch fewer": (o) => {
      o.result.currentMismatches.pop();
    },
    "a known mismatch replaced by another row": (o) => {
      o.result.currentMismatches[0] = "queries/other#row";
    },
    "a mismatch moved to indeterminate": (o) => {
      o.result.indeterminate.push(o.result.currentMismatches.pop());
    },
    "a new mismatch": (o) => {
      o.result.newMismatches = ["x#y"];
    },
    "a new indeterminate": (o) => {
      o.result.newIndeterminate = ["x#y"];
    },
    "no indeterminate row": (o) => {
      o.result.indeterminate = [];
    },
    "another binary before": (o) => {
      o.result.artifact.sha256Before = "f".repeat(64);
    },
    "another binary after": (o) => {
      o.result.artifact.sha256After = "f".repeat(64);
    },
    "no result": (o) => {
      o.result = undefined;
    },
  };
  for (const [name, breakIt] of Object.entries(breakers)) {
    const observed = { exitCode: 0, result: passingHistorical(), raw: passingRaw() };
    breakIt(observed);
    assert.notDeepEqual(
      judgeFsDataWriteHistorical(regression().historical, observed, BINARY),
      [],
      name,
    );
  }
});

// --- FUNCTIONS-HTTP ---------------------------------------------------------------------------

const functionsHttp = () => readJson(`${EVIDENCE}/FUNCTIONS-HTTP-comparison.json`);
const passingFunctions = () => {
  const expected = functionsHttp();
  const strict = expected.runs.find((run) => run.profile === "strict");
  const recording = { "functions-http/http/request-shape": {} };
  for (let index = 0; index < expected.totalCases; index += 1)
    recording["functions-http/http/request-shape"][`case-${index}`] = { status: 200 };
  return {
    exitCode: 0,
    outputSha256: strict.recordingSha256,
    output: { recordings: [recording, clone(recording)] },
    nodeVersion: expected.nodeVersion,
    fixtureIndexSha256: expected.fixtureIndexSha256,
    fixturePackageLockSha256: expected.fixturePackageLockSha256,
    log: "  profile: strict (behaves like production Firebase where the official emulators do not)\n",
  };
};

test("the FUNCTIONS-HTTP stand-in passes on the committed figures", () => {
  assert.deepEqual(judgeFunctionsHttp(functionsHttp(), passingFunctions()), []);
});

test("every departure of the FUNCTIONS-HTTP stand-in fails it", () => {
  const breakers = {
    "a nonzero exit": (o) => {
      o.exitCode = 1;
    },
    "another recording": (o) => {
      o.outputSha256 = "0".repeat(64);
    },
    "two different recordings": (o) => {
      o.output.recordings[1]["functions-http/http/request-shape"]["case-0"].status = 500;
    },
    "a missing case": (o) => {
      delete o.output.recordings[0]["functions-http/http/request-shape"]["case-0"];
      delete o.output.recordings[1]["functions-http/http/request-shape"]["case-0"];
    },
    "one recording": (o) => {
      o.output.recordings.pop();
    },
    "three recordings": (o) => {
      o.output.recordings.push(clone(o.output.recordings[0]));
    },
    "another Node": (o) => {
      o.nodeVersion = "v24.14.0";
    },
    "another fixture": (o) => {
      o.fixtureIndexSha256 = "0".repeat(64);
    },
    "another lock": (o) => {
      o.fixturePackageLockSha256 = "0".repeat(64);
    },
    "the emulator profile": (o) => {
      o.log = "  profile: emulator (reproduces the pinned official emulators)\n";
    },
    "no output": (o) => {
      o.output = undefined;
    },
  };
  for (const [name, breakIt] of Object.entries(breakers)) {
    const observed = passingFunctions();
    breakIt(observed);
    assert.notDeepEqual(judgeFunctionsHttp(functionsHttp(), observed), [], name);
  }
});

// --- the release job --------------------------------------------------------------------------

const strictProductionJob = () => {
  const workflow = readFileSync(repo(".github/workflows/release.yml"), "utf8");
  const start = workflow.indexOf("\n  strict-production:");
  const end = workflow.indexOf("\n  publish:", start);
  assert.ok(start > 0 && end > start, "the strict-production job is in release.yml");
  return workflow.slice(start, end);
};

test("the strict-production job installs the blocking fixture's dependencies before the loopback run", () => {
  const job = strictProductionJob();
  const install = job.indexOf("npm ci --prefix conformance/src/auth-tenant-blocking/function");
  assert.ok(install > 0, "the blocking fixture's npm ci");
  assert.match(job.slice(install, install + 120), /--ignore-scripts/);
  assert.ok(install < job.indexOf("unshare --net"), "installed while the network is still there");
});

test("the loopback run passes the Functions Node to the harnesses", () => {
  const job = strictProductionJob();
  assert.match(job.slice(job.indexOf("unshare --net")), /FIREEMU_NODE="\$FIREEMU_NODE"/);
});

// --- exclusions and the run table ------------------------------------------------------------

test("an exclusion of a kind an injected run reproduces stops the release", () => {
  const kind = "synthetic-excluded-v1";
  const plan = planComparisons([], () => undefined, {
    excludedKinds: [{ kind, reason: "a reason long enough to be a real one", issue: "s.md" }],
    runs: [{ id: "S1", kind, clear: [], commands: [] }],
  });
  assert.ok(
    plan.errors.some((error) => error.includes(kind) && error.includes("a run reproduces")),
  );
  // The live table's runs do not stand in for the injected ones.
  const live = planComparisons([], () => undefined, {
    excludedKinds: [{ kind, reason: "a reason long enough to be a real one", issue: "s.md" }],
    runs: [],
  });
  assert.ok(!live.errors.some((error) => error.includes("a run reproduces")));
});

const atbRuns = () => RUNS.filter((run) => run.kind === "auth-tenant-blocking-comparison-v1");

test("every AUTH-TENANT-BLOCKING run runs the packaged runner in every command", () => {
  assert.deepEqual(
    atbRuns().map((run) => run.id),
    ["R13", "R14"],
  );
  for (const run of atbRuns()) {
    assert.ok(run.commands.length > 0, run.id);
    for (const command of run.commands) {
      assert.equal(command.env.AUTH_TENANT_PACKAGED_RUNNER, "1", `${run.id} ${command.mode}`);
    }
  }
});

test("every AUTH-TENANT-BLOCKING run names its suite and the rows of that suite", () => {
  const suites = atbRuns().map((run) => run.commands[0].env.AUTH_TENANT_SUITE);
  assert.deepEqual(suites.toSorted(), ["blocking", "tenant"]);
  for (const run of atbRuns()) {
    for (const command of run.commands) {
      assert.equal(command.env.AUTH_TENANT_SUITE, run.commands[0].env.AUTH_TENANT_SUITE, run.id);
    }
    assert.equal(run.rowPrefix, `atb/${run.commands[0].env.AUTH_TENANT_SUITE}/`, run.id);
  }
});

test("every AUTH-FEDERATION run runs the packet of its own kind, in both commands", () => {
  const runs = RUNS.filter((run) =>
    run.commands[0].argv.some((arg) => arg.endsWith("auth-federation/compare.mjs")),
  );
  assert.deepEqual(
    runs.map((run) => run.id),
    ["R15", "R16", "R17"],
  );
  for (const run of runs) {
    const [check, exported] = run.commands;
    const packet = check.argv[check.argv.indexOf("check") + 1];
    assert.equal(COMPARISONS[packet]?.kind, run.kind, run.id);
    assert.equal(exported.argv[exported.argv.indexOf("export-comparison") + 1], packet, run.id);
    assert.equal(exported.argv.at(-1), "{export}", run.id);
  }
  assert.equal(new Set(runs.map((run) => run.kind)).size, runs.length);
});

// --- the installed package ---------------------------------------------------------------------

test("a runner override in the environment refuses the run", () => {
  assert.deepEqual(forbiddenEnvironment({ FIREEMU_RUNNER_NODE: "/checkout/index.mjs" }), [
    "FIREEMU_RUNNER_NODE",
  ]);
});

test("the run refuses a binary that ships no runner beside it", () => {
  const present = new Set(["/install/bin/runner-node/index.mjs"]);
  const deps = { exists: (path) => present.has(path), realpath: (path) => path };
  assert.equal(packagedRunnerError("/install/bin/fireemu", deps), undefined);
  assert.match(packagedRunnerError("/checkout/target/release/fireemu", deps), /no packaged runner/);
});

test("the script refuses to start on a build that ships no runner, before it reaches for the network", () => {
  const dir = mkdtempSync(join(tmpdir(), "fireemu-strict-refusal-"));
  try {
    const binary = join(dir, "fireemu");
    writeFileSync(binary, "");
    const out = join(dir, "out");
    const run = spawnSync(
      process.execPath,
      [repo("conformance/src/release-strict-regression.mjs"), "--out", out],
      {
        env: { PATH: process.env.PATH, FIREEMU_BIN: binary, FIREEMU_NODE: process.execPath },
        encoding: "utf8",
      },
    );
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, /no packaged runner beside/);
    assert.equal(existsSync(out), false);
    mkdirSync(join(dir, "runner-node"));
    writeFileSync(join(dir, "runner-node", "index.mjs"), "");
    const packaged = spawnSync(
      process.execPath,
      [repo("conformance/src/release-strict-regression.mjs"), "--out", out],
      {
        env: {
          PATH: process.env.PATH,
          FIREEMU_BIN: binary,
          FIREEMU_NODE: process.execPath,
          FIREEMU_RUNNER_NODE: "x",
        },
        encoding: "utf8",
      },
    );
    assert.match(packaged.stderr, /refusing to run with FIREEMU_RUNNER_NODE set/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// --- the local tenant setup (FS-RULES and AUTH-FS-CROSS stage 1) ------------------------------

const SETUP = () => ({ digest: localSetupDigest(), actions: [...EXPECTED_ACTIONS] });

test("FS-RULES (R4) and AUTH-FS-CROSS stage 1 (R18) are rerun, with their local setup named", () => {
  for (const [id, kind] of [
    ["R4", "fs-rules-comparison-v1"],
    ["R18", "auth-fs-cross-comparison-v1"],
  ]) {
    const run = RUNS.find((r) => r.id === id);
    assert.equal(run?.kind, kind, id);
    assert.equal(run.localSetup, true, id);
    assert.deepEqual(
      run.commands.map((c) => c.mode),
      ["check", "export-comparison"],
      id,
    );
    assert.deepEqual(
      run.commands.map((c) => c.expectedExitCodes),
      [[0], [0]],
      id,
    );
    assert.ok(!EXCLUDED_KINDS.some((ex) => ex.kind === kind), `${kind} is not excluded`);
  }
});

test("only AUTH-FS-CROSS stage 2 is excluded of the three, for its real-time window", () => {
  const kinds = EXCLUDED_KINDS.map((ex) => ex.kind);
  assert.ok(!kinds.includes("fs-rules-comparison-v1"));
  assert.ok(!kinds.includes("auth-fs-cross-comparison-v1"));
  const stage2 = EXCLUDED_KINDS.find((ex) => ex.kind === "auth-fs-cross-stage2-comparison-v1");
  assert.match(stage2.reason, /real time/);
  assert.match(stage2.reason, /browser/);
  assert.ok(!/needs the local tenant setup/.test(stage2.reason));
});

test("a run that prepared the local target must name the setup it made", () => {
  assert.deepEqual(localSetupDifferences({ localSetup: SETUP() }), []);
  assert.match(localSetupDifferences({}).join("\n"), /names no local setup/);
  assert.match(localSetupDifferences(undefined).join("\n"), /names no local setup/);
  assert.match(localSetupDifferences({ localSetup: "x" }).join("\n"), /names no local setup/);
  assert.match(
    localSetupDifferences({ localSetup: { ...SETUP(), digest: "0".repeat(64) } }).join("\n"),
    /localSetup\.digest/,
  );
  assert.match(
    localSetupDifferences({ localSetup: { ...SETUP(), actions: [] } }).join("\n"),
    /localSetup\.actions/,
  );
  assert.match(
    localSetupDifferences({
      localSetup: { ...SETUP(), actions: EXPECTED_ACTIONS.slice(0, 1) },
    }).join("\n"),
    /localSetup\.actions/,
  );
  assert.match(
    localSetupDifferences({ localSetup: { ...SETUP(), extra: 1 } }).join("\n"),
    /unexpected extra/,
  );
});

test("the judgement of a run with a local setup fails without it, and only for those runs", () => {
  const closure = "spec/compatibility/closure/evidence";
  // R4's kind is named by two committed files (FS-RULES' own and AUTH-FS-CROSS' copy on its artifact).
  for (const [runId, file] of [
    ["R4", "FS-RULES-comparison.json"],
    ["R4", "AUTH-FS-CROSS-fs-rules-regression.json"],
    ["R18", "AUTH-FS-CROSS-stage1-comparison.json"],
  ]) {
    const path = `${closure}/${file}`;
    const committed = readJson(path);
    const comparison = { path, kind: committed.kind, runIds: [runId] };
    const context = { readJson, binarySha256: BINARY };
    const observed = { ...committed, artifactSha256: BINARY };
    assert.match(
      judge(comparison, { [runId]: observed }, context).join("\n"),
      /names no local setup/,
      file,
    );
    assert.deepEqual(
      judge(comparison, { [runId]: { ...observed, localSetup: SETUP() } }, context),
      [],
      file,
    );
  }
  // A run without the flag is judged on its rows alone.
  const path = `${EVIDENCE}/AUTH-MFA-comparison.json`;
  const observed = exportOf(path);
  assert.deepEqual(
    judge(
      { path, kind: observed.kind, runIds: ["R8"] },
      { R8: observed },
      { readJson, binarySha256: BINARY },
    ),
    [],
  );
});

test("the release plan stops on a harness binding problem, and is clean with none", () => {
  const stopped = planRelease(committedClosures(), readJson, { binding: () => ["a", "b"] });
  assert.deepEqual(
    stopped.errors.filter((e) => e.startsWith("harness binding")),
    ["harness binding: a", "harness binding: b"],
  );
  assert.deepEqual(planRelease(committedClosures(), readJson, { binding: () => [] }).errors, []);
  // The binding of this checkout: a shallow clone would fail here, as the release job must.
  assert.deepEqual(planRelease(committedClosures(), readJson).errors, []);
});

/** The text of the job of a workflow that holds `needle` (jobs are the two-space keys). */
const jobContaining = (workflow, needle) => {
  const text = readFileSync(repo(`.github/workflows/${workflow}`), "utf8");
  const jobs = text.split(/^(?=  [a-z0-9-]+:\n)/m);
  const found = jobs.filter((job) => job.includes(needle));
  assert.equal(found.length, 1, `${workflow}: one job holds ${needle}`);
  return found[0];
};

test("the jobs that verify the harness lineage check out the whole history", () => {
  // A shallow clone cannot verify a hop, and the selftest and the gate both refuse one: without
  // fetch-depth 0 the release would stop rather than pass unverified.
  for (const [workflow, needle] of [
    ["conformance.yml", "pnpm -C conformance run selftest"],
    ["release.yml", "release-strict-regression.mjs --out strict-regression"],
  ]) {
    const job = jobContaining(workflow, needle);
    const lines = job.split("\n");
    const checkout = lines.findIndex((line) => /uses: actions\/checkout@/.test(line));
    assert.ok(checkout >= 0, `${workflow}: a checkout step`);
    // The `with:` block of the checkout step: the lines indented deeper than the step's `uses`.
    const block = [];
    for (const line of lines.slice(checkout + 1)) {
      if (line.startsWith("      - ") || /^    \S/.test(line)) break;
      block.push(line.trim());
    }
    assert.ok(
      block.includes("fetch-depth: 0"),
      `${workflow}: the checkout fetches the whole history`,
    );
  }
});

test("unsupported OpenSSL records a failure for each federation run before either harness command", async () => {
  const { chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "fireemu-release-openssl-"));
  try {
    const tool = join(dir, "openssl");
    writeFileSync(tool, '#!/bin/sh\necho "OpenSSL 3.0.22"\n');
    chmodSync(tool, 0o700);
    for (const run of RUNS.filter(({ id }) => ["R15", "R16", "R17"].includes(id))) {
      const entry = await runEntry(run, {
        binary: "/unused/fireemu",
        functionsNode: process.execPath,
        out: dir,
        env: { PATH: process.env.PATH, FIREEMU_FEDERATION_OPENSSL_DIR: dir },
      });
      assert.deepEqual(entry.record.commands, []);
      assert.deepEqual(entry.outputs, []);
      assert.equal(entry.record.errors.length, 1);
      assert.match(
        entry.record.errors[0],
        new RegExp(`${run.id} requires OpenSSL >= 3\\.4.*3\\.0\\.22`),
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("R11 actual argv explicitly selects strict in the Node historical harness", () => {
  assert.deepEqual(RUNS.find(({ id }) => id === "R11").commands[0].argv.slice(-2), [
    "--profile",
    "strict",
  ]);
});

test("R11 refuses the old historical receipt without actual strict profile binding", () => {
  const result = passingHistorical();
  delete result.profileBinding;
  assert.notDeepEqual(
    judgeFsDataWriteHistorical(
      regression().historical,
      { exitCode: 0, result, raw: passingRaw() },
      BINARY,
    ),
    [],
  );
});

test("R11 profile receipt fails closed on readback, config and binary near misses", () => {
  const breakers = [
    (b) => {
      b.daemonLogSha256 = "f".repeat(64);
    },
    (b) => {
      b.requestedProfile = "emulator";
    },
    (b) => {
      b.effectiveProfile = "emulator";
    },
    (b) => {
      b.daemonLog = "requested profile: strict\n";
    },
    (b) => {
      b.daemonLog = b.daemonLog.replace("profile: strict", "profile: emulator");
      b.daemonLogSha256 = createHash("sha256").update(b.daemonLog).digest("hex");
    },
    (b) => {
      b.daemonLog += b.daemonLog;
    },
    (b) => {
      b.config.sha256After = "b".repeat(64);
    },
    (b) => {
      b.config.sourceSha256After = "b".repeat(64);
    },
    (b) => {
      b.binary.sha256After = "b".repeat(64);
    },
    (b) => {
      b.argv[2] = "/foreign/config.json";
    },
    (b) => {
      delete b.config.bytesBase64;
    },
    (b) => {
      b.config.bytesBase64 += "!";
    },
    (b) => {
      const json = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      json.profile = "emulator";
      const bytes = Buffer.from(JSON.stringify(json));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
    },
    (b) => {
      const json = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      json.firestore.rules += "-foreign";
      const bytes = Buffer.from(JSON.stringify(json));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
    },
  ];
  for (const [index, breakIt] of breakers.entries()) {
    const result = passingHistorical();
    breakIt(result.profileBinding);
    assert.notDeepEqual(
      judgeFsDataWriteHistorical(
        regression().historical,
        { exitCode: 0, result, raw: passingRaw() },
        BINARY,
      ),
      [],
      String(index),
    );
  }
});

test("generated strict profile receipts agree with an independent five-condition model", () => {
  for (let mask = 0; mask < 32; mask++) {
    const result = passingHistorical(),
      b = result.profileBinding;
    b.requestedProfile = mask & 1 ? "strict" : "emulator";
    b.effectiveProfile = mask & 2 ? "strict" : "emulator";
    b.daemonLog = `  profile: ${mask & 4 ? "strict" : "emulator"} (actual daemon fixture)\n`;
    b.daemonLogSha256 = createHash("sha256").update(b.daemonLog).digest("hex");
    const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
    config.profile = mask & 8 ? "strict" : "emulator";
    const bytes = Buffer.from(JSON.stringify(config));
    b.config.bytesBase64 = bytes.toString("base64");
    b.config.sha256Before = b.config.sha256After = createHash("sha256").update(bytes).digest("hex");
    if (!(mask & 16)) b.binary.sha256After = "c".repeat(64);
    assert.equal(
      judgeFsDataWriteHistorical(
        regression().historical,
        { exitCode: 0, result, raw: passingRaw() },
        BINARY,
      ).length === 0,
      mask === 31,
      String(mask),
    );
  }
});

test("R11 binds source path and rules resolution to the actual launch cwd", () => {
  for (const kind of ["cwd", "source-path", "foreign-settings", "source-bytes"]) {
    const result = passingHistorical(),
      b = result.profileBinding;
    if (kind === "source-path") b.config.sourcePath = "/foreign/source.json";
    else {
      const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      if (kind === "cwd") {
        b.cwd = "/foreign";
        config.firestore.rules = "/foreign/firestore-probe.rules";
      } else config.daemon.clockStart = "2027-01-02T03:04:05Z";
      const bytes = Buffer.from(JSON.stringify(config));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
      if (kind === "source-bytes") {
        const source = JSON.parse(Buffer.from(b.config.sourceBytesBase64, "base64"));
        source.daemon.clockStart = config.daemon.clockStart;
        const sourceBytes = Buffer.from(JSON.stringify(source));
        b.config.sourceBytesBase64 = sourceBytes.toString("base64");
        b.config.sourceSha256Before = b.config.sourceSha256After = createHash("sha256")
          .update(sourceBytes)
          .digest("hex");
      }
    }
    assert.notDeepEqual(
      judgeFsDataWriteHistorical(
        regression().historical,
        { exitCode: 0, result, raw: passingRaw() },
        BINARY,
      ),
      [],
      kind,
    );
  }
});

test("R11 refuses a strict receipt missing the recorded production index prerequisite", () => {
  const result = passingHistorical();
  delete result.profileBinding.indexes;
  assert.notDeepEqual(
    judgeFsDataWriteHistorical(
      regression().historical,
      { exitCode: 0, result, raw: passingRaw() },
      BINARY,
    ),
    [],
  );
});

test("R11 rejects forged index authority, changed bytes and unbound catalog relationships", () => {
  const breakers = [
    (b) => {
      b.indexes.authority.sourceGit = "a".repeat(40);
    },
    (b) => {
      b.indexes.authority.file += "-foreign";
    },
    (b) => {
      b.indexes.authority.bytes++;
    },
    (b) => {
      b.indexes.authority.sha256 = "sha256-" + "a".repeat(64);
    },
    (b) => {
      b.indexes.bytesBase64 = Buffer.from("{}\n").toString("base64");
    },
    (b) => {
      b.indexes.sourceBytesBase64 = Buffer.from("{}\n").toString("base64");
    },
    (b) => {
      b.indexes.path = "relative/indexes.json";
    },
    (b) => {
      b.indexes.sourcePath = "/foreign/recorded.json";
    },
    (b) => {
      b.indexes.bytesBefore++;
    },
    (b) => {
      b.indexes.bytesAfter++;
    },
    (b) => {
      b.indexes.sourceBytesBefore++;
    },
    (b) => {
      b.indexes.sourceBytesAfter++;
    },
    (b) => {
      b.indexes.sha256Before = "f".repeat(64);
    },
    (b) => {
      b.indexes.sha256After = "f".repeat(64);
    },
    (b) => {
      b.indexes.sourceSha256Before = "f".repeat(64);
    },
    (b) => {
      b.indexes.sourceSha256After = "f".repeat(64);
    },
    (b) => {
      const bytes = Buffer.from(b.indexes.bytesBase64, "base64");
      bytes[0] = 32;
      b.indexes.bytesBase64 = b.indexes.sourceBytesBase64 = bytes.toString("base64");
      const digest = createHash("sha256").update(bytes).digest("hex");
      b.indexes.sha256Before =
        b.indexes.sha256After =
        b.indexes.sourceSha256Before =
        b.indexes.sourceSha256After =
          digest;
    },
    (b) => {
      const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      delete config.firestore.indexFile;
      const bytes = Buffer.from(JSON.stringify(config));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
    },
    (b) => {
      const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      b.indexes.path = config.firestore.indexFile = "/foreign/private/indexes.json";
      const bytes = Buffer.from(JSON.stringify(config));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
    },
    (b) => {
      const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      b.indexes.path = config.firestore.indexFile = b.indexes.sourcePath;
      const bytes = Buffer.from(JSON.stringify(config));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
    },
  ];
  for (const [index, breakIt] of breakers.entries()) {
    const result = passingHistorical();
    breakIt(result.profileBinding);
    assert.notDeepEqual(
      judgeFsDataWriteHistorical(
        regression().historical,
        { exitCode: 0, result, raw: passingRaw() },
        BINARY,
      ),
      [],
      String(index),
    );
  }
});

test("generated index receipts agree with an independent four-condition model", () => {
  for (let mask = 0; mask < 16; mask++) {
    const result = passingHistorical(),
      b = result.profileBinding;
    if (!(mask & 1)) delete b.indexes;
    if (!(mask & 2) && b.indexes) b.indexes.authority.sourceGit = "b".repeat(40);
    if (!(mask & 4) && b.indexes) b.indexes.sha256After = "b".repeat(64);
    if (!(mask & 8)) {
      const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
      delete config.firestore.indexFile;
      const bytes = Buffer.from(JSON.stringify(config));
      b.config.bytesBase64 = bytes.toString("base64");
      b.config.sha256Before = b.config.sha256After = createHash("sha256")
        .update(bytes)
        .digest("hex");
    }
    assert.equal(
      judgeFsDataWriteHistorical(
        regression().historical,
        { exitCode: 0, result, raw: passingRaw() },
        BINARY,
      ).length === 0,
      mask === 15,
      String(mask),
    );
  }
});

import { probeProfileBindingProblems } from "./firestore-probe/run.mjs";

test("index validator refuses coherent relative paths, fixture reuse and emulator receipts", () => {
  for (const kind of ["relative", "fixture-reuse", "emulator"]) {
    const result = passingHistorical(),
      b = result.profileBinding;
    const config = JSON.parse(Buffer.from(b.config.bytesBase64, "base64"));
    if (kind === "relative") {
      b.config.path = "relative/run/config.json";
      b.indexes.path = config.firestore.indexFile = "relative/run/indexes.json";
    } else if (kind === "fixture-reuse") {
      b.config.path = repo("conformance/generated-config.json");
      b.indexes.path = config.firestore.indexFile = b.indexes.sourcePath;
    } else {
      b.requestedProfile = b.effectiveProfile = config.profile = "emulator";
      config.firestore.rules = JSON.parse(
        Buffer.from(b.config.sourceBytesBase64, "base64"),
      ).firestore.rules;
      b.daemonLog = "  profile: emulator (actual daemon fixture)\n";
      b.daemonLogSha256 = createHash("sha256").update(b.daemonLog).digest("hex");
    }
    b.argv[2] = b.config.path;
    const bytes = Buffer.from(JSON.stringify(config));
    b.config.bytesBase64 = bytes.toString("base64");
    b.config.sha256Before = b.config.sha256After = createHash("sha256").update(bytes).digest("hex");
    if (kind === "emulator")
      assert.notDeepEqual(
        probeProfileBindingProblems(b, "emulator", BINARY, undefined, b.indexes.authority),
        [],
        kind,
      );
    else
      assert.notDeepEqual(
        judgeFsDataWriteHistorical(
          regression().historical,
          { exitCode: 0, result, raw: passingRaw() },
          BINARY,
        ),
        [],
        kind,
      );
  }
});

test("R11 rejects historical counts without retained raw comparands", () => {
  assert.notDeepEqual(
    judgeFsDataWriteHistorical(
      regression().historical,
      { exitCode: 0, result: passingHistorical() },
      BINARY,
    ),
    [],
  );
});

const resolvedObservation = () => {
  const live = baselineRaw();
  const saved = readJson("conformance/firestore-production-matrix.json");
  for (const id of [
    "commit-on-the-named-database-route",
    "named-database-document",
    "get-named-database",
  ])
    live["emulator/routes"].steps[id] = saved.programs.find(
      (p) => p.id === "emulator/routes",
    ).steps[id].production;
  const raw = historicalRawObservation(Buffer.from(JSON.stringify(live)));
  return {
    exitCode: 0,
    raw,
    result: {
      ...passingHistorical(),
      localRawSha256: raw.sha256,
      ...historicalProductionSummary(live),
    },
  };
};

test("R11 accepts complete canonical matches for the three resolved legacy rows", () => {
  const observed = resolvedObservation();
  assert.equal(observed.result.currentMismatches.length, 13);
  assert.deepEqual(judgeFsDataWriteHistorical(regression().historical, observed, BINARY), []);
});

test("R11 raw proof rejects digest, inventory, summary and resolution forgeries", () => {
  const breakers = {
    "wrong raw SHA": (o) => {
      o.raw.sha256 = "b".repeat(64);
    },
    "coherent wrong digest": (o) => {
      o.raw.sha256 = o.result.localRawSha256 = "b".repeat(64);
    },
    "wrong bound SHA": (o) => {
      o.result.localRawSha256 = "b".repeat(64);
    },
    "altered raw body": (o) => {
      const live = JSON.parse(Buffer.from(o.raw.bytesBase64, "base64"));
      live["emulator/routes"].steps["get-named-database"].code = "INTERNAL";
      o.raw = historicalRawObservation(Buffer.from(JSON.stringify(live)));
    },
    "forged comparable": (o) => {
      o.result.comparable--;
    },
    "forged baseline": (o) => {
      o.result.baselineMismatches.pop();
    },
    "forged current summary": (o) => {
      o.result.currentMismatches.pop();
    },
    "forged new summary": (o) => {
      o.result.newMismatches = ["fake#row"];
    },
    "forged indeterminate": (o) => {
      o.result.indeterminate = [];
    },
    "forged new indeterminate": (o) => {
      o.result.newIndeterminate = ["fake#row"];
    },
    "duplicate raw key": (o) => {
      const text = Buffer.from(o.raw.bytesBase64, "base64").toString(),
        live = JSON.parse(text),
        key = Object.keys(live)[0];
      o.raw = historicalRawObservation(
        Buffer.from(`{${JSON.stringify(key)}:${JSON.stringify(live[key])},${text.slice(1)}`),
      );
      o.result.localRawSha256 = o.raw.sha256;
    },
  };
  for (const [label, breakIt] of Object.entries(breakers)) {
    const observed = resolvedObservation();
    breakIt(observed);
    assert.notDeepEqual(
      judgeFsDataWriteHistorical(regression().historical, observed, BINARY),
      [],
      label,
    );
  }
});

test("R11 complete inventory and unchanged debt are mandatory even with coherent hashes and summaries", () => {
  const breakers = {
    "missing program": (live) => {
      delete live["emulator/routes"];
    },
    "unknown program": (live) => {
      live.unknown = { steps: {} };
    },
    "missing resolved row": (live) => {
      delete live["emulator/routes"].steps["get-named-database"];
    },
    "missing excluded row": (live) => {
      delete live["writes/transforms"].steps["maximum-and-minimum"];
    },
    "unknown row": (live) => {
      live["emulator/routes"].steps.unknown = { status: 200, code: "OK" };
    },
    "incomplete resolution": (live) => {
      live["emulator/routes"].steps["get-named-database"] = { skipped: true };
    },
    "changed indeterminate": (live) => {
      live["values/type-order"].steps[Object.keys(live["values/type-order"].steps)[0]] = {
        skipped: true,
      };
    },
    "unlisted mismatch": (live) => {
      live["queries/collection-group"].steps["partition-query"] = { status: 500, code: "INTERNAL" };
    },
    "new mismatch": (live) => {
      live["values/type-order"].steps[Object.keys(live["values/type-order"].steps)[0]] = {
        status: 500,
        code: "INTERNAL",
      };
    },
  };
  for (const [label, breakIt] of Object.entries(breakers)) {
    const observed = resolvedObservation(),
      live = JSON.parse(Buffer.from(observed.raw.bytesBase64, "base64"));
    breakIt(live);
    observed.raw = historicalRawObservation(Buffer.from(JSON.stringify(live)));
    observed.result.localRawSha256 = observed.raw.sha256;
    try {
      Object.assign(observed.result, historicalProductionSummary(live));
    } catch {}
    assert.notDeepEqual(
      judgeFsDataWriteHistorical(regression().historical, observed, BINARY),
      [],
      label,
    );
  }
});

test("R11 binds every supplied summary and receipt field to the collected comparison snapshot", () => {
  const observed = resolvedObservation();
  observed.comparison = historicalRawObservation(Buffer.from(JSON.stringify(observed.result)));
  assert.deepEqual(judgeHistorical(regression().historical, observed, BINARY), []);
  for (const mutate of [
    (o) => {
      delete o.comparison;
    },
    (o) => {
      o.comparison.sha256 = "b".repeat(64);
    },
    (o) => {
      o.result.artifact.version = "forged";
    },
    (o) => {
      o.result.comparable--;
    },
  ]) {
    const changed = clone(observed);
    mutate(changed);
    assert.notDeepEqual(judgeHistorical(regression().historical, changed, BINARY), []);
  }
});

test("R11 trusted collector preserves exact raw and comparison snapshots and their hashes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "strict-raw-collector-")),
    out = join(dir, "out");
  mkdirSync(out);
  try {
    const observed = resolvedObservation(),
      bytes = Buffer.from(observed.raw.bytesBase64, "base64"),
      summary = Buffer.from(`${JSON.stringify(observed.result, null, 2)}\n`);
    writeFileSync(join(dir, "fireemu-historical-production.json"), bytes);
    writeFileSync(join(dir, "historical-production-comparison.json"), summary);
    const collected = await collectHistoricalReplay(dir, out);
    assert.deepEqual(collected.raw, historicalRawObservation(bytes));
    assert.deepEqual(collected.comparison, historicalRawObservation(summary));
    assert.deepEqual(readFileSync(join(out, "R11-fireemu-historical-production.json")), bytes);
    assert.deepEqual(readFileSync(join(out, "R11-historical-production-comparison.json")), summary);
    assert.deepEqual(
      judgeHistorical(regression().historical, { exitCode: 0, ...collected }, BINARY),
      [],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("R11 generated proof combinations agree with an independent six-condition model", () => {
  for (let mask = 0; mask < 64; mask++) {
    const observed = resolvedObservation();
    observed.comparison = historicalRawObservation(Buffer.from(JSON.stringify(observed.result)));
    if (!(mask & 1)) delete observed.raw;
    if (!(mask & 2)) observed.comparison.sha256 = "b".repeat(64);
    if (!(mask & 4)) observed.result.profileBinding.effectiveProfile = "emulator";
    if (!(mask & 8)) observed.result.comparable--;
    if (!(mask & 16) && observed.raw) observed.raw.sha256 = "b".repeat(64);
    if (!(mask & 32)) delete observed.result.profileBinding.indexes;
    assert.equal(
      judgeHistorical(regression().historical, observed, BINARY).length === 0,
      mask === 63,
      String(mask),
    );
  }
});

// The historical FS-DATA-WRITE replay (R11) sends the recorded transaction-lifecycle program to
// the strict binary. Its `out-of-band-write` step is a writer held behind a read-write
// transaction's lock; production answered it 409 ABORTED "Too much contention on these
// documents. Please try again." (conformance/firestore-production-matrix.json,
// transactions/lifecycle#out-of-band-write). Strict holds such a writer for
// STRICT_CONTENTION_WAIT before it answers, and the probe session abandons any request after
// FIRESTORE_PROBE_TIMEOUT_MS (20 s unless set), which turned the answer into "no-response" (an
// indeterminate row) once the wait reached 20 s. Production was recorded with the timeout of
// run.mjs (`recordProduction`), so the replay uses that value.
test("the historical FS-DATA-WRITE replay waits for a held writer longer than strict holds it, as the production recording did", () => {
  const root = fileURLToPath(new URL("../..", import.meta.url));
  const localSource = readFileSync(join(root, "crates/fireemu-adapter-grpc/src/local.rs"), "utf8");
  const strictWait =
    /STRICT_CONTENTION_WAIT: std::time::Duration =\s*std::time::Duration::from_secs\((\d+)\)/.exec(
      localSource,
    );
  assert.ok(strictWait, "the strict contention wait is a whole number of seconds");
  const strictWaitMs = Number(strictWait[1]) * 1000;
  const probeSource = readFileSync(join(root, "conformance/src/firestore-probe/run.mjs"), "utf8");
  const recorded =
    /FIRESTORE_PROBE_TARGET: "production"[\s\S]*?FIRESTORE_PROBE_TIMEOUT_MS: "(\d+)"/.exec(
      probeSource,
    );
  assert.ok(recorded, "the production recording names its request timeout");
  const r11 = RUNS.find((run) => run.id === "R11");
  assert.ok(r11, "R11 is the historical FS-DATA-WRITE replay");
  for (const command of r11.commands) {
    const timeout = Number(command.env.FIRESTORE_PROBE_TIMEOUT_MS);
    assert.equal(
      command.env.FIRESTORE_PROBE_TIMEOUT_MS,
      recorded[1],
      `${command.mode}: the replay's request timeout is the recording's`,
    );
    assert.ok(
      timeout > strictWaitMs + 10_000,
      `${command.mode}: ${timeout} ms is not above ${strictWaitMs} ms`,
    );
  }
});

test("FS-LISTEN-SDK uses its disclosed exclusion as a verified closure", () => {
  const closures = committedClosures();
  const listen = closures.find((entry) => entry.closure.parent === "FS-LISTEN-SDK");
  assert.equal(listen.closure.parentStatus, "COMPAT_VERIFIED");
  const reviewed = planComparisons(closures, readJson);
  assert.deepEqual(reviewed.errors, []);
  assert.ok(reviewed.excluded.some((entry) => entry.kind === "fs-listen-sdk-comparison-v1"));
});

test("every release command binds its declared mode to the actual CLI action", () => {
  for (const run of RUNS) {
    for (const command of run.commands) {
      assert.ok(ALLOWED_MODES.has(command.mode), `${run.id}: ${command.mode}`);
      assert.ok(command.argv.includes(command.mode), `${run.id}: ${command.mode}`);
    }
  }
});

test("R19 executes with the reviewed interpreter and owns both expanded output paths", async () => {
  const { chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "fireemu R19 setup-"));
  try {
    mkdirSync(join(dir, "logs"));
    const fakeUv = `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
const output = args[args.indexOf("--out") + 1];
if (JSON.stringify(args.slice(0, 4)) !== JSON.stringify(["run", "--python", "3.12.13", "python"])) process.exit(3);
if (!output.startsWith(process.env.R19_OWNED_OUT + "/")) process.exit(4);
fs.writeFileSync(output + ".receipt", JSON.stringify(args));
console.log(JSON.stringify({ args }));
`;
    for (const executable of ["uv", "python3"]) {
      const path = join(dir, executable);
      writeFileSync(path, fakeUv);
      chmodSync(path, 0o700);
    }
    const run = clone(RUNS.find(({ id }) => id === "R19"));
    run.clear = [];
    const entry = await runEntry(run, {
      binary: join(dir, "installed binary"),
      functionsNode: process.execPath,
      out: dir,
      env: { PATH: dir, R19_OWNED_OUT: dir },
    });
    assert.deepEqual(entry.record.errors, []);
    assert.equal(entry.record.commands.length, 2);
    for (const [index, command] of entry.record.commands.entries()) {
      assert.deepEqual(command.argv.slice(0, 5), ["uv", "run", "--python", "3.12.13", "python"]);
      const output = command.argv[command.argv.indexOf("--out") + 1];
      assert.equal(output, join(dir, index === 0 ? "R19-export.json.check" : "R19-export.json"));
      assert.ok(existsSync(output + ".receipt"));
      assert.deepEqual(
        JSON.parse(readFileSync(output + ".receipt", "utf8")),
        command.argv.slice(1),
      );
      assert.equal(command.exitCode, 0);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the strict-production job prepares pinned Python and Chromium before offline replay", () => {
  const job = strictProductionJob();
  const isolated = job.indexOf("unshare --net");
  const installUv = job.indexOf("pipx install uv==0.11.28");
  const installPython = job.indexOf("uv python install 3.12.13");
  const checkPython = job.indexOf("assert sys.version_info[:3] == (3, 12, 13)");
  const installNode = job.indexOf("pnpm -C conformance install --frozen-lockfile");
  const installChromium = job.indexOf(
    "pnpm -C conformance exec playwright install --with-deps chromium",
  );
  assert.ok(
    installUv >= 0 &&
      installPython > installUv &&
      checkPython > installPython &&
      checkPython < isolated,
  );
  assert.ok(installNode >= 0 && installChromium > installNode && installChromium < isolated);
  assert.match(job, /UV_OFFLINE: "1"/);
  assert.match(job, /UV_PYTHON_DOWNLOADS: never/);
  const launch = job.slice(isolated);
  assert.match(launch, /PATH="\$PATH" HOME="\$HOME"/);
  assert.match(launch, /UV_OFFLINE="\$UV_OFFLINE" UV_PYTHON_DOWNLOADS="\$UV_PYTHON_DOWNLOADS"/);
});

const eventarcComparisonPath = "spec/compatibility/closure/evidence/EVENTARC-comparison.json";
const pendingEventarcFixture = () => ({
  kind: "eventarc-production-comparison-v1",
  parent: "EVENTARC",
  fixtureSha256: "b".repeat(64),
  artifactSha256: BINARY,
  inputPins: { "B.jsonl": "c".repeat(64) },
  fixturePins: { "neutral-functions/index.js": "d".repeat(64) },
  sourcePins: { "conformance/src/eventarc-production/run.mjs": "e".repeat(64) },
  rows: [{ row: "eventarc/channel-lifecycle#list-channels", transport: "rest", status: "PENDING" }],
  summary: { PENDING: 1 },
});
const pendingEventarcClosure = () => ({
  name: "EVENTARC.json",
  closure: {
    parent: "EVENTARC",
    parentStatus: "IMPLEMENTING",
    integratedRegression: { comparisons: [{ path: eventarcComparisonPath }] },
  },
});

test("R20 declares the real check and evidence-reusing export CLI with scoped deadlines", () => {
  const run = RUNS.find(({ id }) => id === "R20");
  assert.ok(run);
  assert.equal(run.kind, "eventarc-production-comparison-v1");
  assert.equal(run.rowPrefix, "eventarc/");
  assert.deepEqual(run.clear, ["eventarc-production"]);
  assert.deepEqual(
    run.commands.map(({ mode }) => mode),
    ["check", "export-comparison"],
  );
  assert.deepEqual(run.commands[0].argv, [
    "{functionsNode}",
    "conformance/src/eventarc-production/run.mjs",
    "check",
    "--binary",
    "{bin}",
    "--out",
    "{export}.check",
  ]);
  assert.deepEqual(run.commands[1].argv, [
    "{functionsNode}",
    "conformance/src/eventarc-production/run.mjs",
    "export-comparison",
    "--binary",
    "{bin}",
    "--out",
    "{export}.check",
    "--evidence",
    "{export}.check/check-evidence.json",
    "--comparison",
    "{export}",
  ]);
  assert.equal(run.commands[0].timeoutMs, 7420000);
  assert.equal(run.commands[1].timeoutMs, undefined);
  for (const command of run.commands) {
    assert.deepEqual(command.expectedExitCodes, [0]);
    assert.deepEqual(command.env, {});
  }
  for (const other of RUNS.filter(({ id }) => id !== "R20"))
    for (const command of other.commands) assert.equal(command.timeoutMs, undefined, other.id);
  assert.match(strictProductionJob(), /timeout-minutes: 180\n/);
});

test("R20 pending EVENTARC plans exports but refuses missing semantic evidence", () => {
  const document = pendingEventarcFixture();
  const entries = [
    pendingEventarcClosure(),
    {
      name: "OTHER.json",
      closure: {
        parent: "OTHER",
        parentStatus: "IMPLEMENTING",
        integratedRegression: { comparisons: [{ path: "never-read.json" }] },
      },
    },
  ];
  const plan = planComparisons(
    entries,
    (path) => {
      assert.equal(path, eventarcComparisonPath);
      return document;
    },
    { excludedKinds: [] },
  );
  assert.deepEqual(plan.errors, []);
  assert.deepEqual(plan.comparisons, [
    { path: eventarcComparisonPath, kind: document.kind, parents: ["EVENTARC"], runIds: ["R20"] },
  ]);
  assert.deepEqual(exportCopies(plan.comparisons, RUNS), [
    { from: "R20-export.json", to: "EVENTARC-comparison.json" },
  ]);
  assert.match(
    judge(
      plan.comparisons[0],
      { R20: clone(document) },
      { binarySha256: BINARY, readJson: () => document },
    ).join("\n"),
    /missing bound semantic comparands/,
  );
  assert.equal(entries[0].closure.parentStatus, "IMPLEMENTING");
  const changed = clone(document);
  changed.rows[0].status = "MATCH";
  assert.notDeepEqual(
    judge(
      plan.comparisons[0],
      { R20: changed },
      { binarySha256: BINARY, readJson: () => document },
    ),
    [],
  );
});

test("R20 refuses absent registration and malformed pending EVENTARC rows", () => {
  const absent = pendingEventarcClosure();
  delete absent.closure.integratedRegression;
  assert.ok(
    planComparisons([absent], () => assert.fail("no authentic reference"), {
      excludedKinds: [],
    }).errors.some((x) => /R20.*comparison/.test(x)),
  );
  const breakers = {
    "foreign kind": (x) => {
      x.kind = "foreign-v1";
    },
    "empty rows": (x) => {
      x.rows = [];
    },
    "foreign prefix": (x) => {
      x.rows[0].row = "foreign/case";
    },
    "duplicate row": (x) => {
      x.rows.push(clone(x.rows[0]));
    },
    "foreign transport": (x) => {
      x.rows[0].transport = "grpc";
    },
  };
  for (const [name, change] of Object.entries(breakers)) {
    const document = pendingEventarcFixture();
    change(document);
    assert.ok(
      planComparisons([pendingEventarcClosure()], () => document, { excludedKinds: [] }).errors
        .length,
      name,
    );
  }
});

test("R20 actual command expansion owns both outputs and passes the same evidence to export", async () => {
  const { chmodSync } = await import("node:fs");
  const dir = mkdtempSync(join(tmpdir(), "fireemu R20 argv-"));
  try {
    mkdirSync(join(dir, "logs"));
    const executable = join(dir, "fixture-node");
    writeFileSync(
      executable,
      `#!${process.execPath}
const fs=require('node:fs');const args=process.argv.slice(2);const flag=k=>args[args.indexOf(k)+1];
if(args[0]!=='conformance/src/eventarc-production/run.mjs'||flag('--binary')!==process.env.R20_TEST_BINARY)process.exit(3);
const out=flag('--out');if(out!==process.env.R20_TEST_OUT+'/R20-export.json.check')process.exit(4);
if(args[1]==='check'){fs.mkdirSync(out);fs.writeFileSync(out+'/check-evidence.json',JSON.stringify({testOnly:true}));}
else{if(flag('--evidence')!==out+'/check-evidence.json'||!JSON.parse(fs.readFileSync(flag('--evidence'))).testOnly)process.exit(5);if(flag('--comparison')!==process.env.R20_TEST_OUT+'/R20-export.json')process.exit(6);fs.writeFileSync(flag('--comparison'),JSON.stringify({testOnly:true}));}
console.log(JSON.stringify({args}));
`,
    );
    chmodSync(executable, 0o700);
    const run = clone(RUNS.find(({ id }) => id === "R20"));
    run.clear = [];
    const binary = join(dir, "installed binary");
    const entry = await runEntry(run, {
      binary,
      functionsNode: executable,
      out: dir,
      env: { PATH: process.env.PATH, R20_TEST_BINARY: binary, R20_TEST_OUT: dir },
    });
    assert.deepEqual(entry.record.errors, []);
    assert.equal(entry.record.commands.length, 2);
    assert.equal(entry.record.commands[0].timeoutMs, 7420000);
    assert.equal(entry.record.commands[1].timeoutMs, 600000);
    assert.ok(existsSync(join(dir, "R20-export.json")));
    for (const output of entry.outputs) assert.ok(JSON.parse(output).args.includes(binary));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("R20 invalid explicit deadlines refuse before spawning", async () => {
  const dir = mkdtempSync(join(tmpdir(), "fireemu R20 deadline-"));
  try {
    mkdirSync(join(dir, "logs"));
    const marker = join(dir, "spawned");
    for (const timeoutMs of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, null, "50"]) {
      const run = {
        id: "R20",
        clear: [],
        commands: [
          {
            mode: "check",
            argv: [
              process.execPath,
              "-e",
              `require('node:fs').writeFileSync(${JSON.stringify(marker)},'unexpected')`,
              "check",
            ],
            env: {},
            expectedExitCodes: [0],
            timeoutMs,
          },
        ],
      };
      await assert.rejects(
        runEntry(run, {
          binary: marker,
          functionsNode: process.execPath,
          out: dir,
          env: process.env,
        }),
        /positive safe.*timeout/,
      );
      assert.ok(!existsSync(marker));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("R20 bounded timeout is a failure and removes its owned process group", async () => {
  const dir = mkdtempSync(join(tmpdir(), "fireemu R20 timeout-"));
  try {
    mkdirSync(join(dir, "logs"));
    const run = {
      id: "R20",
      clear: [],
      commands: [
        {
          mode: "check",
          argv: [
            process.execPath,
            "-e",
            "console.log(JSON.stringify({pid:process.pid}));setInterval(()=>{},1000)",
            "check",
          ],
          env: {},
          expectedExitCodes: [0],
          timeoutMs: 200,
        },
      ],
    };
    const entry = await runEntry(run, {
      binary: join(dir, "unused binary"),
      functionsNode: process.execPath,
      out: dir,
      env: process.env,
    });
    assert.equal(entry.record.commands[0].exitCode, "timeout");
    assert.ok(entry.record.errors.some((x) => /exited timeout/.test(x)));
    const { pid } = JSON.parse(entry.outputs[0].trim());
    assert.throws(
      () => process.kill(-pid, 0),
      (error) => error.code === "ESRCH",
    );
    assert.ok(readFileSync(join(dir, "logs/R20-1-check.log"), "utf8").includes(String(pid)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("R20 rejects changed stable native input fixture and source pins", () => {
  const expected = pendingEventarcFixture();
  assert.deepEqual(compareLaneExport(expected, clone(expected), BINARY), [
    "EVENTARC semantic evidence: missing bound semantic comparands",
  ]);
  for (const field of ["inputPins", "fixturePins", "sourcePins"]) {
    for (const change of ["missing", "digest", "foreign path"]) {
      const actual = clone(expected);
      const [path] = Object.keys(actual[field]);
      if (change === "missing") delete actual[field];
      if (change === "digest") actual[field][path] = "f".repeat(64);
      if (change === "foreign path") {
        delete actual[field][path];
        actual[field]["foreign/" + path] = expected[field][path];
      }
      assert.ok(
        compareLaneExport(expected, actual, BINARY).some((difference) =>
          difference.startsWith(field + ":"),
        ),
        field + "/" + change,
      );
    }
  }
  const unrelated = { ...expected, kind: "unrelated-comparison-v1" };
  const unrelatedActual = clone(unrelated);
  unrelatedActual.inputPins = { different: "f".repeat(64) };
  assert.deepEqual(compareLaneExport(unrelated, unrelatedActual, BINARY), []);
});

test("R20 registration cannot substitute another implemented comparison kind", () => {
  const document = pendingEventarcFixture();
  document.kind = "other-implemented-comparison-v1";
  const plan = planComparisons([pendingEventarcClosure()], () => document, {
    excludedKinds: [],
    runs: [{ id: "Other", kind: document.kind }],
  });
  assert.ok(plan.errors.some((error) => /R20.*kind/.test(error)));
  assert.deepEqual(plan.comparisons, []);
});

test("R20 export preserves its parent and schema identity", () => {
  const expected = { ...pendingEventarcFixture(), schemaVersion: 1 };
  assert.deepEqual(compareLaneExport(expected, clone(expected), BINARY), [
    "EVENTARC semantic evidence: missing bound semantic comparands",
  ]);
  for (const field of ["parent", "schemaVersion"]) {
    for (const change of ["missing", "foreign"]) {
      const actual = clone(expected);
      if (change === "missing") delete actual[field];
      else actual[field] = field === "parent" ? "FOREIGN" : 2;
      assert.ok(
        compareLaneExport(expected, actual, BINARY).some((difference) =>
          difference.startsWith(field + ":"),
        ),
        field + "/" + change,
      );
    }
  }
});

test("R20 plans all seventy producer inventory rows with their declared transports", () => {
  const inventory = readJson("spec/compatibility/closure/EVENTARC.json");
  const document = pendingEventarcFixture();
  document.rows = inventory.conditions.flatMap((condition) =>
    condition.cases.flatMap((caseId) =>
      condition.transports.map((transport) => ({
        row: `${condition.recipeIds[0]}#${caseId}`,
        conditionId: condition.conditionId,
        caseId,
        transport,
        status: "PENDING",
        reason: "Collection does not grant criterion closure",
      })),
    ),
  );
  document.summary = { PENDING: document.rows.length };
  assert.equal(document.rows.length, 70);
  assert.equal(document.rows.filter(({ transport }) => transport === "rest").length, 63);
  assert.equal(document.rows.filter(({ transport }) => transport === "artifact").length, 7);
  assert.deepEqual(
    planComparisons([pendingEventarcClosure()], () => document, { excludedKinds: [] }).errors,
    [],
  );
  for (const [index, original] of document.rows.entries()) {
    const changed = clone(document);
    changed.rows[index].transport = original.transport === "rest" ? "artifact" : "rest";
    assert.ok(
      planComparisons([pendingEventarcClosure()], () => changed, { excludedKinds: [] }).errors
        .length,
      original.row,
    );
  }
  for (let offset = 0; offset < document.rows.length; offset++) {
    const reordered = clone(document);
    reordered.rows = [...reordered.rows.slice(offset), ...reordered.rows.slice(0, offset)];
    assert.deepEqual(
      planComparisons([pendingEventarcClosure()], () => reordered, { excludedKinds: [] }).errors,
      [],
    );
    assert.deepEqual(compareLaneExport(document, reordered, BINARY), [
      "EVENTARC semantic evidence: missing bound semantic comparands",
    ]);
  }
});

test("the exact EVENTARC gzip canonical preserves decoded bytes and plain artifact aliases", () => {
  const root = mkdtempSync(join(tmpdir(), "eventarc-gzip-"));
  const path = "spec/compatibility/closure/evidence/EVENTARC-comparison.json.gz";
  const raw = Buffer.from('{"rows":[{"row":"eventarc/test#case"}],"summary":{"PENDING":1}}\n');
  const zipped = gzipSync(raw, { mtime: 0 });
  const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
  const entry = {
    path,
    sha256: digest(zipped),
    decodedSha256: digest(raw),
    decodedBytes: raw.length,
  };
  const target = join(root, path);
  mkdirSync(join(root, "spec/compatibility/closure/evidence"), { recursive: true });
  const save = () => {
    writeFileSync(target, zipped);
    writeFileSync(
      join(root, "spec/compatibility/closure/EVENTARC.json"),
      JSON.stringify({ integratedRegression: { comparisons: [entry] } }),
    );
  };
  try {
    save();
    assert.deepEqual(readReleaseJson(root, path), JSON.parse(raw));
    const plain = "plain.json";
    writeFileSync(join(root, plain), raw);
    assert.deepEqual(readReleaseJson(root, plain), JSON.parse(raw));
    assert.deepEqual(exportCopies([{ path, runIds: ["R20"] }], RUNS), [
      { from: "R20-export.json", to: "EVENTARC-comparison.json" },
    ]);
    entry.sha256 = "0".repeat(64);
    save();
    assert.throws(() => readReleaseJson(root, path));
    entry.sha256 = digest(zipped);
    save();
    entry.decodedSha256 = "0".repeat(64);
    save();
    assert.throws(() => readReleaseJson(root, path));
    entry.decodedSha256 = digest(raw);
    entry.decodedBytes = raw.length - 1;
    save();
    assert.throws(() => readReleaseJson(root, path));
    entry.decodedBytes = raw.length;
    save();
    writeFileSync(target, zipped.subarray(0, zipped.length - 1));
    assert.throws(() => readReleaseJson(root, path));
    entry.sha256 = digest(zipped.subarray(0, zipped.length - 1));
    writeFileSync(
      join(root, "spec/compatibility/closure/EVENTARC.json"),
      JSON.stringify({ integratedRegression: { comparisons: [entry] } }),
    );
    assert.throws(() => readReleaseJson(root, path));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
