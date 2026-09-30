// The release comparison of the strict profile with the committed production recordings: its
// judgements (rows, coverage, the FS-DATA-WRITE and FUNCTIONS-HTTP parts) and its safety
// checks (no recording mode, no production credential, no route out) are tested here on inputs
// built from the committed evidence, each broken in one place.
import assert from "node:assert/strict";
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
  judgeFsDataWriteHistorical,
  judgeFunctionsHttp,
  localSetupDifferences,
  packagedRunnerError,
  parseArguments,
  planComparisons,
  planRelease,
} from "./release-strict-regression.mjs";
import { COMPARISONS } from "./auth-federation/compare.mjs";

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const readJson = (path) => JSON.parse(readFileSync(repo(path), "utf8"));
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
  // Each run serves a comparison: no run is kept for nothing.
  const used = new Set(plan.comparisons.flatMap((c) => c.runIds));
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
  ]);
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

const passingHistorical = () => {
  const historical = regression().historical;
  const indeterminate = ["transactions/lifecycle#phantom-write"];
  return {
    artifact: { sha256Before: BINARY, sha256After: BINARY },
    comparable: historical.comparable,
    currentMismatches: historical.rows.filter((row) => !indeterminate.includes(row)),
    newMismatches: [],
    indeterminate,
    newIndeterminate: [],
  };
};

test("the historical production replay passes on the committed figures", () => {
  assert.deepEqual(
    judgeFsDataWriteHistorical(
      regression().historical,
      { exitCode: 0, result: passingHistorical() },
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
    const observed = { exitCode: 0, result: passingHistorical() };
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
