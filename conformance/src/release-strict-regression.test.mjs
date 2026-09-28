// The release comparison of the strict profile with the committed production recordings: its
// judgements (rows, coverage, the FS-DATA-WRITE and FUNCTIONS-HTTP parts) and its safety
// checks (no recording mode, no production credential, no route out) are tested here on inputs
// built from the committed evidence, each broken in one place.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  ALLOWED_MODES,
  EXCLUDED_PARTS,
  RUNS,
  assertNoOutboundNetwork,
  commandModes,
  compareLaneExport,
  forbiddenEnvironment,
  judgeFsDataWriteCurrent,
  judgeFsDataWriteHistorical,
  judgeFunctionsHttp,
  parseArguments,
  planComparisons,
} from "./release-strict-regression.mjs";

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
  const paths = new Set(plan.comparisons.map((c) => c.path));
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
