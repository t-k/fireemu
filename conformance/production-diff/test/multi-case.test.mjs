// pilot.mjs must dispatch by --case rather than hard-coding the batch-write case. These tests
// exercise that dispatch through the public CLI entrypoints (list/plan), which need no native
// binary, plus buildExecArgs's per-case project wiring.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { CASE, CASES, COMMIT_TRANSFORM_CASE, G0_CASE, TRANSFORMS_CASE, PRECONDITIONS_CASE, PROJECTION_CASE, AGGREGATIONS_CASE, selectCase } from "../registry.mjs";
import { buildExecArgs, main } from "../pilot.mjs";
import { resultEnvelope } from "../core.mjs";

async function captureStdout(run) {
  const original = console.log;
  const lines = [];
  console.log = (line) => lines.push(line);
  let code;
  try {
    code = await run();
  } finally {
    console.log = original;
  }
  return [lines, code];
}

test("registry exposes registered cases and rejects an unknown id", () => {
  assert.deepEqual(
    CASES.map((c) => c.id),
    [CASE.id, COMMIT_TRANSFORM_CASE.id, G0_CASE.id, TRANSFORMS_CASE.id, PRECONDITIONS_CASE.id, PROJECTION_CASE.id, AGGREGATIONS_CASE.id],
  );
  assert.equal(selectCase(COMMIT_TRANSFORM_CASE.id).adapter, "commit-transform");
  assert.equal(selectCase(G0_CASE.id).adapter, "g0");
  assert.throws(() => selectCase("not-a-case"), /unknown-case/);
});

test("pilot.mjs list reports registered cases", async () => {
  const [lines, code] = await captureStdout(() => main(["list"]));
  assert.equal(code, 0);
  const parsed = JSON.parse(lines[0]);
  assert.deepEqual(
    parsed.cases.map((c) => c.id),
    [CASE.id, COMMIT_TRANSFORM_CASE.id, G0_CASE.id, TRANSFORMS_CASE.id, PRECONDITIONS_CASE.id, PROJECTION_CASE.id, AGGREGATIONS_CASE.id],
  );
});

test("pilot.mjs refuses G0 planning when the private input binding is absent", async () => {
  const [lines, code] = await captureStdout(() => main(["plan", "--case", G0_CASE.id]));
  if (process.env.G0_PRIVATE_PRODUCTION_RESULT) {
    assert.equal(code, 0);
    assert.equal(JSON.parse(lines[0]).operations, 12);
    return;
  }
  assert.equal(code, 2);
  assert.equal(lines.length, 0);
});

test("pilot.mjs plan works for the commit-transform case without a binary", async () => {
  const [lines, code] = await captureStdout(() =>
    main(["plan", "--case", COMMIT_TRANSFORM_CASE.id]),
  );
  assert.equal(code, 0);
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.case, COMMIT_TRANSFORM_CASE.id);
  assert.equal(parsed.operations, 17);
  assert.equal(parsed.evidenceKind, "documented-production-outcome-reference");
  assert.equal(parsed.oracleKind, "documented-outcome-contract");
});

test("pilot.mjs plan reports the batch-write case's own evidence kind, not the commit-transform one", async () => {
  const [lines, code] = await captureStdout(() => main(["plan", "--case", CASE.id]));
  assert.equal(code, 0);
  const parsed = JSON.parse(lines[0]);
  assert.equal(parsed.evidenceKind, "saved-production-reference");
  assert.equal(parsed.oracleKind, "legacy-normalized-production-observation");
});

// Regression for the owner review finding (2026-09-21, item 2 of the 95c5b994a review): before
// the fix, resultEnvelope() hard-coded evidenceKind/oracleKind for every case, so a Commit-case
// replay/compare result and its report.md disagreed with what `plan` correctly reported. Each
// case's own evidenceKind/oracleKind (registry.mjs) must reach resultEnvelope() unchanged, so plan
// and the post-replay/compare result always agree.
for (const entry of [CASE, COMMIT_TRANSFORM_CASE])
  test(`resultEnvelope reports ${entry.id}'s own evidence and oracle kind, matching plan`, async () => {
    const [lines] = await captureStdout(() => main(["plan", "--case", entry.id]));
    const planned = JSON.parse(lines[0]);
    const result = resultEnvelope({
      entry,
      comparison: { verdict: "MATCH", counts: { match: 1, mismatch: 0, indeterminate: 0 } },
      execution: {
        state: "completed",
        cleanup: { state: "confirmed" },
        process: { state: "stopped" },
      },
      provenance: { testOnly: true },
    });
    assert.equal(result.evidenceKind, planned.evidenceKind);
    assert.equal(result.oracleKind, planned.oracleKind);
    assert.equal(result.evidenceKind, entry.evidenceKind);
    assert.equal(result.oracleKind, entry.oracleKind);
  });

test("resultEnvelope refuses a case definition missing its evidence kind", () => {
  assert.throws(
    () =>
      resultEnvelope({
        entry: { ...CASE, evidenceKind: undefined },
        comparison: { verdict: "MATCH", counts: { match: 1, mismatch: 0, indeterminate: 0 } },
        execution: {
          state: "completed",
          cleanup: { state: "confirmed" },
          process: { state: "stopped" },
        },
        provenance: {},
      }),
    /case-missing-evidence-kind/,
  );
});

test("buildExecArgs defaults to the batch-write project and accepts an override", () => {
  const withoutProject = buildExecArgs("/binary", "/dir", "/entry.mjs", "/node");
  assert.equal(withoutProject.args[withoutProject.args.indexOf("--project") + 1], CASE.project);
  const withProject = buildExecArgs(
    "/binary",
    "/dir",
    "/entry.mjs",
    "/node",
    COMMIT_TRANSFORM_CASE.project,
  );
  assert.equal(
    withProject.args[withProject.args.indexOf("--project") + 1],
    COMMIT_TRANSFORM_CASE.project,
  );
});

test("buildExecArgs selects auth and firestore only for G0", () => {
  const args = buildExecArgs("/binary", "/dir", "/entry.mjs", "/node", G0_CASE.project, "auth,firestore").args;
  assert.equal(args[args.indexOf("--only") + 1], "auth,firestore");
  assert.equal(args.includes("--auth-port"), false);
  assert.equal(args[args.indexOf("--firestore-port") + 1], "0");
});

test("buildExecArgs uses only options supported by the fireemu exec interface", async (t) => {
  const binary = process.env.G0_RETAINED_ARTIFACT;
  if (!binary) {
    t.skip("set G0_RETAINED_ARTIFACT to validate the retained native CLI help");
    return;
  }
  let help;
  try {
    help = execFileSync(binary, ["--help"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error) {
    assert.equal(error.status, 2);
    help = error.stderr;
  }
  assert.match(help, /exec\|emulators:exec/);
  assert.match(help, /--firestore-port <n>/);
  assert.doesNotMatch(help, /--auth-port/);
  const args = buildExecArgs(binary, "/dir", "/entry.mjs", "/node", G0_CASE.project, "auth,firestore").args;
  assert.equal(args.some((arg) => arg === "--auth-port"), false);
});

// Requires the actual pinned matrix and historical Git objects, not a synthetic oracle.
test("pilot.mjs plan joins the saved transforms program with its production evidence", async () => {
  const [lines, code] = await captureStdout(() => main(["plan", "--case", TRANSFORMS_CASE.id]));
  assert.equal(code, 0);
  const planned = JSON.parse(lines[0]);
  assert.equal(planned.case, TRANSFORMS_CASE.id);
  assert.equal(planned.operations, 18);
  assert.equal(planned.productionRequests, 0);
  assert.equal(planned.evidenceKind, "saved-production-reference");
  assert.equal(planned.oracleKind, "legacy-normalized-production-observation");
});
