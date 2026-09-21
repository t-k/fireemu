// pilot.mjs must dispatch by --case rather than hard-coding the batch-write case. These tests
// exercise that dispatch through the public CLI entrypoints (list/plan), which need no native
// binary, plus buildExecArgs's per-case project wiring.
import assert from "node:assert/strict";
import { test } from "node:test";
import { CASE, CASES, COMMIT_TRANSFORM_CASE, selectCase } from "../registry.mjs";
import { buildExecArgs, main } from "../pilot.mjs";

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

test("registry exposes both cases and rejects an unknown id", () => {
  assert.deepEqual(
    CASES.map((c) => c.id),
    [CASE.id, COMMIT_TRANSFORM_CASE.id],
  );
  assert.equal(selectCase(COMMIT_TRANSFORM_CASE.id).adapter, "commit-transform");
  assert.throws(() => selectCase("not-a-case"), /unknown-case/);
});

test("pilot.mjs list reports both cases", async () => {
  const [lines, code] = await captureStdout(() => main(["list"]));
  assert.equal(code, 0);
  const parsed = JSON.parse(lines[0]);
  assert.deepEqual(
    parsed.cases.map((c) => c.id),
    [CASE.id, COMMIT_TRANSFORM_CASE.id],
  );
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
