import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildComparison, generateComparison } from "./closure-comparison.mjs";
import { compareProfiles } from "./compare.mjs";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const recordings = [2, 3, 4].map((n) => ({
  path: `conformance/scheduled-delivery/local/production-run${n}.json`,
  sha256: sha(`run${n}`),
  data: { run: { id: `run${n}` }, frames: [], attempts: {}, jobs: {} },
}));
const row = (id, production, local, verdict = "MATCH") => ({
  id,
  production,
  strict: { local, verdict },
});
const build = (table, extra = {}) =>
  buildComparison({
    report: { run: { id: "run3" }, table },
    recordings,
    artifactSha256: sha("binary"),
    runnerTreeManifest: `tools/runner-node/index.mjs\t${sha("runner")}\n`,
    ...extra,
  });
const find = (result, caseId) => result.rows.find((r) => r.caseId === caseId);

test("CLI accepts the gate's table argument and reads the named file", () => {
  assert.throws(
    () =>
      execFileSync(
        process.execPath,
        [
          new URL("./closure-comparison.mjs", import.meta.url).pathname,
          "--table",
          "missing-run-compare.json",
          "--fireemu",
          "missing",
          "--out",
          "unused",
        ],
        { stdio: "pipe" },
      ),
    (error) => /ENOENT.*missing-run-compare\.json/.test(error.stderr.toString()),
  );
});

test("case aggregation preserves divergence and missing rows never match", () => {
  const result = build([
    row("v2.request.method", ["POST"], ["POST"]),
    row("v2.request.url", ["/"], ["/"], "DIVERGES"),
  ]);
  assert.equal(find(result, "request-method").status, "DIVERGES");
  assert.equal(find(result, "published-data").status, "NOT_COMPARABLE");
  assert.deepEqual(
    find(result, "request-method").recordings,
    [recordings[1]].map(({ data: _data, ...r }) => r),
  );
  assert.equal(result.runnerSha256, sha(result.runnerTreeManifest));
});

test("all proposal differences retain references and cannot become matches", () => {
  const result = build([
    row("v2.request.header-names", [], []),
    row("cadence.every-1-minutes.phase", [], []),
    row("cadence.every-5-minutes.alignment", [], []),
    row("forced-run", "next", "now", "NOT_COMPARABLE"),
  ]);
  for (const r of result.rows.filter((item) => item.proposalRef)) {
    assert.match(r.proposalRef, /#3\.[1-7]$/);
    assert.notEqual(r.status, "MATCH");
  }
  assert.equal(find(result, "Cloud-Scheduler-run-now").status, "NOT_COMPARABLE");
});

test("implicit cases cite recorded fields without inventing local acknowledgements", () => {
  const result = build([row("cadence.every-1-minutes.spacing", 60, 60)]);
  for (const id of [
    "handler-success-ack",
    "handler-throw-ack",
    "success-stops-retry",
    "next-schedule-after-failure",
    "retry-stable-occurrence-identity",
  ]) {
    const r = find(result, id);
    assert.equal(r.status, "NOT_COMPARABLE");
    assert.ok(r.recordedFields.length > 0);
    assert.equal(r.observation, null);
  }
});

test("wrong binary binding, duplicate ids, unknown verdicts and recordings are refused", () => {
  assert.throws(
    () =>
      build([], {
        report: { run: { id: "run3" }, table: [], fireemu: { binarySha256: sha("other") } },
      }),
    /binary/,
  );
  assert.throws(
    () => build([row("v2.request.body", [], []), row("v2.request.body", [], [])]),
    /duplicate/,
  );
  assert.throws(() => build([row("v2.request.body", [], [], "PASS")]), /verdict/);
  assert.throws(() => build([], { report: { run: { id: "absent" }, table: [] } }), /recording/);
});

test("implicit observations change with recorded outcomes and identity regressions diverge", () => {
  const rs = structuredClone(recordings);
  const job = "firebase-schedule-schedRetryV2-us-central1";
  const instant = "2026-10-05T08:45:00Z";
  const frame = (at, failing, scheduleTime = instant) => ({
    handler: "schedRetryV2",
    at,
    failing,
    event: { jobName: job, scheduleTime },
    headers: { "x-cloudscheduler-jobname": job, "x-cloudscheduler-scheduletime": scheduleTime },
  });
  rs[1].data.frames = [
    frame(0, true),
    frame(4000, true),
    frame(12000, false),
    frame(300000, true, "2026-10-05T08:50:00Z"),
    frame(600000, true, "2026-10-05T08:55:00Z"),
  ];
  rs[1].data.attempts = {
    [job]: [{ kind: "AttemptFinished", status: "INTERNAL", debugInfo: "code number = 500" }],
    "firebase-schedule-schedOkV2-us-central1": [
      { kind: "AttemptFinished", status: null, debugInfo: "code number = 200" },
    ],
  };
  const table = [row("retry.retryFour", [0, 4, 12], [0, 4, 12])];
  const result = build(table, { recordings: rs });
  assert.equal(find(result, "retry-stable-occurrence-identity").status, "MATCH");
  for (const id of [
    "handler-success-ack",
    "handler-throw-ack",
    "success-stops-retry",
    "next-schedule-after-failure",
  ])
    assert.equal(find(result, id).observation, true, id);
  rs[1].data.frames[1].event.scheduleTime = "2026-10-05T08:46:00Z";
  assert.equal(
    find(build(table, { recordings: rs }), "retry-stable-occurrence-identity").status,
    "DIVERGES",
  );
  rs[1].data.frames[1].event.scheduleTime = instant;
  rs[1].data.frames.push(frame(16000, true));
  assert.equal(
    find(
      build([row("retry.retryFour", [0, 4, 12, 16], [0, 4, 12, 16])], { recordings: rs }),
      "success-stops-retry",
    ).observation,
    false,
  );
  assert.throws(() => build(table, { recordings: rs }), /disagrees with recording/);
});

test("committed digests cover exactly the nine frozen delivery case sets with correct provenance", () => {
  const committed = recordings.map(({ path }) => {
    const bytes = readFileSync(new URL(`../../../${path}`, import.meta.url));
    return { path, sha256: sha(bytes), data: JSON.parse(bytes) };
  });
  const empty = { natural: { lines: [], pulled: [] }, probe: { lines: [] } };
  const table = compareProfiles(committed[1].data, empty, empty, [
    committed[0].data,
    committed[2].data,
  ]);
  const result = build(table, {
    recordings: committed,
    report: { run: committed[1].data.run, table },
  });
  const closure = JSON.parse(
    readFileSync(
      new URL("../../../spec/compatibility/closure/SCHEDULED-FUNCTIONS.json", import.meta.url),
    ),
  );
  const ids = new Set(
    [
      "declarations-v1-v2",
      "v2-http-delivery",
      "v1-pubsub-delivery",
      "forced-and-natural-invocation",
      "retry-config-validation",
      "v2-retry-limits",
      "v2-backoff",
      "v1-two-stage-retry",
      "deadline-and-overlap",
    ].map((id) => `SCHEDULED-FUNCTIONS/${id}`),
  );
  const expected = closure.conditions
    .filter((c) => ids.has(c.conditionId))
    .flatMap((c) => c.cases.map((id) => `${c.conditionId}/${id}`))
    .toSorted();
  assert.equal(ids.size, 9);
  assert.equal(expected.length, 59);
  assert.deepEqual(
    result.rows
      .filter((r) => r.frozenCase)
      .map((r) => `${r.conditionId}/${r.caseId}`)
      .toSorted(),
    expected,
  );
  for (const r of result.rows)
    for (const recording of r.recordings)
      assert.ok(committed.some((c) => c.path === recording.path && c.sha256 === recording.sha256));
  assert.equal(find(result, "exponential-doubling").recordings[0].path, committed[2].path);
  assert.equal(find(result, "handler-success-ack").observation, true);
  assert.equal(find(result, "handler-throw-ack").observation, true);
  assert.equal(find(result, "success-stops-retry").observation, true);
  assert.equal(find(result, "next-schedule-after-failure").observation, true);
  assert.throws(() => generateComparison({ reportPath: "missing", fireemu: "missing" }), /ENOENT/);
});
