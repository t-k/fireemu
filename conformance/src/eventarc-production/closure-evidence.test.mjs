import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildEvidence, bindStageReport, stageFacets } from "./closure-evidence.mjs";
import { join } from "node:path";

const closure = JSON.parse(
  readFileSync(new URL("../../../spec/compatibility/closure/EVENTARC.json", import.meta.url)),
);
const artifact = { binarySha256: "a".repeat(64), runnerSha256: "b".repeat(64) };
const report = (runId, packet = "H2-A") => ({
  packet,
  production: { runId, closed: true, sha256: "c".repeat(64) },
  artifact,
  rows: [
    {
      case: "object",
      verdict: "MATCH",
      facets: ["EVENTARC/publish-content/json-object"],
      declaredDifferences: [],
    },
  ],
});

test("closure evidence requires two independent closed recordings for every frozen case", () => {
  const original = JSON.stringify(closure);
  const reports = [report("aaaa"), report("bbbb", "H2-B")];
  const result = buildEvidence({ closure, reports, artifact });
  const object = result.rows.find(
    (r) => r.conditionId === "EVENTARC/publish-content" && r.caseId === "json-object",
  );
  assert.equal(object.status, "MATCH");
  assert.equal(object.productionRuns.length, 2);
  assert.equal(
    result.conditions.find((c) => c.conditionId === "EVENTARC/publish-content").status,
    "NOT_COMPARABLE",
  );
  assert.equal(
    result.rows.find((r) => r.caseId === "independent-approval").status,
    "NOT_COMPARABLE",
  );
  assert.equal(JSON.stringify(closure), original);
  for (const bad of [
    [],
    [reports[0]],
    [reports[0], { ...reports[1], production: reports[0].production }],
    [reports[0], { ...reports[1], production: { ...reports[1].production, closed: false } }],
  ])
    assert.equal(
      buildEvidence({ closure, reports: bad, artifact }).rows.find(
        (r) => r.caseId === "json-object",
      ).status,
      "NOT_COMPARABLE",
    );
});

test("divergences, missing variants and mismatched artifact bindings remain closure blockers", () => {
  const a = report("aaaa"),
    b = report("bbbb", "H2-B");
  b.rows[0].verdict = "DIVERGES";
  assert.equal(
    buildEvidence({ closure, reports: [a, b], artifact }).rows.find(
      (r) => r.caseId === "json-object",
    ).status,
    "DIVERGES",
  );
  b.artifact = { ...artifact, binarySha256: "d".repeat(64) };
  assert.throws(() => buildEvidence({ closure, reports: [a, b], artifact }), /artifact/);
  b.artifact = artifact;
  b.rows[0].declaredDifferences = ["anything-goes"];
  assert.throws(() => buildEvidence({ closure, reports: [a, b], artifact }), /difference/);
});

test("declared scope exceptions are accepted only with their exact reviewed reason", () => {
  const a = report("aaaa"),
    b = report("bbbb", "H2-B");
  for (const r of [a, b])
    Object.assign(r.rows[0], {
      verdict: "NOT_COMPARABLE",
      reason: "project-number-not-configured",
      declaredDifferences: ["numeric-project-alias"],
    });
  assert.equal(
    buildEvidence({ closure, reports: [a, b], artifact }).rows.find(
      (r) => r.caseId === "json-object",
    ).status,
    "MATCH",
  );
  b.rows[0].reason = "incomplete-observation";
  assert.equal(
    buildEvidence({ closure, reports: [a, b], artifact }).rows.find(
      (r) => r.caseId === "json-object",
    ).status,
    "NOT_COMPARABLE",
  );
});

const runs = process.env.EVENTARC_RECORDINGS_ROOT;
test(
  "B/C/D native recordings bind measured rows and cover content without inventing request-byte boundaries",
  { skip: !runs },
  () => {
    const sources = [
      ["B", "eventarc-stage-b-20261005-r1", "43a83839852f"],
      ["C", "eventarc-stage-c-20261005-r1", "fe404dee592e"],
      ["D", "eventarc-packet-d-20261006-r1", "bd0b44db5477"],
    ];
    const reports = sources.map(([packet, directory, runId]) => {
      const capture = readFileSync(join(runs, directory, `capture-${runId}.jsonl`), "utf8")
        .split("\n")
        .filter(Boolean)
        .map(JSON.parse);
      const comparison = {
        rows: capture
          .filter((r) => r.request && r.response)
          .map((r) => ({ n: r.n, verdict: "MATCH" })),
      };
      const bound = bindStageReport({
        packet,
        capture,
        comparison,
        production: { runId, closed: true, sha256: "c".repeat(64) },
        artifact,
      });
      assert.ok(
        bound.rows.some((r) =>
          r.facets.includes("EVENTARC/channel-lifecycle/providerless-create-capability"),
        ),
      );
      assert.ok(
        !bound.rows.some((r) =>
          r.facets.includes("EVENTARC/publish-limits/request-bytes-boundary"),
        ),
      );
      const n = comparison.rows[0].n;
      assert.throws(
        () => bindStageReport({ packet, capture, comparison: { rows: [{ n }, { n }] } }),
        /duplicate/,
      );
      return bound;
    });
    const evidence = buildEvidence({ closure, reports, artifact });
    assert.equal(
      evidence.conditions.find((c) => c.conditionId === "EVENTARC/publish-content").status,
      "MATCH",
    );
    assert.equal(
      evidence.rows.find((r) => r.caseId === "request-bytes-boundary").status,
      "NOT_COMPARABLE",
    );
    assert.equal(
      evidence.rows.find((r) => r.caseId === "client-validation-refusal").status,
      "NOT_COMPARABLE",
    );
    assert.deepEqual(stageFacets({ case: "cleanup", op: "getChannel" }), []);
  },
);
