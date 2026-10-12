import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  ADJUDICATION_MODE,
  APPROVED_EXCLUDED_STEPS,
  COMPARISON_KIND,
  COMPARISON_PATH,
  NEGATIVE_CACHE_COORDINATES,
  assertPubsubAdjudication,
} from "./pubsub-closure-adjudication.mjs";

const root = new URL("../../", import.meta.url);
const readRepo = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const sha256 = (path) =>
  createHash("sha256")
    .update(readFileSync(new URL(path, root)))
    .digest("hex");

const committed = () => ({
  closure: readRepo("spec/compatibility/closure/PUBSUB.json"),
  comparison: readRepo(COMPARISON_PATH),
});

// Deterministic PRNG (mulberry32) so the property loops replay exactly.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (random, list) => list[Math.floor(random() * list.length)];
const check = (closure, comparison, hashOf = sha256) =>
  assertPubsubAdjudication(closure, comparison, hashOf);
// Mutated fixtures change the comparison object, so pin its digest to the object itself.
const hashOfObject = (comparison) => (path) =>
  path === COMPARISON_PATH
    ? createHash("sha256")
        .update(JSON.stringify(comparison, null, 2) + "\n")
        .digest("hex")
    : sha256(path);
function rebind(closure, comparison) {
  const summary = {};
  for (const { status } of comparison.rows) summary[status] = (summary[status] ?? 0) + 1;
  comparison.summary = Object.fromEntries(Object.entries(summary).toSorted());
  const digest = hashOfObject(comparison)(COMPARISON_PATH);
  closure.perCaseAdjudication.sha256 = digest;
  closure.integratedRegression.comparisons[0].sha256 = digest;
  closure.integratedRegression.comparisons[0].rows = comparison.rows.length;
  closure.integratedRegression.comparisons[0].summary = comparison.summary;
  for (const condition of closure.conditions) condition.evidence.comparisonSha256 = digest;
  return hashOfObject(comparison);
}

/** An explicit pre-review fixture: one named row forced PENDING, independent of the committed state. */
function pendingFixture(coordinate = "/conditions/2/cases/1") {
  const fixture = committed();
  for (const row of fixture.comparison.rows)
    if (row.coordinate === coordinate) {
      row.status = "PENDING";
      row.pendingReason = "awaiting the independent parent review";
    }
  for (const condition of fixture.closure.conditions) condition.status = "PENDING_REVIEW";
  fixture.closure.parentStatus = "IMPLEMENTING";
  fixture.closure.closureReview = { decision: "PENDING" };
  fixture.hashOf = rebind(fixture.closure, fixture.comparison);
  return fixture;
}
/** An explicit promoted fixture: no PENDING row, every condition VERIFIED, an approved review with a report. */
function verifiedFixture() {
  const fixture = committed();
  for (const row of fixture.comparison.rows)
    if (row.status === "PENDING") {
      row.status = "MATCH";
      row.rules = [];
      delete row.pendingReason;
    }
  for (const condition of fixture.closure.conditions) condition.status = "VERIFIED";
  fixture.closure.parentStatus = "COMPAT_VERIFIED";
  fixture.closure.closureReview = {
    decision: "APPROVED",
    reviews: [{ reportPath: "docs.local/reviews/review.md", reportSha256: "4".repeat(64) }],
  };
  fixture.hashOf = rebind(fixture.closure, fixture.comparison);
  return fixture;
}
const checkFixture = (fixture) => check(fixture.closure, fixture.comparison, fixture.hashOf);

test("explicit pending and verified fixtures are both accepted", () => {
  checkFixture(pendingFixture());
  checkFixture(verifiedFixture());
});

test("a verified closure needs a review report path and digest", () => {
  for (const change of [
    (review) => delete review.reviews,
    (review) => (review.reviews = []),
    (review) => (review.reviews[0].reportSha256 = "x"),
    (review) => delete review.reviews[0].reportPath,
  ]) {
    const fixture = verifiedFixture();
    change(fixture.closure.closureReview);
    assert.throws(() => checkFixture(fixture), /review report/, String(change));
  }
});

test("excluded steps are exactly the approved source steps", () => {
  const fixture = committed();
  const row = fixture.comparison.rows.find(
    ({ coordinate }) => coordinate === "/conditions/1/cases/4",
  );
  row.excludedSteps = row.excludedSteps
    .slice(1)
    .concat([{ recording: "966b6f3f", cell: "R2", n: 90 }]);
  let hashOf = rebind(fixture.closure, fixture.comparison);
  assert.throws(() => check(fixture.closure, fixture.comparison, hashOf), /approved source steps/);
  const disclosure = committed();
  disclosure.closure.knownDifferences.restNegativeCache.excludedSteps["/conditions/3/cases/0"] = [
    { recording: "a8ed1cce", n: 11 },
  ];
  assert.throws(
    () => check(disclosure.closure, disclosure.comparison),
    /restNegativeCache.excludedSteps/,
  );
  assert.deepEqual(
    disclosure.comparison.rows
      .filter(({ status }) => status === "EXCLUDED_STEP")
      .map(({ excludedSteps }) => excludedSteps.length),
    [6, 6, 1, 1, 1, 1],
  );
  assert.deepEqual(
    Object.keys(APPROVED_EXCLUDED_STEPS).toSorted(),
    [...NEGATIVE_CACHE_COORDINATES].toSorted(),
  );
});

test("the 1390 rule says headers were neither recorded nor compared", () => {
  const { closure, comparison } = committed();
  assert.match(comparison.rules["1390"], /neither recorded nor compared/);
  assert.doesNotMatch(comparison.rules["1390"], /header semantics/);
  assert.ok(comparison.rules["1404"]);
  assert.doesNotMatch(comparison.method, /applied exactly/);
  assert.match(comparison.method, /1391 and 1401 are coordinator readings/);
  assert.match(closure.knownDifferences.judgingRules.statement, /neither recorded nor compared/);
  for (const [name, change] of [
    [
      "header claim",
      (c) =>
        (c.comparison.rules["1390"] =
          "status, header semantics and body content are equal; headers were neither recorded nor compared"),
    ],
    ["no disclosure", (c) => (c.comparison.rules["1390"] = "status and body content are equal")],
  ]) {
    const fixture = committed();
    change(fixture);
    const hashOf = rebind(fixture.closure, fixture.comparison);
    assert.throws(() => check(fixture.closure, fixture.comparison, hashOf), /1390|1404/, name);
  }
});

test("the 1404 clarification must be defined even when no row cites it", () => {
  const fixture = committed();
  for (const row of fixture.comparison.rows)
    row.rules = row.rules.filter((rule) => rule !== "1404");
  delete fixture.comparison.rules["1404"];
  const hashOf = rebind(fixture.closure, fixture.comparison);
  assert.throws(
    () => check(fixture.closure, fixture.comparison, hashOf),
    /rule 1404 \(the 1390 clarification\)/,
  );
});

test("the disclosed excluded steps name exactly the excluded coordinates", () => {
  const fixture = committed();
  delete fixture.closure.knownDifferences.restNegativeCache.excludedSteps["/conditions/14/cases/2"];
  assert.throws(
    () => check(fixture.closure, fixture.comparison),
    /restNegativeCache.excludedSteps/,
  );
});

test("the REST Content-Type difference is disclosed", () => {
  const fixture = committed();
  assert.match(
    fixture.closure.knownDifferences.restContentType.statement,
    /application\/json; charset=UTF-8/,
  );
  fixture.closure.knownDifferences.restContentType.statement = "none";
  assert.throws(() => check(fixture.closure, fixture.comparison), /Content-Type/);
});

test("the committed PUBSUB closure binds its public per-case adjudication", () => {
  const { closure, comparison } = committed();
  assert.equal(closure.perCaseAdjudication.mode, ADJUDICATION_MODE);
  assert.equal(closure.perCaseAdjudication.path, COMPARISON_PATH);
  assert.equal(comparison.kind, COMPARISON_KIND);
  check(closure, comparison);
});

test("the committed adjudication covers all 122 frozen cases once per declared transport", () => {
  const { closure, comparison } = committed();
  const cases = closure.conditions.reduce((n, condition) => n + condition.cases.length, 0);
  assert.equal(cases, 122);
  const expected = closure.conditions.reduce(
    (n, condition) => n + condition.cases.length * condition.transports.length,
    0,
  );
  assert.equal(comparison.rows.length, expected);
});

test("the REST negative cache is disclosed as not emulated for exactly the excluded steps", () => {
  const { closure, comparison } = committed();
  const known = closure.knownDifferences.restNegativeCache;
  assert.match(known.statement, /NOT emulated/);
  assert.doesNotMatch(known.statement, /nondeterminis/i);
  assert.deepEqual(
    known.affectedCoordinates.toSorted(),
    [...NEGATIVE_CACHE_COORDINATES].toSorted(),
  );
  const excluded = new Set(
    comparison.rows.filter(({ status }) => status === "EXCLUDED_STEP").map((r) => r.coordinate),
  );
  assert.deepEqual([...excluded].toSorted(), [...NEGATIVE_CACHE_COORDINATES].toSorted());
  assert.match(known.followUp, /pubsub-rest-negative-cache-emulation\.md/);
});

test("keyed starvation under continuous unkeyed traffic is a disclosed limitation", () => {
  const { closure } = committed();
  const known = closure.knownDifferences.orderedUnaryPullKeyedStarvation;
  assert.match(known.statement, /unkeyed/);
  assert.match(known.statement, /starv/);
  assert.match(known.statement, /unary Pull/);
});

test("the judging rules 1392, 1394, 1399, 1400, 1401 and 1402 are disclosed", () => {
  const { closure, comparison } = committed();
  assert.match(
    closure.knownDifferences.judgingRules.statement,
    /delivered fewer of the key messages/,
  );
  for (const id of ["1392", "1394", "1399", "1400", "1401", "1402"]) {
    assert.ok(comparison.rules[id], id);
    assert.ok(closure.knownDifferences.judgingRules.rules.includes(id), id);
  }
});

test("a COMPAT_VERIFIED PUBSUB needs every condition verified and an approved review", () => {
  const unverified = verifiedFixture();
  unverified.closure.conditions[3].status = "PENDING_REVIEW";
  assert.throws(() => checkFixture(unverified), /all required conditions must be verified/);
  const unreviewed = verifiedFixture();
  unreviewed.closure.closureReview = { decision: "PENDING" };
  assert.throws(() => checkFixture(unreviewed), /approved independent parent review/);
});

test("a COMPAT_VERIFIED PUBSUB cannot keep a PENDING row", () => {
  const fixture = verifiedFixture();
  fixture.comparison.rows[0].status = "PENDING";
  fixture.comparison.rows[0].pendingReason = "x";
  fixture.hashOf = rebind(fixture.closure, fixture.comparison);
  assert.throws(() => checkFixture(fixture), /COMPAT_VERIFIED with a PENDING row/);
});

test("a condition with a PENDING row cannot be VERIFIED", () => {
  const fixture = pendingFixture("/conditions/2/cases/1");
  fixture.closure.conditions[2].status = "VERIFIED";
  assert.throws(() => checkFixture(fixture), /VERIFIED with a PENDING row/);
});

test("the adjudication bytes, kind, parent and artifact are pinned", () => {
  for (const [name, change, expected] of [
    ["digest", (c) => (c.closure.perCaseAdjudication.sha256 = "0".repeat(64)), /bytes/],
    ["kind", (c) => (c.comparison.kind = "other"), /kind/],
    ["parent", (c) => (c.comparison.parent = "EVENTARC"), /parent/],
    ["artifact", (c) => (c.comparison.artifactSha256 = "1".repeat(64)), /artifact/],
    [
      "condition artifact",
      (c) => (c.closure.conditions[5].evidence.finalArtifactSha256 = "2".repeat(64)),
      /artifact/,
    ],
    [
      "condition binding",
      (c) => (c.closure.conditions[7].evidence.comparisonPath = "x.json"),
      /binding/,
    ],
    [
      "regression binding",
      (c) => (c.closure.integratedRegression.comparisons[0].path = "x.json"),
      /integratedRegression/,
    ],
  ]) {
    const fixture = committed();
    change(fixture);
    const hashOf = ["kind", "parent", "artifact"].includes(name)
      ? rebind(fixture.closure, fixture.comparison)
      : sha256;
    assert.throws(() => check(fixture.closure, fixture.comparison, hashOf), expected, name);
  }
});

test("property: dropping, duplicating or retargeting any row is refused", () => {
  const random = rng(0x5eed1394);
  for (let i = 0; i < 200; i += 1) {
    const { closure, comparison } = committed();
    const index = Math.floor(random() * comparison.rows.length);
    const action = pick(random, ["drop", "duplicate", "transport", "row"]);
    if (action === "drop") comparison.rows.splice(index, 1);
    if (action === "duplicate") comparison.rows.push(structuredClone(comparison.rows[index]));
    if (action === "transport")
      comparison.rows[index].transport =
        comparison.rows[index].transport === "rest" ? "artifact" : "rest";
    if (action === "row") comparison.rows[index].row += "-x";
    const hashOf = rebind(closure, comparison);
    assert.throws(() => check(closure, comparison, hashOf), /row/, `${action} ${index}`);
  }
});

test("property: an unknown status, a relation without rules or an unknown rule is refused", () => {
  const random = rng(0x1399);
  for (let i = 0; i < 200; i += 1) {
    const { closure, comparison } = committed();
    const candidates = comparison.rows
      .map((row, index) => ({ row, index }))
      .filter(({ row }) => row.status === "MATCH_BY_RELATION");
    const { index } = pick(random, candidates);
    const action = pick(random, ["status", "norules", "unknownrule"]);
    if (action === "status")
      comparison.rows[index].status = pick(random, ["DIVERGES", "NOT_COMPARABLE", "match", ""]);
    if (action === "norules") comparison.rows[index].rules = [];
    if (action === "unknownrule") comparison.rows[index].rules = ["9999"];
    const hashOf = rebind(closure, comparison);
    assert.throws(() => check(closure, comparison, hashOf), /status|rule/, `${action} ${index}`);
  }
});

test("property: an excluded step outside the negative-cache coordinates is refused", () => {
  const random = rng(0x1385);
  for (let i = 0; i < 100; i += 1) {
    const { closure, comparison } = committed();
    const candidates = comparison.rows
      .map((row, index) => ({ row, index }))
      .filter(
        ({ row }) =>
          !NEGATIVE_CACHE_COORDINATES.includes(row.coordinate) && row.status !== "PENDING",
      );
    const { index } = pick(random, candidates);
    comparison.rows[index].status = "EXCLUDED_STEP";
    comparison.rows[index].rules = ["1385"];
    comparison.rows[index].excludedSteps = [{ owner: "1385", reason: "x" }];
    const hashOf = rebind(closure, comparison);
    assert.throws(() => check(closure, comparison, hashOf), /negative cache|excluded/, `${index}`);
  }
});

test("an excluded step needs its exclusion rule and the named steps", () => {
  const { closure, comparison } = committed();
  const index = comparison.rows.findIndex(({ status }) => status === "EXCLUDED_STEP");
  const withoutSteps = structuredClone(comparison);
  delete withoutSteps.rows[index].excludedSteps;
  let hashOf = rebind(closure, withoutSteps);
  assert.throws(() => check(closure, withoutSteps, hashOf), /excluded steps/);
  const withoutRule = structuredClone(comparison);
  withoutRule.rows[index].rules = ["1390"];
  const closure2 = committed().closure;
  hashOf = rebind(closure2, withoutRule);
  assert.throws(() => check(closure2, withoutRule, hashOf), /exclusion rule/);
});

test("each binding and bookkeeping field is checked on its own", () => {
  const cases = [
    ["closure parent", (f) => (f.closure.parent = "EVENTARC"), /closure parent/, false],
    [
      "mode",
      (f) => (f.closure.perCaseAdjudication.mode = "other"),
      /perCaseAdjudication binding/,
      false,
    ],
    [
      "second listed comparison",
      (f) =>
        f.closure.integratedRegression.comparisons.push({
          ...f.closure.integratedRegression.comparisons[0],
        }),
      /exactly the pinned comparison/,
      false,
    ],
    [
      "listed sha256",
      (f) => (f.closure.integratedRegression.comparisons[0].sha256 = "3".repeat(64)),
      /exactly the pinned comparison/,
      false,
    ],
    [
      "listed rows",
      (f) => (f.closure.integratedRegression.comparisons[0].rows += 1),
      /exactly the pinned comparison/,
      false,
    ],
    [
      "production requests",
      (f) => (f.closure.integratedRegression.productionRequests = 1),
      /production/,
      false,
    ],
    ["comparison summary", (f) => (f.comparison.summary.MATCH += 1), /comparison summary/, "pin"],
    [
      "regression summary",
      (f) => (f.closure.integratedRegression.comparisons[0].summary = { MATCH: 1 }),
      /integratedRegression summary/,
      false,
    ],
    [
      "cache statement",
      (f) => (f.closure.knownDifferences.restNegativeCache.statement = "emulated"),
      /NOT emulated/,
      false,
    ],
    [
      "cache coordinates",
      (f) => f.closure.knownDifferences.restNegativeCache.affectedCoordinates.pop(),
      /exactly the excluded coordinates/,
      false,
    ],
  ];
  for (const [name, change, expected, mode] of cases) {
    const fixture = committed();
    change(fixture);
    let hashOf = sha256;
    if (mode === "pin") {
      const digest = hashOfObject(fixture.comparison)(COMPARISON_PATH);
      fixture.closure.perCaseAdjudication.sha256 = digest;
      fixture.closure.integratedRegression.comparisons[0].sha256 = digest;
      for (const condition of fixture.closure.conditions)
        condition.evidence.comparisonSha256 = digest;
      hashOf = hashOfObject(fixture.comparison);
    }
    assert.throws(() => check(fixture.closure, fixture.comparison, hashOf), expected, name);
  }
});

test("row checks refuse an extra row, a wrong coordinate and a PENDING row without a reason", () => {
  const extra = committed();
  extra.comparison.rows.push({ ...extra.comparison.rows[0], row: "pubsub/unknown#case" });
  let hashOf = rebind(extra.closure, extra.comparison);
  assert.throws(() => check(extra.closure, extra.comparison, hashOf), /unexpected row/);

  const coordinate = committed();
  coordinate.comparison.rows[4].coordinate = "/conditions/0/cases/0";
  hashOf = rebind(coordinate.closure, coordinate.comparison);
  assert.throws(
    () => check(coordinate.closure, coordinate.comparison, hashOf),
    /names \/conditions\/0\/cases\/0/,
  );

  const reason = pendingFixture();
  const pending = reason.comparison.rows.find(({ status }) => status === "PENDING");
  delete pending.pendingReason;
  hashOf = rebind(reason.closure, reason.comparison);
  assert.throws(() => check(reason.closure, reason.comparison, hashOf), /PENDING without a reason/);
});

test("a COMPAT_VERIFIED closure names the PENDING row it still holds", () => {
  const fixture = pendingFixture();
  fixture.closure.parentStatus = "COMPAT_VERIFIED";
  for (const condition of fixture.closure.conditions) condition.status = "VERIFIED";
  fixture.closure.closureReview = verifiedFixture().closure.closureReview;
  assert.throws(() => checkFixture(fixture), /COMPAT_VERIFIED with a PENDING row/);
});

test("an excluded step outside the negative cache is refused even when the disclosure lists it", () => {
  const { closure, comparison } = committed();
  const index = comparison.rows.findIndex(
    ({ coordinate }) => coordinate === "/conditions/0/cases/0",
  );
  comparison.rows[index].status = "EXCLUDED_STEP";
  comparison.rows[index].rules = ["1385"];
  comparison.rows[index].excludedSteps = [{ owner: "1385", reason: "x" }];
  comparison.rows[index + 1].status = "EXCLUDED_STEP";
  comparison.rows[index + 1].rules = ["1385"];
  comparison.rows[index + 1].excludedSteps = [{ owner: "1385", reason: "x" }];
  closure.knownDifferences.restNegativeCache.affectedCoordinates.push("/conditions/0/cases/0");
  const hashOf = rebind(closure, comparison);
  assert.throws(() => check(closure, comparison, hashOf), /outside the REST negative cache/);
});

test("a rule the comparison does not define is refused", () => {
  const { closure, comparison } = committed();
  const index = comparison.rows.findIndex(({ status }) => status === "MATCH");
  comparison.rows[index].rules = ["9999"];
  const hashOf = rebind(closure, comparison);
  assert.throws(() => check(closure, comparison, hashOf), /unknown rule 9999/);
});

test("the committed record is pre-review with only 17/0 pending, or promoted with none", () => {
  const { closure, comparison } = committed();
  const pending = comparison.rows
    .filter(({ status }) => status === "PENDING")
    .map(({ coordinate }) => coordinate);
  if (closure.parentStatus === "IMPLEMENTING") {
    assert.ok(closure.conditions.every(({ status }) => status === "PENDING_REVIEW"));
    assert.deepEqual([...new Set(pending)], ["/conditions/17/cases/0"]);
  } else {
    assert.equal(closure.parentStatus, "COMPAT_VERIFIED");
    assert.deepEqual(pending, []);
  }
  const limited = comparison.rows.filter(
    ({ coordinate }) => coordinate === "/conditions/6/cases/8",
  );
  assert.ok(
    limited.every(({ status, rules }) => status === "MATCH_BY_RELATION" && rules.includes("1402")),
  );
});

test("the method states what each recording family compares on REST rows", () => {
  const { closure, comparison } = committed();
  assert.doesNotMatch(comparison.method, /D raw body bytes/);
  assert.match(comparison.method, /REST body bytes are not compared/);
  assert.match(comparison.method, /raw bytes only for recovered native Pull responses/);
  assert.match(comparison.method, /No comparison judges any response header/);
  assert.match(comparison.method, /physicalVerdict also becomes DIVERGES when a timestamp proof/);
  assert.match(closure.knownDifferences.restResponseHeaders.statement, /10 response headers/);
  assert.match(closure.knownDifferences.restResponseHeaders.statement, /sends 3/);
});
