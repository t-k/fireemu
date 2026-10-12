// Validates the PUBSUB closure against its public per-case adjudication
// (spec/compatibility/closure/evidence/PUBSUB-comparison.json). The adjudication carries one row per
// frozen case and declared transport, the case verdict, and the owner decision ledger entries applied.

export const ADJUDICATION_MODE = "per-case-adjudication";
export const COMPARISON_KIND = "pubsub-production-comparison-v1";
export const COMPARISON_PATH = "spec/compatibility/closure/evidence/PUBSUB-comparison.json";
// Owner 1383/1385/1391: the only steps excluded from comparison (production REST negative cache).
export const NEGATIVE_CACHE_COORDINATES = Object.freeze([
  "/conditions/1/cases/4",
  "/conditions/3/cases/0",
  "/conditions/14/cases/2",
]);
// The exact source steps 1383/1385/1391 exclude, by recording run prefix and row number.
const r2 = (recording, n) => Object.freeze({ recording, cell: "R2", n });
export const APPROVED_EXCLUDED_STEPS = Object.freeze({
  "/conditions/1/cases/4": Object.freeze([
    r2("3efb4c7c", 249),
    r2("3efb4c7c", 253),
    r2("966b6f3f", 88),
    r2("966b6f3f", 92),
    r2("de14f6d9", 93),
    r2("de14f6d9", 97),
  ]),
  "/conditions/14/cases/2": Object.freeze([Object.freeze({ recording: "14802609", n: 484 })]),
  "/conditions/3/cases/0": Object.freeze([Object.freeze({ recording: "a8ed1cce", n: 10 })]),
});
const EXCLUSION_RULES = new Set(["1383", "1385", "1391"]);
const canonicalSteps = (steps) =>
  JSON.stringify(
    (steps ?? [])
      .map((step) => ({ recording: step.recording, cell: step.cell, n: step.n }))
      .toSorted((a, b) =>
        a.recording === b.recording ? a.n - b.n : a.recording < b.recording ? -1 : 1,
      ),
  );
const STATUSES = new Set(["MATCH", "MATCH_BY_RELATION", "EXCLUDED_STEP", "PENDING"]);
const hex = /^[a-f0-9]{64}$/;

function fail(message) {
  throw new Error(`PUBSUB adjudication: ${message}`);
}

function expectedRows(closure) {
  const expected = new Map();
  closure.conditions.forEach((condition, i) => {
    condition.cases.forEach((name, j) => {
      for (const transport of condition.transports)
        expected.set(`${condition.recipeIds[0]}#${name}|${transport}`, {
          coordinate: `/conditions/${i}/cases/${j}`,
          condition: i,
        });
    });
  });
  return expected;
}

/**
 * Throws when the closure and its adjudication disagree. `sha256Of(path)` returns the digest of a
 * repository file.
 */
export function assertPubsubAdjudication(closure, comparison, sha256Of) {
  if (closure.parent !== "PUBSUB") fail("closure parent must be PUBSUB");
  const verified = closure.parentStatus === "COMPAT_VERIFIED";
  if (verified && !closure.conditions.every(({ status }) => status === "VERIFIED"))
    throw new Error("all required conditions must be verified");
  if (verified && closure.closureReview?.decision !== "APPROVED")
    fail("COMPAT_VERIFIED needs an approved independent parent review");
  if (
    verified &&
    (!Array.isArray(closure.closureReview.reviews) ||
      closure.closureReview.reviews.length === 0 ||
      !closure.closureReview.reviews.every(
        ({ reportPath, reportSha256 }) =>
          typeof reportPath === "string" && reportPath && hex.test(reportSha256 ?? ""),
      ))
  )
    fail("COMPAT_VERIFIED needs each review report path and sha256");

  const binding = closure.perCaseAdjudication;
  if (binding?.mode !== ADJUDICATION_MODE || binding.path !== COMPARISON_PATH)
    fail("perCaseAdjudication binding must name the public comparison");
  if (!hex.test(binding.sha256 ?? "") || sha256Of(binding.path) !== binding.sha256)
    fail("public adjudication bytes do not match the pinned sha256");
  if (comparison.kind !== COMPARISON_KIND) fail(`comparison kind must be ${COMPARISON_KIND}`);
  if (comparison.parent !== "PUBSUB") fail("comparison parent must be PUBSUB");

  const regression = closure.integratedRegression;
  const artifact = regression?.releaseBinarySha256;
  if (!hex.test(artifact ?? "") || comparison.artifactSha256 !== artifact)
    fail("comparison artifact must equal the integratedRegression release binary");
  const listed = regression.comparisons;
  if (
    !Array.isArray(listed) ||
    listed.length !== 1 ||
    listed[0].path !== COMPARISON_PATH ||
    listed[0].sha256 !== binding.sha256 ||
    listed[0].rows !== comparison.rows?.length
  )
    fail("integratedRegression must list exactly the pinned comparison and its row count");
  if (regression.productionRequests !== 0) fail("integratedRegression must not send to production");

  const expected = expectedRows(closure);
  const seen = new Set();
  const pendingConditions = new Set();
  const summary = {};
  for (const row of comparison.rows) {
    const key = `${row.row}|${row.transport}`;
    const want = expected.get(key);
    if (!want) fail(`unexpected row ${key}`);
    if (seen.has(key)) fail(`duplicate row ${key}`);
    seen.add(key);
    if (row.coordinate !== want.coordinate) fail(`row ${key} names ${row.coordinate}`);
    if (!STATUSES.has(row.status)) fail(`row ${key} has unknown status ${row.status}`);
    summary[row.status] = (summary[row.status] ?? 0) + 1;
    if (!Array.isArray(row.rules)) fail(`row ${key} rules must be a list`);
    for (const rule of row.rules)
      if (!Object.hasOwn(comparison.rules ?? {}, rule))
        fail(`row ${key} cites unknown rule ${rule}`);
    if (row.status === "MATCH_BY_RELATION" && row.rules.length === 0)
      fail(`row ${key} is MATCH_BY_RELATION without a rule`);
    if (row.status === "EXCLUDED_STEP") {
      if (!NEGATIVE_CACHE_COORDINATES.includes(row.coordinate))
        fail(`row ${key} excludes a step outside the REST negative cache coordinates`);
      if (!row.rules.some((rule) => EXCLUSION_RULES.has(rule)))
        fail(`row ${key} is EXCLUDED_STEP without an exclusion rule`);
      if (!Array.isArray(row.excludedSteps) || row.excludedSteps.length === 0)
        fail(`row ${key} must name its excluded steps`);
      if (
        canonicalSteps(row.excludedSteps) !==
        canonicalSteps(APPROVED_EXCLUDED_STEPS[row.coordinate])
      )
        fail(`row ${key} excluded steps differ from the approved source steps`);
    }
    if (row.status === "PENDING") {
      if (!row.pendingReason) fail(`row ${key} is PENDING without a reason`);
      if (verified) fail(`COMPAT_VERIFIED with a PENDING row ${key}`);
      pendingConditions.add(want.condition);
    }
  }
  for (const key of expected.keys()) if (!seen.has(key)) fail(`missing row ${key}`);
  const sortedSummary = Object.fromEntries(Object.entries(summary).toSorted());
  if (JSON.stringify(sortedSummary) !== JSON.stringify(comparison.summary ?? null))
    fail("comparison summary does not match its rows");
  if (JSON.stringify(sortedSummary) !== JSON.stringify(listed[0].summary ?? null))
    fail("integratedRegression summary does not match the comparison rows");

  closure.conditions.forEach((condition, i) => {
    const evidence = condition.evidence ?? {};
    if (evidence.comparisonPath !== COMPARISON_PATH || evidence.comparisonSha256 !== binding.sha256)
      fail(`${condition.conditionId} evidence must carry the comparison binding`);
    if (evidence.finalArtifactSha256 !== artifact)
      fail(`${condition.conditionId} final artifact must equal the release binary`);
    if (condition.status === "VERIFIED" && pendingConditions.has(i))
      fail(`${condition.conditionId} is VERIFIED with a PENDING row`);
  });

  const rules = comparison.rules ?? {};
  if (
    !/neither recorded nor compared/.test(rules["1390"] ?? "") ||
    /header semantics/.test(rules["1390"])
  )
    fail("rule 1390 must say the original REST headers were neither recorded nor compared");
  if (!rules["1404"]) fail("rule 1404 (the 1390 clarification) must be defined");

  const known = closure.knownDifferences ?? {};
  if (!/application\/json; charset=UTF-8/.test(known.restContentType?.statement ?? ""))
    fail("knownDifferences.restContentType must disclose the production Content-Type");
  const cache = known.restNegativeCache;
  if (!/NOT emulated/.test(cache?.statement ?? ""))
    fail("knownDifferences.restNegativeCache must say the cache is NOT emulated");
  const excluded = new Set(
    comparison.rows.filter(({ status }) => status === "EXCLUDED_STEP").map((r) => r.coordinate),
  );
  if (
    JSON.stringify([...excluded].toSorted()) !==
    JSON.stringify([...(cache.affectedCoordinates ?? [])].toSorted())
  )
    fail("knownDifferences.restNegativeCache must list exactly the excluded coordinates");
  const disclosed = cache.excludedSteps ?? {};
  if (
    JSON.stringify(Object.keys(disclosed).toSorted()) !==
      JSON.stringify([...excluded].toSorted()) ||
    Object.entries(disclosed).some(
      ([coordinate, steps]) =>
        canonicalSteps(steps) !== canonicalSteps(APPROVED_EXCLUDED_STEPS[coordinate]),
    )
  )
    fail("knownDifferences.restNegativeCache.excludedSteps must be the approved source steps");
}
