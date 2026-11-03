// What lets the FS-ENT-ORACLE pipeline lane exit 0 although its export still reports raw MISMATCH
// and UNKNOWN rows. One table names every such row and the recorded decision that covers it; the
// row's own answer must then stay inside the decision's allowance. A row outside the table, a row
// of the table whose answer goes beyond its allowance, and a table row the corpus lost all fail.
//
//   2114  the two O-6 sort ties: all typed rows and the ordered prefix exact, only the tied rows
//         permute (or two distinct rows of the three eligible ones are chosen)
//   2211  the 20 O-7 aggregate rows that differ in order only: the same groups as a multiset;
//         the now-dependent value of timestamp-diff-now
//   2214  the 3 O-7 rows under a limit or an offset: exact count, no duplicates, every group equal
//         to a group of the complete companion result
//   nesting observation  the two O-8A gRPC rows the recorder could not send
//
// The raw statuses are never rewritten: `coveredBy` only decides whether a row may stay.
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";

import { evaluate as evaluateO6 } from "./o6-sort-policy.mjs";
import { evaluate as evaluateO7 } from "./o7-order-policy.mjs";

const O7_POLICY = JSON.parse(
  readFileSync(new URL("./o7-order-policy-data.json", import.meta.url), "utf8"),
);
const NESTING_OBSERVATION = JSON.parse(
  readFileSync(new URL("../../fs-ent-pipeline-nesting-observation.json", import.meta.url), "utf8"),
);

export const CLOCK_ROW = "fs-ent-pipeline/o8c/timestamps-main#timestamp-diff-now";
const V_DESC = "fs-ent-pipeline/o6/sort-kinds-cross#v-desc";
const TIES = "fs-ent-pipeline/o6/sort-ties#g-asc-limit2";
const O6_ROWS = [V_DESC, TIES];

/** The one table: row id to the decision that covers it and the rule that bounds the difference. */
export const COVERAGE = new Map([
  ...O7_POLICY.recipes.map((recipe) => [
    recipe.id,
    { decision: recipe.mode === "selection" ? "2214" : "2211", rule: "o7-groups" },
  ]),
  ...O6_ROWS.map((row) => [row, { decision: "2114", rule: "o6-tie" }]),
  [CLOCK_ROW, { decision: "2211", rule: "clock-value" }],
  ...NESTING_OBSERVATION.productionObservation.rows.map((item) => [
    item.row,
    { decision: "nesting-observation", rule: "later-observation" },
  ]),
]);

const splitRow = (row) => {
  const at = row.lastIndexOf("#");
  return [row.slice(0, at), row.slice(at + 1)];
};

export function allowsClockValue(production, fireemu) {
  const valid = (step) => {
    const value = step?.body?.[0]?.results?.[0]?.fields?.v;
    return (
      step?.status === 200 &&
      Array.isArray(step.body) &&
      step.body.length === 1 &&
      step.body[0].results?.length === 1 &&
      Object.keys(step.body[0].results[0].fields).length === 1 &&
      value &&
      Object.keys(value).length === 1 &&
      typeof value.integerValue === "string" &&
      /^(0|-?[1-9]\d*)$/.test(value.integerValue)
    );
  };
  if (!valid(production) || !valid(fireemu)) return false;
  const blank = (step) => {
    const copy = structuredClone(step);
    copy.body[0].results[0].fields.v.integerValue = "<value>";
    return copy;
  };
  return isDeepStrictEqual(blank(production), blank(fireemu));
}

function allowsLaterObservation(row, production, fireemu) {
  const observed = NESTING_OBSERVATION.productionObservation.rows.find((item) => item.row === row);
  if (!observed || observed.code !== 3 || observed.rounds !== 2) return false;
  // The recorded row is the recorder's own client failure, and the lane's local client fails the
  // same way: neither side sent the request. fireemu's real answer is pinned by the replay test.
  const { unknown, ...recorded } = production ?? {};
  return (
    typeof unknown === "string" &&
    recorded.code === 13 &&
    typeof recorded.message === "string" &&
    isDeepStrictEqual(recorded, fireemu)
  );
}

/**
 * Whether a row that is not a MATCH may stay, and under which decision.
 * `localSteps` are the lane's local answers of the whole program (companions and preludes).
 * Returns `{ decision, rule }` or `{ rejected }`; `undefined` when the table does not name the row.
 */
export function coveredBy({ row, status, program, saved, localSteps }) {
  const entry = COVERAGE.get(row);
  if (!entry) return undefined;
  const [, stepId] = splitRow(row);
  const production = saved?.steps?.[stepId];
  const fireemu = localSteps?.[stepId];
  const second = (id) => saved?.second?.[id] ?? saved?.steps?.[id];
  const step = (id) => program?.steps?.find((item) => item.id === id);
  const reject = (reason) => ({ rejected: `${row}: ${reason}` });
  const ok = (proof) => ({ decision: entry.decision, rule: entry.rule, proof });
  try {
    if (entry.rule === "later-observation") {
      if (status !== "UNKNOWN") return reject(`status ${status}, not UNKNOWN`);
      return allowsLaterObservation(row, production, fireemu)
        ? ok("RECORDED_CLIENT_FAILURE_WITH_LATER_OBSERVATION")
        : reject("the answer is not the recorded client failure");
    }
    if (status !== "MISMATCH") return reject(`status ${status}, not MISMATCH`);
    if (entry.rule === "clock-value")
      return allowsClockValue(production, fireemu)
        ? ok("CLOCK_DEPENDENT_VALUE_ONLY")
        : reject("the difference is more than the clock-dependent value");
    const input = {
      id: row,
      profile: "strict",
      rawStatus: status,
      request: step(stepId),
      seed: program.seed,
      production,
      production2: second(stepId),
      local: fireemu,
    };
    const withCompanion = (id) => ({
      companionRequest: step(id),
      companionProduction: saved.steps[id],
      companionProduction2: second(id),
      companionLocal: localSteps[id],
    });
    if (entry.rule === "o7-groups") {
      const recipe = O7_POLICY.recipes.find((item) => item.id === row);
      if (recipe.companion) Object.assign(input, withCompanion(splitRow(recipe.companion)[1]));
      const proof = evaluateO7(input);
      return proof
        ? ok(proof.proofClassification)
        : reject("the groups differ from the recorded groups");
    }
    if (stepId === "v-desc")
      Object.assign(input, {
        preludeRequest: step("seed-vector"),
        preludeProduction: saved.steps["seed-vector"],
        preludeLocal: localSteps["seed-vector"],
      });
    else Object.assign(input, withCompanion("g-asc"));
    const proof = evaluateO6(input);
    return proof
      ? ok(proof.proofClassification)
      : reject("the difference is more than the tied rows");
  } catch (error) {
    return reject(`the answer cannot be read (${error.message})`);
  }
}

/**
 * Splits the non-passing rows into covered and uncovered ones and lists table rows the corpus no
 * longer has. `cover(row)` is `coveredBy` bound to the row's program and answers.
 */
export function judgeCoverage(rows, passing, cover, table = COVERAGE) {
  const covered = [];
  const uncovered = [];
  for (const row of rows) {
    if (passing.has(row.status)) continue;
    const verdict = cover(row);
    if (verdict?.decision) covered.push({ row: row.row, ...verdict });
    else
      uncovered.push({
        row: row.row,
        status: row.status,
        reason: verdict?.rejected ?? "no decision names the row",
      });
  }
  const present = new Set(rows.map((row) => row.row));
  const missing = [...table.keys()].filter((row) => !present.has(row));
  return { covered, uncovered, missing };
}

/** The steps of a covered row's program whose local answers its allowance reads. */
export function stepsNeededBy(row) {
  const stepId = splitRow(row)[1];
  const recipe = O7_POLICY.recipes.find((item) => item.id === row);
  if (recipe?.companion) return [stepId, splitRow(recipe.companion)[1]];
  if (row === V_DESC) return [stepId, "seed-vector"];
  if (row === TIES) return [stepId, "g-asc"];
  return [stepId];
}

/**
 * The lane's exit code with coverage: 1 when the check is not sound (an uncovered row, a table
 * row the corpus lost, a fixture program the corpus lost, a failed local run), 0 when every row
 * that is not a MATCH is named by a recorded decision and its answer stays inside the decision's
 * allowance. The export keeps the raw statuses either way, and the release job expects 0.
 */
export function laneExitCode({ coverage, orphans, failures }) {
  if (coverage.uncovered.length > 0 || coverage.missing.length > 0) return 1;
  return orphans.length > 0 || failures.length > 0 ? 1 : 0;
}
