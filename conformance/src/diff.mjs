// Classification (recording) and comparison (checking).
//
// Recording folds the two sides of one scenario into a fixture: a step both sides answered
// identically is `parity`; a step listed in `divergences.json` is a `documented-divergence`;
// anything else that differs is `debt`. Checking replays only fireemu and asks whether
// the fixture still describes it.

import { err, ok } from "neverthrow";

import { STATUS } from "./config.mjs";

/** Structural equality over the normalized JSON the corpus records. */
export function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]));
  }
  const keys = Object.keys(a);
  if (keys.length !== Object.keys(b).length) return false;
  return keys.every((k) => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
}

const ABSENT = { absent: "this side recorded no such step" };

const stepsById = (scenario) => new Map((scenario?.steps ?? []).map((s) => [s.id, s]));

/** Union of both sides' step ids, in oracle order first so the fixture reads in corpus order. */
function mergedIds(oracleScenario, testdScenario) {
  const ids = (oracleScenario?.steps ?? []).map((s) => s.id);
  for (const step of testdScenario?.steps ?? []) if (!ids.includes(step.id)) ids.push(step.id);
  return ids;
}

/**
 * Folds one scenario's two runs into fixture steps.
 *
 * @param annotations map of `<scenarioId>#<stepId>` to `{documents, reason}`.
 */
export function classifyScenario({ scenarioId, oracleScenario, testdScenario, annotations }) {
  const oracleSteps = stepsById(oracleScenario);
  const testdSteps = stepsById(testdScenario);
  const steps = [];
  for (const id of mergedIds(oracleScenario, testdScenario)) {
    const o = oracleSteps.get(id);
    const t = testdSteps.get(id);

    // A row the corpus itself declared unanswerable: both sides declare it identically,
    // because it is a statement in the corpus rather than an observation.
    if (o?.pending && t?.pending) {
      steps.push({
        id,
        status: STATUS.pending,
        reason: o.reason,
        production: o.production,
      });
      continue;
    }

    const oracleValue = o?.pending ? { pendingOnOracleOnly: o.reason } : (o?.value ?? ABSENT);
    const testdValue = t?.pending ? { pendingOnTestdOnly: t.reason } : (t?.value ?? ABSENT);

    if (o && t && deepEqual(oracleValue, testdValue)) {
      steps.push({ id, status: STATUS.parity, value: oracleValue });
      continue;
    }

    const annotation = annotations[`${scenarioId}#${id}`];
    if (annotation) {
      steps.push({
        id,
        status: STATUS.documentedDivergence,
        oracle: oracleValue,
        testd: testdValue,
        documents: annotation.documents,
        reason: annotation.reason,
      });
      continue;
    }
    steps.push({ id, status: STATUS.debt, oracle: oracleValue, testd: testdValue });
  }
  return steps;
}

/**
 * Compares a replayed fireemu scenario against its fixture.
 *
 * @returns Result of `{scenarioId, checked, warnings}`, or the failures that fail the gate.
 */
export function compareScenario({ fixture, testdScenario }) {
  const failures = [];
  const warnings = [];
  const actual = stepsById(testdScenario);
  const seen = new Set();
  let checked = 0;

  for (const step of fixture.steps) {
    seen.add(step.id);
    const row = actual.get(step.id);

    if (step.status === STATUS.pending) {
      if (row && !row.pending) {
        failures.push(
          `${fixture.id}#${step.id}: recorded as pending (${step.reason}) but this run produced an observation; ` +
            "re-record the fixture rather than treating a local result as production behaviour",
        );
      }
      continue;
    }

    if (!row) {
      failures.push(`${fixture.id}#${step.id}: the fixture has this step but the run does not`);
      continue;
    }
    const value = row.pending ? { pendingOnTestdOnly: row.reason } : row.value;

    if (step.status === STATUS.parity) {
      checked += 1;
      if (!deepEqual(step.value, value)) {
        failures.push(
          `${fixture.id}#${step.id}: parity drift\n  fixture: ${JSON.stringify(step.value)}\n  run:     ${JSON.stringify(value)}`,
        );
      }
      continue;
    }

    if (step.status === STATUS.documentedDivergence) {
      checked += 1;
      if (!deepEqual(step.testd, value)) {
        failures.push(
          `${fixture.id}#${step.id}: documented divergence drifted from its recorded fireemu value\n` +
            `  documents: ${step.documents}\n  fixture: ${JSON.stringify(step.testd)}\n  run:     ${JSON.stringify(value)}`,
        );
      }
      continue;
    }

    // Debt rows are reported, never a gate: they are already known mismatches.
    if (!deepEqual(step.testd, value)) {
      warnings.push(`${fixture.id}#${step.id}: known debt row changed since it was recorded`);
    }
  }

  for (const step of testdScenario?.steps ?? []) {
    if (!seen.has(step.id)) {
      failures.push(
        `${fixture.id}#${step.id}: the run produced a step the fixture does not describe; ` +
          "an undocumented row cannot be compared against the oracle",
      );
    }
  }
  if (testdScenario?.fault) {
    failures.push(`${fixture.id}: the scenario faulted during the run: ${testdScenario.fault}`);
  }

  return failures.length === 0
    ? ok({ scenarioId: fixture.id, checked, warnings })
    : err({ scenarioId: fixture.id, failures, warnings });
}
