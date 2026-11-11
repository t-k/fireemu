// The judge of the pipeline regex observation. Pure functions; regex-report.mjs reads the files.
//
// A recorded answer is read only in the shapes FS-ENT-ORACLE O-8B recorded for the regex
// functions (fs-ent-pipeline-production.json, program `fs-ent-pipeline/o8b/strings-main`):
//   200  one frame {executionTime, results:[{fields:{v}}]} with v a boolean, a string, null, or an
//        array of strings (an unmatched group in an array may come back as null);
//   400  one frame {error:{code:400, status:"INVALID_ARGUMENT", message}} with the message
//        "Unsupported regex syntax." or, for find and find_all with several groups,
//        "At most one capture group is supported.".
// fireemu's own refusal of a function it has not observed is a 501 UNIMPLEMENTED. Anything else is
// `unknown`: the row is not used, and nothing is guessed.

import { PAIRS, REGEX_FUNCTIONS, REGEX_PREFIX, stepIdOf } from "./regex-corpus.mjs";

const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hasKeys = (value, keys) =>
  isObject(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const unknown = (reason) => ({ kind: "unknown", reason });

const SYNTAX_MESSAGE = "Unsupported regex syntax.";
// Recorded by FS-PIPELINE-REGEX (2026-11-10) for regex_find and regex_find_all with two groups.
const CAPTURES_MESSAGE = "At most one capture group is supported.";

function readItem(value) {
  if (hasKeys(value, ["stringValue"]) && typeof value.stringValue === "string")
    return { kind: "string", value: value.stringValue };
  if (hasKeys(value, ["nullValue"]) && value.nullValue === null) return { kind: "null" };
  return undefined;
}

function readValue(value) {
  if (!isObject(value) || Object.keys(value).length !== 1) return unknown("value is not one key");
  if (hasKeys(value, ["booleanValue"]) && typeof value.booleanValue === "boolean")
    return { kind: "bool", value: value.booleanValue };
  const item = readItem(value);
  if (item) return item;
  if (hasKeys(value, ["arrayValue"]) && isObject(value.arrayValue)) {
    const inner = value.arrayValue;
    if (Object.keys(inner).length === 0) return { kind: "array", items: [] };
    if (hasKeys(inner, ["values"]) && Array.isArray(inner.values) && inner.values.length > 0) {
      const items = inner.values.map(readItem);
      if (items.every(Boolean)) return { kind: "array", items };
    }
    return unknown("array holds an unrecorded item");
  }
  return unknown("value kind was not recorded");
}

/** Reads one saved answer `{status, body}` into an outcome. */
export function readAnswer(answer) {
  if (!hasKeys(answer, ["status", "body"])) return unknown("not a {status, body} answer");
  const { status, body } = answer;
  if (!Array.isArray(body) || body.length !== 1 || !isObject(body[0]))
    return unknown(`status ${status} with an unrecorded body`);
  const [frame] = body;
  if (status === 200) {
    if (!hasKeys(frame, ["executionTime", "results"]) || !Array.isArray(frame.results))
      return unknown("200 frame has an unrecorded layout");
    if (frame.results.length !== 1) return unknown("200 frame has not exactly one result");
    const [result] = frame.results;
    if (!hasKeys(result, ["fields"]) || !hasKeys(result.fields, ["v"]))
      return unknown("200 result has an unrecorded layout");
    return readValue(result.fields.v);
  }
  if ((status === 400 || status === 501) && hasKeys(frame, ["error"])) {
    const { error } = frame;
    if (!hasKeys(error, ["code", "message", "status"])) return unknown("error has other keys");
    if (error.code !== status) return unknown("error code differs from the status");
    if (status === 400 && error.status === "INVALID_ARGUMENT") {
      if (error.message === SYNTAX_MESSAGE) return { kind: "refused-syntax" };
      if (error.message === CAPTURES_MESSAGE) return { kind: "refused-captures" };
    }
    if (status === 501 && typeof error.message === "string" && error.status === "UNIMPLEMENTED")
      return { kind: "unimplemented" };
  }
  return unknown(`status ${status} was not recorded for these functions`);
}

const FIELD = {
  regex_contains: "contains",
  regex_match: "match",
};

const predictedItem = (item) =>
  item.kind === "unmatched" ? { kind: "either" } : { kind: "string", value: item.value ?? "" };

/** The outcome RE2 (read through the prediction file) gives for one function. */
export function expectedOutcome(name, prediction) {
  if (!REGEX_FUNCTIONS.includes(name)) throw new Error(`unknown function ${name}`);
  if (prediction.error) return { kind: "refused-syntax" };
  if (name in FIELD) return { kind: "bool", value: prediction[FIELD[name]] };
  if (name === "regex_find") {
    if (prediction.find === null) return { kind: "null" };
    return predictedItem(prediction.find);
  }
  return { kind: "array", items: prediction.findAll.map(predictedItem) };
}

/** Equal outcomes; `either` (an unmatched group) is null or an empty string; unknown is never equal. */
export function sameOutcome(a, b) {
  if (a.kind === "unknown" || b.kind === "unknown") return false;
  if (a.kind === "either" || b.kind === "either") {
    const other = a.kind === "either" ? b : a;
    return (
      other.kind === "either" ||
      other.kind === "null" ||
      (other.kind === "string" && other.value === "")
    );
  }
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "bool":
    case "string":
      return a.value === b.value;
    case "array":
      return (
        a.items.length === b.items.length && a.items.every((x, i) => sameOutcome(x, b.items[i]))
      );
    default:
      return true;
  }
}

/** Production against fireemu and against the prediction. */
export function verdictOf({ production, fireemu, prediction }) {
  if (production.kind === "unknown") return { vsFireemu: "unknown", vsPrediction: "unknown" };
  const vsPrediction = sameOutcome(production, prediction) ? "agrees" : "differs";
  let vsFireemu;
  if (fireemu.kind === "unknown") vsFireemu = "unknown";
  else if (fireemu.kind === "unimplemented") vsFireemu = "unobserved";
  else vsFireemu = sameOutcome(production, fireemu) ? "agrees" : "differs";
  return { vsFireemu, vsPrediction };
}

const bump = (counts, key) => {
  counts[key] = (counts[key] ?? 0) + 1;
};

/**
 * Every pair of every function: the saved production answer, fireemu strict and emulator, the
 * prediction, and the verdicts. Missing or doubtful production rows are unknown, not absent.
 */
export function reportRows({ fixture, strict, emulator, predictions }) {
  const rows = [];
  const counts = { vsPrediction: {}, strict: {}, emulator: {} };
  for (const pair of PAIRS) {
    const programId = `${REGEX_PREFIX}rx/${pair.group}`;
    for (const name of REGEX_FUNCTIONS) {
      const stepId = stepIdOf(name, pair.label);
      const saved = fixture.programs?.[programId];
      const production =
        saved?.second && Object.hasOwn(saved.second, stepId)
          ? unknown("second recording differs from the first")
          : readAnswer(saved?.steps?.[stepId]);
      const prediction = expectedOutcome(name, predictions.pairs[pair.label]);
      const profile = (side) => readAnswer(side.results?.[programId]?.steps?.[stepId]);
      const strictRead = profile(strict);
      const emulatorRead = profile(emulator);
      const strictVerdict = verdictOf({ production, fireemu: strictRead, prediction });
      const emulatorVerdict = verdictOf({ production, fireemu: emulatorRead, prediction });
      rows.push({
        id: `${programId}#${stepId}`,
        function: name,
        pair: pair.label,
        production,
        prediction,
        strict: strictRead,
        emulator: emulatorRead,
        vsPrediction: strictVerdict.vsPrediction,
        vsStrict: strictVerdict.vsFireemu,
        vsEmulator: emulatorVerdict.vsFireemu,
      });
      bump(counts.vsPrediction, strictVerdict.vsPrediction);
      bump(counts.strict, strictVerdict.vsFireemu);
      bump(counts.emulator, emulatorVerdict.vsFireemu);
    }
  }
  return { rows, counts };
}
