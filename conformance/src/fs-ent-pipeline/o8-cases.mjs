// Shared by the function-family and stage corpora of O-8B and O-8C: a case is one call of one
// function with the arguments written out, run as `select({v: call})` over a probe collection.
// Cases carry a kind, so the tests can require every function to be asked its typical,
// null, absent, wrong-type and wrong-arity questions.

import { int, str } from "../fs-query-index/values.mjs";
import { fn, read, select, stage } from "./builders.mjs";

/** ok: a typical answer; edge: a boundary of the value; range: out of the type's range. */
export const KINDS = ["ok", "edge", "null", "absent", "type", "arity", "range"];

/** One case: a label (`[a-z0-9-]+`), a kind, and the arguments of the call. */
export function c(label, kind, ...args) {
  if (!KINDS.includes(kind)) throw new Error(`unknown case kind ${kind}`);
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(label)) throw new Error(`bad case label ${label}`);
  return { label, kind, args };
}

export const caseStepId = (name, label) => `${name.replaceAll("_", "-")}-${label}`;

/**
 * A program that asks each function its cases, one step each: a `select` of one call over the
 * collection of the probe document(s).
 */
export function functionProgram({ id, collection, seed, functions }) {
  const steps = [];
  const seen = new Set();
  for (const [name, cases] of Object.entries(functions)) {
    for (const { label, args } of cases) {
      const stepId = caseStepId(name, label);
      if (seen.has(stepId)) throw new Error(`duplicate step ${stepId}`);
      seen.add(stepId);
      steps.push(read(stepId, collection, select({ v: fn(name, ...args) })));
    }
  }
  return { id, seed, steps };
}

/**
 * The argument count a function accepts, read from the text production refused a call with no
 * arguments in (FS-ENT-ORACLE O-5): the one range, or the widest of the overloads. Undefined
 * when the text says nothing about counts.
 */
export function arityOf(message) {
  // `[2..3]` is closed; `[2..+\u221e)` is open at the top.
  const ranges = [...message.matchAll(/(?:takes|with) \[(\d+)\.\.(?:(\d+)\]|\+\u221e\))/g)].map(
    (m) => [Number(m[1]), m[2] === undefined ? Infinity : Number(m[2])],
  );
  if (ranges.length === 0) return undefined;
  return {
    min: Math.min(...ranges.map(([min]) => min)),
    max: Math.max(...ranges.map(([, max]) => max)),
  };
}

// --- stages with options and stages that embed a pipeline ---

/** A stage with an options map. */
export const stageWith = (name, args, options) => ({ name, args, options });

/** `union`: the other pipeline is a pipeline value of its stages. */
export const union = (...stages) => stage("union", { pipelineValue: { stages } });

/** `unnest`: the expression, then the alias as a field reference; the index field is an option. */
export function unnest(expression, alias, indexField) {
  const base = stage("unnest", expression, { fieldReferenceValue: alias });
  return indexField === undefined
    ? base
    : { ...base, options: { index_field: { fieldReferenceValue: indexField } } };
}

/** `sample`: the rate as a number (an integer stays an integer), then the mode as a string. */
export const sample = (rate, mode) =>
  stage("sample", Number.isInteger(rate) ? int(rate) : { doubleValue: rate }, str(mode));
