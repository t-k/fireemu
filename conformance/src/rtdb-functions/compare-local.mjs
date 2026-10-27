// Compares the frames a local fireemu delivered for the CV14 fixture and write sequence with the production
// recording (recorded/production-rtdb-triggers.json), one row per write and handler: MATCH or DIFFERENCE,
// with every member that differs. Production is the oracle. Values that are different in every delivery are
// compared by their form, not their value: the event id and the time (the form production uses), and the
// traceparent. Everything else, the member names included, is compared exactly. Timing, delivery order
// across handlers and the sequence numbers the fixture counts are not compared.

import { readFileSync } from "node:fs";

import { FIXTURE_HANDLERS } from "./frames.mjs";
import { MASKED_NONCE } from "./mask-recording.mjs";
import { buildSteps, matchFrame } from "./sequence.mjs";

const BASE64_20 = /^[A-Za-z0-9+/]{27}=$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const TIME_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const TIME_OTHER = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/u;
const TRACEPARENT = /^00-[0-9a-f]{32}-[0-9a-f]{16}-0[0-3]$/u;

/** The form of an event id: the production form is base64 of 20 bytes. */
export function idForm(value) {
  if (typeof value !== "string") return `<id:${typeof value}>`;
  if (BASE64_20.test(value)) return "<id:base64-20-bytes>";
  if (UUID.test(value)) return "<id:uuid>";
  return "<id:other>";
}

/** The form of an event time: the production form is RFC 3339 UTC with exactly three fraction digits. */
export function timeForm(value) {
  if (typeof value !== "string") return `<time:${typeof value}>`;
  if (TIME_MS.test(value)) return "<time:rfc3339-utc-ms>";
  if (TIME_OTHER.test(value)) return `<time:rfc3339-other:${value.replace(/\d/gu, "9")}>`;
  return "<time:other>";
}

export function traceForm(value) {
  return typeof value === "string" && TRACEPARENT.test(value)
    ? "<traceparent:w3c>"
    : "<traceparent:other>";
}

/** A frame with its per-delivery values reduced to their forms; the rest is untouched. */
export function normalizeFrame(frame) {
  const copy = structuredClone(frame.event);
  if (frame.generation === 1) {
    copy.context.eventId = idForm(copy.context.eventId);
    copy.context.timestamp = timeForm(copy.context.timestamp);
  } else {
    copy.id = idForm(copy.id);
    copy.time = timeForm(copy.time);
    if (copy.context?.eventId !== undefined) {
      /* the printed `context` is a type and key list, nothing per delivery */
    }
    if ("traceparent" in (copy.extras ?? {}))
      copy.extras.traceparent = traceForm(copy.extras.traceparent);
  }
  return copy;
}

/** Every path at which two JSON values differ, as {path, production, local}. */
export function diffValues(production, local, path = "") {
  const here = path === "" ? "$" : path;
  if (
    production === null ||
    local === null ||
    typeof production !== "object" ||
    typeof local !== "object" ||
    Array.isArray(production) !== Array.isArray(local)
  ) {
    return JSON.stringify(production) === JSON.stringify(local)
      ? []
      : [{ path: here, production, local }];
  }
  const out = [];
  if (Array.isArray(production)) {
    if (production.length !== local.length) return [{ path: here, production, local }];
    production.forEach((value, index) =>
      out.push(...diffValues(value, local[index], `${here}[${index}]`)),
    );
    return out;
  }
  for (const key of [...new Set([...Object.keys(production), ...Object.keys(local)])].toSorted()) {
    const inProduction = key in production;
    const inLocal = key in local;
    if (inProduction && inLocal)
      out.push(...diffValues(production[key], local[key], `${here}.${key}`));
    else
      out.push({
        path: `${here}.${key}`,
        production: inProduction ? production[key] : "<absent>",
        local: inLocal ? local[key] : "<absent>",
      });
  }
  return out;
}

const steps = buildSteps(MASKED_NONCE);
const eventTime = (frame) =>
  frame.generation === 1 ? frame.event.context.timestamp : frame.event.time;

function group(frames) {
  const byRow = new Map();
  const unattributed = [];
  for (const frame of frames) {
    const { step } = matchFrame(frame, steps);
    if (step === null) {
      unattributed.push(frame.handler);
      continue;
    }
    const key = `${step}/${frame.handler}`;
    byRow.set(key, [...(byRow.get(key) ?? []), frame]);
  }
  return { byRow, unattributed };
}

/**
 * Rows for every write and handler, plus the cross-delivery facts production showed: every delivery of
 * one write carries one time, and two deliveries never share an event id.
 */
export function compareRecordings({ production, local }) {
  const p = group(production);
  const l = group(local);
  const rows = [];
  for (const step of steps) {
    for (const handler of FIXTURE_HANDLERS) {
      const key = `${step.id}/${handler.name}`;
      const a = p.byRow.get(key) ?? [];
      const b = l.byRow.get(key) ?? [];
      const differences = [];
      if (a.length !== b.length)
        differences.push({ path: "deliveries", production: a.length, local: b.length });
      else if (a.length === 1)
        differences.push(...diffValues(normalizeFrame(a[0]), normalizeFrame(b[0])));
      rows.push({
        row: key,
        verdict: differences.length === 0 ? "MATCH" : "DIFFERENCE",
        production: a.length,
        local: b.length,
        differences,
      });
    }
  }
  const facts = [];
  for (const [name, set] of [
    ["production", production],
    ["local", local],
  ]) {
    const bySteps = new Map();
    for (const frame of set) {
      const { step } = matchFrame(frame, steps);
      if (step !== null)
        bySteps.set(step, new Set([...(bySteps.get(step) ?? []), eventTime(frame)]));
    }
    const ids = set.map((f) => (f.generation === 1 ? f.event.context.eventId : f.event.id));
    facts.push({
      side: name,
      oneTimePerWrite: [...bySteps.values()].every((times) => times.size === 1),
      distinctIds: new Set(ids).size === ids.length,
    });
  }
  return {
    rows,
    facts,
    unattributed: { production: p.unattributed, local: l.unattributed },
    totals: {
      rows: rows.length,
      match: rows.filter((r) => r.verdict === "MATCH").length,
      difference: rows.filter((r) => r.verdict === "DIFFERENCE").length,
    },
  };
}

export const readFrames = (file) =>
  readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [localFrames] = process.argv.slice(2);
  const production = JSON.parse(
    readFileSync(new URL("./recorded/production-rtdb-triggers.json", import.meta.url), "utf8"),
  ).frames.map(({ n: _n, step: _step, ...frame }) => frame);
  const result = compareRecordings({ production, local: readFrames(localFrames) });
  console.log(JSON.stringify(result, null, 1));
}
