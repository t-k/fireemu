// Compares the frames two runs of the kinds fixture delivered (production and a local fireemu, or two
// local profiles), one row per write, handler and node: MATCH or DIFFERENCE, with every member that
// differs. Per-delivery values (event id, time, traceparent) are compared by form, the uid of the run's
// user is masked, the token key names are compared as a set and the custom claim values exactly. Timing,
// the order across handlers and the sequence numbers are not compared.

import { readFileSync } from "node:fs";
import { diffValues, normalizeFrame as normalizeCV14 } from "./compare-local.mjs";
import { MASKED_NONCE } from "./mask-recording.mjs";
import { buildSteps, matchFrame } from "./kinds-sequence.mjs";

export function normalizeFrame(frame) {
  const event = normalizeCV14(frame);
  const context = frame.generation === 1 ? event.context : event;
  if (context.auth?.uid != null) context.auth.uid = "<uid>";
  if (context.authId != null && ["USER", "api_key", "app_user"].includes(context.authType))
    context.authId = "<uid>";
  if (Array.isArray(context.auth?.tokenKeys))
    context.auth.tokenKeys = Object.fromEntries(context.auth.tokenKeys.map((key) => [key, true]));
  const { n: _n, step: _step, seq: _seq, receivedAt: _receivedAt, ...rest } = frame;
  return { ...rest, event };
}

function group(frames, steps) {
  const rows = new Map();
  const unattributed = [];
  for (const frame of frames) {
    const { step, reason } = matchFrame(frame, steps);
    if (!step) {
      unattributed.push({ handler: frame.handler, reason });
      continue;
    }
    const params = frame.generation === 1 ? frame.event.context.params : frame.event.params;
    const key = JSON.stringify([step, frame.handler, params.group, params.id ?? null]);
    if (!rows.has(key)) rows.set(key, []);
    rows.get(key).push(frame);
  }
  return { rows, unattributed };
}

/** The deliveries of one row, one entry per event id (a redelivery is the same event), in a stable order. */
function events(frames) {
  const byId = new Map();
  for (const frame of frames) {
    const id = frame.generation === 1 ? frame.event.context.eventId : frame.event.id;
    if (!byId.has(id)) byId.set(id, []);
    byId.get(id).push(normalizeFrame(frame));
  }
  return [...byId.values()]
    .map((deliveries) => ({ deliveries: deliveries.length, frame: deliveries[0] }))
    .toSorted((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

export function compareRecordings({ production, local }) {
  const steps = buildSteps(MASKED_NONCE);
  const p = group(production, steps);
  const l = group(local, steps);
  const rows = [...new Set([...p.rows.keys(), ...l.rows.keys()])].toSorted().map((key) => {
    const a = p.rows.get(key) ?? [];
    const b = l.rows.get(key) ?? [];
    const differences = diffValues(events(a), events(b));
    return {
      row: JSON.parse(key),
      verdict: differences.length ? "DIFFERENCE" : "MATCH",
      production: a.length,
      local: b.length,
      differences,
    };
  });
  return {
    rows,
    unattributed: { production: p.unattributed, local: l.unattributed },
    totals: {
      rows: rows.length,
      match: rows.filter((r) => r.verdict === "MATCH").length,
      difference: rows.filter((r) => r.verdict === "DIFFERENCE").length,
    },
  };
}

export const readFrames = (file) =>
  readFileSync(file, "utf8").split("\n").filter(Boolean).map(JSON.parse);

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [production, local] = process.argv.slice(2);
  console.log(
    JSON.stringify(
      compareRecordings({
        production: JSON.parse(readFileSync(production, "utf8")).frames,
        local: readFrames(local),
      }),
      null,
      2,
    ),
  );
}
