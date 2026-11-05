import { readFileSync } from "node:fs";
import { diffValues, normalizeFrame as normalizeCV14 } from "./compare-local.mjs";
import { buildSteps, matchFrame } from "./breadth-sequence.mjs";
import { MASKED_NONCE } from "./mask-breadth.mjs";

function normalizeFrame(frame) {
  const event = normalizeCV14(frame);
  const context = frame.generation === 1 ? event.context : event;
  if (context.auth?.uid != null) context.auth.uid = "<uid>";
  if (context.authId != null && ["USER", "api_key", "app_user"].includes(context.authType))
    context.authId = "<uid>";
  if (Array.isArray(context.auth?.tokenKeys))
    context.auth.tokenKeys = Object.fromEntries(context.auth.tokenKeys.map((key) => [key, true]));
  const { n: _n, step: _step, seq: _seq, receivedAt: _receivedAt, attempt, ...rest } = frame;
  const { ageMs: _ageMs, threw: _threw, ...attemptRest } = attempt ?? {};
  return { ...rest, event, ...(attempt === undefined ? {} : { attempt: attemptRest }) };
}
function group(frames) {
  const rows = new Map(),
    unattributed = [];
  const steps = buildSteps(MASKED_NONCE);
  for (const frame of frames) {
    const { step, reason } = matchFrame(frame, steps);
    if (!step) {
      unattributed.push({ handler: frame.handler, reason });
      continue;
    }
    const params = frame.generation === 1 ? frame.event.context.params : frame.event.params;
    const key = JSON.stringify([step, frame.handler, params.group, params.id]);
    if (!rows.has(key)) rows.set(key, []);
    rows.get(key).push(frame);
  }
  return { rows, unattributed };
}
function events(frames) {
  const grouped = new Map();
  for (const frame of frames) {
    const id = frame.generation === 1 ? frame.event.context.eventId : frame.event.id;
    if (!grouped.has(id)) grouped.set(id, []);
    grouped.get(id).push(frame);
  }
  return [...grouped.values()]
    .map((attempts) => {
      const pattern = attempts.map((f) =>
        f.attempt?.threw === true ? "threw" : f.attempt?.threw === false ? "ok" : null,
      );
      const frames = attempts.map(normalizeFrame);
      if (
        pattern.length > 2 &&
        pattern.at(-1) === "ok" &&
        pattern.slice(0, -1).every((p) => p === "threw")
      ) {
        const failures = frames.slice(0, -1);
        return {
          pattern: ["threw", "ok"],
          frames: [
            ...failures.filter(
              (frame, index) =>
                failures.findIndex((other) => JSON.stringify(other) === JSON.stringify(frame)) ===
                index,
            ),
            frames.at(-1),
          ],
        };
      }
      return { pattern, frames };
    })
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
export function compareRecordings({ production, local }) {
  const p = group(production),
    l = group(local);
  const rows = [...new Set([...p.rows.keys(), ...l.rows.keys()])].sort().map((key) => {
    const a = p.rows.get(key) ?? [],
      b = l.rows.get(key) ?? [];
    const differences = diffValues(events(a), events(b));
    return {
      row: JSON.parse(key),
      verdict: differences.length ? "DIFFERENCE" : "MATCH",
      production: a.length,
      local: b.length,
      differences,
    };
  });
  const timing = [
    ["production", production],
    ["local", local],
  ].map(([side, frames]) => ({
    side,
    deliveries: frames.map((f) => ({
      handler: f.handler,
      seq: f.seq,
      receivedAt: f.receivedAt,
      ageMs: f.attempt?.ageMs,
    })),
  }));
  return {
    rows,
    timing,
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
