// The judge of a whole CV14 run. Production is the oracle and no RTDB trigger event has ever been
// recorded, so the run is `recorded` only when everything the log held was read, every frame belongs to
// exactly one write, every documented delivery came, and no frame carries a member nobody named. Anything
// else is kept in full in the report and adds a reason, so the coordinator reads the observation before
// it is called recorded. It never rejects an observation: it only refuses to call it clean.

import { NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS } from "./frames.mjs";

const DROPPED_CLASSES = ["unparsed", "unknownHandler", "foreignOrigin"];
const LIST_LIMIT = 8;
const listed = (items) =>
  items.length > LIST_LIMIT
    ? `${items.slice(0, LIST_LIMIT).join(", ")} and ${items.length - LIST_LIMIT} more`
    : items.join(", ");

/** The member names of a frame that the fixture did not name (from the keys it listed and its extras). */
function unnamedMembers(frame) {
  const found = new Set();
  const named = frame.generation === 1 ? NAMED_CONTEXT_MEMBERS : NAMED_EVENT_MEMBERS;
  const holder = frame.generation === 1 ? frame.event?.context : frame.event;
  const keys = frame.generation === 1 ? holder?.contextKeys : holder?.eventKeys;
  for (const key of Array.isArray(keys) ? keys : []) if (!named.includes(key)) found.add(key);
  for (const key of Object.keys(holder?.extras ?? {})) found.add(key);
  return [...found];
}

/**
 * The reasons a run cannot be called recorded as it stands; an empty list means there is nothing for the
 * coordinator to decide. The frame, log and member checks run whatever the writes were answered: a run
 * whose writes were all refused can still hold a stranger's frames or dropped entries.
 */
export function judgeRun({ report, frames, writes, ignored }) {
  const reasons = [];
  const answered = Object.values(writes).filter((w) => w?.outcome === "ok").length;

  // Every write is designed to be answered ok (an admin write bypasses the Rules, and the unauthenticated
  // ones carry the nonce the Rules ask for), so a refusal is a departure from the design. An unknown
  // answer has its own reason in the flow.
  for (const step of report.steps) {
    const outcome = step.write?.outcome;
    if (outcome !== undefined && outcome !== "ok" && outcome !== "unknown") {
      reasons.push(
        `write ${step.id} was not answered ok (${outcome}, status ${step.write.status})`,
      );
    }
  }

  if (answered > 0 && frames.length === 0) {
    reasons.push(`no frame was read although ${answered} write(s) were answered ok`);
  }

  if (report.totals.unattributed > 0) {
    const byReason = {};
    for (const entry of report.unattributed) {
      byReason[entry.reason] = (byReason[entry.reason] ?? 0) + 1;
    }
    const detail = Object.entries(byReason)
      .toSorted()
      .map(([reason, count]) => `${reason}: ${count}`)
      .join(", ");
    reasons.push(
      `${report.totals.unattributed} frame(s) could not be attributed to a write (${detail})`,
    );
  }

  const dropped = DROPPED_CLASSES.filter((klass) => (ignored?.[klass] ?? 0) > 0);
  if (dropped.length > 0) {
    reasons.push(
      `log entries were dropped by the parser: ${dropped.map((klass) => `${klass} ${ignored[klass]}`).join(", ")}`,
    );
  }

  // What each write was documented to deliver against what came. A step whose answer is unknown is skipped
  // (its frames may be real); a step that was refused or never sent expects nothing at all.
  const missing = [];
  const repeated = [];
  const unexpected = [];
  for (const step of report.steps) {
    const outcome = step.write?.outcome ?? null;
    if (outcome === "unknown") continue;
    for (const [handler, seen] of Object.entries(step.handlers)) {
      const expected = outcome === "ok" && seen.documented === 1;
      const label = `${step.id} ${handler}`;
      if (expected && seen.frames === 0) missing.push(label);
      else if (expected && (seen.duplicateFrames > 0 || seen.distinctEventIds > 1)) {
        repeated.push(`${label} (${seen.frames} frames, ${seen.distinctEventIds} event ids)`);
      } else if (!expected && seen.frames > 0) {
        unexpected.push(`${label} (${seen.frames} frames)`);
      }
    }
  }
  if (missing.length > 0)
    reasons.push(`a documented delivery received no frame: ${listed(missing)}`);
  if (repeated.length > 0) {
    reasons.push(
      `a delivery came more than once (a repeat or a second event): ${listed(repeated)}`,
    );
  }
  if (unexpected.length > 0) {
    reasons.push(`a delivery came that the documentation does not expect: ${listed(unexpected)}`);
  }

  const unnamed = new Set();
  for (const frame of frames) for (const member of unnamedMembers(frame)) unnamed.add(member);
  if (unnamed.size > 0) {
    reasons.push(
      `frames carry members the fixture did not name: ${listed([...unnamed].toSorted())}`,
    );
  }
  return reasons;
}
