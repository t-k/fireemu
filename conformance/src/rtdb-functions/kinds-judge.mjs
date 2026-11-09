import { NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS, isRecordedMember } from "./kinds-frames.mjs";

const writeOk = (write) => !write?.outcome || ["ok", "unknown"].includes(write.outcome);

/**
 * Reasons a kinds run cannot be called recorded as it stands. It never rejects what production did: a
 * delivery nobody expected is a reason to review, and so is a missing one, except on an observation-only
 * step (priority-only change, large payloads) whose absence is itself the observation.
 */
export function judgeRun({ report, frames, writes, ignored, userUid, deployed }) {
  const reasons = [];
  const check = (step, label, seen) => {
    if (!writeOk(step.write) && seen.frames > 0) reasons.push(`unexpected delivery: ${label}`);
    else if (writeOk(step.write) && seen.expected === 0 && seen.frames > 0)
      reasons.push(`unexpected delivery: ${label}`);
    else if (
      step.write?.outcome === "ok" &&
      seen.expected === 1 &&
      seen.frames === 0 &&
      !step.observeOnly
    )
      reasons.push(`missing delivery: ${label}`);
    if (seen.distinctEventIds > 1) reasons.push(`multiple event ids: ${label}`);
    if (seen.duplicateFrames > 0) reasons.push(`repeated delivery: ${label}`);
  };
  for (const step of report.steps) {
    if (!writeOk(step.write)) reasons.push(`write ${step.id} was not answered ok`);
    for (const leaf of step.leaves ?? [])
      for (const [name, seen] of Object.entries(leaf.handlers)) {
        if (deployed && !deployed.includes(name)) continue;
        check(step, `${step.id} ${name} ${leaf.group}/${leaf.id}`, seen);
      }
    for (const group of step.groups ?? [])
      for (const [name, seen] of Object.entries(group.handlers)) {
        if (deployed && !deployed.includes(name)) continue;
        check(step, `${step.id} ${name} ${group.group}`, seen);
      }
  }
  if (Object.values(writes ?? {}).some((w) => w?.outcome === "ok") && frames.length === 0)
    reasons.push("no frames read");
  if (report.totals.unattributed)
    reasons.push(`${report.totals.unattributed} frame(s) could not be attributed`);
  for (const key of ["unparsed", "unknownHandler", "foreignOrigin"])
    if (ignored?.[key]) reasons.push(`log entries dropped: ${key}`);
  const unnamed = new Set();
  for (const frame of frames) {
    const holder = frame.generation === 1 ? frame.event?.context : frame.event;
    const auth = frame.generation === 1 ? holder?.auth : null;
    if (
      userUid &&
      ((auth?.uid && auth.uid !== userUid) ||
        (frame.generation === 2 && holder?.authId != null && holder.authId !== userUid))
    )
      reasons.push(`stranger auth: ${frame.handler}`);
    const named = frame.generation === 1 ? NAMED_CONTEXT_MEMBERS : NAMED_EVENT_MEMBERS;
    const keys = frame.generation === 1 ? holder?.contextKeys : holder?.eventKeys;
    for (const key of new Set([
      ...(Array.isArray(keys) ? keys : []),
      ...Object.keys(holder?.extras ?? {}),
    ]))
      if (
        !named.includes(key) &&
        !isRecordedMember(frame.handler, frame.generation, key, holder?.extras?.[key])
      )
        unnamed.add(key);
  }
  if (unnamed.size) reasons.push(`frames carry unnamed members: ${[...unnamed].sort().join(", ")}`);
  return reasons;
}
