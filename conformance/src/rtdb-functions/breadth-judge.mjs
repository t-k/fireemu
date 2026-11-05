import { NAMED_CONTEXT_MEMBERS, NAMED_EVENT_MEMBERS, isRecordedMember } from "./breadth-frames.mjs";

export function judgeRun({ report, frames, writes, ignored, userUid, deployed }) {
  const reasons = [];
  for (const step of report.steps) {
    if (step.write?.outcome && !["ok", "unknown"].includes(step.write.outcome))
      reasons.push(`write ${step.id} was not answered ok`);
    for (const leaf of step.leaves ?? [])
      for (const [name, seen] of Object.entries(leaf.handlers)) {
        if (deployed && !deployed.includes(name)) continue;
        const label = `${step.id} ${name} ${leaf.group}/${leaf.id}`;
        if (
          step.write?.outcome &&
          !["ok", "unknown"].includes(step.write.outcome) &&
          seen.frames > 0
        )
          reasons.push(`unexpected delivery: ${label}`);
        if (step.write?.outcome === "ok" && step.path?.split("/").length >= 4 && seen.frames === 0)
          reasons.push(`missing delivery: ${label}`);
        if (step.path?.split("/").length >= 4 && seen.distinctEventIds > 1)
          reasons.push(`multiple event ids: ${label}`);
        const failing =
          leaf.group === "gr" && typeof (leaf.after ?? leaf.before)?.failForMs === "number";
        if (seen.duplicateFrames > 0 && !failing && step.path?.split("/").length >= 4)
          reasons.push(`repeated delivery: ${label}`);
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
