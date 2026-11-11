// The A2 read-back of a closed or stopped recording: at least ten minutes after its last request, one
// complete LIST per kind. Absence from a complete LIST settles a confirmed resource and an unknown
// DELETE. It never settles an unknown CREATE (a name that was never confirmed stays reported), and a
// partial or failed LIST settles nothing. A2 is read-only: a resource still listed becomes the work of
// a recovery packet.

export const A2_MIN_AGE_MS = 600000;

const SETTLES_ON_ABSENCE = new Set([
  "delete-unknown",
  "delete-404-present",
  "live-suspect",
  "live",
  "delete-unread",
  "delete-present",
]);

/**
 * @param {{open: {name:string,status:string}[], lists: Record<string, {complete:boolean, names:string[]}>, kindOf:(n:string)=>string, ageMs:number}} input
 */
export function settleA2({ open, lists, kindOf, ageMs }) {
  if (!(ageMs >= A2_MIN_AGE_MS))
    throw new Error("A2 needs at least ten minutes after the last request");
  const out = {
    settled: [],
    stillPresent: [],
    unconfirmed: [],
    presentUnconfirmed: [],
    unreadable: [],
  };
  for (const { name, status } of open) {
    if (status === "unconfirmed-create") {
      // Absence never settles an unknown create; a complete LIST that shows the name is positive
      // evidence that it exists, and the recovery packet must delete it.
      const list = lists[kindOf(name)];
      if (list?.complete === true && list.names.includes(name)) out.presentUnconfirmed.push(name);
      else out.unconfirmed.push(name);
      continue;
    }
    if (!SETTLES_ON_ABSENCE.has(status)) continue;
    const list = lists[kindOf(name)];
    if (!list || list.complete !== true) out.unreadable.push(name);
    else if (list.names.includes(name)) out.stillPresent.push(name);
    else out.settled.push(name);
  }
  return out;
}
