// Ownership tracking is pure; observing a snapshot never signals any process.
export function parseProcessSnapshot(text, observerPid) {
  if (observerPid !== undefined && (!Number.isSafeInteger(observerPid) || observerPid <= 1))
    throw new Error("invalid process snapshot observer PID");
  if (typeof text !== "string" || !text.trim()) throw new Error("unreadable process snapshot");
  return text
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      const match =
        /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(\S+)\s+(.+)$/.exec(
          line,
        );
      if (!match) throw new Error("unreadable process snapshot row");
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        pgid: Number(match[3]),
        uid: Number(match[4]),
        started: match[5].replace(/\s+/g, " "),
        comm: match[6],
        args: match[7],
      };
    })
    .filter((row) => row.pid !== observerPid);
}
const valid = (row) =>
  row &&
  Number.isSafeInteger(row.pid) &&
  row.pid >= 1 &&
  Number.isSafeInteger(row.ppid) &&
  row.ppid >= 0 &&
  Number.isSafeInteger(row.uid) &&
  row.uid >= 0 &&
  [row.comm, row.args, row.started].every((value) => typeof value === "string" && value.length > 0);
const same = (a, b) => ["pid", "uid", "comm", "args", "started"].every((key) => a[key] === b[key]);
export { same as sameProcessIdentity };
const birth = (a, b) => ["pid", "uid", "started"].every((key) => a[key] === b[key]);

export function ownedProcessTracker(root, { branchPid, canAcquireBranch = () => true } = {}) {
  if (!valid(root) || root.pid <= 1) throw new Error("invalid owned root identity");
  const owned = new Map([[root.pid, Object.freeze({ ...root })]]);
  const groups = new Map();
  let permanentDebt = false;
  const metadataDebtGroups = new Set();
  const retiredGroups = new Set(),
    invalidGroups = new Set(),
    groupEvents = [];
  const note = (pgid, reason) => {
    if (!groupEvents.some((row) => row.pgid === pgid && row.reason === reason))
      groupEvents.push({ pgid, reason });
  };
  const snapshot = (rows) => {
    if (
      !Array.isArray(rows) ||
      rows.some((row) => !valid(row)) ||
      new Set(rows.map((row) => row.pid)).size !== rows.length
    )
      throw new Error("unreadable owned process snapshot");
    return rows;
  };
  return {
    observe(rows) {
      const current = snapshot(rows);
      for (const [id, anchor] of groups) {
        const members = current.filter((row) => row.pgid === id);
        if (!members.length) {
          groups.delete(id);
          metadataDebtGroups.delete(id);
          retiredGroups.add(id);
          continue;
        }
        const captain = current.find((row) => row.pid === id);
        if (captain && !same(anchor, captain)) {
          if (birth(anchor, captain)) {
            metadataDebtGroups.add(id);
            note(id, "same-birth captain command changed");
          } else {
            permanentDebt = true;
            note(id, "captain birth identity changed");
            invalidGroups.add(id);
          }
        }
      }
      let changed;
      do {
        changed = false;
        for (const row of current) {
          if (row.pid <= 1 || owned.has(row.pid)) continue;
          const parent = owned.get(row.ppid),
            liveParent = current.find((value) => value.pid === row.ppid);
          const anchor = groups.get(row.pgid),
            captain = anchor && current.find((value) => value.pid === anchor.pid);
          const sameGroup =
            anchor &&
            !invalidGroups.has(row.pgid) &&
            (!captain || same(anchor, captain)) &&
            row.uid === anchor.uid &&
            Number.isFinite(Date.parse(row.started)) &&
            Date.parse(row.started) >= Date.parse(anchor.started);
          if (
            sameGroup ||
            (parent &&
              liveParent &&
              same(parent, liveParent) &&
              (branchPid === undefined ||
                parent.pid !== root.pid ||
                (row.pid === branchPid && canAcquireBranch(row))))
          ) {
            owned.set(row.pid, Object.freeze({ ...row }));
            if (row.pid === row.pgid && row.pid !== root.pid && !retiredGroups.has(row.pgid))
              groups.set(row.pgid, Object.freeze({ ...row }));
            changed = true;
          }
        }
      } while (changed);
      for (const [id, anchor] of groups) {
        for (const row of current.filter((value) => value.pgid === id)) {
          const acquired = owned.get(row.pid);
          if (row.uid !== anchor.uid && (!acquired || !birth(acquired, row))) {
            permanentDebt = true;
            note(id, "unproved foreign UID member");
          }
        }
      }
      for (const row of current) {
        const acquired = owned.get(row.pid);
        if (acquired && birth(acquired, row) && acquired.pgid !== row.pgid) {
          permanentDebt = true;
          note(acquired.pgid, "known birth escaped original group");
        }
      }
    },
    owned: () => structuredClone([...owned.values()]),
    groupDebt: () => permanentDebt || metadataDebtGroups.size > 0,
    groupEvents: () => structuredClone(groupEvents),
    present: (rows) =>
      snapshot(rows).filter((row) => owned.has(row.pid) && birth(owned.get(row.pid), row)),
    live: (rows) =>
      snapshot(rows).filter((row) => owned.has(row.pid) && same(owned.get(row.pid), row)),
  };
}
