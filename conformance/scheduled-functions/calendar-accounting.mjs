// Stage3 launch accounting (owner ledger 786, design v4). Pure judges; no process is started here.

/** Lane-owned roles: each writes its own record file, and its parent records its identity. */
const LANE_ROLES = ["outer", "inner"];
const ROLES = ["measure", ...LANE_ROLES];
const digits = (value) => typeof value === "string" && /^\d+$/.test(value);
const pidOk = (value) => Number.isSafeInteger(value) && value > 1;
const text = (value) => typeof value === "string" && value.length > 0;

/**
 * Condition (C): every direct child of a lane-owned process has exactly one birth and one exit
 * record, paired by handle (never by PID), and the set of record files is the one the parents'
 * birth records imply, starting from the measuring entry. Returns the harness signals too, for
 * condition (D).
 */
export function validateRecords(files) {
  const problems = [],
    signals = [],
    byRole = new Map();
  if (!files || typeof files !== "object")
    return { ok: false, problems: ["no record files"], signals, roles: [] };
  for (const [name, rows] of Object.entries(files)) {
    const header = Array.isArray(rows) ? rows[0] : undefined;
    if (header?.type !== "header") {
      problems.push(`${name}: the first row is not a header`);
      continue;
    }
    if (
      !ROLES.includes(header.role) ||
      !pidOk(header.pid) ||
      !text(header.started) ||
      !text(header.harnessVersion)
    ) {
      problems.push(`${name}: malformed header`);
      continue;
    }
    if (byRole.has(header.role)) problems.push(`${name}: a second ${header.role} record file`);
    else byRole.set(header.role, { name, header, rows });
  }
  const lanes = new Map();
  for (const { name, rows } of byRole.values()) {
    const births = new Map(),
      exits = new Map(),
      identities = new Map();
    for (const row of rows.slice(1)) {
      switch (row?.type) {
        case "birth":
          if (
            !text(row.handle) ||
            !pidOk(row.pid) ||
            !Number.isSafeInteger(row.uid) ||
            !text(row.purpose) ||
            !text(row.file) ||
            !/^[0-9a-f]{64}$/.test(row.argvSha256 ?? "") ||
            !digits(row.spawnMonoNs)
          )
            problems.push(`${name}: malformed birth row`);
          else if (births.has(row.handle))
            problems.push(`${name}: handle ${row.handle} is born twice`);
          else births.set(row.handle, row);
          break;
        case "spawn-failed":
          if (!text(row.handle) || (row.pid !== null && row.pid !== undefined))
            problems.push(`${name}: a failed spawn carries a PID or no handle`);
          else if (births.has(row.handle))
            problems.push(`${name}: handle ${row.handle} is born twice`);
          else births.set(row.handle, { ...row, failed: true });
          break;
        case "identity":
          if (!text(row.handle) || !pidOk(row.pid) || !text(row.started))
            problems.push(`${name}: malformed identity row`);
          else identities.set(row.handle, row);
          break;
        case "exit":
          if (!text(row.handle) || !digits(row.exitMonoNs))
            problems.push(`${name}: malformed exit row`);
          else if (exits.has(row.handle))
            problems.push(`${name}: handle ${row.handle} exits twice`);
          else exits.set(row.handle, row);
          break;
        case "signal":
          if (
            !pidOk(row.target?.pid) ||
            !text(row.target?.started) ||
            !["SIGTERM", "SIGKILL"].includes(row.kind)
          )
            problems.push(`${name}: malformed signal row`);
          else signals.push({ file: name, ...row });
          break;
        default:
          problems.push(`${name}: unexpected row ${JSON.stringify(row?.type ?? row)}`);
      }
    }
    for (const [handle, birth] of births) {
      const exit = exits.get(handle);
      if (birth.failed) {
        if (exit) problems.push(`${name}: failed spawn ${handle} has an exit`);
      } else if (!exit) problems.push(`${name}: ${handle} has no exit`);
      else if (BigInt(exit.exitMonoNs) < BigInt(birth.spawnMonoNs))
        problems.push(`${name}: ${handle} exits before it was born`);
    }
    for (const handle of exits.keys())
      if (!births.has(handle)) problems.push(`${name}: exit without a birth for ${handle}`);
    for (const [handle, identity] of identities)
      if (births.get(handle)?.pid !== identity.pid)
        problems.push(`${name}: identity row ${handle} names no matching birth`);
    for (const birth of births.values())
      if (LANE_ROLES.includes(birth.purpose) && !birth.failed) {
        const identity = identities.get(birth.handle);
        if (!identity)
          problems.push(`${name}: lane-owned child ${birth.handle} has no identity row`);
        lanes.set(birth.handle + "@" + name, {
          parent: name,
          role: birth.purpose,
          pid: birth.pid,
          started: identity?.started,
        });
      }
  }
  // The expected files: the measuring entry's, then one per lane-owned birth reachable from it.
  const roles = [],
    queue = ["measure"],
    reached = new Set();
  if (!byRole.has("measure")) problems.push("no measuring-entry record file");
  while (queue.length) {
    const role = queue.shift();
    const file = byRole.get(role);
    if (!file) continue;
    reached.add(role);
    roles.push(role);
    const children = [...lanes.values()].filter((lane) => lane.parent === file.name);
    for (const lane of children) {
      if (children.filter((other) => other.role === lane.role).length > 1) {
        problems.push(`${file.name}: more than one ${lane.role} child`);
        continue;
      }
      const child = byRole.get(lane.role);
      if (!child) problems.push(`missing ${lane.role} record file`);
      else if (child.header.pid !== lane.pid || child.header.started !== lane.started)
        problems.push(`${child.name}: header identity differs from its parent's birth record`);
      else if (!reached.has(lane.role)) queue.push(lane.role);
    }
  }
  for (const [role, file] of byRole)
    if (!reached.has(role)) problems.push(`${file.name}: record file no parent accounts for`);
  return { ok: problems.length === 0, problems, signals, roles };
}

/** One inventory pass (condition (E)); rows carry `sid` as a number, "ESRCH" or another error. */
function judgePass(rows, ctx) {
  const byPid = new Map(rows.map((row) => [row.pid, row]));
  const members = new Set(rows.filter((row) => row.sid === ctx.sessionId).map((row) => row.pid));
  const recordedPid = (pid) => ctx.recorded.some((identity) => identity.pid === pid);
  const survivors = [],
    inconclusive = [],
    unrelatedZombies = [],
    ignored = [];
  let trigger = false;
  for (const row of rows) {
    if (typeof row.sid !== "number" && row.sid !== "ESRCH") {
      inconclusive.push({ row, reason: "session query failed" });
      continue;
    }
    const zombie = /^Z/.test(row.stat ?? "");
    const rules = [];
    if (row.sid === ctx.sessionId) rules.push("session");
    if (
      ctx.recorded.some(
        (identity) =>
          identity.pid === row.pid && identity.uid === row.uid && identity.started === row.started,
      )
    )
      rules.push("identity");
    const path =
      Date.parse(row.started) >= ctx.launchTime &&
      typeof row.args === "string" &&
      row.args.includes(ctx.privateDir);
    if (path) rules.push("path");
    if (zombie && (recordedPid(row.pid) || recordedPid(row.ppid) || members.has(row.ppid)))
      rules.push("zombie");
    if (rules.length) {
      survivors.push({ row, rules });
      continue;
    }
    if (row.sid !== "ESRCH") continue;
    const parent = byPid.get(row.ppid);
    if (zombie) {
      // A zombie whose live parent is outside the session is someone else's; otherwise unknown.
      if (parent && typeof parent.sid === "number" && parent.sid !== ctx.sessionId)
        unrelatedZombies.push(row);
      else inconclusive.push({ row, reason: "zombie with an unknown parent" });
      continue;
    }
    // Only a row that could have been in the session asks for another pass.
    if (row.ppid === 1 || members.has(row.ppid) || recordedPid(row.ppid) || parent?.sid === "ESRCH")
      trigger = true;
    else ignored.push(row);
  }
  return { survivors, inconclusive, unrelatedZombies, ignored, trigger };
}

/** At most five passes; the verdict needs two consecutive clean passes. */
export function judgeInventory(passes, ctx) {
  const report = { passes: [] };
  if (!Array.isArray(passes) || passes.length < 1 || passes.length > 5)
    return {
      ...report,
      outcome: "inconclusive",
      reason: "an inventory has one to five passes",
      survivors: [],
    };
  let previousClean = false;
  for (const rows of passes) {
    const pass = judgePass(rows, ctx);
    report.passes.push(pass);
    if (pass.survivors.length)
      return { ...report, outcome: "survivors", survivors: pass.survivors };
    if (pass.inconclusive.length)
      return {
        ...report,
        outcome: "inconclusive",
        reason: pass.inconclusive[0].reason,
        survivors: [],
      };
    const clean = !pass.trigger;
    if (clean && previousClean) return { ...report, outcome: "clean", survivors: [] };
    previousClean = clean;
  }
  return {
    ...report,
    outcome: "inconclusive",
    reason: "no two consecutive clean passes",
    survivors: [],
  };
}

/** Condition (F): `lsof -F pcn` answers; exit 1 is "none" only when it printed nothing. */
export function interpretLsof({ code, stdout, stderr, timedOut }) {
  if (timedOut) return { result: "inconclusive" };
  if (code === 1)
    return stdout === "" && stderr === "" ? { result: "none" } : { result: "inconclusive" };
  if (code !== 0 || stderr !== "") return { result: "inconclusive" };
  const lines = stdout.split("\n").filter((line) => line !== "");
  if (!lines.length || lines.some((line) => !/^[pcnfPt]/.test(line)))
    return { result: "inconclusive" };
  const pids = lines.filter((line) => /^p\d+$/.test(line)).map((line) => Number(line.slice(1)));
  return pids.length ? { result: "listener", pids } : { result: "inconclusive" };
}

export const refusalVerdict = () => {
  throw new Error("not implemented");
};
