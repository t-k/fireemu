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
    return { ok: false, problems: ["no record files"], signals, roles: [], births: {} };
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
  const versions = new Set([...byRole.values()].map(({ header }) => header.harnessVersion));
  if (versions.size > 1) problems.push("record files disagree on the harness version");
  const lanes = new Map(),
    purposes = {};
  for (const [fileRole, { name, rows }] of byRole) {
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
          // The parent's own wait reports exactly one of an exit code and a signal.
          if (
            !text(row.handle) ||
            !digits(row.exitMonoNs) ||
            (Number.isSafeInteger(row.code)
              ? row.signal !== null
              : !(row.code === null && text(row.signal)))
          )
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
    purposes[fileRole] = [...births.values()]
      .filter((birth) => !birth.failed)
      .map((birth) => birth.purpose);
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
  return { ok: problems.length === 0, problems, signals, roles, births: purposes };
}

/** One inventory pass (condition (E)); rows carry `sid` as a number, "ESRCH" or another error. */
function judgePass(rows, ctx) {
  // A complete pass lists launchd and the measuring entry itself (review round 2, M3).
  if (
    !Number.isSafeInteger(ctx.rootPid) ||
    !rows.some((row) => row.pid === 1) ||
    !rows.some((row) => row.pid === ctx.rootPid)
  )
    return {
      survivors: [],
      inconclusive: [{ row: null, reason: "incomplete inventory pass" }],
      unrelatedZombies: [],
      ignored: [],
      repass: [],
      trigger: false,
    };
  const byPid = new Map(rows.map((row) => [row.pid, row]));
  const members = new Set(rows.filter((row) => row.sid === ctx.sessionId).map((row) => row.pid));
  const recordedPid = (pid) => ctx.recorded.some((identity) => identity.pid === pid);
  const survivors = [],
    inconclusive = [],
    unrelatedZombies = [],
    ignored = [],
    repass = [];
  let trigger = false;
  const privateDirs = (Array.isArray(ctx.privateDirs) ? ctx.privateDirs : [ctx.privateDir]).filter(
    (dir) => typeof dir === "string" && dir.length > 1,
  );
  // Whether an ESRCH row could have been in S: its parent is launchd, a member of S or a recorded
  // identity, or an ESRCH row whose own chain could reach S. A process in S has every ancestor
  // up to S's leader in S (setsid makes a new session, never S), so a chain that reaches a live
  // ancestor answering another session cannot have been in S; one whose parent left no row is
  // ignored, as the condition's other ESRCH rows are; a cycle is unknown.
  const couldHaveBeenInSession = (row) => {
    const seen = new Set();
    for (let pid = row.ppid; !seen.has(pid);) {
      seen.add(pid);
      if (pid === 1 || members.has(pid) || recordedPid(pid)) return true;
      const ancestor = byPid.get(pid);
      if (ancestor?.sid !== "ESRCH") return false;
      pid = ancestor.ppid;
    }
    return true;
  };
  for (const row of rows) {
    if (typeof row.sid !== "number" && row.sid !== "ESRCH") {
      inconclusive.push({ row, reason: "session query failed" });
      continue;
    }
    // The inventory reads `lstart` with TZ=UTC, so no daylight-saving change can shift it.
    const startedAt = Date.parse(row.started + " GMT");
    if (!Number.isFinite(startedAt)) {
      inconclusive.push({ row, reason: "unreadable start time" });
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
    // Clause 3, over both private directories (review S6), as a whole path component.
    const path =
      startedAt >= ctx.launchTime &&
      typeof row.args === "string" &&
      privateDirs.some(
        (dir) => row.args.includes(dir + "/") || row.args.split(/\s+/).includes(dir),
      );
    if (path) rules.push("path");
    if (zombie && (recordedPid(row.pid) || recordedPid(row.ppid) || members.has(row.ppid)))
      rules.push("zombie");
    if (rules.length) {
      survivors.push({ row, rules });
      continue;
    }
    const parent = byPid.get(row.ppid);
    // The run's session did not exist before the launch: nothing older can have been in it.
    const young = startedAt >= ctx.launchTime;
    if (zombie) {
      // D4: a zombie no clause covers is not judged by its session answer (getsid answers ESRCH
      // for every zombie on macOS). One launchd adopted after the launch may be ours and is
      // reaped within milliseconds: another pass, and inconclusive if it persists. Otherwise it
      // is unrelated only under a parent in the same pass that is not a zombie and answers a
      // session other than S.
      if (row.ppid === 1 && young) {
        trigger = true;
        repass.push(row);
      } else if (
        parent &&
        !/^Z/.test(parent.stat ?? "") &&
        typeof parent.sid === "number" &&
        parent.sid !== ctx.sessionId
      )
        unrelatedZombies.push(row);
      else inconclusive.push({ row, reason: "zombie with an unknown parent" });
      continue;
    }
    if (row.sid !== "ESRCH") continue;
    // Only a row that could have been in the session asks for another pass (S2: started at or
    // after the launch).
    if (young && couldHaveBeenInSession(row)) {
      trigger = true;
      repass.push(row);
    } else ignored.push(row);
  }
  return { survivors, inconclusive, unrelatedZombies, ignored, repass, trigger };
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
export function interpretLsof({ code, stdout, stderr, timedOut, truncated }) {
  if (timedOut || truncated !== false) return { result: "inconclusive" };
  if (code === 1)
    return stdout === "" && stderr === "" ? { result: "none" } : { result: "inconclusive" };
  if (code !== 0 || stderr !== "") return { result: "inconclusive" };
  const lines = stdout.split("\n").filter((line) => line !== "");
  if (!lines.length || lines.some((line) => !/^[pcnfPt]/.test(line)))
    return { result: "inconclusive" };
  const pids = lines.filter((line) => /^p\d+$/.test(line)).map((line) => Number(line.slice(1)));
  return pids.length ? { result: "listener", pids } : { result: "inconclusive" };
}

/**
 * The format strings that produce the refusal line at the pinned source (design v4 section 3):
 * the zone error, the manifest wrapper, the codebase-label wrapper and the CLI's failure line.
 */
export const REFUSAL_FORMATS = Object.freeze({
  zone: Object.freeze({
    path: "crates/fireemu-adapter-functions/src/zone.rs",
    text: 'format!("unknown time zone {name:?}")',
  }),
  manifest: Object.freeze({
    path: "crates/fireemu-adapter-functions/src/manifest_json.rs",
    text: 'format!("manifest: function {name:?}: time zone: {e}")',
  }),
  label: Object.freeze({
    path: "crates/fireemu/src/functions.rs",
    text: 'format!("the Functions codebase {label:?}: {e}")',
  }),
  fail: Object.freeze({
    path: "crates/fireemu/src/main.rs",
    text: 'eprintln!("error: {}", e.message)',
  }),
});

const DEBUG_ESCAPES = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\0": "\\0",
};

/**
 * `{value:?}` for a Rust `&str`, for printable ASCII and control characters only; anything else
 * (where Rust's escaping depends on Unicode tables) is not modelled and gives null.
 */
export function rustDebugString(value) {
  if (typeof value !== "string") return null;
  let out = '"';
  for (const char of value) {
    const code = char.codePointAt(0);
    if (Object.hasOwn(DEBUG_ESCAPES, char)) out += DEBUG_ESCAPES[char];
    else if (code < 0x20 || code === 0x7f) out += `\\u{${code.toString(16)}}`;
    else if (code < 0x7f) out += char;
    else return null;
  }
  return out + '"';
}

/**
 * Whether `line` is exactly what the pinned source prints for the fixture's refusal: the CLI's
 * `error: ` prefix, any number of codebase-label wrappers, then the manifest and zone errors.
 * `sources` maps each REFUSAL_FORMATS path to its text at the pinned commit.
 */
export function refusalLineCheck(line, { functionName, timeZone, sources }) {
  const problems = [];
  for (const { path, text } of Object.values(REFUSAL_FORMATS))
    if (typeof sources?.[path] !== "string" || !sources[path].includes(text))
      problems.push(`format string missing at the pinned source: ${path}`);
  const name = rustDebugString(functionName),
    zone = rustDebugString(timeZone);
  if (name === null || zone === null) problems.push("the fixture's names are not modelled");
  else if (typeof line !== "string") problems.push("no pinned refusal line");
  else {
    const core = `manifest: function ${name}: time zone: unknown time zone ${zone}`;
    const wrappers = /^error: (?:the Functions codebase "(?:[^"\\]|\\.)*": )*$/;
    if (!line.endsWith(core) || !wrappers.test(line.slice(0, line.length - core.length)))
      problems.push("the pinned refusal line is not explained by the pinned format strings");
  }
  return { ok: problems.length === 0, problems };
}

const PINNED = [
  "sourceCommit",
  "harnessVersion",
  "binarySha256",
  "runnerSha256",
  "fixtureSha256",
  "configSha256",
  "portctlSha256",
];

/**
 * The verdict of one run under owner ledger 786: conditions (A)-(G). Any failed condition fails
 * the run; otherwise any unanswered one makes it inconclusive; only all seven pass a run.
 */
export function refusalVerdict(run) {
  const conditions = {};
  const check = (letter, inputs, judge) => {
    const missing = inputs.filter((key) => run?.[key] === undefined || run[key] === null);
    if (missing.length) {
      conditions[letter] = { ok: false, outcome: "inconclusive", reasons: [`missing ${missing}`] };
      return;
    }
    const reasons = [],
      unknown = [];
    judge(reasons, unknown);
    conditions[letter] = {
      ok: reasons.length === 0 && unknown.length === 0,
      outcome: reasons.length ? "fail" : unknown.length ? "inconclusive" : "pass",
      reasons: [...reasons, ...unknown],
    };
  };
  check("A", ["pins", "identity", "refusalCheck", "daemon"], (fail) => {
    if (run.identity.controlMode !== undefined || run.identity.controlsSha256 !== undefined)
      fail.push("the run's identity names a control fixture");
    if (run.refusalCheck.ok !== true)
      fail.push(...(run.refusalCheck.problems?.length ? run.refusalCheck.problems : ["unchecked"]));
    for (const key of PINNED)
      if (run.identity[key] !== run.pins[key]) fail.push(`${key} differs from its pin`);
    if (run.daemon.exitCode !== run.pins.exitCode)
      fail.push("the daemon's exit status differs from its pin");
    if (
      !Array.isArray(run.daemon.diagnostics) ||
      !run.daemon.diagnostics.includes(run.pins.refusalLine)
    )
      fail.push("the pinned refusal line was not printed");
  });
  check("B", ["chain", "records"], (fail) => {
    const { rootSid, outerPid, outerSid } = run.chain;
    if (!pidOk(rootSid) || !pidOk(outerSid) || outerSid !== outerPid || outerSid === rootSid)
      fail.push("the outer launcher is not the leader of its own session");
    const births = run.records.births ?? {};
    if (!(births.measure ?? []).includes("outer"))
      fail.push("the measuring entry did not start the outer launcher");
    for (const purpose of ["claim", "inner"])
      if (!(births.outer ?? []).includes(purpose))
        fail.push(`the outer launcher has no ${purpose} child`);
    if (!(births.inner ?? []).includes("daemon"))
      fail.push("the inner supervisor did not start the daemon");
  });
  check("C", ["records"], (fail) => {
    if (run.records.ok !== true)
      fail.push(...(run.records.problems?.length ? run.records.problems : ["records invalid"]));
  });
  check("D", ["records", "daemon", "settle", "supervision"], (fail, unknown) => {
    if ((run.records.signals ?? []).length)
      fail.push(`${run.records.signals.length} harness signal(s)`);
    if (run.daemon.timedOut || run.daemon.cancelled) fail.push("the daemon did not exit by itself");
    // A pipe that never closes means some process still holds the daemon's output.
    if (run.daemon.diagnosticsDrained !== true)
      fail.push("the daemon's output pipes stayed open after it exited");
    for (const role of ["inner", "outer"]) {
      const supervision = run.supervision[role];
      if (supervision?.timedOut !== false || supervision?.cancelled !== false)
        fail.push(`the ${role} supervision timed out, was cancelled or did not say`);
      // A failed tracker poll may have missed a sighting that (E) clause 2 relies on.
      if (supervision?.inventoryFailures !== 0)
        unknown.push(`the ${role} supervision's tracker polls failed or were not counted`);
    }
    if (run.settle.inner !== true || run.settle.outer !== true)
      fail.push("a settle phase did not empty without escalation");
  });
  check("E", ["inventory"], (fail, unknown) => {
    if (run.inventory.outcome === "survivors")
      fail.push(`${run.inventory.survivors.length} survivor(s)`);
    else if (run.inventory.outcome !== "clean") unknown.push(`inventory ${run.inventory.outcome}`);
  });
  check("F", ["ports"], (fail, unknown) => {
    if (!Array.isArray(run.ports.claims) || run.ports.claims.length)
      fail.push("the private registry still holds a claim");
    const lsof = Array.isArray(run.ports.lsof) ? run.ports.lsof : [];
    if (!lsof.length) unknown.push("no lsof answer");
    if (lsof.some((answer) => answer.result === "listener")) fail.push("a TCP listener is held");
    else if (lsof.some((answer) => answer.result !== "none"))
      unknown.push("an lsof answer is inconclusive");
  });
  check("G", ["escalation", "validatorControls"], (fail, unknown) => {
    if (run.certificate !== true) fail.push("not a certificate run");
    else if (run.escalation !== "on") fail.push("escalation off is for control runs only");
    if (run.validatorControls.ok !== true) fail.push("a validator control did not hold");
    // Review S4: what the supervisors ran with, not only what the plan asked for.
    if (run.certificate === true)
      for (const role of ["inner", "outer"])
        if (!run.supervision?.[role])
          unknown.push(`the ${role} supervisor's escalation is unknown`);
        else if (run.supervision[role].escalate !== true)
          fail.push(`the ${role} supervisor did not run with escalation on`);
  });
  const outcomes = Object.values(conditions).map((condition) => condition.outcome);
  const verdict = outcomes.includes("fail")
    ? "fail"
    : outcomes.includes("inconclusive")
      ? "inconclusive"
      : "pass";
  return { verdict, conditions };
}

/** Rows of `ps -ww -axo pid=,ppid=,pgid=,uid=,lstart=,stat=,args=` (condition (E) inventory). */
export function parseInventory(text) {
  if (typeof text !== "string" || !text.trim()) throw new Error("unreadable inventory");
  return text
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      const match =
        /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+\s+\S+\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(\S+)\s+(.+)$/.exec(
          line,
        );
      if (!match) throw new Error("unreadable inventory row");
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        pgid: Number(match[3]),
        uid: Number(match[4]),
        started: match[5].replace(/\s+/g, " "),
        stat: match[6],
        args: match[7],
      };
    });
}

/**
 * Whether a control run showed what it is for (condition (G)). A negative control counts only
 * when its named rule fired on the injected row; the positive control must pass (B)-(F),
 * including (D), and observe the runner and the `--calendar-child` branch.
 */
export function controlOutcome(control, result) {
  if (control.mode === "positive") {
    const ok = ["B", "C", "D", "E", "F"].every(
      (letter) => result.conditions?.[letter]?.ok === true,
    );
    const seen =
      result.observation?.runner === true &&
      result.observation?.child === true &&
      result.observation?.matched === true &&
      result.observation?.cleanupVerified === true;
    return { counts: ok && seen, rulesFired: [] };
  }
  // Review S5: the helper is its PID and start time, never the PID alone.
  const { pid, started } = control.injected ?? {};
  if (!Number.isSafeInteger(pid) || !text(started)) return { counts: false, rulesFired: [] };
  const survivor = (result.inventory?.survivors ?? []).find(
    (entry) => entry.row?.pid === pid && entry.row?.started === started,
  );
  const rulesFired = [...(survivor?.rules ?? [])];
  const listened = (result.ports?.lsof ?? []).some(
    (answer) => answer.result === "listener" && answer.pids?.includes(pid),
  );
  // (iii) counts only when its helper recorded the bind before the final inventory began, and
  // was still itself (its row) when the inventory listed it.
  if (
    listened &&
    survivor &&
    (control.mode !== "listener" || control.bound?.beforeInventory === true)
  )
    rulesFired.push("port");
  if (
    (result.records?.signals ?? []).some(
      (signal) => signal.target?.pid === pid && signal.target?.started === started,
    )
  )
    rulesFired.push("harness-signal");
  const inSession = rulesFired.includes("session");
  // The topology each control is for (design v4 section 7).
  const shaped = {
    orphan: () => inSession && survivor?.row?.ppid === 1,
    escaper: () => !inSession,
    listener: () => !inSession,
    leftover: () => control.injected.acquired === true && control.injected.pgid === pid,
  }[control.mode];
  const named = {
    orphan: "session",
    escaper: "identity",
    listener: "port",
    leftover: "harness-signal",
  }[control.mode];
  return { counts: rulesFired.includes(named) && shaped?.() === true, rulesFired };
}

const LANE_FILES = ["outer.jsonl", "inner.jsonl"];

/**
 * The validator controls of condition (G), run on a run's own records: a removed lane-owned
 * file (control (v)), a dropped exit row and a failed spawn with a PID are refused, and PID reuse
 * across two short children is paired by handle.
 */
export function validatorControls(files, validate = validateRecords) {
  const controls = [];
  if (!files || typeof files !== "object" || validate(files).ok !== true)
    return { ok: false, controls, reason: "the base records do not validate" };
  const size = (set) => Object.values(set).reduce((total, rows) => total + rows.length, 0);
  const probe = (name, expected, change) => {
    const set = structuredClone(files);
    change(set);
    const result = validate(set);
    controls.push({
      name,
      expected,
      observed: result.ok ? "accepted" : "refused",
      rowsChanged: size(set) - size(files),
      problems: result.problems ?? [],
    });
  };
  for (const name of LANE_FILES) probe(`${name} removed`, "refused", (set) => delete set[name]);
  probe("dropped exit row", "refused", (set) => {
    const rows = set["measure.jsonl"];
    rows.splice(
      rows.findIndex((row) => row.type === "exit"),
      1,
    );
  });
  const extra = (set, rows) => set["measure.jsonl"].push(...rows);
  probe("spawn-failed with a PID", "refused", (set) =>
    extra(set, [
      { type: "spawn-failed", handle: "measure:control-failed", pid: 4242, purpose: "ps" },
    ]),
  );
  probe("PID reuse across two short children", "accepted", (set) => {
    // Monotonic times past any real one; pairing needs only exit >= birth per handle.
    let mono = 10n ** 30n;
    const child = (handle) => [
      {
        type: "birth",
        handle,
        pid: 4242,
        uid: 501,
        purpose: "ps",
        file: "ps",
        argvSha256: "0".repeat(64),
        spawnMonoNs: String((mono += 1n)),
      },
      { type: "exit", handle, code: 0, signal: null, exitMonoNs: String((mono += 1n)) },
    ];
    extra(set, [...child("measure:control-a"), ...child("measure:control-b")]);
  });
  return {
    ok: controls.length === 5 && controls.every((control) => control.observed === control.expected),
    controls,
  };
}

const CONTROL_KINDS = ["positive", "orphan", "escaper", "listener", "leftover"];
const utcDay = (time) => (Number.isFinite(time) ? new Date(time).toISOString().slice(0, 10) : null);

/**
 * The limits every certificate quotes word for word (condition text, ledger 786: "Limits that
 * cannot be caught (quoted in every certificate)").
 */
export const CERTIFICATE_LIMITS = Object.freeze([
  "Without privilege the run cannot prove that no short-lived grandchild was born, nor count, pair, read the exit status of, or confirm the reaping of such a process. Examples: the daemon's Node `--version` and `-p` probes, `/bin/kill` in the probe timeout path, a Functions runner or `--calendar-child` that lives shorter than the polling interval, children of portctl, `ps`, `lsof` or `python3`.",
  "A descendant that leaves the session (`setsid`) and is still alive at the end is missed by (E) unless its identity was recorded or its arguments name a run path.",
  "Survivors are judged at the time of the final inventory.",
  "(F) covers TCP listeners only, not UDP or Unix-domain sockets.",
  "The certificate proves that nothing survived and no TCP port was held. It does not prove that nothing else started.",
]);

/** The pins of the refusal run's identity, and the build pins every control must share. */
const IDENTITY_PINS = [
  "sourceCommit",
  "binarySha256",
  "runnerSha256",
  "portctlSha256",
  "harnessVersion",
  "fixtureSha256",
  "configSha256",
];
const BUILD_PINS = [
  "sourceCommit",
  "binarySha256",
  "runnerSha256",
  "portctlSha256",
  "harnessVersion",
];

/**
 * The certificate (condition (G)): a passing refusal run and every control, each counting, all
 * under the same build, portctl and harness version H and on the same UTC day, each with its
 * validator controls. A passing certificate names the pins, the root, the exact refusal, every
 * report with its path and SHA-256 (`files`, in input order) and the limits (review round 2,
 * M1). A report of the stand-in runner is never certified.
 */
export function certificateVerdict({ refusal, controls, files = [], standInRunnerSha256 }) {
  const problems = [];
  if (refusal?.kind !== "certificate") problems.push("the refusal report is not a certificate run");
  if (refusal?.verdict?.verdict !== "pass") problems.push("the refusal run did not pass");
  if (refusal?.validatorControls?.ok !== true)
    problems.push("the refusal run's validator controls did not hold");
  const day = utcDay(refusal?.launchTime);
  if (!day || typeof refusal?.harnessVersion !== "string")
    problems.push("the refusal run names no harness version or day");
  const identity = refusal?.identity,
    pins = refusal?.pins;
  if (!identity || typeof identity !== "object") problems.push("the refusal run names no build");
  if (!pins || typeof pins !== "object") problems.push("the refusal run names no pins");
  if (identity && pins) {
    for (const key of IDENTITY_PINS)
      if (!text(identity[key]) || identity[key] !== pins[key])
        problems.push(`the refusal run's ${key} differs from its pin`);
    if (refusal.refusal?.exitCode !== pins.exitCode)
      problems.push("the refusal run's exit status differs from its pin");
    if (!text(pins.refusalLine) || refusal.refusal?.line !== pins.refusalLine)
      problems.push("the refusal run's refusal line differs from its pin");
  }
  const root = refusal?.root;
  if (!pidOk(root?.pid) || !text(root?.started) || !pidOk(root?.sid))
    problems.push("the refusal run names no root");
  if (text(standInRunnerSha256) && identity?.runnerSha256 === standInRunnerSha256)
    problems.push("the refusal run used the stand-in runner");
  const list = Array.isArray(controls) ? controls : [];
  for (const kind of CONTROL_KINDS) {
    const found = list.filter((report) => report?.kind === kind || report?.control?.mode === kind);
    if (found.length !== 1) {
      problems.push(`control ${kind}: ${found.length} report(s)`);
      continue;
    }
    const [report] = found;
    if (report.control?.counts !== true) problems.push(`control ${kind} did not count`);
    if (report.harnessVersion !== refusal?.harnessVersion)
      problems.push(`control ${kind} ran another harness version`);
    if (utcDay(report.launchTime) !== day) problems.push(`control ${kind} ran on another day`);
    if (report.validatorControls?.ok !== true)
      problems.push(`control ${kind}: validator controls did not hold`);
    if (!report.identity || typeof report.identity !== "object")
      problems.push(`control ${kind} names no build`);
    else {
      for (const key of BUILD_PINS)
        if (report.identity[key] !== identity?.[key])
          problems.push(`control ${kind} ran another ${key}`);
      if (text(standInRunnerSha256) && report.identity.runnerSha256 === standInRunnerSha256)
        problems.push(`control ${kind} used the stand-in runner`);
    }
  }
  if (problems.length) return { verdict: "fail", problems, certificate: null };
  const entry = (report, index) => ({
    kind: report.kind,
    mode: report.control?.mode ?? null,
    path: files[index]?.path ?? null,
    sha256: files[index]?.sha256 ?? null,
  });
  return {
    verdict: "pass",
    problems,
    certificate: {
      pins: { ...pins },
      root: { pid: root.pid, started: root.started, sid: root.sid },
      refusal: { exitCode: refusal.refusal.exitCode, line: refusal.refusal.line },
      reports: [refusal, ...list].map(entry),
      limits: CERTIFICATE_LIMITS,
    },
  };
}
