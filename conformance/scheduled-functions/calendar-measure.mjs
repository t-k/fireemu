// Harness H of the stage3 launch accounting (owner ledger 786; design v4). The measuring entry
// stays outside the run's session, starts the outer launcher as the leader of a new session,
// waits for it, then takes the final inventory with no exclusion. Every child process goes
// through the recorder. Nothing here asks for privilege or contacts anything but loopback.
import { chmod, mkdir, mkdtemp, readFile, readdir, writeFile } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRecorder, createSelfRecorder, readRecords } from "./calendar-recorder.mjs";
import {
  REFUSAL_FORMATS,
  controlOutcome,
  interpretLsof,
  judgeInventory,
  parseInventory,
  refusalLineCheck,
  refusalVerdict,
  validateRecords,
} from "./calendar-accounting.mjs";
import { parseProcessSnapshot } from "./calendar-processes.mjs";
import { prepareCalendarSession, superviseCalendarProcess } from "./calendar-session.mjs";
import { CONTROL_VARIANTS } from "./calendar-controls.mjs";

const here = (name) => fileURLToPath(new URL("./" + name, import.meta.url));
const runLocal = here("calendar-run-local.mjs");
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const privateJson = (path, value) => writeFile(path, JSON.stringify(value) + "\n", { mode: 0o600 });
const cleanEnv = () =>
  Object.fromEntries(
    ["PATH", "HOME", "TMPDIR", "LANG"]
      .filter((key) => process.env[key] !== undefined)
      .map((key) => [key, process.env[key]]),
  );

/** The files whose bytes make harness version H (the import closure and the control assets). */
export const HARNESS_FILES = [
  "calendar-measure.mjs",
  "calendar-run-local.mjs",
  "calendar-session.mjs",
  "calendar-processes.mjs",
  "calendar-recorder.mjs",
  "calendar-accounting.mjs",
  "calendar-controls.mjs",
  "calendar-control-preamble.cjs.txt",
  "calendar-control-helper.py",
  "calendar-local.mjs",
  "calendar.mjs",
  "calendar-settled-topic.mjs",
  "recovery.mjs",
  "shape.mjs",
];
export async function harnessVersion() {
  const hash = createHash("sha256");
  for (const name of HARNESS_FILES) hash.update(name + "\0").update(await readFile(here(name)));
  return hash.digest("hex");
}

/** `ps` rows for the ownership tracker, through the recorder. */
export async function snapshotWith(recorder) {
  const answer = await recorder.execFile(
    "ps",
    ["-ww", "-axo", "pid=,ppid=,pgid=,uid=,lstart=,comm=,args="],
    { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C" } },
    "ps",
  );
  if (answer.code !== 0) throw new Error("process snapshot failed");
  return parseProcessSnapshot(answer.stdout, answer.pid);
}

const GETSID =
  "import os,sys,json\nout={}\nfor p in sys.argv[1:]:\n  try: out[p]=os.getsid(int(p))\n  except ProcessLookupError: out[p]='ESRCH'\n  except OSError as e: out[p]='E'+str(e.errno)\nprint(json.dumps(out))";

/** Session IDs of `pids`: a number, "ESRCH", or another error code. */
export async function sessionsOf(recorder, pids) {
  const answer = await recorder.execFile(
    "python3",
    ["-c", GETSID, ...pids.map(String)],
    { env: cleanEnv(), timeoutMs: 20000 },
    "getsid",
  );
  if (answer.code !== 0) throw new Error("session query failed");
  const result = JSON.parse(answer.stdout);
  return Object.fromEntries(pids.map((pid) => [pid, result[String(pid)]]));
}

/** One inventory pass over every process (condition (E)): state, arguments and session. */
export async function inventoryPass(recorder) {
  const answer = await recorder.execFile(
    "ps",
    ["-ww", "-axo", "pid=,ppid=,pgid=,uid=,lstart=,stat=,args="],
    { env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C" } },
    "inventory",
  );
  if (answer.code !== 0) throw new Error("inventory failed");
  const rows = parseInventory(answer.stdout).filter((row) => row.pid !== answer.pid);
  const sessions = await sessionsOf(
    recorder,
    rows.map((row) => row.pid),
  );
  return rows.map((row) => ({ ...row, sid: sessions[row.pid] }));
}

/** Up to five passes, until two consecutive clean ones or a definite answer. */
export async function finalInventory(recorder, ctx) {
  const passes = [];
  let result;
  for (let i = 0; i < 5; i++) {
    passes.push(await inventoryPass(recorder));
    result = judgeInventory(passes, ctx);
    if (result.outcome !== "inconclusive" || result.reason !== "no two consecutive clean passes")
      return result;
  }
  return result;
}

/** Condition (F): `lsof` field output with a timeout, interpreted strictly. */
export async function listenersOn(recorder, { port, pids = [] }) {
  const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C" };
  const answers = [];
  const run = async (args) =>
    interpretLsof(await recorder.execFile("lsof", args, { env, timeoutMs: 10000 }, "lsof"));
  answers.push(await run(["-nP", "-F", "pcn", `-iTCP:${port}`, "-sTCP:LISTEN"]));
  if (pids.length)
    answers.push(
      await run(["-nP", "-F", "pcn", "-a", "-iTCP", "-sTCP:LISTEN", "-p", pids.join(",")]),
    );
  return answers;
}

const CLAIMS =
  "import sys,pathlib,json,sqlite3; db=pathlib.Path(sys.argv[1]); c=sqlite3.connect(db.as_uri()+'?mode=ro',uri=True,timeout=2); c.row_factory=sqlite3.Row; rows=[dict(r) for r in c.execute('SELECT * FROM reservations WHERE service = ?', (sys.argv[2],))]; c.close(); print(json.dumps({'db':str(db),'claims':rows}))";

/** The run's own claims in its private registry (read only). */
export async function readOwnClaims(recorder, { service, database }) {
  if (typeof database !== "string" || resolve(database) !== database)
    throw new Error("explicit absolute private database required for own calendar claims");
  const answer = await recorder.execFile(
    "python3",
    ["-c", CLAIMS, database, service],
    { env: cleanEnv() },
    "claims-read",
  );
  if (answer.code !== 0) throw new Error("own calendar claim proof is unreadable");
  const result = JSON.parse(answer.stdout);
  if (
    result.db !== database ||
    !Array.isArray(result.claims) ||
    result.claims.some((row) => row.service !== service)
  )
    throw new Error("own calendar claim proof is unreadable");
  return result;
}

/** The portctl `claim` arguments for the run's private registry (design v4 section 1, M2). */
export function claimArguments({ script, database, cwd, service }) {
  if (![script, database, cwd].every((path) => typeof path === "string" && resolve(path) === path))
    throw new Error("portctl claim paths must be absolute");
  return [
    script,
    "--db",
    database,
    "--cwd",
    cwd,
    "claim",
    "--service",
    service,
    "--range",
    "10000-19999",
    "--ttl",
    "5m",
    "--format",
    "json",
  ];
}

/** Condition (A): the pinned refusal line against the format strings at the pinned source. */
export async function checkPinnedRefusalLine(recorder, { sourceRepo, sourceCommit, line, input }) {
  if (typeof sourceRepo !== "string" || resolve(sourceRepo) !== sourceRepo)
    throw new Error("explicit absolute source repository required");
  if (!/^[a-f0-9]{40}$/.test(sourceCommit ?? ""))
    throw new Error("full pinned source commit required");
  const sources = {};
  for (const { path } of Object.values(REFUSAL_FORMATS)) {
    const answer = await recorder.execFile(
      "git",
      ["-C", sourceRepo, "show", `${sourceCommit}:${path}`],
      { env: cleanEnv(), timeoutMs: 20000 },
      "pinned-source",
    );
    if (answer.code === 0) sources[path] = answer.stdout;
  }
  return refusalLineCheck(line, {
    functionName: "calendarProbe",
    timeZone: input?.timeZone,
    sources,
  });
}

const identityOf = (row) => ({ pid: row.pid, uid: row.uid, started: row.started });

const zoneIsValid = (timeZone) => {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone });
    return true;
  } catch {
    return false;
  }
};

/**
 * Which run a plan asks for: the certificate (refusal fixture, escalation on), the positive
 * control (valid fixture) or a negative control on its own fixture variant (design v4 section 7).
 */
export function planKind(plan) {
  const fixture = zoneIsValid(plan?.session?.input?.timeZone) ? "valid" : "refusal";
  if (plan?.control && plan?.positive) throw new Error("a run is one control at most");
  if (plan?.control) {
    if (!Object.hasOwn(CONTROL_VARIANTS, plan.control.mode ?? ""))
      throw new Error("unknown control mode");
    const variant = CONTROL_VARIANTS[plan.control.mode];
    if (variant.fixture !== fixture) throw new Error("control fixture variant differs");
    return { kind: "control", escalation: variant.escalation, certificate: false };
  }
  if (plan?.positive) {
    if (fixture !== "valid") throw new Error("the positive control needs a valid time zone");
    return { kind: "positive", escalation: "on", certificate: false };
  }
  if (fixture !== "refusal") throw new Error("the certificate run needs the refusal fixture");
  return { kind: "certificate", escalation: "on", certificate: true };
}

/** The outer launcher: prepares the run, claims the port, starts and waits for the inner supervisor. */
export async function accountingOuter(accDir) {
  const plan = JSON.parse(await readFile(join(accDir, "plan.json"), "utf8"));
  const recorder = await createSelfRecorder({
    path: join(accDir, "records", "outer.jsonl"),
    role: "outer",
    harnessVersion: plan.harnessVersion,
  });
  const result = { phase: "prepare" };
  const write = () => privateJson(join(accDir, "outer-result.json"), result);
  try {
    const control = plan.control
      ? { ...plan.control, helperPath: here("calendar-control-helper.py") }
      : undefined;
    const prepared = await prepareCalendarSession({
      ...plan.session,
      childPath: runLocal,
      control,
    });
    result.identity = prepared.identity;
    result.directory = prepared.directory;
    const database = join(prepared.directory, "ports.sqlite3"),
      service = "lane8-calendar-" + randomBytes(8).toString("hex"),
      conformanceRoot = join(plan.session.root, "conformance");
    Object.assign(result, { phase: "claim", database, service });
    const claimed = await recorder.execFile(
      "python3",
      claimArguments({ script: plan.portctl, database, cwd: conformanceRoot, service }),
      { env: cleanEnv(), timeoutMs: 10000 },
      "claim",
    );
    if (claimed.code !== 0) throw new Error("port claim failed");
    const claim = JSON.parse(claimed.stdout);
    if (!Number.isSafeInteger(claim.port) || typeof claim.token !== "string")
      throw new Error("port claim answer is unreadable");
    result.port = claim.port;
    await privateJson(join(prepared.directory, "port.json"), { port: claim.port });
    const launcherPath = join(prepared.directory, "launcher.json");
    await privateJson(launcherPath, {
      prepared,
      conformanceRoot,
      accDir,
      escalation: plan.escalation,
      harnessVersion: plan.harnessVersion,
    });
    result.phase = "inner";
    const state = { done: false, code: null };
    const inner = recorder.spawn(
      process.execPath,
      [runLocal, "--calendar-supervisor", launcherPath],
      {
        stdio: "ignore",
        env: {
          ...cleanEnv(),
          PORT: String(claim.port),
          PORT_REGISTRY_TOKEN: claim.token,
          PORT_REGISTRY_DB: database,
        },
      },
      "inner",
    );
    inner.once("error", () => {
      state.done = true;
      state.code = -1;
      state.spawnFailed = true;
    });
    inner.once("exit", (code) => {
      state.done = true;
      state.code = code ?? -1;
    });
    if (Number.isSafeInteger(inner.pid))
      recorder.identity(inner.recordHandle, inner.pid, await recorder.startedOf(inner.pid));
    const rows = await snapshotWith(recorder);
    const root = rows.find((row) => row.pid === process.pid);
    if (!root) throw new Error("outer launcher identity unavailable");
    result.supervision = await superviseCalendarProcess({
      root,
      child: { pid: inner.pid, state: () => state },
      snapshot: () => snapshotWith(recorder),
      signal: (pid, kind, owned) =>
        recorder.signal(
          identityOf(owned ?? { pid, uid: process.getuid(), started: "unknown" }),
          kind,
          async () => process.kill(pid, kind),
        ),
      escalate: plan.escalation !== "off",
      ownershipComplete: async () => true,
      deadlineMs: 170000,
      graceMs: 30000,
      killGraceMs: 2000,
    });
    await inner.recordExit;
    result.phase = "release";
    const released = await recorder.execFile(
      "python3",
      [plan.portctl, "--db", database, "release", "--token", claim.token],
      { env: cleanEnv(), timeoutMs: 10000 },
      "release",
    );
    result.releaseCode = released.code;
    result.claimsAfter = (await readOwnClaims(recorder, { service, database })).claims;
    try {
      result.inner = JSON.parse(await readFile(prepared.supervisorOutputPath, "utf8"));
    } catch {
      result.inner = null;
    }
    try {
      result.callback = JSON.parse(await readFile(prepared.outputPath, "utf8"));
    } catch {
      result.callback = null;
    }
    result.phase = "done";
  } catch (error) {
    result.error = String(error?.message ?? error);
  }
  await write();
  recorder.close();
  if (result.phase !== "done") process.exitCode = 1;
}

async function recordFiles(directory) {
  const files = {};
  for (const name of (await readdir(directory)).filter((value) => value.endsWith(".jsonl")).sort())
    files[name] = await readRecords(join(directory, name));
  return files;
}

/**
 * The measuring entry: verifies the pins it can before launching, starts the outer launcher in
 * a new session (the only `detached` spawn in the harness), waits for it, and judges the run.
 */
export async function measure(planPath) {
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const { escalation, certificate } = planKind(plan);
  const version = await harnessVersion();
  const base = join(plan.session.root, "conformance/.runs");
  await mkdir(base, { recursive: true, mode: 0o700 });
  const accDir = await mkdtemp(join(base, "accounting-"));
  await chmod(accDir, 0o700);
  await mkdir(join(accDir, "records"), { mode: 0o700 });
  const recorder = await createSelfRecorder({
    path: join(accDir, "records", "measure.jsonl"),
    role: "measure",
    harnessVersion: version,
  });
  const portctlSha256 = digest(await readFile(plan.portctl));
  const refusalCheck = await checkPinnedRefusalLine(recorder, {
    sourceRepo: plan.sourceRepo,
    sourceCommit: plan.pins?.sourceCommit,
    line: plan.pins?.refusalLine,
    input: plan.session.input,
  });
  // Checked before the launch: a certificate whose pinned line the source does not explain is
  // never run.
  if (certificate && !refusalCheck.ok) {
    recorder.close();
    throw new Error("the pinned refusal line is not explained by the pinned source");
  }
  await privateJson(join(accDir, "plan.json"), { ...plan, escalation, harnessVersion: version });
  const launchTime = Math.floor(Date.now() / 1000) * 1000;
  const rootRows = await snapshotWith(recorder);
  const root = rootRows.find((row) => row.pid === process.pid);
  const rootSid = (await sessionsOf(recorder, [process.pid]))[process.pid];
  const outer = recorder.spawn(
    process.execPath,
    [runLocal, "--accounting-outer", accDir],
    { detached: true, stdio: "ignore", env: cleanEnv() },
    "outer",
  );
  const chain = { rootSid, outerPid: outer.pid, outerSid: null };
  if (Number.isSafeInteger(outer.pid)) {
    recorder.identity(outer.recordHandle, outer.pid, await recorder.startedOf(outer.pid));
    chain.outerSid = (await sessionsOf(recorder, [outer.pid]))[outer.pid];
  }
  await outer.recordExit;
  let outerResult = null;
  try {
    outerResult = JSON.parse(await readFile(join(accDir, "outer-result.json"), "utf8"));
  } catch {
    /* Missing proof fails the verdict. */
  }
  const prepared = outerResult?.directory;
  const recorded = [];
  for (const rows of Object.values(await recordFiles(join(accDir, "records"))))
    for (const row of rows) if (row.type === "identity") recorded.push(row);
  const inner = outerResult?.inner ?? null;
  for (const row of inner?.ownedProcesses ?? []) recorded.push(row);
  for (const row of outerResult?.supervision?.ownedProcesses ?? []) recorded.push(row);
  const identities = recorded
    .filter((row) => row.pid !== process.pid)
    .map((row) => ({ pid: row.pid, uid: row.uid ?? process.getuid(), started: row.started }));
  const inventory = await finalInventory(recorder, {
    sessionId: chain.outerSid,
    recorded: identities,
    privateDir: prepared ?? accDir,
    launchTime,
  });
  const claims = outerResult?.service
    ? (
        await readOwnClaims(recorder, {
          service: outerResult.service,
          database: outerResult.database,
        })
      ).claims
    : null;
  const alive = inventory.passes.at(-1)?.survivors?.map((entry) => entry.row.pid) ?? [];
  const lsof = outerResult?.port
    ? await listenersOn(recorder, { port: outerResult.port, pids: alive })
    : [];
  recorder.close();
  const records = validateRecords(await recordFiles(join(accDir, "records")));
  const verdict = refusalVerdict({
    certificate,
    escalation,
    pins: plan.pins,
    identity: outerResult?.identity ? { ...outerResult.identity, portctlSha256 } : undefined,
    refusalCheck,
    daemon: inner
      ? {
          exitCode: inner.exitCode,
          diagnostics: inner.diagnostics,
          timedOut: inner.timedOut,
          cancelled: inner.cancelled,
        }
      : undefined,
    chain,
    records,
    settle:
      inner && outerResult?.supervision
        ? {
            inner: inner.settledWithoutEscalation,
            outer: outerResult.supervision.settledWithoutEscalation,
          }
        : undefined,
    inventory,
    ports: claims ? { claims, lsof } : undefined,
  });
  let control = null;
  if (plan.control || plan.positive) {
    let injected;
    try {
      injected = JSON.parse(await readFile(join(prepared, "control-ready.json"), "utf8"));
    } catch {
      injected = undefined;
    }
    control = {
      injected: inner?.injected ?? null,
      ...controlOutcome(
        plan.positive ? { mode: "positive" } : { mode: plan.control.mode, injected },
        {
          ...verdict,
          inventory,
          ports: { lsof },
          records,
          observation: {
            runner: inner?.observationHandshake === true,
            child: inner?.observationHandshake === true,
            matched: outerResult?.callback?.matched === true,
          },
        },
      ),
    };
  }
  const report = {
    harnessVersion: version,
    root: root ? identityOf(root) : null,
    rootSid,
    launchTime,
    chain,
    verdict,
    control,
    inventory: {
      outcome: inventory.outcome,
      reason: inventory.reason,
      survivors: inventory.survivors,
    },
    lsof,
    // Design v4 section 6: the per-PID query runs only when a recorded identity is alive.
    lsofByPid: alive.length ? "ran" : "skipped: no recorded identity alive",
    // Condition (D): what each settle phase saw end by itself.
    selfEnded: {
      inner: inner?.selfEnded ?? null,
      outer: outerResult?.supervision?.selfEnded ?? null,
    },
    claims,
    records: { ok: records.ok, problems: records.problems, signals: records.signals.length },
    accountingDirectory: accDir,
  };
  await privateJson(join(accDir, "verdict.json"), report);
  // Controls leave their helpers running on purpose; stop them now, by verified identity, in a
  // record file outside the judged set.
  if (plan.control) {
    const post = createRecorder({
      path: join(accDir, "post-verdict.jsonl"),
      role: "measure",
      pid: process.pid,
      started: root?.started ?? "unknown",
      harnessVersion: version,
    });
    const current = await snapshotWith(post);
    const targets = inventory.survivors
      .map((entry) =>
        current.find((row) => row.pid === entry.row.pid && row.started === entry.row.started),
      )
      .filter(Boolean);
    // The injected helper, too, when it is not a survivor (it may hold the port from outside S).
    const helper = current.find(
      (row) =>
        row.pid === control?.injected?.pid &&
        typeof prepared === "string" &&
        row.args.includes(prepared + "/"),
    );
    if (helper && !targets.some((row) => row.pid === helper.pid)) targets.push(helper);
    for (const live of targets)
      await post.signal(identityOf(live), "SIGKILL", async () => process.kill(live.pid, "SIGKILL"));
    post.close();
  }
  return report;
}
