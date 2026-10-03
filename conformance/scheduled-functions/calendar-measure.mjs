// Harness H of the stage3 launch accounting (owner ledger 786; design v4). The measuring entry
// stays outside the run's session, starts the outer launcher as the leader of a new session,
// waits for it, then takes the final inventory with no exclusion. Every child process goes
// through the recorder. Nothing here asks for privilege or contacts anything but loopback.
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  writeFile,
  open,
  realpath,
  lstat,
} from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { createRecorder, createSelfRecorder, psEnv, readRecords } from "./calendar-recorder.mjs";
import {
  REFUSAL_FORMATS,
  certificateVerdict,
  controlOutcome,
  interpretLsof,
  judgeInventory,
  parseInventory,
  refusalLineCheck,
  refusalVerdict,
  validateRecords,
  validatorControls,
} from "./calendar-accounting.mjs";
import { parseProcessSnapshot } from "./calendar-processes.mjs";
import {
  calendarConfig,
  prepareCalendarSession,
  superviseCalendarProcess,
} from "./calendar-session.mjs";
import { calendarFixture } from "./calendar-local.mjs";
import { CONTROL_VARIANTS } from "./calendar-controls.mjs";
import { createAttemptLedger, validateAttemptLedger } from "./calendar-attempt-ledger.mjs";
import { isDeepStrictEqual } from "node:util";

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
  "calendar-attempt-ledger.mjs",
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

/**
 * Whether a recorded query answered completely: exit 0, nothing on stderr, nothing cut at
 * maxBuffer (review round 2, M3). Anything else is unreadable output.
 */
export const complete = (answer) =>
  answer.code === 0 && answer.stderr === "" && answer.truncated === false && !answer.timedOut;

/** `ps` rows for the ownership tracker, through the recorder. */
export async function snapshotWith(recorder) {
  const answer = await recorder.execFile(
    "ps",
    ["-ww", "-axo", "pid=,ppid=,pgid=,uid=,lstart=,stat=,comm=,args="],
    { env: psEnv() },
    "ps",
  );
  if (!complete(answer)) throw new Error("process snapshot failed");
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
  if (!complete(answer)) throw new Error("session query failed");
  const result = JSON.parse(answer.stdout);
  return Object.fromEntries(pids.map((pid) => [pid, result[String(pid)]]));
}

/** One inventory pass over every process (condition (E)): state, arguments and session. */
export async function inventoryPass(recorder) {
  const answer = await recorder.execFile(
    "ps",
    ["-ww", "-axo", "pid=,ppid=,pgid=,uid=,lstart=,stat=,args="],
    { env: psEnv() },
    "inventory",
  );
  if (!complete(answer)) throw new Error("inventory failed");
  const rows = parseInventory(answer.stdout).filter((row) => row.pid !== answer.pid);
  const sessions = await sessionsOf(
    recorder,
    rows.map((row) => row.pid),
  );
  return rows.map((row) => ({ ...row, sid: sessions[row.pid] }));
}

/** Up to five passes (`pass` takes one), until two consecutive clean ones or a definite answer. */
export async function finalInventory(pass, ctx) {
  const passes = [];
  let result;
  for (let i = 0; i < 5; i++) {
    passes.push(await pass());
    result = judgeInventory(passes, ctx);
    if (result.outcome !== "inconclusive" || result.reason !== "no two consecutive clean passes")
      return result;
  }
  return result;
}

/** Condition (F): `lsof` field output with a timeout, interpreted strictly. */
export async function listenersOn(recorder, { port, pids = [] }) {
  const env = psEnv();
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
  if (!complete(answer)) throw new Error("own calendar claim proof is unreadable");
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
    // Random candidates: every private registry would otherwise hand out the lowest free port,
    // and concurrent runs collided on it (review round 2, M4).
    "--random",
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

/**
 * A supervisor's signal callback that sends only through the recorder's verified path (a fresh
 * `ps` shows the recorded PID, UID and start time, not a zombie), and a direct child only by its
 * handle and never once its own wait has seen it exit (review round 2, M2).
 */
export function ownedSender(recorder, directChildren = []) {
  return async (pid, kind, owned) => {
    if (typeof owned?.started !== "string" || !Number.isSafeInteger(owned?.uid)) return false;
    const direct = directChildren.find((child) => child.pid === pid);
    if (direct?.recordExited) return false;
    return recorder.verifiedSignal(identityOf(owned), kind, async () => {
      if (direct) {
        // Node refuses to signal a child it has reaped.
        if (!direct.recordExited) direct.kill(kind);
      } else process.kill(pid, kind);
    });
  };
}

/** Stops a recorded child by its recorded identity and waits for its exit (failure paths only). */
export async function stopRecordedChild(recorder, child, started, wait = delay) {
  // Without a recorded start time there is no identity to verify: only the wait.
  if (typeof started === "string") {
    const send = ownedSender(recorder, [child]);
    const owned = { pid: child.pid, uid: process.getuid(), started };
    for (const [kind, waitMs] of [
      ["SIGTERM", 5000],
      ["SIGKILL", 5000],
    ]) {
      if (child.recordExited) return;
      await send(child.pid, kind, owned);
      if (await Promise.race([child.recordExit.then(() => true), wait(waitMs).then(() => false)]))
        return;
    }
  }
  await child.recordExit;
}

/**
 * Which processes the post-verdict cleanup may stop: members of the run's session, recorded
 * identities and the injected helper by PID and start time, all started at or after the launch.
 * Never a zombie, never a process only a run path names (review round 2, M2).
 */
export function cleanupTargets({ rows, chain, launchTime, recorded, injected, selfPid }) {
  const session =
    Number.isSafeInteger(chain?.outerSid) && chain.outerSid > 1 && chain.outerSid !== chain.rootSid
      ? chain.outerSid
      : null;
  return rows.filter((row) => {
    const startedAt = Date.parse(row.started + " GMT");
    if (row.pid === selfPid || /^Z/.test(row.stat ?? "")) return false;
    if (!Number.isFinite(startedAt) || startedAt < launchTime) return false;
    return (
      (session !== null && row.sid === session) ||
      (recorded ?? []).some(
        (identity) =>
          identity.pid === row.pid && identity.uid === row.uid && identity.started === row.started,
      ) ||
      (injected?.pid === row.pid && injected?.started === row.started)
    );
  });
}

/** The outer launcher: prepares the run, claims the port, starts and waits for the inner supervisor. */
export async function accountingOuter(accDir) {
  const plan = JSON.parse(await readFile(join(accDir, "plan.json"), "utf8"));
  // Each lane-owned process hashes the harness it loaded itself; (C) needs every header to agree.
  const recorder = await createSelfRecorder({
    path: join(accDir, "records", "outer.jsonl"),
    role: "outer",
    harnessVersion: await harnessVersion(),
  });
  const result = { phase: "prepare" };
  let inner = null,
    innerStarted,
    claim = null,
    database,
    service,
    prepared;
  try {
    const control = plan.control
      ? { ...plan.control, helperPath: here("calendar-control-helper.py") }
      : undefined;
    prepared = await prepareCalendarSession({
      ...plan.session,
      childPath: runLocal,
      control,
    });
    result.identity = prepared.identity;
    result.directory = prepared.directory;
    database = join(prepared.directory, "ports.sqlite3");
    service = "lane8-calendar-" + randomBytes(8).toString("hex");
    const conformanceRoot = join(plan.session.root, "conformance");
    Object.assign(result, { phase: "claim", database, service });
    const claimed = await recorder.execFile(
      "python3",
      claimArguments({ script: plan.portctl, database, cwd: conformanceRoot, service }),
      { env: cleanEnv(), timeoutMs: 10000 },
      "claim",
    );
    if (claimed.code !== 0) throw new Error("port claim failed");
    const answer = JSON.parse(claimed.stdout);
    if (!Number.isSafeInteger(answer.port) || typeof answer.token !== "string")
      throw new Error("port claim answer is unreadable");
    claim = answer;
    result.port = claim.port;
    await privateJson(join(prepared.directory, "port.json"), { port: claim.port });
    const launcherPath = join(prepared.directory, "launcher.json");
    await privateJson(launcherPath, {
      prepared,
      conformanceRoot,
      accDir,
      escalation: plan.escalation,
    });
    result.phase = "inner";
    const state = { done: false, code: null };
    inner = recorder.spawn(
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
    if (!Number.isSafeInteger(inner.pid)) {
      await inner.recordExit;
      inner = null;
      throw new Error("the inner supervisor did not start");
    }
    innerStarted = await recorder.startedOf(inner.pid);
    recorder.identity(inner.recordHandle, inner.pid, innerStarted);
    const rows = await snapshotWith(recorder);
    const root = rows.find((row) => row.pid === process.pid);
    if (!root) throw new Error("outer launcher identity unavailable");
    result.supervision = await superviseCalendarProcess({
      root,
      child: { pid: inner.pid, state: () => state },
      snapshot: () => snapshotWith(recorder),
      signal: ownedSender(recorder, [inner]),
      escalate: plan.escalation !== "off",
      ownershipComplete: async () => true,
      deadlineMs: 170000,
      graceMs: 30000,
      killGraceMs: 2000,
    });
    await inner.recordExit;
    inner = null;
    result.phase = "collect";
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
  } catch (error) {
    result.error = String(error?.message ?? error);
  } finally {
    // A failure after the inner supervisor started never leaves it unwaited, and the claim is
    // always released by its token before the record file closes.
    if (inner) await stopRecordedChild(recorder, inner, innerStarted).catch(() => {});
    if (claim) {
      try {
        const released = await recorder.execFile(
          "python3",
          [plan.portctl, "--db", database, "release", "--token", claim.token],
          { env: cleanEnv(), timeoutMs: 10000 },
          "release",
        );
        result.releaseCode = released.code;
        result.claimsAfter = (await readOwnClaims(recorder, { service, database })).claims;
      } catch (error) {
        result.error ??= String(error?.message ?? error);
      }
    }
  }
  if (!result.error) result.phase = "done";
  await privateJson(join(accDir, "outer-result.json"), result);
  recorder.close();
  if (result.phase !== "done") process.exitCode = 1;
}

async function recordFiles(directory) {
  const files = {};
  for (const name of (await readdir(directory)).sort())
    try {
      files[name] = name.endsWith(".jsonl") ? await readRecords(join(directory, name)) : [];
    } catch {
      // An unreadable file stays in the set without a header, so (C) refuses it.
      files[name] = [];
    }
  return files;
}

const readJson = async (path) => {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
};

/** Words of a process API that the refusal fixture must never contain (condition (A)). */
const PROCESS_API = /child_process|spawn|exec|fork|controls\.cjs/;

/**
 * Condition (A), checked before the launch: every run kind uses the pinned source, build,
 * runner, portctl and harness version H; the certificate also uses the pinned refusal fixture and
 * config, a refusal fixture that names no process API (review S6) and a refusal line the pinned
 * source explains. `binaryDigest` and `runnerDigest` are the files' digests on disk (null when
 * unreadable).
 */
export function pinProblems({
  plan,
  certificate,
  version,
  portctlSha256,
  refusalCheck,
  binaryDigest,
  runnerDigest,
}) {
  const pins = plan.pins ?? {},
    session = plan.session ?? {},
    problems = [];
  for (const [key, value] of [
    ["sourceCommit", session.sourceCommit],
    ["binarySha256", session.binarySha256],
    ["binarySha256", binaryDigest],
    ["runnerSha256", session.runnerSha256],
    ["runnerSha256", runnerDigest],
    ["portctlSha256", portctlSha256],
    ["harnessVersion", version],
  ])
    if (typeof value !== "string" || value !== pins[key])
      problems.push(`${key} differs from its pin`);
  if (certificate) {
    let fixture = null;
    try {
      fixture = calendarFixture(session.input);
    } catch {
      /* An unreadable fixture differs from its pin. */
    }
    if (fixture === null || digest(fixture) !== pins.fixtureSha256)
      problems.push("fixtureSha256 differs from its pin");
    else if (PROCESS_API.test(fixture)) problems.push("the refusal fixture names a process API");
    if (digest(calendarConfig(session.anchor)) !== pins.configSha256)
      problems.push("configSha256 differs from its pin");
    if (refusalCheck?.ok !== true)
      problems.push("the pinned refusal line is not explained by the pinned source");
  }
  return problems;
}

/** The pre-launch check, with the binary and runner read from disk. */
export async function preLaunchProblems(input) {
  const fileDigest = async (path) => {
    try {
      return digest(await readFile(path));
    } catch {
      return null;
    }
  };
  return pinProblems({
    ...input,
    binaryDigest: await fileDigest(input.plan.session?.binary),
    runnerDigest: await fileDigest(input.plan.session?.runner),
  });
}

/** The fields of a supervision result the verdict reads (with the escalation it ran, S4). */
export const supervisionOf = (result) =>
  result
    ? {
        timedOut: result.timedOut,
        cancelled: result.cancelled,
        inventoryFailures: result.inventoryFailures,
        escalate: result.escalate,
      }
    : undefined;

/** Recorded identities: identity rows and both trackers' owned processes, never the entry. */
export function recordedIdentities({ files, inner, outerSupervision, selfPid, selfUid }) {
  const rows = [];
  for (const fileRows of Object.values(files ?? {}))
    for (const row of fileRows) if (row.type === "identity") rows.push(row);
  for (const row of inner?.ownedProcesses ?? []) rows.push(row);
  for (const row of outerSupervision?.ownedProcesses ?? []) rows.push(row);
  return rows
    .filter((row) => row.pid !== selfPid)
    .map((row) => ({ pid: row.pid, uid: row.uid ?? selfUid, started: row.started }));
}

/** The injected helper's identity and topology, from the inner supervisor's first sighting. */
export function helperIdentity(inner) {
  const sighting = inner?.injected?.firstSighting;
  if (!sighting) return null;
  return {
    pid: inner.injected.pid,
    started: sighting.started,
    acquired: inner.injected.acquired,
    pgid: sighting.pgid,
  };
}

/** The listener's bind record, judged against the moment the final inventory began. */
export function boundBefore(written, inventoryStartedAt) {
  if (!written) return null;
  return {
    ...written,
    beforeInventory:
      Number.isFinite(written.boundAt) && written.boundAt * 1000 < inventoryStartedAt,
  };
}

/**
 * Assembles one run's verdict and report from what the measuring entry collected. Pure: every
 * input is data, so the assembly is unit-tested and mutated (review round 2, M5).
 */
export function assembleRun({
  plan,
  kind,
  version,
  outerResult,
  chain,
  records,
  validator,
  inventory,
  claims,
  lsof,
  alive,
  bound,
  extra,
}) {
  const inner = outerResult?.inner ?? null;
  const supervision = {
    inner: supervisionOf(inner),
    outer: supervisionOf(outerResult?.supervision),
  };
  const identity = outerResult?.identity
    ? { ...outerResult.identity, portctlSha256: extra.portctlSha256, harnessVersion: version }
    : null;
  const verdict = refusalVerdict({
    certificate: kind.certificate,
    escalation: kind.escalation,
    pins: plan.pins,
    identity: identity ?? undefined,
    refusalCheck: extra.refusalCheck,
    daemon: inner
      ? {
          exitCode: inner.exitCode,
          diagnostics: inner.diagnostics,
          diagnosticsDrained: inner.diagnosticsDrained,
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
    supervision,
    inventory,
    ports: claims ? { claims, lsof } : undefined,
    validatorControls: validator,
  });
  let control = null;
  if (kind.kind !== "certificate") {
    const mode = kind.kind === "positive" ? "positive" : plan.control.mode;
    const injected = helperIdentity(inner);
    control = {
      mode,
      injected,
      bound,
      ...controlOutcome(mode === "positive" ? { mode } : { mode, injected, bound }, {
        ...verdict,
        inventory,
        ports: { lsof },
        records,
        observation: {
          runner: inner?.observationHandshake === true,
          child: inner?.observationHandshake === true,
          matched: outerResult?.callback?.matched === true,
          cleanupVerified:
            inner?.cleanupVerified === true &&
            outerResult?.supervision?.cleanupVerified === true &&
            outerResult?.releaseCode === 0 &&
            Array.isArray(outerResult?.claimsAfter) &&
            outerResult.claimsAfter.length === 0,
        },
      }),
    };
  }
  const diagnostics = Array.isArray(inner?.diagnostics) ? inner.diagnostics : [];
  const line = diagnostics.includes(plan.pins?.refusalLine)
    ? plan.pins.refusalLine
    : (diagnostics.find((value) => /unknown time zone/.test(value)) ?? null);
  return {
    // The run's full identity (review round 2, M1): what it ran, and what it refused with.
    identity,
    refusal: { exitCode: inner?.exitCode ?? null, line },
    verdict,
    control,
    validatorControls: validator,
    supervision,
    inventory: {
      outcome: inventory.outcome,
      reason: inventory.reason,
      survivors: inventory.survivors,
      // Review S7: every pass's evidence (re-pass rows, unrelated zombies, ignored ESRCH rows).
      passes: inventory.passes.map((pass) => ({
        repass: pass.repass,
        unrelatedZombies: pass.unrelatedZombies,
        ignored: pass.ignored,
        inconclusive: pass.inconclusive,
      })),
    },
    lsof,
    // Design v4 section 6: the per-PID query runs only when a recorded identity is alive.
    lsofByPid: alive.length ? "ran" : "skipped: no recorded identity alive",
    // M4: the daemon's private stderr tail explains an (A) failure; never quoted here.
    daemonStderrTail: verdict.conditions.A?.ok === true ? null : (inner?.stderrTailPath ?? null),
    // Condition (D): what each settle phase saw end by itself.
    selfEnded: {
      inner: inner?.selfEnded ?? null,
      outer: outerResult?.supervision?.selfEnded ?? null,
    },
    claims,
    records: { ok: records.ok, problems: records.problems, signals: records.signals.length },
  };
}

/** Judges a launched run once the outer launcher has been reaped. */
async function judgeRun({
  plan,
  kind,
  version,
  recorder,
  accDir,
  launchTime,
  chain,
  outer,
  extra,
}) {
  if (Number.isSafeInteger(outer.pid)) {
    recorder.identity(outer.recordHandle, outer.pid, await recorder.startedOf(outer.pid));
    chain.outerSid = (await sessionsOf(recorder, [outer.pid]))[outer.pid];
  }
  await outer.recordExit;
  const outerResult = await readJson(join(accDir, "outer-result.json"));
  const prepared = outerResult?.directory;
  extra.prepared = prepared;
  const inner = outerResult?.inner ?? null;
  const identities = recordedIdentities({
    files: await recordFiles(join(accDir, "records")),
    inner,
    outerSupervision: outerResult?.supervision,
    selfPid: process.pid,
    selfUid: process.getuid(),
  });
  // What the post-verdict cleanup may stop besides the run's session (review round 2, M2).
  extra.identities = identities;
  extra.injected = helperIdentity(inner);
  const inventoryStartedAt = Date.now();
  const inventory = await finalInventory(() => inventoryPass(recorder), {
    sessionId: chain.outerSid,
    recorded: identities,
    privateDir: prepared ?? accDir,
    privateDirs: [prepared, accDir].filter((dir) => typeof dir === "string"),
    launchTime,
    rootPid: process.pid,
  });
  extra.survivors = inventory.survivors;
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
  const files = await recordFiles(join(accDir, "records"));
  const bound =
    plan.control?.mode === "listener" && prepared
      ? boundBefore(await readJson(join(prepared, "bound.json")), inventoryStartedAt)
      : null;
  const assembled = assembleRun({
    plan,
    kind,
    version,
    outerResult,
    chain,
    records: validateRecords(files),
    validator: validatorControls(files),
    inventory,
    claims,
    lsof,
    alive,
    bound,
    extra,
  });
  const rawRecords = {};
  for (const name of await readdir(join(accDir, "records")))
    rawRecords[name] = (await readFile(join(accDir, "records", name))).toString("base64");
  assembled.native = {
    schema: "calendar-native-proof/v1",
    rawPlan: extra.rawPlan,
    rawOuterResult: (await readFile(join(accDir, "outer-result.json"))).toString("base64"),
    rawRecords,
    queries: extra.queries,
    inventoryStartedAt,
    rawBound:
      bound === null ? null : (await readFile(join(prepared, "bound.json"))).toString("base64"),
    portctlSha256: extra.portctlSha256,
  };
  return assembled;
}

/**
 * After the verdict, in a record file outside the judged set: stops by verified identity every
 * process of the run still alive (survivors, a control's helper, anything left in the run's
 * session or naming its private directories after a failure).
 */
async function postVerdictCleanup({ accDir, root, version, launchTime, chain, extra }) {
  const post = createRecorder({
    path: join(accDir, "post-verdict.jsonl"),
    role: "measure",
    pid: process.pid,
    started: root?.started ?? "unknown",
    harnessVersion: version,
  });
  const queries = [];
  const rawExec = post.execFile;
  post.execFile = async (file, args, options, purpose) => {
    const answer = await rawExec(file, args, options, purpose);
    queries.push({ file, args, purpose, answer });
    return answer;
  };
  try {
    const cleanup = await cleanupOwned({
      inventory: () => inventoryPass(post),
      signal: (target) =>
        post.verifiedSignal(identityOf(target), "SIGKILL", async () =>
          process.kill(target.pid, "SIGKILL"),
        ),
      context: {
        chain,
        launchTime,
        recorded: extra.identities,
        injected: extra.injected,
        selfPid: process.pid,
      },
    });
    post.close();
    return {
      ...cleanup,
      queries,
      rawRecords: (await readFile(join(accDir, "post-verdict.jsonl"))).toString("base64"),
    };
  } finally {
    post.close();
  }
}

/**
 * The measuring entry: verifies the pins before launching, starts the outer launcher in a new
 * session (the only `detached` spawn in the harness), waits for it, judges the run, and cleans up.
 */
export async function measure(planPath, { planBytes, runRoot } = {}) {
  const retained = planBytes === undefined ? await readFile(planPath) : Buffer.from(planBytes);
  const plan = JSON.parse(retained.toString("utf8"));
  const kind = planKind(plan);
  const version = await harnessVersion();
  const base = runRoot ?? join(plan.session.root, "conformance/.runs");
  await mkdir(base, { recursive: true, mode: 0o700 });
  const accDir = await mkdtemp(join(base, "accounting-"));
  await chmod(accDir, 0o700);
  await mkdir(join(accDir, "records"), { mode: 0o700 });
  const recorder = await createSelfRecorder({
    path: join(accDir, "records", "measure.jsonl"),
    role: "measure",
    harnessVersion: version,
  });
  try {
    const extra = { queries: [], rawPlan: retained.toString("base64") };
    const rawExec = recorder.execFile;
    recorder.execFile = async (file, args, options, purpose) => {
      const answer = await rawExec(file, args, options, purpose);
      extra.queries.push({ file, args, purpose, answer });
      return answer;
    };
    extra.portctlSha256 = digest(await readFile(plan.portctl));
    extra.refusalCheck = await checkPinnedRefusalLine(recorder, {
      sourceRepo: plan.sourceRepo,
      sourceCommit: plan.pins?.sourceCommit,
      line: plan.pins?.refusalLine,
      input: plan.session.input,
    });
    const problems = await preLaunchProblems({
      plan,
      certificate: kind.certificate,
      version,
      portctlSha256: extra.portctlSha256,
      refusalCheck: extra.refusalCheck,
    });
    if (problems.length) {
      recorder.close();
      throw new Error("not launched: " + problems.join("; "));
    }
    await privateJson(join(accDir, "plan.json"), {
      ...plan,
      kind: kind.kind,
      escalation: kind.escalation,
    });
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
    const header = {
      kind: kind.kind,
      escalation: kind.escalation,
      harnessVersion: version,
      // The root of the chain, as the certificate names it (review round 2, M1).
      root: root ? { ...identityOf(root), sid: rootSid } : null,
      rootSid,
      // What this run pinned, whatever its outcome.
      pins: plan.pins ?? null,
      launchTime,
      chain,
    };
    let report;
    try {
      report = {
        ...header,
        ...(await judgeRun({
          plan,
          kind,
          version,
          recorder,
          accDir,
          launchTime,
          chain,
          outer,
          extra,
        })),
      };
    } catch (error) {
      // The outer launcher is still waited for; the run is inconclusive and its processes are
      // cleaned up below like any other run's.
      await outer.recordExit;
      recorder.close();
      report = {
        ...header,
        error: String(error?.message ?? error),
        verdict: { verdict: "inconclusive", conditions: {} },
        control: null,
      };
    }
    report.accountingDirectory = accDir;
    await privateJson(join(accDir, "verdict.json"), report);
    try {
      report.cleanup = await postVerdictCleanup({
        accDir,
        root,
        version,
        launchTime,
        chain,
        extra,
      });
    } catch (error) {
      report.cleanup = { outcome: "unknown", error: String(error.message ?? error), after: null };
    }
    await privateJson(join(accDir, "verdict.json"), report);
    return report;
  } finally {
    recorder.close();
  }
}

/** Condition (G): the certificate over one refusal report and the control reports. */
export async function certify(listPath, { requireCampaign = false, trustedPacketVerifier } = {}) {
  if (requireCampaign) return certifyCampaignManifest(listPath, trustedPacketVerifier);
  const list = JSON.parse(await readFile(listPath, "utf8"));
  const load = async (path) => {
    const bytes = await readFile(path).catch(() => null);
    let report = null;
    if (bytes) {
      try {
        report = JSON.parse(bytes.toString("utf8"));
      } catch {
        // Unreadable raw evidence remains unknown even when its digest has an explanation.
      }
    }
    return { file: { path, sha256: bytes ? digest(bytes) : null }, report };
  };
  const loaded = [];
  for (const path of [list.refusal, ...(list.controls ?? [])]) loaded.push(await load(path));
  // Load caller-listed attempts; a separate trusted inventory must establish completeness.
  const attemptPaths = list.attempts === undefined ? [] : list.attempts;
  const attempts = [];
  if (Array.isArray(attemptPaths)) for (const path of attemptPaths) attempts.push(await load(path));
  // The stand-in runner of the offline tests is never certified (review round 2, M1).
  const standIn = await readFile(here("testdata/fake-runner.cjs")).catch(() => null);
  const predicate = certificateVerdict({
    refusal: loaded[0].report,
    controls: loaded.slice(1).map((entry) => entry.report),
    files: loaded.map((entry) => entry.file),
    standInRunnerSha256: standIn ? digest(standIn) : undefined,
    attempts: Array.isArray(attemptPaths) ? attempts : attemptPaths,
    explanations: list.explanations ?? {},
  });
  return {
    ...predicate,
    predicateOnly: true,
    nativeCertificateIssued: false,
    externalApprovalVerified: false,
  };
}

/** One handle owns all accepted births. Mock I/O tests establish ordering, not native proof. */
export async function produceCampaign({
  scope,
  authorityId,
  attempts,
  bootstrap,
  readPlan = readFile,
  createLedger = createAttemptLedger,
  measureAttempt,
  readSnapshot,
}) {
  let ledger;
  let receipt;
  let authorityBytes;
  try {
    const infrastructure = await bootstrap();
    scope = infrastructure.scope;
    receipt = infrastructure.receipt;
    authorityBytes = Buffer.from(
      JSON.stringify({ schema: "scoped-attempt-authority/v1", authorityId, scope }),
    );
    ledger = await createLedger({ authorityBytes, authoritySha256: digest(authorityBytes) });
    for (const attempt of attempts) {
      // Retain the only read before its ack; no attempt effects can use a later file version.
      const planBytes = Buffer.from(await readPlan(attempt.planPath));
      const birth = await ledger.registerBirth({ attemptId: attempt.attemptId, planBytes });
      if (birth.durable !== true) throw new Error("birth durability is unknown");
      let rawReport = null;
      let error = null;
      try {
        if (digest(planBytes) !== attempt.planSha256)
          throw new Error("raw plan differs from packet");
        rawReport = Buffer.from(await measureAttempt(planBytes, attempt, scope));
      } catch (failure) {
        error = String(failure.message ?? failure);
      }
      let report;
      try {
        report = rawReport === null ? null : JSON.parse(rawReport.toString("utf8"));
      } catch {
        report = null;
      }
      const outcome = ["pass", "fail"].includes(report?.verdict?.verdict)
        ? report.verdict.verdict
        : "unknown";
      const envelope = Buffer.from(
        JSON.stringify({
          schema: "attempt-report/v1",
          scope,
          attemptId: attempt.attemptId,
          outcome,
          rawPlan: planBytes.toString("base64"),
          rawPlanSha256: digest(planBytes),
          rawReport: rawReport?.toString("base64") ?? null,
          rawReportSha256: rawReport === null ? null : digest(rawReport),
          error,
        }),
      );
      const terminal = await ledger.recordTerminal({
        attemptId: attempt.attemptId,
        reportBytes: envelope,
      });
      if (terminal.durable !== true) throw new Error("terminal durability is unknown");
    }
    const sealed = await ledger.seal();
    if (sealed.state !== "complete" || sealed.durabilityAcknowledged !== true)
      throw new Error("sealed durability is unknown");
    const snapshot = await readSnapshot(scope);
    return {
      ...sealed,
      snapshot,
      receipt,
      authorityBytes,
      externalApprovalVerified: false,
      allDayCertified: false,
      historicalCompleteness: "UNKNOWN",
    };
  } catch (error) {
    return {
      state: "unknown",
      reasons: [String(error.message ?? error)],
      receipt,
      externalApprovalVerified: false,
      allDayCertified: false,
      historicalCompleteness: "UNKNOWN",
    };
  } finally {
    if (ledger) await ledger.close();
  }
}

/** Cleanup is a separate observation; it cannot rescue the pre-cleanup native verdict. */
export async function cleanupOwned({ inventory, signal, context }) {
  const before = await inventory();
  const targets = cleanupTargets({ ...context, rows: before });
  const signals = [];
  for (const target of targets)
    signals.push({ target: identityOf(target), sent: await signal(target) });
  const after = await inventory();
  const remaining = cleanupTargets({ ...context, rows: after });
  const uncertain = after.some(
    (row) => row.sid === "ESRCH" || !Number.isSafeInteger(row.sid) || /^Z/.test(row.stat ?? ""),
  );
  return {
    outcome:
      signals.every((row) => row.sent === true) && remaining.length === 0 && !uncertain
        ? "clean"
        : "unknown",
    before,
    signals,
    after,
  };
}

const rawObject = (base64) => JSON.parse(Buffer.from(base64, "base64").toString("utf8"));

/** Re-evaluates A-G and native controls from the retained raw producer inputs. */
export function recomputeNativeReport(report) {
  try {
    const proof = report.native;
    if (proof?.schema !== "calendar-native-proof/v1") throw new Error("missing native proof");
    const plan = rawObject(proof.rawPlan);
    const outerResult = rawObject(proof.rawOuterResult);
    const files = {};
    for (const [name, raw] of Object.entries(proof.rawRecords)) {
      const text = Buffer.from(raw, "base64").toString("utf8");
      if (!text.endsWith("\n")) throw new Error("incomplete raw records");
      files[name] = text
        .slice(0, -1)
        .split("\n")
        .map((line) => JSON.parse(line));
    }
    const records = validateRecords(files);
    const validator = validatorControls(files);
    if (
      !records.ok ||
      !validator.ok ||
      files["measure.jsonl"][0].harnessVersion !== report.harnessVersion
    )
      throw new Error("invalid native record set");
    const measuring = files["measure.jsonl"];
    const header = measuring[0];
    if (
      header.pid !== report.root?.pid ||
      header.started !== report.root?.started ||
      report.rootSid !== report.root?.sid
    )
      throw new Error("native root differs");
    const queries = proof.queries;
    for (const q of queries) {
      const birth = measuring.find((r) => r.type === "birth" && r.handle === q.answer.handle);
      const exit = measuring.find((r) => r.type === "exit" && r.handle === q.answer.handle);
      if (
        !birth ||
        !exit ||
        birth.pid !== q.answer.pid ||
        birth.file !== q.file ||
        birth.purpose !== q.purpose ||
        birth.argvSha256 !== digest(Buffer.from(JSON.stringify([q.file, ...q.args]))) ||
        exit.code !== q.answer.code
      )
        throw new Error("raw query differs from its own wait");
    }
    const sources = {};
    for (const { path } of Object.values(REFUSAL_FORMATS)) {
      const query = queries.find(
        (q) =>
          q.purpose === "pinned-source" && q.args.at(-1) === `${plan.pins.sourceCommit}:${path}`,
      );
      if (!query || !complete(query.answer)) throw new Error("missing pinned source query");
      sources[path] = query.answer.stdout;
    }
    const refusalCheck = refusalLineCheck(plan.pins.refusalLine, {
      functionName: "calendarProbe",
      timeZone: plan.session.input.timeZone,
      sources,
    });
    const passes = [];
    for (let i = 0; i < queries.length; i++) {
      if (queries[i].purpose !== "inventory") continue;
      const inventoryQuery = queries[i];
      const sessionQuery = queries[i + 1];
      if (
        !complete(inventoryQuery.answer) ||
        sessionQuery?.purpose !== "getsid" ||
        !complete(sessionQuery.answer)
      )
        throw new Error("unreadable native inventory");
      const rows = parseInventory(inventoryQuery.answer.stdout).filter(
        (r) => r.pid !== inventoryQuery.answer.pid,
      );
      const sessions = JSON.parse(sessionQuery.answer.stdout);
      passes.push(rows.map((r) => ({ ...r, sid: sessions[String(r.pid)] })));
    }
    const identities = recordedIdentities({
      files,
      inner: outerResult.inner,
      outerSupervision: outerResult.supervision,
      selfPid: report.root.pid,
      selfUid: report.root.uid,
    });
    const inventory = judgeInventory(passes, {
      sessionId: report.chain.outerSid,
      recorded: identities,
      privateDir: outerResult.directory ?? report.accountingDirectory,
      privateDirs: [outerResult.directory, report.accountingDirectory].filter(
        (d) => typeof d === "string",
      ),
      launchTime: report.launchTime,
      rootPid: report.root.pid,
    });
    const claimQuery = queries.find((q) => q.purpose === "claims-read");
    if (!claimQuery || !complete(claimQuery.answer)) throw new Error("missing raw claim proof");
    const claims = JSON.parse(claimQuery.answer.stdout).claims;
    const lsof = queries.filter((q) => q.purpose === "lsof").map((q) => interpretLsof(q.answer));
    const alive = inventory.passes.at(-1)?.survivors?.map((e) => e.row.pid) ?? [];
    const kind = planKind(plan);
    const assembled = assembleRun({
      plan,
      kind,
      version: report.harnessVersion,
      outerResult,
      chain: report.chain,
      records,
      validator,
      inventory,
      claims,
      lsof,
      alive,
      bound:
        proof.rawBound === null
          ? null
          : boundBefore(rawObject(proof.rawBound), proof.inventoryStartedAt),
      extra: { portctlSha256: proof.portctlSha256, refusalCheck },
    });
    for (const key of [
      "identity",
      "refusal",
      "verdict",
      "control",
      "validatorControls",
      "supervision",
      "inventory",
      "lsof",
      "claims",
      "records",
    ])
      if (!isDeepStrictEqual(JSON.parse(JSON.stringify(assembled[key])), report[key]))
        throw new Error(`summary contradicts raw ${key}`);
    if (kind.kind !== report.kind || kind.escalation !== report.escalation)
      throw new Error("kind differs from raw plan");
    verifyCleanupProof(
      report.cleanup,
      {
        chain: report.chain,
        launchTime: report.launchTime,
        recorded: identities,
        injected: helperIdentity(outerResult.inner),
        selfPid: report.root.pid,
      },
      report.root,
      report.harnessVersion,
    );
    return { ok: true, report, plan };
  } catch (error) {
    return { ok: false, problems: [String(error.message ?? error)] };
  }
}

/** The separately built real stage3 artifact; a caller cannot nominate a stand-in build. */
export const FIXED_BUILD_PINS = Object.freeze({
  sourceCommit: "33970bf501ac85e62fd8aee488d16a9405a8a019",
  binarySha256: "2fa4f8795d692d29715f7fa9628d00779ff56d365e5ec87a6d1688880caf19bd",
  runnerSha256: "5fa364b83f2d23c56336acafd36c72ed3d772a95ee9c03d5c0e042732614248e",
});
const hash64 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const identifier = (value) =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(value);
const absolute = (value) => typeof value === "string" && resolve(value) === value;
const frozenDay = () => new Date().toISOString().slice(0, 10);

/** Consistency with an external packet is technical scope, never authenticated owner approval. */
export function validateCampaignPacket(packet, { utcDay, harnessH, filePins }) {
  const problems = [];
  if (
    packet?.schema !== "calendar-campaign/v1" ||
    !identifier(packet.campaign) ||
    !identifier(packet.authorityId)
  )
    problems.push("invalid campaign packet");
  if (packet?.utcDay !== utcDay || packet?.harnessH !== harnessH || !hash64(harnessH))
    problems.push("current day or H differs");
  if (
    !isDeepStrictEqual(packet?.harnessFiles, filePins) ||
    !isDeepStrictEqual(Object.keys(filePins).sort(), [...HARNESS_FILES].sort()) ||
    !Object.values(filePins).every(hash64)
  )
    problems.push("whole H file pins differ");
  if (!isDeepStrictEqual(packet?.buildPins, FIXED_BUILD_PINS))
    problems.push("fixed real build differs");
  if (!absolute(packet?.runRoot) || packet?.bootstrap !== "ordinary-user-own-ps")
    problems.push("explicit fresh root and infrastructure bootstrap required");
  if (packet?.externalApprovalVerified !== undefined || packet?.allDayCertified !== undefined)
    problems.push("external approval cannot be supplied as a flag");
  const attempts = Array.isArray(packet?.attempts) ? packet.attempts : [];
  if (
    attempts.length < 6 ||
    attempts.length > 64 ||
    attempts.some(
      (a) => !identifier(a?.attemptId) || !absolute(a.planPath) || !hash64(a.planSha256),
    ) ||
    new Set(attempts.map((a) => a.attemptId)).size !== attempts.length ||
    new Set(attempts.map((a) => a.planPath)).size !== attempts.length
  )
    problems.push("invalid exact attempt sequence");
  const selected = [
    packet?.refusalAttemptId,
    ...(Array.isArray(packet?.controlAttemptIds) ? packet.controlAttemptIds : []),
  ];
  if (
    selected.length !== 6 ||
    new Set(selected).size !== 6 ||
    selected.some((id) => !attempts.some((a) => a.attemptId === id))
  )
    problems.push("invalid selected report partition");
  return problems;
}

async function currentCampaignContext() {
  const filePins = {};
  for (const name of HARNESS_FILES) filePins[name] = digest(await readFile(here(name)));
  return { utcDay: frozenDay(), harnessH: await harnessVersion(), filePins };
}

/** An exclusive publication's full write, file+directory sync and exact raw readback. */
async function publishCampaignBytes(path, raw) {
  const handle = await open(path, "wx", 0o600);
  try {
    let offset = 0;
    while (offset < raw.length) {
      const { bytesWritten } = await handle.write(raw, offset, raw.length - offset, offset);
      if (bytesWritten <= 0) throw new Error("publication made no progress");
      offset += bytesWritten;
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
  const directory = await open(resolve(path, ".."), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
  const retained = await readFile(path);
  if (!retained.equals(raw)) throw new Error("durable publication readback differs");
  return retained;
}

async function readCampaignSnapshot(scope) {
  const directory = join(scope.runRoot, "attempt-ledger");
  if ((await realpath(directory)) !== directory || (await lstat(directory)).isSymbolicLink())
    throw new Error("ledger namespace alias");
  const authorityBytes = await readFile(join(directory, "authority.json"));
  const ledgerBytes = await readFile(join(directory, "ledger.jsonl"));
  const records = ledgerBytes
    .toString("utf8")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line));
  const names = records
    .filter((r) => r.type === "terminal" && r.reportFile !== null)
    .map((r) => r.reportFile);
  if (
    new Set(names).size !== names.length ||
    names.some((n) => !/^report-[1-9][0-9]*\.json$/.test(n))
  )
    throw new Error("invalid report enumeration");
  if (
    !isDeepStrictEqual(
      (await readdir(directory)).sort(),
      ["authority.json", "ledger.jsonl", ...names].sort(),
    )
  )
    throw new Error("omitted or extra ledger publication");
  const reports = new Map();
  for (const name of names) {
    const path = join(directory, name);
    const stat = await lstat(path);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.nlink !== 1 ||
      (await realpath(path)) !== path
    )
      throw new Error("report namespace alias");
    reports.set(name, await readFile(path));
  }
  return { authorityBytes, ledgerBytes, reports };
}

/** Explicit single-lifetime local producer; an external ROOT packet is required to run it. */
export async function campaign(packetPath, { trustedPacketVerifier } = {}) {
  if (typeof trustedPacketVerifier !== "function")
    return campaignFailure(["an external trusted packet verifier is required"]);
  const packetBytes = await readFile(packetPath);
  const packet = JSON.parse(packetBytes.toString("utf8"));
  const context = await currentCampaignContext();
  const problems = validateCampaignPacket(packet, context);
  if (problems.length) return campaignFailure(problems);
  const lifetime = { id: randomBytes(24).toString("hex"), pid: process.pid, openedAt: Date.now() };
  const scope = {
    campaign: packet.campaign,
    utcDay: packet.utcDay,
    runRoot: packet.runRoot,
    harnessH: packet.harnessH,
    buildPins: packet.buildPins,
  };
  const produced = await produceCampaign({
    scope,
    authorityId: packet.authorityId,
    attempts: packet.attempts,
    bootstrap: async () => {
      const rootStat = await lstat(scope.runRoot);
      if (
        !rootStat.isDirectory() ||
        rootStat.isSymbolicLink() ||
        (await realpath(scope.runRoot)) !== scope.runRoot ||
        (await readdir(scope.runRoot)).length !== 0
      )
        throw new Error("fresh exclusive real run root required");
      const directory = join(scope.runRoot, "campaign-bootstrap");
      await mkdir(directory, { mode: 0o700 });
      const recorder = await createSelfRecorder({
        path: join(directory, "records.jsonl"),
        role: "measure",
        harnessVersion: scope.harnessH,
      });
      try {
        const rows = await snapshotWith(recorder);
        const root = rows.find((row) => row.pid === process.pid);
        const sid = (await sessionsOf(recorder, [process.pid]))[process.pid];
        if (!root || typeof root.started !== "string" || !Number.isSafeInteger(sid))
          throw new Error("bootstrap native root unknown");
        scope.nativeRoot = { pid: root.pid, start: root.started, sid };
        recorder.close();
        const receipt = {
          phase: "infrastructure",
          operation: "ordinary-user-own-ps",
          nativeRoot: scope.nativeRoot,
          lifetime,
          rawRecords: (await readFile(join(directory, "records.jsonl"))).toString("base64"),
          packetSha256: digest(packetBytes),
        };
        await publishCampaignBytes(
          join(directory, "receipt.json"),
          Buffer.from(JSON.stringify(receipt) + "\n"),
        );
        await verifyTrustedBinding(
          trustedPacketVerifier,
          bindingRequest(packet, context, scope.nativeRoot, lifetime, "birth-admission"),
          packetBytes,
        );
        return { scope, receipt };
      } finally {
        recorder.close();
      }
    },
    measureAttempt: async (raw, attempt) => {
      const plan = JSON.parse(raw.toString("utf8"));
      if (
        plan.pins?.harnessVersion !== scope.harnessH ||
        Object.entries(scope.buildPins).some(
          ([key, value]) => plan.pins?.[key] !== value || plan.session?.[key] !== value,
        )
      )
        throw new Error("attempt plan differs from frozen build/H");
      const report = await measure(attempt.planPath, { planBytes: raw, runRoot: scope.runRoot });
      return publishCampaignBytes(
        join(report.accountingDirectory, "durable-verdict.json"),
        Buffer.from(JSON.stringify(report) + "\n"),
      );
    },
    readSnapshot: readCampaignSnapshot,
  });
  if (produced.state !== "complete")
    return { ...campaignFailure(produced.reasons), producer: produced };
  const manifest = {
    schema: "calendar-campaign-snapshot/v1",
    packetPath: resolve(packetPath),
    packetSha256: digest(packetBytes),
    runRoot: scope.runRoot,
  };
  const manifestPath = join(scope.runRoot, "campaign-snapshot.json");
  await publishCampaignBytes(manifestPath, Buffer.from(JSON.stringify(manifest) + "\n"));
  const certified = await certifyCampaignManifest(manifestPath, trustedPacketVerifier);
  return { ...certified, manifestPath };
}

const campaignFailure = (problems) => ({
  verdict: "fail",
  problems,
  certificate: null,
  nativeCertificateIssued: false,
  externalApprovalVerified: false,
  allDayCertified: false,
  historicalCompleteness: "UNKNOWN",
});
const exactBase64 = (value) => {
  if (typeof value !== "string") throw new Error("missing retained raw bytes");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error("invalid retained raw encoding");
  return bytes;
};

/** Sealed births, not a caller's report list, enumerate every native attempt in this scope. */
export function evaluateCampaignSnapshot(packet, snapshot, standInRunnerSha256) {
  try {
    const { authorityBytes, ledgerBytes, reports } = snapshot;
    const authority = JSON.parse(authorityBytes.toString("utf8"));
    const scope = authority.scope;
    const ledger = validateAttemptLedger({
      authorityBytes,
      authoritySha256: digest(authorityBytes),
      ledgerBytes,
      reports,
    });
    if (ledger.state !== "complete")
      throw new Error(`ledger ${ledger.state}: ${ledger.reasons.join("; ")}`);
    if (
      authority.authorityId !== packet.authorityId ||
      ["campaign", "utcDay", "runRoot", "harnessH", "buildPins"].some(
        (key) => !isDeepStrictEqual(scope[key], packet[key]),
      )
    )
      throw new Error("foreign campaign authority");
    const records = ledgerBytes
      .toString("utf8")
      .trimEnd()
      .split("\n")
      .map((line) => JSON.parse(line));
    const births = records.filter((r) => r.type === "birth");
    const terminals = records.filter((r) => r.type === "terminal");
    if (
      !isDeepStrictEqual(
        births.map((r) => ({ attemptId: r.attemptId, planSha256: r.planSha256 })),
        packet.attempts.map((a) => ({ attemptId: a.attemptId, planSha256: a.planSha256 })),
      )
    )
      throw new Error("omitted, extra or duplicate accepted attempt");
    if (!isDeepStrictEqual([...reports.keys()].sort(), terminals.map((r) => r.reportFile).sort()))
      throw new Error("omitted or extra raw report");
    const entries = births.map((birth) => {
      const terminal = terminals.find((r) => r.attemptId === birth.attemptId);
      const envelope = JSON.parse(reports.get(terminal.reportFile).toString("utf8"));
      const rawPlan = exactBase64(envelope.rawPlan);
      const rawReport = exactBase64(envelope.rawReport);
      if (
        digest(rawPlan) !== birth.planSha256 ||
        digest(rawPlan) !== envelope.rawPlanSha256 ||
        digest(rawReport) !== envelope.rawReportSha256
      )
        throw new Error("nested raw bytes SHA differs");
      const report = JSON.parse(rawReport.toString("utf8"));
      if (envelope.outcome !== report.verdict?.verdict || envelope.error !== null)
        throw new Error("raw terminal outcome differs or is unknown");
      if (
        report.harnessVersion !== scope.harnessH ||
        new Date(report.launchTime).toISOString().slice(0, 10) !== scope.utcDay ||
        report.root?.pid !== scope.nativeRoot.pid ||
        report.root?.started !== scope.nativeRoot.start ||
        report.root?.sid !== scope.nativeRoot.sid
      )
        throw new Error("foreign native root, day or H");
      if (
        Object.entries(scope.buildPins).some(
          ([key, value]) => report.identity?.[key] !== value || report.pins?.[key] !== value,
        )
      )
        throw new Error("foreign native build");
      const native = recomputeNativeReport(report);
      if (!native.ok || !exactBase64(report.native.rawPlan).equals(rawPlan))
        throw new Error(
          `native proof invalid: ${native.problems?.join("; ") ?? "raw plan differs"}`,
        );
      return {
        attemptId: birth.attemptId,
        report,
        file: {
          path: join(report.accountingDirectory, "durable-verdict.json"),
          sha256: digest(rawReport),
        },
        envelopeSha256: terminal.reportSha256,
      };
    });
    const selectedIds = [packet.refusalAttemptId, ...packet.controlAttemptIds];
    if (selectedIds.length !== 6 || new Set(selectedIds).size !== 6)
      throw new Error("selected report partition differs");
    const selected = selectedIds.map((id) => entries.find((entry) => entry.attemptId === id));
    if (selected.some((entry) => !entry)) throw new Error("missing selected report");
    const attempts = entries.filter((entry) => !selectedIds.includes(entry.attemptId));
    const predicate = certificateVerdict({
      refusal: selected[0].report,
      controls: selected.slice(1).map((e) => e.report),
      files: selected.map((e) => e.file),
      attempts,
      explanations: packet.explanations ?? {},
      standInRunnerSha256,
    });
    if (predicate.verdict !== "pass") return campaignFailure(predicate.problems);
    return {
      ...predicate,
      predicateOnly: true,
      nativeCertificateIssued: false,
      externalApprovalVerified: false,
      allDayCertified: false,
      historicalCompleteness: "UNKNOWN",
      technicalScope: { ...scope },
      ledgerSha256: digest(ledgerBytes),
      authoritySha256: digest(authorityBytes),
      allBirths: entries.map((e) => ({
        attemptId: e.attemptId,
        rawReportSha256: e.file.sha256,
        envelopeSha256: e.envelopeSha256,
      })),
    };
  } catch (error) {
    return campaignFailure([String(error.message ?? error)]);
  }
}

async function certifyCampaignManifest(manifestPath, trustedPacketVerifier) {
  try {
    if (typeof trustedPacketVerifier !== "function")
      throw new Error("an external trusted packet verifier is required");
    const manifest = JSON.parse((await readFile(manifestPath)).toString("utf8"));
    if (
      manifest.schema !== "calendar-campaign-snapshot/v1" ||
      !absolute(manifest.packetPath) ||
      !absolute(manifest.runRoot) ||
      !hash64(manifest.packetSha256)
    )
      throw new Error("a sealed native campaign is required");
    const packetBytes = await readFile(manifest.packetPath);
    if (digest(packetBytes) !== manifest.packetSha256)
      throw new Error("external packet raw bytes differ");
    const packet = JSON.parse(packetBytes.toString("utf8"));
    const context = await currentCampaignContext();
    const problems = validateCampaignPacket(packet, context);
    if (
      problems.length ||
      packet.runRoot !== manifest.runRoot ||
      (await realpath(packet.runRoot)) !== packet.runRoot ||
      (await lstat(packet.runRoot)).isSymbolicLink()
    )
      return campaignFailure(problems.length ? problems : ["foreign real campaign root"]);
    const snapshot = await readCampaignSnapshot({ runRoot: packet.runRoot });
    const bootstrapBytes = await readFile(
      join(packet.runRoot, "campaign-bootstrap", "receipt.json"),
    );
    const bootstrap = JSON.parse(bootstrapBytes.toString("utf8"));
    const authority = JSON.parse(snapshot.authorityBytes.toString("utf8"));
    if (
      bootstrap.phase !== "infrastructure" ||
      bootstrap.operation !== "ordinary-user-own-ps" ||
      bootstrap.packetSha256 !== manifest.packetSha256 ||
      !isDeepStrictEqual(bootstrap.nativeRoot, authority.scope.nativeRoot)
    )
      throw new Error("missing or foreign native bootstrap receipt");
    const nativePaths = new Set();
    for (const rawEnvelope of snapshot.reports.values()) {
      const envelope = JSON.parse(rawEnvelope.toString("utf8"));
      const raw = exactBase64(envelope.rawReport);
      const report = JSON.parse(raw.toString("utf8"));
      const directory = report.accountingDirectory;
      if (
        !absolute(directory) ||
        !directory.startsWith(packet.runRoot + "/accounting-") ||
        nativePaths.has(directory)
      )
        throw new Error("foreign or duplicate native publication directory");
      nativePaths.add(directory);
      const path = join(directory, "durable-verdict.json");
      const stat = await lstat(path);
      if (
        !stat.isFile() ||
        stat.isSymbolicLink() ||
        stat.nlink !== 1 ||
        (await realpath(path)) !== path ||
        !(await readFile(path)).equals(raw)
      )
        throw new Error("durable native raw file differs from envelope");
    }
    const standIn = digest(await readFile(here("testdata/fake-runner.cjs")));
    const evaluated = evaluateCampaignSnapshot(packet, snapshot, standIn);
    if (evaluated.verdict === "pass")
      await verifyTrustedBinding(
        trustedPacketVerifier,
        bindingRequest(
          packet,
          context,
          authority.scope.nativeRoot,
          bootstrap.lifetime,
          "sealed-certificate",
          digest(snapshot.authorityBytes),
          digest(snapshot.ledgerBytes),
        ),
        packetBytes,
      );
    return evaluated.verdict === "pass"
      ? { ...evaluated, predicateOnly: false, nativeCertificateIssued: true }
      : evaluated;
  } catch (error) {
    return campaignFailure([String(error.message ?? error)]);
  }
}

function verifyCleanupProof(cleanup, context, root, version) {
  if (cleanup?.outcome !== "clean" || !Array.isArray(cleanup.after))
    throw new Error("post-verdict cleanup unknown");
  const text = exactBase64(cleanup.rawRecords).toString("utf8");
  if (!text.endsWith("\n")) throw new Error("cleanup raw records truncated");
  const rows = text
    .slice(0, -1)
    .split("\n")
    .map((line) => JSON.parse(line));
  const header = rows[0];
  if (
    header?.type !== "header" ||
    header.pid !== root.pid ||
    header.started !== root.started ||
    header.harnessVersion !== version
  )
    throw new Error("cleanup root differs");
  const observations = [];
  for (let i = 0; i < cleanup.queries.length; i++) {
    const q = cleanup.queries[i];
    const birth = rows.find((r) => r.type === "birth" && r.handle === q.answer.handle);
    const exits = rows.filter((r) => r.type === "exit" && r.handle === q.answer.handle);
    if (
      !birth ||
      exits.length !== 1 ||
      birth.pid !== q.answer.pid ||
      birth.argvSha256 !== digest(Buffer.from(JSON.stringify([q.file, ...q.args]))) ||
      exits[0].code !== q.answer.code
    )
      throw new Error("cleanup query lacks own wait");
    if (q.purpose !== "inventory") continue;
    const session = cleanup.queries[i + 1];
    if (!complete(q.answer) || session?.purpose !== "getsid" || !complete(session.answer))
      throw new Error("cleanup inventory unreadable");
    const sids = JSON.parse(session.answer.stdout);
    observations.push(
      parseInventory(q.answer.stdout)
        .filter((r) => r.pid !== q.answer.pid)
        .map((r) => ({ ...r, sid: sids[String(r.pid)] })),
    );
  }
  if (
    observations.length !== 2 ||
    !isDeepStrictEqual(observations[0], cleanup.before) ||
    !isDeepStrictEqual(observations[1], cleanup.after)
  )
    throw new Error("missing independent after inventory or contradictory body");
  const targets = cleanupTargets({ ...context, rows: cleanup.before });
  const signals = rows.filter((r) => r.type === "signal");
  if (
    targets.length !== cleanup.signals.length ||
    signals.length !== targets.length ||
    targets.some(
      (target, i) =>
        cleanup.signals[i].sent !== true ||
        !isDeepStrictEqual(cleanup.signals[i].target, identityOf(target)) ||
        signals[i].kind !== "SIGKILL" ||
        !isDeepStrictEqual(signals[i].target, identityOf(target)),
    )
  )
    throw new Error("cleanup signal outcome unknown");
  if (
    cleanupTargets({ ...context, rows: cleanup.after }).length ||
    cleanup.after.some(
      (r) => r.sid === "ESRCH" || !Number.isSafeInteger(r.sid) || /^Z/.test(r.stat ?? ""),
    )
  )
    throw new Error("cleanup after inventory unknown");
}

function bindingRequest(
  packet,
  context,
  nativeRoot,
  lifetime,
  phase,
  authoritySha256 = null,
  ledgerSha256 = null,
) {
  return {
    schema: "calendar-trusted-binding/v1",
    phase,
    packetSha256: null,
    harnessH: context.harnessH,
    harnessFiles: context.filePins,
    utcDay: context.utcDay,
    buildPins: packet.buildPins,
    nativeRoot,
    campaign: packet.campaign,
    runRoot: packet.runRoot,
    lifetime,
    authoritySha256,
    ledgerSha256,
  };
}

/** Only an external host can supply this capability; a file or boolean is never a verifier. */
export async function verifyTrustedBinding(trustedPacketVerifier, binding, packetBytes) {
  if (typeof trustedPacketVerifier !== "function" || !Buffer.isBuffer(packetBytes))
    throw new Error("missing external host verifier");
  const expected = structuredClone(binding);
  if (expected.packetSha256 !== null && expected.packetSha256 !== digest(packetBytes))
    throw new Error("binding raw packet differs");
  expected.packetSha256 = digest(packetBytes);
  if (
    !expected.lifetime ||
    typeof expected.lifetime.id !== "string" ||
    !Number.isSafeInteger(expected.lifetime.pid)
  )
    throw new Error("missing producer lifetime");
  const receipt = await trustedPacketVerifier({
    binding: structuredClone(expected),
    packetBytes: Buffer.from(packetBytes),
  });
  if (!isDeepStrictEqual(receipt, { ...expected, closed: true }))
    throw new Error("external verifier did not close this exact binding");
  return receipt;
}
