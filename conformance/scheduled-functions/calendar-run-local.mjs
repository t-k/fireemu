// This launcher only contacts loopback services. It never obtains production credentials. Every
// child process goes through the recorder (stage3 launch accounting, owner ledger 786).
import { readFile, writeFile, lstat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createSelfRecorder } from "./calendar-recorder.mjs";
import { localCalendarClient, exerciseCalendarSession } from "./calendar-local.mjs";
import {
  sessionArguments,
  superviseCalendarProcess,
  calendarOwnedBranches,
} from "./calendar-session.mjs";
import {
  accountingOuter,
  certify,
  harnessVersion,
  ownedSender,
  measure,
  snapshotWith,
} from "./calendar-measure.mjs";

const self = fileURLToPath(import.meta.url);
const sameIdentity = (a, b) =>
  a && b && ["pid", "comm", "args", "uid", "started"].every((key) => a[key] === b[key]);
const privateJson = (path, value) => writeFile(path, JSON.stringify(value) + "\n", { mode: 0o600 });
const cleanEnv = () =>
  Object.fromEntries(
    ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"]
      .filter((key) => process.env[key] !== undefined)
      .map((key) => [key, process.env[key]]),
  );

/** The last `limit` characters of the daemon's stderr, kept privately to explain an (A) failure. */
export function stderrTail(tail, chunk, limit = 4096) {
  return (tail + chunk).slice(-limit);
}

/**
 * Notes the injected helper's first sighting and whether the tracker acquired it as itself (its
 * PID and the start time of that first sighting), design v4 F2 and review S5.
 */
export function noteSighting(injected, rows, owned, afterMs) {
  if (!Number.isSafeInteger(injected.pid)) return injected;
  const row = rows.find((value) => value.pid === injected.pid);
  if (row && !injected.firstSighting)
    injected.firstSighting = { afterMs, ppid: row.ppid, pgid: row.pgid, started: row.started };
  injected.acquired ||= owned.some(
    (value) => value.pid === injected.pid && value.started === injected.firstSighting?.started,
  );
  return injected;
}

/** The diagnostic lines kept from the daemon: startup and refusal lines, never headers or dumps. */
export function calendarDiagnostics(text) {
  return text
    .split("\n")
    .filter((line) =>
      /functions loaded:|calendarProbe|calendarReceipt|invalid schedule|invalid time.?zone|unknown time zone/i.test(
        line,
      ),
    )
    .slice(0, 20);
}

async function childSession(path) {
  const plan = JSON.parse(await readFile(path, "utf8"));
  const until = performance.now() + 10000;
  for (;;) {
    try {
      await lstat(plan.proceedPath);
      break;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    if (performance.now() >= until)
      throw new Error("owned calendar process observation handshake timed out");
    await delay(50);
  }
  const client = localCalendarClient({
    controlUrl: process.env.FIREEMU_CONTROL_URL,
    functionsHost: process.env.FIREEMU_FUNCTIONS_HOST,
    token: process.env.FIREEMU_CONTROL_TOKEN,
  });
  const result = await exerciseCalendarSession({
    input: plan.input,
    anchor: plan.anchor,
    ...client,
  });
  await privateJson(plan.outputPath, result);
  if (!result.matched) process.exitCode = 1;
}

/** The inner supervisor: a waited direct child of the outer launcher that starts the daemon. */
async function superviseSession(path) {
  let stopped = false;
  const stop = () => {
    stopped = true;
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  const plan = JSON.parse(await readFile(path, "utf8")),
    prepared = plan.prepared;
  const recorder = await createSelfRecorder({
    path: join(plan.accDir, "records", "inner.jsonl"),
    role: "inner",
    harnessVersion: await harnessVersion(),
  });
  const snapshot = () => snapshotWith(recorder);
  const before = await snapshot(),
    root = before.find((row) => row.pid === process.pid),
    parent = before.find((row) => row.pid === process.ppid);
  if (!root || !parent) throw new Error("local calendar supervisor identity unavailable");
  await privateJson(prepared.ackPath, root);
  const state = { done: false, code: null };
  const daemon = recorder.spawn(
    prepared.binary,
    sessionArguments({ ...prepared, port: Number(process.env.PORT) }),
    {
      cwd: plan.conformanceRoot,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...cleanEnv(), FIREEMU_RUNNER_NODE: prepared.runner },
    },
    "daemon",
  );
  daemon.once("error", () => {
    state.done = true;
    state.code = -1;
    state.spawnFailed = true;
  });
  daemon.once("exit", (code) => {
    state.done = true;
    state.code = code ?? -1;
  });
  let diagnostic = "",
    observed = false,
    parentLost = false;
  // A control run records its injected helper's first sighting and whether the tracker acquired
  // it (design v4 F2).
  const injected = prepared.identity.controlMode ? { pid: null } : null;
  const started = performance.now();
  const sight = async (rows, owned) => {
    if (!injected) return;
    if (injected.pid === null) {
      try {
        injected.pid = JSON.parse(await readFile(prepared.readyPath, "utf8")).pid;
      } catch {
        return;
      }
    }
    noteSighting(injected, rows, owned, Math.round(performance.now() - started));
  };
  const collect = (chunk) => {
    if (diagnostic.length < 262144)
      diagnostic += chunk.toString().slice(0, 262144 - diagnostic.length);
  };
  let tail = "";
  daemon.stdout?.on("data", collect);
  daemon.stderr?.on("data", collect);
  daemon.stderr?.on("data", (chunk) => {
    tail = stderrTail(tail, chunk.toString());
  });
  // Diagnostics are read once the daemon's pipes close, so a buffered refusal line is not lost.
  const drained = new Promise((resolve) => daemon.once("close", resolve));
  const result = await superviseCalendarProcess({
    root,
    child: { pid: daemon.pid, state: () => state },
    snapshot,
    signal: ownedSender(recorder, [daemon]),
    escalate: plan.escalation !== "off",
    stopping: () => stopped || parentLost,
    ownershipComplete: () => observed,
    onObserved: async (owned, rows, acquired) => {
      await sight(rows, acquired);
      parentLost ||= !sameIdentity(
        parent,
        rows.find((row) => row.pid === parent.pid),
      );
      const branches = calendarOwnedBranches(owned, prepared);
      if (!observed && branches.runner && branches.child) {
        await privateJson(prepared.proceedPath, { observed: true });
        observed = true;
      }
    },
  });
  await daemon.recordExit;
  result.diagnosticsDrained = await Promise.race([
    drained.then(() => true),
    delay(2000).then(() => false),
  ]);
  result.observationHandshake = observed;
  if (injected) result.injected = { acquired: false, firstSighting: null, ...injected };
  result.parentLost = parentLost;
  result.loadedExports = ["calendarProbe", "calendarReceipt"].every((name) =>
    diagnostic.includes(name),
  );
  result.diagnostics = calendarDiagnostics(diagnostic);
  // A private file in the run's directory, referenced from the report only when (A) fails.
  result.stderrTailPath = join(prepared.directory, "daemon-stderr-tail.txt");
  await writeFile(result.stderrTailPath, tail, { mode: 0o600 });
  await privateJson(prepared.supervisorOutputPath, result);
  recorder.close();
  process.off("SIGTERM", stop);
  process.off("SIGINT", stop);
  if (!result.cleanupVerified || state.code !== 0) process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const [mode, argument] = process.argv.slice(2);
  try {
    if (process.argv.length !== 4) throw new Error("explicit local calendar mode required");
    if (mode === "--calendar-child") await childSession(argument);
    else if (mode === "--calendar-supervisor") await superviseSession(argument);
    else if (mode === "--accounting-outer") await accountingOuter(argument);
    else if (mode === "--certify") {
      const result = await certify(argument);
      console.log(JSON.stringify(result));
      if (result.verdict !== "pass") process.exitCode = 1;
    } else if (mode === "--measure") {
      const report = await measure(argument);
      console.log(
        JSON.stringify({
          verdict: report.verdict.verdict,
          control: report.control,
          accountingDirectory: report.accountingDirectory,
          productionParity: false,
        }),
      );
      if (report.verdict.verdict !== "pass" && !report.control?.counts) process.exitCode = 1;
    } else throw new Error("explicit local calendar mode required");
  } catch {
    console.error("local calendar session failed; inspect its private proof artifacts");
    process.exitCode = 1;
  }
}

export { self as calendarRunLocalPath };
