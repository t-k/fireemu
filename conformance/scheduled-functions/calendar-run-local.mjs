// This launcher only contacts loopback services. It never obtains production credentials.
import { execFile as execFileCallback, spawn } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, lstat } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { parseProcessSnapshot } from "./calendar-processes.mjs";
import { localCalendarClient, exerciseCalendarSession } from "./calendar-local.mjs";
import {
  prepareCalendarSession,
  sessionArguments,
  superviseCalendarProcess,
  calendarOwnedBranches,
} from "./calendar-session.mjs";

const execFile = promisify(execFileCallback),
  self = fileURLToPath(import.meta.url);
const sameIdentity = (a, b) =>
  a && b && ["pid", "comm", "args", "uid", "started"].every((key) => a[key] === b[key]);
const privateJson = (path, value) => writeFile(path, JSON.stringify(value) + "\n", { mode: 0o600 });
const cleanEnv = () =>
  Object.fromEntries(
    ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"]
      .filter((key) => process.env[key] !== undefined)
      .map((key) => [key, process.env[key]]),
  );

// Redirection has its own original-identity guard because its target differs from the wrapper.
export function createCalendarSignalRelay({ wrapperPid, innerArgs, snapshot: readSnapshot, kill }) {
  let inner,
    identityDebt = false;
  return {
    observe(owned) {
      if (!inner) {
        const captured = owned.find((row) => row.ppid === wrapperPid && row.args === innerArgs);
        if (captured) inner = Object.freeze({ ...captured });
      }
    },
    debt: () => identityDebt,
    async signal(pid, kind) {
      if (pid !== wrapperPid || kind !== "SIGTERM") return kill(pid, kind);
      try {
        const rows = await readSnapshot();
        if (!inner || !rows.some((row) => sameIdentity(inner, row)))
          throw new Error("original calendar supervisor identity unavailable for cancellation");
        return await kill(inner.pid, "SIGTERM");
      } catch (error) {
        identityDebt = true;
        throw error;
      }
    },
  };
}

async function snapshot() {
  const operation = execFile("ps", ["-ww", "-axo", "pid=,ppid=,pgid=,uid=,lstart=,comm=,args="], {
    encoding: "utf8",
    maxBuffer: 16777216,
    timeout: 5000,
    env: { ...cleanEnv(), LC_ALL: "C" },
  });
  const observerPid = operation.child?.pid;
  if (!Number.isSafeInteger(observerPid) || observerPid <= 1)
    throw new Error("process snapshot observer identity unavailable");
  const { stdout } = await operation;
  return parseProcessSnapshot(stdout, observerPid);
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

async function releaseClaim(
  script,
  capability = { token: process.env.PORT_REGISTRY_TOKEN, db: process.env.PORT_REGISTRY_DB },
) {
  if (!capability.token || !capability.db)
    throw new Error("missing own calendar port claim capability");
  const code =
    "import importlib.util,sys,os,pathlib; s=importlib.util.spec_from_file_location('calendar_portctl',sys.argv[1]); m=importlib.util.module_from_spec(s); sys.modules[s.name]=m; s.loader.exec_module(m); m.release(pathlib.Path(os.environ['PORT_REGISTRY_DB']),token=os.environ['PORT_REGISTRY_TOKEN'],port=None)";
  await execFile("python3", ["-c", code, script], {
    env: {
      ...cleanEnv(),
      PORT_REGISTRY_TOKEN: capability.token,
      PORT_REGISTRY_DB: capability.db,
    },
    timeout: 5000,
  });
}

async function superviseSession(path) {
  let stopped = false,
    parentLost = false;
  const stop = () => {
    stopped = true;
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  const plan = JSON.parse(await readFile(path, "utf8")),
    prepared = plan.prepared;
  const before = await snapshot(),
    root = before.find((row) => row.pid === process.pid),
    parent = before.find((row) => row.pid === process.ppid);
  if (!root || !parent) throw new Error("local calendar supervisor identity unavailable");
  await privateJson(prepared.ackPath, root);
  const state = { done: false, code: null };
  const daemon = spawn(
    prepared.binary,
    sessionArguments({ ...prepared, port: Number(process.env.PORT) }),
    {
      cwd: plan.conformanceRoot,
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...cleanEnv(), FIREEMU_RUNNER_NODE: prepared.runner },
    },
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
    observed = false;
  const collect = (chunk) => {
    if (diagnostic.length < 262144)
      diagnostic += chunk.toString().slice(0, 262144 - diagnostic.length);
  };
  daemon.stdout.on("data", collect);
  daemon.stderr.on("data", collect);
  const result = await superviseCalendarProcess({
    root,
    child: { pid: daemon.pid, state: () => state },
    snapshot,
    signal: async (pid, signal) => process.kill(pid, signal),
    stopping: () => stopped || parentLost,
    ownershipComplete: () => observed,
    onObserved: async (owned, rows) => {
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
  result.observationHandshake = observed;
  result.parentLost = parentLost;
  result.loadedExports = ["calendarProbe", "calendarReceipt"].every((name) =>
    diagnostic.includes(name),
  );
  // Keep only the trusted fixture's startup/refusal lines, never headers or environment dumps.
  result.diagnostics = diagnostic
    .split("\n")
    .filter((line) =>
      /functions loaded:|calendarProbe|calendarReceipt|invalid schedule|invalid time.?zone/i.test(
        line,
      ),
    )
    .slice(0, 20);
  await privateJson(prepared.supervisorOutputPath, result);
  if (parentLost && result.cleanupVerified) await releaseClaim(plan.portctl);
  process.off("SIGTERM", stop);
  process.off("SIGINT", stop);
  if (!result.cleanupVerified || state.code !== 0) process.exitCode = 1;
}

export function calendarPortctlInvocation({ prepared, script, cwd, service, launcherPath }) {
  const database = join(prepared.directory, "ports.sqlite3");
  return {
    database,
    args: [
      script,
      "--db",
      database,
      "--cwd",
      cwd,
      "run",
      "--service",
      service,
      "--range",
      "10000-19999",
      "--ttl",
      "5m",
      "--",
      process.execPath,
      self,
      "--calendar-supervisor",
      launcherPath,
    ],
  };
}

export async function readOwnCalendarClaims({ service, database }) {
  if (typeof database !== "string" || resolve(database) !== database)
    throw new Error("explicit absolute private database required for own calendar claims");
  const code =
    "import sys,pathlib,json,sqlite3; db=pathlib.Path(sys.argv[1]); c=sqlite3.connect(db.as_uri()+'?mode=ro',uri=True,timeout=2); c.row_factory=sqlite3.Row; rows=[dict(r) for r in c.execute('SELECT * FROM reservations WHERE service = ?', (sys.argv[2],))]; c.close(); print(json.dumps({'db':str(db),'claims':rows}))";
  const { stdout } = await execFile("python3", ["-c", code, database, service], {
    env: cleanEnv(),
    timeout: 5000,
  });
  const result = JSON.parse(stdout);
  if (
    result.db !== database ||
    !Array.isArray(result.claims) ||
    result.claims.some((row) => row.service !== service)
  )
    throw new Error("own calendar claim proof is unreadable");
  return result;
}

export async function runCalendarLocal({
  root,
  binary,
  runner,
  sourceCommit,
  binarySha256,
  runnerSha256,
  input,
  anchor,
  portctl,
}) {
  const prepared = await prepareCalendarSession({
    root,
    binary,
    runner,
    sourceCommit,
    binarySha256,
    runnerSha256,
    input,
    anchor,
    childPath: self,
  });
  const service = "lane8-calendar-" + randomBytes(8).toString("hex"),
    conformanceRoot = join(root, "conformance"),
    launcherPath = join(prepared.directory, "launcher.json");
  await privateJson(launcherPath, { prepared, conformanceRoot, portctl });
  let stopped = false;
  const stop = () => {
    stopped = true;
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  const rootIdentity = (await snapshot()).find((row) => row.pid === process.pid);
  if (!rootIdentity) throw new Error("outer calendar launcher identity unavailable");
  const invocation = calendarPortctlInvocation({
    prepared,
    script: portctl,
    cwd: conformanceRoot,
    service,
    launcherPath,
  });
  const wrapper = spawn("python3", invocation.args, {
    stdio: ["ignore", "ignore", "ignore"],
    env: cleanEnv(),
  });
  const wrapperState = { done: false, code: null };
  wrapper.once("error", () => {
    wrapperState.done = true;
    wrapperState.code = -1;
    wrapperState.spawnFailed = true;
  });
  wrapper.once("exit", (value) => {
    wrapperState.done = true;
    wrapperState.code = value ?? -1;
  });
  const relay = createCalendarSignalRelay({
    wrapperPid: wrapper.pid,
    innerArgs: [process.execPath, self, "--calendar-supervisor", launcherPath].join(" "),
    snapshot,
    kill: (pid, kind) => process.kill(pid, kind),
  });
  let launcher;
  try {
    launcher = await superviseCalendarProcess({
      root: rootIdentity,
      child: { pid: wrapper.pid, state: () => wrapperState },
      snapshot,
      stopping: () => stopped,
      onObserved: (_current, _rows, owned) => relay.observe(owned),
      ownershipComplete: async () => {
        try {
          return (
            !relay.debt() &&
            JSON.parse(await readFile(prepared.supervisorOutputPath, "utf8")).cleanupVerified ===
              true
          );
        } catch {
          return false;
        }
      },
      deadlineMs: 170000,
      graceMs: 30000,
      killGraceMs: 2000,
      signal: relay.signal,
    });
  } finally {
    process.off("SIGTERM", stop);
    process.off("SIGINT", stop);
  }
  let supervisor = null,
    callback = null;
  try {
    supervisor = JSON.parse(await readFile(prepared.supervisorOutputPath, "utf8"));
  } catch {
    /* Missing proof fails acceptance. */
  }
  try {
    callback = JSON.parse(await readFile(prepared.outputPath, "utf8"));
  } catch {
    /* Discovery refusal or missing callback remains evidence. */
  }
  const owned = [
    ...launcher.ownedProcesses.filter((row) => row.pid !== rootIdentity.pid),
    ...(supervisor?.ownedProcesses ?? []),
  ];
  const rows = await snapshot(),
    survivors = owned.filter((ownedRow) =>
      rows.some(
        (row) =>
          row.pid === ownedRow.pid && row.uid === ownedRow.uid && row.started === ownedRow.started,
      ),
    );
  let registry = await readOwnCalendarClaims({ service, database: invocation.database });
  if (launcher.cleanupVerified && survivors.length === 0 && wrapperState.done) {
    for (const claim of registry.claims) {
      if (!owned.some((row) => row.pid === claim.pid)) continue;
      await releaseClaim(portctl, { token: claim.token, db: registry.db });
    }
    registry = await readOwnCalendarClaims({ service, database: invocation.database });
  }
  const claimReleased = registry.claims.length === 0;
  const cleanupVerified =
    launcher.cleanupVerified &&
    supervisor?.cleanupVerified === true &&
    survivors.length === 0 &&
    claimReleased;
  const result = {
    identity: prepared.identity,
    input,
    anchor,
    wrapperExitCode: wrapperState.code,
    launcher,
    callback,
    supervisor,
    survivors,
    claimReleased,
    cleanupVerified,
    productionParity: false,
    matched: callback?.matched === true && supervisor?.loadedExports === true && cleanupVerified,
  };
  await privateJson(join(prepared.directory, "result.json"), result);
  return { ...result, directory: prepared.directory };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length === 4 && process.argv[2] === "--calendar-child")
      await childSession(process.argv[3]);
    else if (process.argv.length === 4 && process.argv[2] === "--calendar-supervisor")
      await superviseSession(process.argv[3]);
    else if (process.argv.length === 4 && process.argv[2] === "--smoke-plan") {
      const plan = JSON.parse(await readFile(process.argv[3], "utf8"));
      const result = await runCalendarLocal(plan);
      console.log(
        JSON.stringify({
          directory: result.directory,
          matched: result.matched,
          cleanupVerified: result.cleanupVerified,
          productionParity: false,
        }),
      );
      if (!result.matched) process.exitCode = 1;
    } else throw new Error("explicit local calendar mode required");
  } catch {
    console.error("local calendar session failed; inspect its private proof artifacts");
    process.exitCode = 1;
  }
}
