// Local launcher contracts; imports start no daemon and read no credentials.
import { setTimeout as delay } from "node:timers/promises";
import { ownedProcessTracker, sameProcessIdentity } from "./calendar-processes.mjs";
import { mkdir, mkdtemp, readFile, writeFile, chmod } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, isAbsolute } from "node:path";
import { calendarFixture } from "./calendar-local.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
export async function prepareCalendarSession({
  root,
  binary,
  runner,
  binarySha256,
  runnerSha256,
  sourceCommit,
  anchor,
  input,
  childPath,
}) {
  if (
    ![root, binary, runner, childPath].every(isAbsolute) ||
    !/^[a-f0-9]{40}$/.test(sourceCommit ?? "")
  )
    throw new Error("invalid local calendar artifact paths or source");
  if (digest(await readFile(binary)) !== binarySha256)
    throw new Error("local calendar binary binding differs");
  if (digest(await readFile(runner)) !== runnerSha256)
    throw new Error("local calendar runner binding differs");
  if (!Number.isFinite(Date.parse(anchor)) || !input || typeof input.scheduleTime !== "string")
    throw new Error("invalid local calendar anchor or input");
  const sdk = JSON.parse(
    await readFile(join(root, "conformance/node_modules/firebase-functions/package.json"), "utf8"),
  );
  const cli = JSON.parse(
    await readFile(join(root, "conformance/node_modules/firebase-tools/package.json"), "utf8"),
  );
  if (sdk.version !== "7.3.2" || cli.version !== "15.28.2")
    throw new Error("local calendar SDK or CLI version differs");
  const base = join(root, "conformance/.runs");
  await mkdir(base, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(base, "calendar-local-"));
  await chmod(directory, 0o700);
  const fixturePath = join(directory, "fixture");
  await mkdir(fixturePath, { mode: 0o700 });
  const fixture = calendarFixture(input),
    config = JSON.stringify({
      schemaVersion: 1,
      profile: "strict",
      daemon: { clockStart: anchor },
    });
  const configPath = join(directory, "fireemu.json"),
    inputPath = join(directory, "input.json");
  await writeFile(join(fixturePath, "index.cjs"), fixture, { mode: 0o600 });
  await writeFile(
    join(fixturePath, "package.json"),
    JSON.stringify({ private: true, main: "index.cjs" }),
    { mode: 0o600 },
  );
  await writeFile(configPath, config, { mode: 0o600 });
  const paths = {
    directory,
    fixturePath,
    configPath,
    inputPath,
    childPath,
    ackPath: join(directory, "supervisor.json"),
    proceedPath: join(directory, "proceed.json"),
    outputPath: join(directory, "callback.json"),
    supervisorOutputPath: join(directory, "supervisor-result.json"),
  };
  await writeFile(inputPath, JSON.stringify({ input, anchor, ...paths }), { mode: 0o600 });
  return {
    ...paths,
    binary,
    runner,
    identity: {
      sourceCommit,
      binarySha256,
      runnerSha256,
      sdkVersion: sdk.version,
      cliVersion: cli.version,
      fixtureSha256: digest(fixture),
      configSha256: digest(config),
      anchor,
    },
  };
}

export async function superviseCalendarProcess({
  root,
  child,
  initial,
  snapshot,
  signal,
  sleep = delay,
  clock = () => performance.now(),
  stopping = () => false,
  onObserved = async () => {},
  ownershipComplete = async () => false,
  deadlineMs = 120000,
  graceMs = 25000,
  killGraceMs = 1000,
  pollMs = 250,
}) {
  let acceptsInitial = Boolean(initial);
  const tracker = ownedProcessTracker(root, {
    branchPid: child.pid ?? null,
    canAcquireBranch: () => acceptsInitial || !child.state().done,
  });
  tracker.observe(initial ?? [root]);
  acceptsInitial = false;
  let childAcquired = tracker.owned().some((row) => row.pid === child.pid);
  const start = clock();
  let timedOut = false,
    cancelled = false,
    inventoryFailures = 0,
    signalFailures = 0;
  const live = async () => {
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const rows = await snapshot();
        tracker.observe(rows);
        const current = tracker.present(rows);
        childAcquired ||= current.some((row) => row.pid === child.pid);
        await onObserved(current, rows, tracker.owned());
        return current.filter((row) => row.pid !== root.pid);
      } catch {
        inventoryFailures++;
        if (attempt < 2) await sleep(pollMs);
      }
    }
    throw new Error("owned process inventory remains unreadable");
  };
  const verifiedSignal = async (pid, kind) => {
    if (
      (await live()).some(
        (row) =>
          row.pid === pid &&
          sameProcessIdentity(
            tracker.owned().find((owned) => owned.pid === pid),
            row,
          ),
      )
    ) {
      try {
        await signal(pid, kind);
      } catch {
        signalFailures++;
      }
    }
  };
  try {
    while (!child.state().done) {
      await live();
      timedOut = clock() - start >= deadlineMs;
      cancelled = stopping();
      if (timedOut || cancelled) {
        await verifiedSignal(child.pid, "SIGTERM");
        break;
      }
      await sleep(pollMs);
    }
  } catch {
    try {
      await verifiedSignal(child.pid, "SIGTERM");
    } catch {
      /* Fresh identity remains required. */
    }
  }
  const settle = async (milliseconds) => {
    const until = clock() + milliseconds;
    let empty = 0;
    while (clock() < until) {
      let remaining;
      try {
        remaining = await live();
      } catch {
        return false;
      }
      if (!remaining.length) {
        if (++empty >= 2) return true;
      } else empty = 0;
      await sleep(pollMs);
    }
    return false;
  };
  let cleanupVerified = await settle(graceMs);
  for (const kind of ["SIGTERM", "SIGKILL"]) {
    if (cleanupVerified) break;
    let survivors;
    try {
      survivors = await live();
    } catch {
      break;
    }
    for (const row of survivors.toReversed()) await verifiedSignal(row.pid, kind);
    cleanupVerified = await settle(killGraceMs);
  }
  const acquisitionComplete = (await ownershipComplete()) === true;
  const explicitSpawnFailure =
    child.pid === undefined && child.state().done && child.state().spawnFailed === true;
  const ownershipDebt = [
    ...(!childAcquired && !explicitSpawnFailure ? ["spawned child identity was not acquired"] : []),
    ...(!acquisitionComplete ? ["complete known fixture branch acquisition was not proved"] : []),
    ...(tracker.groupDebt() ? ["isolated process group identity is ambiguous"] : []),
  ];
  return {
    exitCode: child.state().code,
    timedOut,
    cancelled,
    inventoryFailures,
    signalFailures,
    trackedAbsenceVerified: cleanupVerified,
    cleanupVerified: cleanupVerified && ownershipDebt.length === 0,
    acquisitionComplete,
    ownershipDebt,
    childAcquired,
    groupDebt: tracker.groupDebt(),
    groupEvents: tracker.groupEvents(),
    ownedProcesses: tracker.owned(),
  };
}
export function sessionArguments({ configPath, fixturePath, childPath, inputPath, port }) {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535)
    throw new Error("invalid exclusively claimed control port");
  if (
    ![configPath, fixturePath, childPath, inputPath].every(
      (value) => typeof value === "string" && value.startsWith("/") && !/[\r\n]/.test(value),
    )
  )
    throw new Error("invalid local calendar session path");
  return [
    "exec",
    "--project",
    "demo-scheduled-calendar",
    "--only",
    "functions",
    "--config",
    configPath,
    "--functions",
    fixturePath,
    "--http-port",
    String(port),
    ...[
      "functions",
      "firestore",
      "storage",
      "eventarc",
      "tasks",
      "pubsub",
      "ui",
      "hub",
      "logging",
    ].flatMap((name) => ["--" + name + "-port", "0"]),
    "--",
    process.execPath,
    childPath,
    "--calendar-child",
    inputPath,
  ];
}

export function calendarOwnedBranches(
  rows,
  { runner, fixturePath, childPath, inputPath, node = process.execPath },
) {
  return {
    runner: rows.find((row) =>
      row.args.startsWith(node + " " + runner + " --source " + fixturePath + " "),
    ),
    child: rows.find(
      (row) => row.args === [node, childPath, "--calendar-child", inputPath].join(" "),
    ),
  };
}
