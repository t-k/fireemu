// The plain production recorder for Pub/Sub: unary REST and gRPC conditions against one target, every
// exchange captured as it happens, and everything the run created deleted by prefix at the end with the
// 404s read back. It sends nothing to a push endpoint (no publish to a topic with a push subscription).
//
//   node record.mjs --target emulator --out <dir>                       (PUBSUB_EMULATOR_HOST)
//   node record.mjs --target production --project <id> --out <dir>
//   node record.mjs --target production --project <id> --out <dir> --cleanup-only --run-id <12 hex>
//
// Exit codes: 0 done, 1 cleanup left something, 2 usage, 3 stopped clean on a missing precondition or a
// signal, 4 the request budget was spent.

import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createBudget, createCapture, createFileJournal } from "./capture.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient, newPushState } from "./client.mjs";
import { createGrpc } from "./grpc.mjs";
import {
  MIN_ABSENCE_WAIT_MS,
  createLedger,
  maybeCreated,
  maybeDeleting,
  readLedger,
} from "./ledger.mjs";
import { createOwnership, isRunId, newRunId } from "./names.mjs";
import { createRest } from "./rest.mjs";
import { assertBudgetCovers, exitCodeOf, runCases, selectCases } from "./runner.mjs";
import { createTokenProvider } from "./token.mjs";
import { createPhaseLimit } from "./limits.mjs";
import { admitV2, sha256, claimSourceRun } from "./admission.mjs";
import { createIamOwnership, IAM_WAIT_MS } from "./iam.mjs";
import { setTimeout as sleepTimer } from "node:timers/promises";
import { StopClean } from "./cases/support.mjs";
import { IAM_PREREQUISITE } from "./cases/stream-dlq.mjs";

const PRODUCTION = { rest: "https://pubsub.googleapis.com", grpc: "pubsub.googleapis.com:443" };
export const DEFAULT_MAX_REQUESTS = 1026;
export const CLEANUP_BUDGET = 600;
/** The later --cleanup-only run starts at least this long after the recording's last line. */
export const MIN_A2_WAIT_MS = MIN_ABSENCE_WAIT_MS;

export function parseArgs(argv, env = {}) {
  const options = { transports: ["rest", "grpc"], maxRequests: DEFAULT_MAX_REQUESTS };
  const flags = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--cleanup-only") options.cleanupOnly = true;
    else if (arg === "--prepare") options.prepare = true;
    else if (arg.startsWith("--")) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
      flags.set(arg.slice(2), value);
      i += 1;
    } else throw new Error(`unexpected argument ${arg}`);
  }
  const take = (name) => {
    const value = flags.get(name);
    flags.delete(name);
    return value;
  };
  options.target = take("target");
  if (options.target !== "emulator" && options.target !== "production")
    throw new Error("--target must be emulator or production");
  options.production = options.target === "production";
  options.project = take("project") ?? (options.production ? undefined : "demo-fireemu-pubsub");
  if (options.project === undefined) throw new Error("--project is required for production");
  options.out = take("out");
  if (options.out === undefined) throw new Error("--out is required");
  const max = take("max-requests");
  if (max !== undefined) options.maxRequests = Number(max);
  if (!Number.isSafeInteger(options.maxRequests) || options.maxRequests <= 0)
    throw new Error("--max-requests must be a positive integer");
  const only = take("only");
  if (only !== undefined) options.only = only.split(",");
  const transports = take("transports");
  if (transports !== undefined) {
    options.transports = transports.split(",");
    if (options.transports.some((name) => name !== "rest" && name !== "grpc"))
      throw new Error("--transports is rest, grpc or both");
  }
  if (take("service-agent-project-number") !== undefined)
    throw new Error("service agent number must come from environment, never argv");
  const agent = env.PUBSUB_SERVICE_AGENT_PROJECT_NUMBER;
  if (agent !== undefined) {
    if (typeof agent !== "string" || !/^\d{1,20}$/.test(agent))
      throw new Error("service agent environment value must be digits");
    options.serviceAgent = `serviceAccount:service-${agent}@gcp-sa-pubsub.iam.gserviceaccount.com`;
  }
  options.quotaProject = take("quota-project");
  options.suite = take("suite") ?? "unary";
  options.descriptor = take("descriptor");
  options.authority = take("authority");
  if (options.suite === "stream-dlq-v2" && max === undefined) options.maxRequests = 228;
  if (
    options.suite !== "unary" &&
    options.suite !== "stream-dlq" &&
    options.suite !== "stream-dlq-v2"
  )
    throw new Error("--suite must be unary, stream-dlq or stream-dlq-v2");
  if (options.prepare && options.cleanupOnly)
    throw new Error("--prepare does not perform A2 recovery");
  options.fromCapture = take("from-capture");
  options.runId = take("run-id") ?? (options.cleanupOnly ? undefined : newRunId());
  if (options.runId === undefined || !isRunId(options.runId))
    throw new Error("--run-id must be 12 hex digits (required with --cleanup-only)");
  if (options.cleanupOnly) {
    // The later run reads what the recording issued: its capture (for the time) and the ledger beside it.
    if (options.fromCapture === undefined)
      throw new Error("--cleanup-only needs --from-capture <the recording's capture file>");
    if (basename(options.fromCapture) !== `capture-${options.runId}.jsonl`)
      throw new Error("--from-capture must be capture-<run ID>.jsonl of that run");
    options.ledgerPath = join(dirname(options.fromCapture), `issued-${options.runId}.jsonl`);
  } else if (options.fromCapture !== undefined)
    throw new Error("--from-capture is for --cleanup-only");
  options.host = take("emulator-host") ?? env.PUBSUB_EMULATOR_HOST;
  if (!options.production && !/^[^/\s]+:\d+$/.test(options.host ?? ""))
    throw new Error("an emulator target needs --emulator-host or PUBSUB_EMULATOR_HOST (host:port)");
  if (
    options.suite === "stream-dlq-v2" &&
    (options.maxRequests !== 228 || new Set(options.transports).size !== options.transports.length)
  )
    throw new Error("v2 needs228source requests and distinct transports");
  if (
    options.suite === "stream-dlq-v2" &&
    (options.only !== undefined ||
      JSON.stringify(options.transports) !== JSON.stringify(["rest", "grpc"]))
  )
    throw new Error("v2 requires the full fixed packet and both transports");
  if (flags.size > 0) throw new Error(`unknown option --${[...flags.keys()][0]}`);
  return options;
}

/** What a run leaves behind: the counts, the unknown answers, and whether the run can be closed. */
export function summarize({ options, capture, summary }) {
  return {
    runId: options.runId,
    target: options.target,
    project: options.project,
    ...(options.suite === "stream-dlq-v2"
      ? { sourceHead: options.admitted?.sourceHead, envelopeId: options.admitted?.envelopeId }
      : {}),
    requests: capture.count(),
    unknownAnswers: capture.unknownCount(),
    unknowns: capture.unknowns(),
    // Historical unknown counts stay intact; closure uses outstanding request resolutions.
    closureReady:
      summary.stopped === null &&
      (summary.limited ?? []).length === 0 &&
      summary.cleanup.leftover.length === 0 &&
      summary.cleanup.errors.length === 0 &&
      summary.cleanup.unsettled.length === 0 &&
      (summary.cleanup.outstandingActions ?? []).length === 0,
    perCase: capture.perCase(),
    ...summary,
  };
}

const sleep = (ms, signal) => sleepTimer(ms, undefined, { signal });
export function createSignalSleep({ wait = sleep, signals = process } = {}) {
  const controller = new AbortController();
  const stop = () => controller.abort();
  for (const name of ["SIGINT", "SIGTERM"]) signals.on(name, stop);
  return {
    isStopping: () => controller.signal.aborted,
    async sleep(ms) {
      if (controller.signal.aborted) throw new StopClean("stopped by a signal");
      let cancel;
      const stopped = new Promise((_, reject) => {
        cancel = () => reject(new StopClean("stopped by a signal"));
        controller.signal.addEventListener("abort", cancel, { once: true });
      });
      try {
        await Promise.race([wait(ms, controller.signal), stopped]);
        if (controller.signal.aborted) throw new StopClean("stopped by a signal");
      } finally {
        controller.signal.removeEventListener("abort", cancel);
      }
    },
    close() {
      controller.abort();
      for (const name of ["SIGINT", "SIGTERM"]) signals.removeListener(name, stop);
    },
  };
}

/** The time of the last line of a capture, which the later run waits from. */
function lastLineTime(path) {
  const rows = readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));
  const at = Date.parse(rows.at(-1)?.at);
  if (!Number.isFinite(at)) throw new Error("the capture has no readable last line");
  let anchor = at;
  for (const row of rows)
    if (row.note === "request-dispatch") {
      const deadline = Date.parse(row.requestDeadlineAt);
      if (!Number.isFinite(deadline)) throw new Error("unreadable persisted request deadline");
      anchor = Math.max(anchor, deadline);
    }
  return anchor;
}

const stamp = (ms) => new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d+/, "");

export async function main(
  argv,
  env = process.env,
  io = { stdout: process.stdout, stderr: process.stderr },
  deps = { now: Date.now },
) {
  const wait = deps.sleep ?? sleep;
  let options;
  let cases = [];
  let issued = null;
  let suffix = "";
  let a2ElapsedMs;
  let originalDir;
  let originalStart;
  let iamReplay = [];
  try {
    options = parseArgs(argv, env);
    if (!options.cleanupOnly) {
      cases = selectCases(options.only, options.suite);
      createOwnership({ project: options.project, runId: options.runId });
      if (
        options.suite.startsWith("stream-dlq") &&
        cases.some((item) => item.transports.some((name) => !options.transports.includes(name)))
      )
        throw new Error("the selected stream-dlq cases need every required transport");
      assertBudgetCovers(cases, options.transports, options.maxRequests);
      if (options.prepare) {
        io.stdout.write(
          `${JSON.stringify({ noWire: true, suite: options.suite, cases: cases.map(({ id, requests, transports, resources, timeoutMs }) => ({ id, requests, transports, resources, timeoutMs })), requests: cases.reduce((sum, item) => sum + item.requests * options.transports.filter((name) => item.transports === undefined || item.transports.includes(name)).length, 0), cleanupRequests: CLEANUP_BUDGET, a2Requests: CLEANUP_BUDGET, resources: cases.reduce((sum, item) => sum + (item.resources ?? 0), 0), iamWaitAfterGrantMs: options.suite === "stream-dlq-v2" ? IAM_WAIT_MS : null, iamConvergenceClaim: false, iamFiniteUpperBoundMs: IAM_PREREQUISITE.finiteUpperBoundMs })}\n`,
        );
        return 0;
      }
    } else {
      // A recovery cannot select unary to bypass the recorded v2 source/IAM admission.
      const original = readFileSync(options.fromCapture, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line));
      const start = original.find((row) => row.note === "run-start");
      originalStart = start;
      if (start?.suite === "stream-dlq-v2" && options.suite !== "stream-dlq-v2")
        throw new Error("v2 recovery requires --suite stream-dlq-v2");
      if (
        options.suite === "stream-dlq-v2" &&
        (start?.suite !== options.suite ||
          start.target !== options.target ||
          start.project !== options.project ||
          start.runId !== options.runId)
      )
        throw new Error("v2 recovery source identity mismatch");
      // The later run reads the names the recording issued, and waits for the service to settle.
      issued = readLedger(options.ledgerPath, {});
      const waited = deps.now() - lastLineTime(options.fromCapture);
      if (waited < MIN_A2_WAIT_MS)
        throw new Error(
          `--cleanup-only runs at least ${MIN_A2_WAIT_MS / 60000} minutes after the recording (${Math.ceil(waited / 1000)} s so far)`,
        );
      originalDir = dirname(options.fromCapture);
      if (options.suite === "stream-dlq-v2") {
        options.iamPath = join(originalDir, `iam-${options.runId}.jsonl`);
        iamReplay = readFileSync(options.iamPath, "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => JSON.parse(line));
        const own = createOwnership({ project: options.project, runId: options.runId });
        createIamOwnership({
          journal: {
            write() {
              throw new Error("preflight must not append IAM intent");
            },
          },
          assertOwned: (name) => own.assertOwned(name),
          replay: iamReplay,
        });
      }
      const priorA2 = readdirSync(originalDir).some(
        (file) =>
          file.startsWith(`capture-${options.runId}-a2-`) ||
          file.startsWith(`issued-${options.runId}-a2-`) ||
          file === `a2-started-${options.runId}.json`,
      );
      if (priorA2)
        throw new Error(
          "A2 has already started; use a new recovery packet with the full issued history",
        );
      a2ElapsedMs = waited;
      suffix = `-a2-${stamp(deps.now())}`;
    }
    if (options.production && options.suite === "stream-dlq-v2") {
      options.admitted = admitV2(options, deps.now());
      if (options.cleanupOnly) {
        if (
          originalStart.sourceHead !== options.admitted.sourceHead ||
          originalStart.envelopeId !== options.admitted.envelopeId
        )
          throw new Error("v2 recovery original source/envelope mismatch");
        for (const [key, path] of [
          ["captureSha256", options.fromCapture],
          ["issuedSha256", options.ledgerPath],
          ["iamSha256", options.iamPath],
        ])
          if (options.admitted.cleanupRecovery?.[key] !== sha256(readFileSync(path)))
            throw new Error("v2 recovery input digest mismatch");
      }
    }
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
  }
  if (deps.noWire === true) throw new Error("no-wire test guard refused the actual recorder path");
  if (options.production && options.suite === "stream-dlq-v2" && !options.cleanupOnly) {
    try {
      claimSourceRun(options);
    } catch (error) {
      io.stderr.write(`${error.message}\n`);
      return 2;
    }
  }
  if (options.cleanupOnly) {
    // Keep the atomic one-use marker beside the original input even if output is written elsewhere.
    try {
      writeFileSync(
        join(originalDir, `a2-started-${options.runId}.json`),
        `${JSON.stringify({ runId: options.runId, startedAt: new Date(deps.now()).toISOString() })}\n`,
        { flag: "wx", mode: 0o600 },
      );
    } catch (error) {
      if (error.code === "EEXIST") {
        io.stderr.write(
          "A2 has already started; use a new recovery packet with the full issued history\n",
        );
        return 2;
      }
      io.stderr.write(`${error.message}\n`);
      return 2;
    }
  }
  mkdirSync(options.out, { recursive: true, mode: 0o700 });
  const journal = createFileJournal(join(options.out, `capture-${options.runId}${suffix}.jsonl`));
  const capture = createCapture({ journal });
  const ledgerJournal = createFileJournal(
    join(options.out, `issued-${options.runId}${suffix}.jsonl`),
  );
  // The later run keeps the names it read, and adds what it sends.
  const ledger =
    issued === null ? createLedger({ journal: ledgerJournal }) : issued.withJournal(ledgerJournal);
  const budget = createBudget(options.maxRequests);
  const cleanupBudget = createBudget(CLEANUP_BUDGET);
  const token = options.production ? createTokenProvider() : null;
  const common = {
    capture,
    getToken: token === null ? null : () => token.get(),
    quotaProject: options.quotaProject ?? null,
    journalDispatch: options.suite === "stream-dlq-v2",
  };
  const rest = options.production ? PRODUCTION.rest : `http://${options.host}`;
  const grpcTarget = options.production ? PRODUCTION.grpc : options.host;
  const transports = { rest: createRest({ base: rest, budget, ...common }) };
  const cleanupPhase = options.suite.startsWith("stream-dlq")
    ? createPhaseLimit(600_000, deps.monotonicNow)
    : null;
  const cleanupRawTransport = createRest({ base: rest, budget: cleanupBudget, ...common });
  const cleanupRestTransport =
    cleanupPhase === null ? cleanupRawTransport : cleanupPhase.transport(cleanupRawTransport);
  const grpc = createGrpc({ target: grpcTarget, secure: options.production, budget, ...common });
  transports.grpc = grpc;
  const ownership = createOwnership({ project: options.project, runId: options.runId });
  if (issued !== null)
    // A name that is not the run's by prefix (a probe) is changeable only if the run's own creation of
    // it, or of its deletion, may have happened; a conflict or a refusal never makes it ours.
    for (const [name, item] of issued.state())
      if (!ownership.isOwned(name) && (maybeCreated(item) || maybeDeleting(item)))
        ownership.registerProbe(name);
  const iamJournal =
    options.suite === "stream-dlq-v2"
      ? createFileJournal(join(options.out, `iam-${options.runId}${suffix}.jsonl`))
      : null;
  if (iamJournal) {
    const replay = iamReplay;
    options.iam = createIamOwnership({
      journal: iamJournal,
      assertOwned: (name) => ownership.assertOwned(name),
      now: deps.monotonicNow,
      replay,
      reportEvidence: (data) => capture.note("iam-evidence", data),
    });
    options.monotonicNow = deps.monotonicNow;
  }
  const pushState = newPushState();
  const cleanupRest = createClient({
    transport: cleanupRestTransport,
    ownership,
    pushState,
    caseId: "cleanup",
    ledger,
  });
  const signalWait = createSignalSleep({ wait, signals: deps.signals ?? process });
  capture.note("run-start", {
    runId: options.runId,
    target: options.target,
    project: options.project,
    maxRequests: options.maxRequests,
    suite: options.suite,
    ...(options.suite === "stream-dlq-v2"
      ? { sourceHead: options.admitted?.sourceHead, envelopeId: options.admitted?.envelopeId }
      : {}),
    cleanupOnly: options.cleanupOnly === true,
  });
  let summary;
  try {
    if (options.cleanupOnly) {
      const iamReport = options.iam ? await options.iam.restore(cleanupRest) : { unsettled: [] };
      summary = {
        cases: [],
        stopped: null,
        limited: [],
        cleanup: await cleanup({
          client: cleanupRest,
          ownership,
          project: options.project,
          ledger,
          sleep: cleanupPhase === null ? wait : cleanupPhase.sleep(wait),
          a2ElapsedMs,
          protectedNames: new Set(iamReport.unsettled.map((entry) => entry.resource)),
        }),
      };
      summary.iam = iamReport;
      if (iamReport.unsettled.length)
        summary.cleanup.errors.push("IAM restoration unresolved; retain lock");
    } else
      summary = await runCases({
        cases,
        transportNames: options.transports,
        transports,
        cleanupRest,
        ownership,
        pushState,
        capture,
        options,
        sleep: signalWait.sleep,
        ledger,
        isStopping: signalWait.isStopping,
        cleanupSleep: cleanupPhase === null ? wait : cleanupPhase.sleep(wait),
      });
  } finally {
    signalWait.close();
    grpc.close();
    iamJournal?.close();
  }
  const result = summarize({ options, capture, summary });
  capture.note("run-end", { requests: result.requests, stopped: result.stopped });
  journal.close();
  ledgerJournal.close();
  writeFileSync(
    join(options.out, `summary-${options.runId}${suffix}.json`),
    `${JSON.stringify(result, null, 2)}\n`,
    { mode: 0o600 },
  );
  io.stdout.write(
    `${JSON.stringify({ runId: result.runId, requests: result.requests, stopped: result.stopped, closureReady: result.closureReady, cleanup: { deleted: summary.cleanup.deleted.length, leftover: summary.cleanup.leftover, errors: summary.cleanup.errors, unsettled: summary.cleanup.unsettled } })}\n`,
  );
  return exitCodeOf(summary);
}

if (import.meta.url === `file://${process.argv[1]}`)
  process.exitCode = await main(process.argv.slice(2));
