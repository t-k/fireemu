// The plain production recorder for Pub/Sub: unary REST and gRPC conditions against one target, every
// exchange captured as it happens, and everything the run created deleted by prefix at the end with the
// 404s read back. It sends nothing to a push endpoint (no publish to a topic with a push subscription).
//
//   node record.mjs --target emulator --out <dir>                       (PUBSUB_EMULATOR_HOST)
//   node record.mjs --target production --project <id> --out <dir> [--service-agent-project-number <n>]
//   node record.mjs --target production --project <id> --out <dir> --cleanup-only --run-id <12 hex>
//
// Exit codes: 0 done, 1 cleanup left something, 2 usage, 3 stopped clean on a missing precondition or a
// signal, 4 the request budget was spent.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createBudget, createCapture, createFileJournal } from "./capture.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient, newPushState } from "./client.mjs";
import { createGrpc } from "./grpc.mjs";
import { createLedger, maybeCreated, maybeDeleting, readLedger } from "./ledger.mjs";
import { createOwnership, isRunId, newRunId } from "./names.mjs";
import { createRest } from "./rest.mjs";
import { assertBudgetCovers, exitCodeOf, runCases, selectCases } from "./runner.mjs";
import { createTokenProvider } from "./token.mjs";

const PRODUCTION = { rest: "https://pubsub.googleapis.com", grpc: "pubsub.googleapis.com:443" };
export const DEFAULT_MAX_REQUESTS = 1010;
export const CLEANUP_BUDGET = 600;
/** The later --cleanup-only run starts at least this long after the recording's last line. */
export const MIN_A2_WAIT_MS = 10 * 60 * 1000;

export function parseArgs(argv, env = {}) {
  const options = { transports: ["rest", "grpc"], maxRequests: DEFAULT_MAX_REQUESTS };
  const flags = new Map();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--cleanup-only") options.cleanupOnly = true;
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
  const agent = take("service-agent-project-number");
  if (agent !== undefined) {
    if (!/^\d{1,20}$/.test(agent)) throw new Error("--service-agent-project-number is digits");
    options.serviceAgent = `serviceAccount:service-${agent}@gcp-sa-pubsub.iam.gserviceaccount.com`;
  }
  options.quotaProject = take("quota-project");
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
  if (flags.size > 0) throw new Error(`unknown option --${[...flags.keys()][0]}`);
  return options;
}

/** What a run leaves behind: the counts, the unknown answers, and whether the run can be closed. */
export function summarize({ options, capture, summary }) {
  return {
    runId: options.runId,
    target: options.target,
    project: options.project,
    requests: capture.count(),
    unknownAnswers: capture.unknownCount(),
    unknowns: capture.unknowns(),
    // An unknown answer to a creation or a deletion is only settled by a separate read-back later.
    closureReady:
      capture.unknownCount() === 0 &&
      summary.stopped === null &&
      (summary.limited ?? []).length === 0 &&
      summary.cleanup.leftover.length === 0 &&
      summary.cleanup.errors.length === 0 &&
      summary.cleanup.unsettled.length === 0,
    perCase: capture.perCase(),
    ...summary,
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The time of the last line of a capture, which the later run waits from. */
function lastLineTime(path) {
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "");
  const at = Date.parse(JSON.parse(lines.at(-1) ?? "{}").at);
  if (Number.isNaN(at)) throw new Error("the capture has no readable last line");
  return at;
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
  try {
    options = parseArgs(argv, env);
    if (!options.cleanupOnly) {
      cases = selectCases(options.only);
      assertBudgetCovers(cases, options.transports, options.maxRequests);
    } else {
      // The later run reads the names the recording issued, and waits for the service to settle.
      issued = readLedger(options.ledgerPath, {});
      const waited = deps.now() - lastLineTime(options.fromCapture);
      if (waited < MIN_A2_WAIT_MS)
        throw new Error(
          `--cleanup-only runs at least ${MIN_A2_WAIT_MS / 60000} minutes after the recording (${Math.ceil(waited / 1000)} s so far)`,
        );
      suffix = `-a2-${stamp(deps.now())}`;
    }
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
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
  };
  const rest = options.production ? PRODUCTION.rest : `http://${options.host}`;
  const grpcTarget = options.production ? PRODUCTION.grpc : options.host;
  const transports = { rest: createRest({ base: rest, budget, ...common }) };
  const cleanupRestTransport = createRest({ base: rest, budget: cleanupBudget, ...common });
  const grpc = createGrpc({ target: grpcTarget, secure: options.production, budget, ...common });
  transports.grpc = grpc;
  const ownership = createOwnership({ project: options.project, runId: options.runId });
  if (issued !== null)
    // A name that is not the run's by prefix (a probe) is changeable only if the run's own creation of
    // it, or of its deletion, may have happened; a conflict or a refusal never makes it ours.
    for (const [name, item] of issued.state())
      if (!ownership.isOwned(name) && (maybeCreated(item) || maybeDeleting(item)))
        ownership.registerProbe(name);
  const pushState = newPushState();
  const cleanupRest = createClient({
    transport: cleanupRestTransport,
    ownership,
    pushState,
    caseId: "cleanup",
    ledger,
  });
  let stopping = false;
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => (stopping = true));
  capture.note("run-start", {
    runId: options.runId,
    target: options.target,
    project: options.project,
    maxRequests: options.maxRequests,
    cleanupOnly: options.cleanupOnly === true,
  });
  let summary;
  try {
    if (options.cleanupOnly)
      summary = {
        cases: [],
        stopped: null,
        limited: [],
        cleanup: await cleanup({
          client: cleanupRest,
          ownership,
          project: options.project,
          ledger,
          sleep: wait,
        }),
      };
    else
      summary = await runCases({
        cases,
        transportNames: options.transports,
        transports,
        cleanupRest,
        ownership,
        pushState,
        capture,
        options,
        sleep: wait,
        ledger,
        isStopping: () => stopping,
      });
  } finally {
    grpc.close();
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
