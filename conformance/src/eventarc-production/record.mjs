// The plain production recorder for the stage B of Eventarc, without any deploy: the channel created with
// its name, its lifecycle, publishEvents to a channel that exists (envelope, content, limits), the Admin
// SDK publish and the credential errors, over REST, with the raw bytes of every answer. Every exchange is
// captured as it happens, and every channel the run created is deleted by prefix at the end with the
// long-running operation polled to done and the 404 read back.
//
//   node record.mjs --target emulator --out <dir>                    (CLOUD_EVENTARC_EMULATOR_HOST)
//   node record.mjs --target production --project <id> --out <dir> [--project-number <n>]
//   node record.mjs --target production --project <id> --out <dir> --cleanup-only --run-id <12 hex>
//
// Exit codes: 0 done, 1 cleanup left something, 2 usage, 3 stopped clean (a signal), 4 the budget was spent.

import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve as resolvePath } from "node:path";
import { createBudget, createCapture, createFileJournal } from "../pubsub-production/capture.mjs";
import { createLedger } from "../pubsub-production/ledger.mjs";
import { createTokenProvider } from "../pubsub-production/token.mjs";
import { cleanup, ledgerFacts } from "./cleanup.mjs";
import { createClient } from "./client.mjs";
import { createOwnership, isRunId, newRunId } from "./names.mjs";
import { createRawRest } from "./rest.mjs";
import { createScopedToken } from "./scoped-token.mjs";
import { assertBudgetCovers, exitCodeOf, runCases, selectCases } from "./runner.mjs";
import { directoryOf, ledgerFilesOf, readLedgerFiles } from "./ledger-files.mjs";
import { createSdk } from "./sdk.mjs";

const PRODUCTION = {
  eventarc: "https://eventarc.googleapis.com",
  publishing: "https://eventarcpublishing.googleapis.com",
  usage: "https://serviceusage.googleapis.com",
};
export const DEFAULT_MAX_REQUESTS = 280;
export const CLEANUP_BUDGET = 300;
/** The later --cleanup-only run starts at least this long after the recording's last line. */
export const MIN_A2_WAIT_MS = 10 * 60 * 1000;

/**
 * The names of a ledger that a later run may change although they carry no run prefix: the run's own
 * creation of one, or a deletion of one, may have happened (a conflict or a refusal never makes it ours).
 */
export function probesToRegister(state, ownership) {
  const names = [];
  for (const [name, item] of state) {
    const facts = ledgerFacts(item);
    if (!ownership.isOwned(name) && (facts.mayExist || facts.deleteSent)) names.push(name);
  }
  return names;
}

export function parseArgs(argv, env = {}) {
  const options = { maxRequests: DEFAULT_MAX_REQUESTS };
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
  options.project = take("project") ?? (options.production ? undefined : "demo-fireemu-eventarc");
  if (options.project === undefined) throw new Error("--project is required for production");
  options.out = take("out");
  if (options.out === undefined) throw new Error("--out is required");
  const max = take("max-requests");
  if (max !== undefined) options.maxRequests = Number(max);
  if (!Number.isSafeInteger(options.maxRequests) || options.maxRequests <= 0)
    throw new Error("--max-requests must be a positive integer");
  const only = take("only");
  if (only !== undefined) options.only = only.split(",");
  const number = take("project-number");
  if (number !== undefined && !/^\d{1,20}$/.test(number))
    throw new Error("--project-number is digits");
  options.usageProject = number ?? options.project;
  options.location = take("location") ?? "us-central1";
  if (!/^[a-z][a-z0-9-]{1,40}$/.test(options.location))
    throw new Error("--location is not a location");
  options.fromCapture = take("from-capture");
  options.quotaProject =
    take("quota-project") ?? (options.production ? options.project : undefined);
  options.runId = take("run-id") ?? (options.cleanupOnly ? undefined : newRunId());
  if (options.runId === undefined || !isRunId(options.runId))
    throw new Error("--run-id must be 12 hex digits (required with --cleanup-only)");
  if (options.cleanupOnly) {
    // The later run reads what the recording issued: its capture (for the time) and the ledger beside it.
    if (options.fromCapture === undefined)
      throw new Error("--cleanup-only needs --from-capture <the recording's capture file>");
    if (basename(options.fromCapture) !== `capture-${options.runId}.jsonl`)
      throw new Error("--from-capture must be capture-<run ID>.jsonl of that run");
    // The later run reads the ledgers of the recording and of every earlier later run from the directory
    // of the capture, and writes its own beside them: a different --out would hide the earlier ones.
    if (resolvePath(options.out) !== resolvePath(dirname(options.fromCapture)))
      throw new Error("--out must be the directory of --from-capture (the recording's directory)");
    options.ledgerPath = join(dirname(options.fromCapture), `issued-${options.runId}.jsonl`);
  } else if (options.fromCapture !== undefined)
    throw new Error("--from-capture is for --cleanup-only");
  options.host = take("emulator-host") ?? env.CLOUD_EVENTARC_EMULATOR_HOST;
  if (!options.production && !/^(https?:\/\/)?[^/\s]+:\d+$/.test(options.host ?? ""))
    throw new Error(
      "an emulator target needs --emulator-host or CLOUD_EVENTARC_EMULATOR_HOST (host:port)",
    );
  options.publishPrefix = options.production ? "/v1" : "";
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

/** The time of the last line of a capture. */
function lastLineTime(path) {
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "");
  const at = Date.parse(JSON.parse(lines.at(-1) ?? "{}").at);
  if (Number.isNaN(at)) throw new Error("the capture has no readable last line");
  return at;
}

/**
 * The time of the last line of the newest capture of the run in the directory (the recording's, or an
 * earlier later run's), which the later run waits from.
 */
function newestCaptureTime(directory, runId) {
  const pattern = new RegExp(`^capture-${runId}(-a2-\\d{8}T\\d{6}Z)?\\.jsonl$`);
  const files = readdirSync(directory).filter((name) => pattern.test(name));
  return Math.max(...files.map((name) => lastLineTime(join(directory, name))));
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
      assertBudgetCovers(cases, options.maxRequests);
    } else {
      // The later run reads the channels the recording issued, and waits for the service to settle.
      // The recording's ledger and those of the later runs before this one.
      issued = readLedgerFiles(ledgerFilesOf(directoryOf(options.fromCapture), options.runId), {});
      const waited =
        deps.now() - newestCaptureTime(directoryOf(options.fromCapture), options.runId);
      if (waited < MIN_A2_WAIT_MS)
        throw new Error(
          `--cleanup-only runs at least ${MIN_A2_WAIT_MS / 60000} minutes after the recording and the earlier later runs (${Math.ceil(waited / 1000)} s so far)`,
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
    issued === null
      ? createLedger({ journal: ledgerJournal })
      : issued.ledger.withJournal(ledgerJournal);
  const token = options.production ? createTokenProvider() : null;
  const getToken = token === null ? null : () => token.get();
  const base = (key) =>
    options.production
      ? PRODUCTION[key]
      : options.host.startsWith("http")
        ? options.host
        : `http://${options.host}`;
  const makeTransports = (budget) =>
    Object.fromEntries(
      ["eventarc", "publishing", "usage"].map((key) => [
        key,
        createRawRest({
          base: base(key),
          budget,
          capture,
          getToken,
          quotaProject: options.quotaProject,
        }),
      ]),
    );
  const budget = createBudget(options.maxRequests);
  const transports = makeTransports(budget);
  const cleanupTransports = makeTransports(createBudget(CLEANUP_BUDGET));
  const ownership = createOwnership({ project: options.project, runId: options.runId });
  if (issued !== null) {
    // A name that is not the run's by prefix (a probe) is changeable only if the run's own creation of
    // it, or of its deletion, may have happened; a conflict or a refusal never makes it ours. None is
    // listed: only the location the run records in is.
    for (const name of probesToRegister(issued.ledger.state(), ownership))
      ownership.registerProbe(name, { listable: false });
    ownership.channel(options.location, "cleanup-only");
  }
  const cleanupClient = createClient({
    transports: cleanupTransports,
    ownership,
    caseId: "cleanup",
    usageProject: options.usageProject,
    publishPrefix: options.publishPrefix,
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
  const makeSdk = (parts) =>
    createSdk({
      project: options.project,
      runId: options.runId,
      getToken: getToken ?? (async () => "local-emulator-token"),
      publishPrefix: options.publishPrefix,
      ...parts,
    });
  const summary = options.cleanupOnly
    ? {
        cases: [],
        stopped: null,
        limited: [],
        cleanup: await cleanup({
          client: cleanupClient,
          ownership,
          project: options.project,
          ledger,
          sleep: wait,
          mode: "later",
          noDelete: issued.deletedByLater,
        }),
      }
    : await runCases({
        cases,
        transports,
        cleanupClient,
        ownership,
        capture,
        options,
        sleep: wait,
        makeSdk,
        scopedToken: options.production ? createScopedToken() : async () => null,
        ledger,
        isStopping: () => stopping,
      });
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
    `${JSON.stringify({ runId: result.runId, requests: result.requests, stopped: result.stopped, closureReady: result.closureReady, cleanup: { deleted: summary.cleanup.deleted.length, leftover: summary.cleanup.leftover, errors: summary.cleanup.errors, unsettled: summary.cleanup.unsettled, unconfirmed: summary.cleanup.unconfirmed } })}\n`,
  );
  return exitCodeOf(summary);
}

if (import.meta.url === `file://${process.argv[1]}`)
  process.exitCode = await main(process.argv.slice(2));
