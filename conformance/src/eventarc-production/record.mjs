// The plain production recorder for the stage A of Eventarc, without any deploy: the state of the
// publishing API and its enabling, channel lifecycle, publishEvents (envelope, content, limits), the Admin
// SDK publish and the credential errors, over REST. Every exchange is captured as it happens, and every
// channel the run created is deleted by prefix at the end with the long-running operation polled to done
// and the 404 read back.
//
//   node record.mjs --target emulator --out <dir>                    (CLOUD_EVENTARC_EMULATOR_HOST)
//   node record.mjs --target production --project <id> --out <dir> [--project-number <n>]
//   node record.mjs --target production --project <id> --out <dir> --cleanup-only --run-id <12 hex>
//
// Exit codes: 0 done, 1 cleanup left something, 2 usage, 3 stopped clean (a signal), 4 the budget was spent.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createBudget, createCapture, createFileJournal } from "../pubsub-production/capture.mjs";
import { createRest } from "../pubsub-production/rest.mjs";
import { createTokenProvider } from "../pubsub-production/token.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient } from "./client.mjs";
import { createOwnership, isRunId, newRunId } from "./names.mjs";
import { assertBudgetCovers, exitCodeOf, runCases, selectCases } from "./runner.mjs";
import { createSdk } from "./sdk.mjs";

const PRODUCTION = {
  eventarc: "https://eventarc.googleapis.com",
  publishing: "https://eventarcpublishing.googleapis.com",
  usage: "https://serviceusage.googleapis.com",
};
export const DEFAULT_MAX_REQUESTS = 140;
export const CLEANUP_BUDGET = 60;

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
  options.runId = take("run-id") ?? (options.cleanupOnly ? undefined : newRunId());
  if (options.runId === undefined || !isRunId(options.runId))
    throw new Error("--run-id must be 12 hex digits (required with --cleanup-only)");
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
      summary.cleanup.leftover.length === 0 &&
      summary.cleanup.errors.length === 0,
    perCase: capture.perCase(),
    ...summary,
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function main(
  argv,
  env = process.env,
  io = { stdout: process.stdout, stderr: process.stderr },
) {
  let options;
  let cases = [];
  try {
    options = parseArgs(argv, env);
    if (!options.cleanupOnly) {
      cases = selectCases(options.only);
      assertBudgetCovers(cases, options.maxRequests);
    }
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
  }
  mkdirSync(options.out, { recursive: true, mode: 0o700 });
  const journal = createFileJournal(join(options.out, `capture-${options.runId}.jsonl`));
  const capture = createCapture({ journal });
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
        createRest({ base: base(key), budget, capture, getToken }),
      ]),
    );
  const budget = createBudget(options.maxRequests);
  const transports = makeTransports(budget);
  const cleanupTransports = makeTransports(createBudget(CLEANUP_BUDGET));
  const ownership = createOwnership({ project: options.project, runId: options.runId });
  const cleanupClient = createClient({
    transports: cleanupTransports,
    ownership,
    caseId: "cleanup",
    usageProject: options.usageProject,
    publishPrefix: options.publishPrefix,
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
  let sdk = null;
  try {
    if (options.cleanupOnly) {
      // The cleanup names the locations of the run; a later cleanup-only run has none, so it lists the one given.
      ownership.channel(options.location, "cleanup-only");
      summary = {
        cases: [],
        stopped: null,
        cleanup: await cleanup({
          client: cleanupClient,
          ownership,
          project: options.project,
          sleep,
        }),
      };
    } else {
      sdk = await createSdk({
        project: options.project,
        runId: options.runId,
        getToken: getToken ?? (async () => "local-emulator-token"),
        publishing: transports.publishing,
        publishPrefix: options.publishPrefix,
      });
      summary = await runCases({
        cases,
        transports,
        cleanupClient,
        ownership,
        capture,
        options,
        sleep,
        sdk,
        isStopping: () => stopping,
      });
    }
  } finally {
    if (sdk !== null) await sdk.close();
  }
  const result = summarize({ options, capture, summary });
  capture.note("run-end", { requests: result.requests, stopped: result.stopped });
  journal.close();
  writeFileSync(
    join(options.out, `summary-${options.runId}.json`),
    `${JSON.stringify(result, null, 2)}\n`,
    {
      mode: 0o600,
    },
  );
  io.stdout.write(
    `${JSON.stringify({ runId: result.runId, requests: result.requests, stopped: result.stopped, cleanup: { deleted: summary.cleanup.deleted.length, leftover: summary.cleanup.leftover, errors: summary.cleanup.errors } })}\n`,
  );
  return exitCodeOf(summary);
}

if (import.meta.url === `file://${process.argv[1]}`)
  process.exitCode = await main(process.argv.slice(2));
