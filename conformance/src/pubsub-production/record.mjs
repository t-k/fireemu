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

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createBudget, createCapture, createFileJournal } from "./capture.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient, newPushState } from "./client.mjs";
import { createGrpc } from "./grpc.mjs";
import { createOwnership, isRunId, newRunId } from "./names.mjs";
import { createRest } from "./rest.mjs";
import { assertBudgetCovers, exitCodeOf, runCases, selectCases } from "./runner.mjs";
import { createTokenProvider } from "./token.mjs";

const PRODUCTION = { rest: "https://pubsub.googleapis.com", grpc: "pubsub.googleapis.com:443" };
export const DEFAULT_MAX_REQUESTS = 850;
export const CLEANUP_BUDGET = 400;

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
  options.runId = take("run-id") ?? (options.cleanupOnly ? undefined : newRunId());
  if (options.runId === undefined || !isRunId(options.runId))
    throw new Error("--run-id must be 12 hex digits (required with --cleanup-only)");
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
      assertBudgetCovers(cases, options.transports, options.maxRequests);
    }
  } catch (error) {
    io.stderr.write(`${error.message}\n`);
    return 2;
  }
  mkdirSync(options.out, { recursive: true, mode: 0o700 });
  const journal = createFileJournal(join(options.out, `capture-${options.runId}.jsonl`));
  const capture = createCapture({ journal });
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
  const pushState = newPushState();
  const cleanupRest = createClient({
    transport: cleanupRestTransport,
    ownership,
    pushState,
    caseId: "cleanup",
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
        cleanup: await cleanup({
          client: cleanupRest,
          ownership,
          project: options.project,
          known: [],
          sleep,
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
        sleep,
        isStopping: () => stopping,
      });
  } finally {
    grpc.close();
  }
  const result = summarize({ options, capture, summary });
  capture.note("run-end", { requests: result.requests, stopped: result.stopped });
  journal.close();
  writeFileSync(
    join(options.out, `summary-${options.runId}.json`),
    `${JSON.stringify(result, null, 2)}\n`,
    { mode: 0o600 },
  );
  io.stdout.write(
    `${JSON.stringify({ runId: result.runId, requests: result.requests, stopped: result.stopped, cleanup: { deleted: summary.cleanup.deleted.length, leftover: summary.cleanup.leftover, errors: summary.cleanup.errors } })}\n`,
  );
  return exitCodeOf(summary);
}

if (import.meta.url === `file://${process.argv[1]}`)
  process.exitCode = await main(process.argv.slice(2));
