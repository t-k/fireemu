// Runs the cases against one target and then cleans up by prefix. A case never fails the run: it is
// recorded as aborted when a step it depends on did not answer as needed. A spent budget, a missing
// precondition (StopClean) and a signal stop the run; the cleanup runs after every one of them.

import { BudgetExceeded } from "../pubsub-production/capture.mjs";
import { CaseAbort, StopClean } from "./cases/support.mjs";
import { CASES } from "./cases/index.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient } from "./client.mjs";
import { createLedger } from "../pubsub-production/ledger.mjs";

export function selectCases(only) {
  if (only === undefined) return CASES;
  const wanted = new Set(only);
  const known = new Set(CASES.map((item) => item.id));
  for (const id of wanted) if (!known.has(id)) throw new Error(`unknown case ${id}`);
  return CASES.filter((item) => wanted.has(item.id));
}

/** A case reached the number of requests it declared: its ceiling is a maximum, not a hint. */
export class CaseLimit extends Error {
  constructor(limit) {
    super(`the case reached its limit of ${limit} requests`);
    this.name = "CaseLimit";
    /** Refused before anything was sent. */
    this.unsent = true;
  }
}

/** The same transport, refusing (before the budget is touched) the request after the case's limit. */
function limited(transport, meter, limit) {
  return {
    ...transport,
    request: (call) => {
      if (meter.used >= limit) throw new CaseLimit(limit);
      meter.used += 1;
      return transport.request(call);
    },
  };
}

export const plannedRequests = (cases) => cases.reduce((sum, item) => sum + item.requests, 0);

/** A run that would stop on its budget is not started. */
export function assertBudgetCovers(cases, maxRequests) {
  const planned = plannedRequests(cases);
  if (planned > maxRequests)
    throw new Error(
      `the selected cases may send ${planned} requests, over --max-requests ${maxRequests}`,
    );
}

function createContext({
  item,
  transports,
  ownership,
  capture,
  options,
  sleep,
  makeSdk,
  ledger,
  scopedToken,
}) {
  const caseId = item.id;
  const meter = { used: 0 };
  const guarded = Object.fromEntries(
    Object.entries(transports).map(([name, transport]) => [
      name,
      limited(transport, meter, item.requests),
    ]),
  );
  // The Admin SDK forwarder is made for this case at its first use and closed when the case ends.
  let forwarder = null;
  const note = (kind, data) => capture.note(kind, { case: caseId, ...data });
  const sdk =
    makeSdk === null
      ? null
      : {
          publish: async (spec) => {
            forwarder ??= await makeSdk({
              caseId,
              transport: guarded.publishing,
              ownership,
              note,
            });
            return forwarder.publish(spec);
          },
        };
  const context = {
    caseId,
    project: ownership.project,
    location: options.location,
    production: options.production,
    // The project number in the path of a call, given at run time and never written down (null when the
    // run was given none): the usage project is the number when `--project-number` was passed.
    projectNumber: options.usageProject === ownership.project ? null : options.usageProject,
    /** A real token of `scope`, or null when none can be had: it is never recorded. */
    scopedToken,
    ownership,
    sdk,
    client: createClient({
      ledger,
      transports: guarded,
      ownership,
      caseId,
      usageProject: options.usageProject,
      publishPrefix: options.publishPrefix,
    }),
    channel: (key) => ownership.channel(options.location, `${item.short}-${key}`),
    /** A channel ID sent on purpose that cannot carry the prefix, registered before it is sent. */
    probe: (id, { location = options.location, listable = true } = {}) =>
      ownership.registerProbe(
        `projects/${ownership.project}/locations/${location}/channels/${id}`,
        {
          listable,
        },
      ),
    /** A channel that is not the run's, which may be published to (never deleted): the default channel. */
    publishTarget: (id) =>
      ownership.allowPublish(
        `projects/${ownership.project}/locations/${options.location}/channels/${id}`,
      ),
    sleep,
    note,
  };
  return { context, closeSdk: async () => forwarder?.close() };
}

export async function runCases({
  cases,
  transports,
  cleanupClient,
  ownership,
  capture,
  options,
  sleep,
  makeSdk = null,
  scopedToken = async () => null,
  ledger = createLedger(),
  isStopping = () => false,
}) {
  const summary = { cases: [], stopped: null, limited: [], cleanup: null };
  const stoppable = async (ms) => {
    if (isStopping()) throw new StopClean("stopped by a signal");
    await sleep(ms);
  };
  for (const item of cases) {
    if (isStopping()) {
      summary.stopped = "signal";
      break;
    }
    const before = capture.count();
    const entry = { id: item.id, outcome: "completed" };
    capture.note("case-start", { case: item.id });
    const { context, closeSdk } = createContext({
      item,
      transports,
      ownership,
      capture,
      options,
      sleep: stoppable,
      makeSdk,
      ledger,
      scopedToken,
    });
    try {
      await item.run(context);
    } catch (error) {
      if (error instanceof CaseAbort) {
        entry.outcome = "aborted";
        entry.reason = error.message;
      } else if (error instanceof StopClean) {
        entry.outcome = "stopped";
        entry.reason = error.message;
        summary.stopped = error.message;
      } else if (error instanceof CaseLimit) {
        entry.outcome = "limit";
        entry.reason = error.message;
        summary.limited.push(item.id);
      } else if (error instanceof BudgetExceeded) {
        entry.outcome = "budget";
        entry.reason = error.message;
        summary.stopped = error.message;
      } else {
        entry.outcome = "error";
        entry.reason = `${error?.name ?? "Error"}: ${String(error?.message ?? error).slice(0, 300)}`;
      }
    }
    // The forwarder of the case is closed whatever the case did.
    await closeSdk().catch(() => {});
    entry.requests = capture.count() - before;
    capture.note("case-end", { case: item.id, ...entry });
    summary.cases.push(entry);
    if (summary.stopped !== null && entry.outcome !== "aborted") break;
  }
  summary.cleanup = await cleanup({
    client: cleanupClient,
    ownership,
    project: ownership.project,
    ledger,
    sleep,
  });
  return summary;
}

export function exitCodeOf(summary) {
  if (summary.cleanup.leftover.length > 0 || summary.cleanup.errors.length > 0) return 1;
  if (summary.stopped !== null) return summary.stopped.includes("budget") ? 4 : 3;
  return 0;
}
