// Runs the cases against one target and then cleans up by prefix. A case never fails the run: it is
// recorded as aborted when a step it depends on did not answer as needed. A spent budget, a missing
// precondition (StopClean) and a signal stop the run; the cleanup runs after every one of them.

import { BudgetExceeded } from "../pubsub-production/capture.mjs";
import { CaseAbort, StopClean } from "./cases/support.mjs";
import { CASES } from "./cases/index.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient } from "./client.mjs";

export function selectCases(only) {
  if (only === undefined) return CASES;
  const wanted = new Set(only);
  const known = new Set(CASES.map((item) => item.id));
  for (const id of wanted) if (!known.has(id)) throw new Error(`unknown case ${id}`);
  return CASES.filter((item) => wanted.has(item.id));
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

function createContext({ item, transports, ownership, capture, options, sleep, sdk }) {
  const caseId = item.id;
  return {
    caseId,
    project: ownership.project,
    location: options.location,
    production: options.production,
    ownership,
    sdk,
    client: createClient({
      transports,
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
    note: (kind, data) => capture.note(kind, { case: caseId, ...data }),
  };
}

export async function runCases({
  cases,
  transports,
  cleanupClient,
  ownership,
  capture,
  options,
  sleep,
  sdk = null,
  isStopping = () => false,
}) {
  const summary = { cases: [], stopped: null, cleanup: null };
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
    try {
      await item.run(
        createContext({ item, transports, ownership, capture, options, sleep: stoppable, sdk }),
      );
    } catch (error) {
      if (error instanceof CaseAbort) {
        entry.outcome = "aborted";
        entry.reason = error.message;
      } else if (error instanceof StopClean) {
        entry.outcome = "stopped";
        entry.reason = error.message;
        summary.stopped = error.message;
      } else if (error instanceof BudgetExceeded) {
        entry.outcome = "budget";
        entry.reason = error.message;
        summary.stopped = error.message;
      } else {
        entry.outcome = "error";
        entry.reason = `${error?.name ?? "Error"}: ${String(error?.message ?? error).slice(0, 300)}`;
      }
    }
    entry.requests = capture.count() - before;
    if (entry.requests > item.requests) entry.overDeclared = item.requests;
    capture.note("case-end", { case: item.id, ...entry });
    summary.cases.push(entry);
    if (summary.stopped !== null && entry.outcome !== "aborted") break;
  }
  summary.cleanup = await cleanup({
    client: cleanupClient,
    ownership,
    project: ownership.project,
    sleep,
  });
  return summary;
}

export function exitCodeOf(summary) {
  if (summary.cleanup.leftover.length > 0 || summary.cleanup.errors.length > 0) return 1;
  if (summary.stopped !== null) return summary.stopped.includes("budget") ? 4 : 3;
  return 0;
}
