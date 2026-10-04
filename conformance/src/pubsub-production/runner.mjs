// Runs the cases against one target, once for each transport, then cleans up by prefix. A case never
// fails the run: it is recorded as aborted when a step it depends on did not answer as needed. What stops
// the run is a budget that is spent, a missing precondition (StopClean) or a signal; the cleanup runs in
// every one of these.

import { BudgetExceeded } from "./capture.mjs";
import { CASES } from "./cases/index.mjs";
import { CaseAbort, StopClean } from "./cases/support.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient } from "./client.mjs";

const REST_AND_GRPC = ["rest", "grpc"];

export function selectCases(only) {
  if (only === undefined) return CASES;
  const wanted = new Set(only);
  const known = new Set(CASES.map((item) => item.id));
  for (const id of wanted) if (!known.has(id)) throw new Error(`unknown case ${id}`);
  return CASES.filter((item) => wanted.has(item.id));
}

/** The context a case gets: its clients, names that carry the run's prefix, and the notes it may add. */
function createContext({
  item,
  transportName,
  transports,
  ownership,
  pushState,
  capture,
  options,
  sleep,
}) {
  const tag = `${item.short}-${transportName === "rest" ? "r" : "g"}-`;
  const caseId = `${item.id}/${transportName}`;
  const clientOf = (transport, id) => createClient({ transport, ownership, pushState, caseId: id });
  return {
    transport: transportName,
    project: ownership.project,
    production: options.production,
    serviceAgent: options.serviceAgent ?? null,
    client: clientOf(transports[transportName], caseId),
    // IAM is only available over REST, whichever transport the case is recording.
    rest: clientOf(transports.rest, `${caseId}/rest`),
    maxKeyLength: 255 - (ownership.prefix.length + tag.length),
    name: (kind, key) => ownership.resource(kind, `${tag}${key}`),
    /** A name sent on purpose that cannot carry the prefix; `id` may differ by transport. */
    probe: (kind, id) =>
      ownership.registerProbe(
        `projects/${ownership.project}/${kind}/${typeof id === "string" ? `${id}-${transportName === "rest" ? "r" : "g"}` : id[transportName]}`,
      ),
    sleep,
    note: (kind, data) => capture.note(kind, { case: caseId, ...data }),
  };
}

export async function runCases({
  cases,
  transportNames = REST_AND_GRPC,
  transports,
  cleanupRest,
  ownership,
  pushState,
  capture,
  options,
  sleep,
  isStopping = () => false,
}) {
  const summary = { cases: [], stopped: null, cleanup: null };
  const stoppable = async (ms) => {
    if (isStopping()) throw new StopClean("stopped by a signal");
    await sleep(ms);
  };
  outer: for (const item of cases) {
    for (const transportName of transportNames) {
      if (isStopping()) {
        summary.stopped = "signal";
        break outer;
      }
      const before = capture.count();
      const entry = { id: item.id, transport: transportName, outcome: "completed" };
      capture.note("case-start", { case: `${item.id}/${transportName}` });
      try {
        const ctx = createContext({
          item,
          transportName,
          transports,
          ownership,
          pushState,
          capture,
          options,
          sleep: stoppable,
        });
        await item.run(ctx);
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
      capture.note("case-end", { case: `${item.id}/${transportName}`, ...entry });
      summary.cases.push(entry);
      if (summary.stopped !== null && entry.outcome !== "aborted") break outer;
    }
  }
  summary.cleanup = await cleanup({
    client: cleanupRest,
    ownership,
    project: ownership.project,
    known: ownership.issued(),
    sleep,
  });
  return summary;
}

export function exitCodeOf(summary) {
  if (summary.cleanup.leftover.length > 0 || summary.cleanup.errors.length > 0) return 1;
  if (summary.stopped !== null) return summary.stopped.includes("budget") ? 4 : 3;
  return 0;
}
