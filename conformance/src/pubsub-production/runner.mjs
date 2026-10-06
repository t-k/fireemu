// Runs the cases against one target, once for each transport, then cleans up by prefix. A case never
// fails the run: it is recorded as aborted when a step it depends on did not answer as needed. What stops
// the run is a budget that is spent, a missing precondition (StopClean) or a signal; the cleanup runs in
// every one of these.

import { BudgetExceeded } from "./capture.mjs";
import { CASES } from "./cases/index.mjs";
import { CaseAbort, StopClean } from "./cases/support.mjs";
import { cleanup } from "./cleanup.mjs";
import { createClient } from "./client.mjs";
import { createLedger } from "./ledger.mjs";
import { STREAM_DLQ_CASES, STREAM_DLQ_V2_CASES } from "./cases/stream-dlq.mjs";
import { createPhaseLimit } from "./limits.mjs";

const REST_AND_GRPC = ["rest", "grpc"];

/** A case reached the number of requests it declared: its ceiling is a maximum, not a hint. */
export class CaseLimit extends Error {
  constructor(limit) {
    super(`the case reached its limit of ${limit} requests`);
    this.name = "CaseLimit";
  }
}

/** The same transport, refusing (before the budget is touched) the request after the case's limit. */
function limited(transport, meter, limit) {
  const wrap = (send) => (call) => {
    if (meter.used >= limit) throw new CaseLimit(limit);
    meter.used += 1;
    return send.call(transport, call);
  };
  return {
    ...transport,
    ...(transport.request ? { request: wrap(transport.request) } : {}),
    ...(transport.call ? { call: wrap(transport.call) } : {}),
    ...(transport.stream ? { stream: wrap(transport.stream) } : {}),
  };
}

export function selectCases(only, suite = "unary") {
  if (suite !== "unary" && suite !== "stream-dlq" && suite !== "stream-dlq-v2")
    throw new Error(`unknown suite ${suite}`);
  const available =
    suite === "stream-dlq-v2"
      ? STREAM_DLQ_V2_CASES
      : suite === "stream-dlq"
        ? STREAM_DLQ_CASES
        : CASES;
  if (only === undefined) return available;
  const wanted = new Set(only);
  const known = new Set(available.map((item) => item.id));
  for (const id of wanted) if (!known.has(id)) throw new Error(`unknown case ${id}`);
  return available.filter((item) => wanted.has(item.id));
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
  ledger,
}) {
  const meter = { used: 0 };
  const phase =
    item.timeoutMs === undefined ? null : createPhaseLimit(item.timeoutMs, options.monotonicNow);
  const guarded = Object.fromEntries(
    Object.entries(transports).map(([name, transport]) => [
      name,
      limited(phase === null ? transport : phase.transport(transport), meter, item.requests),
    ]),
  );
  const tag = `${item.short}-${transportName === "rest" ? "r" : "g"}-`;
  const caseId = `${item.id}/${transportName}`;
  const clientOf = (transport, id) =>
    createClient({ transport, ownership, pushState, caseId: id, ledger });
  const allocated = new Set();
  const name = (kind, key) => {
    const value = `${kind}/${key}`;
    if (item.resources !== undefined && !allocated.has(value) && allocated.size >= item.resources)
      throw new CaseLimit(item.resources);
    allocated.add(value);
    return ownership.resource(kind, `${tag}${key}`);
  };
  return {
    transport: transportName,
    project: ownership.project,
    runId: ownership.runId,
    production: options.production,
    serviceAgent: options.serviceAgent ?? null,
    iam: options.iam ?? null,
    monotonicNow: options.monotonicNow ?? (() => performance.now()),
    client: clientOf(guarded[transportName], caseId),
    // IAM is only available over REST, whichever transport the case is recording.
    rest: clientOf(guarded.rest, `${caseId}/rest`),
    maxKeyLength: 255 - (ownership.prefix.length + tag.length),
    name,
    stream: (subscription, frames, timeoutMs, afterReceive) => {
      ownership.assertOwned(subscription);
      if (
        frames.some(
          (frame) => frame.subscription !== undefined && frame.subscription !== subscription,
        )
      )
        throw new Error("stream frame names a foreign subscription");
      return guarded.grpc.stream({
        label: { case: caseId, step: "stream" },
        frames,
        timeoutMs,
        afterReceive,
      });
    },
    /** A name sent on purpose that cannot carry the prefix; `id` may differ by transport. */
    probe: (kind, id) =>
      ownership.registerProbe(
        `projects/${ownership.project}/${kind}/${typeof id === "string" ? `${id}-${transportName === "rest" ? "r" : "g"}` : id[transportName]}`,
      ),
    sleep: phase === null ? sleep : phase.sleep(sleep),
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
  ledger = createLedger(),
  isStopping = () => false,
  cleanupSleep = sleep,
}) {
  const summary = { cases: [], stopped: null, limited: [], cleanup: null };
  const stoppable = async (ms) => {
    if (isStopping()) throw new StopClean("stopped by a signal");
    await sleep(ms);
  };
  outer: for (const item of cases) {
    for (const transportName of transportNames) {
      if (item.transports !== undefined && !item.transports.includes(transportName)) continue;
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
          ledger,
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
        } else if (error instanceof CaseLimit) {
          entry.outcome = "limit";
          entry.reason = error.message;
          summary.limited.push(`${item.id}/${transportName}`);
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
    ledger,
    sleep: cleanupSleep,
  });
  return summary;
}

/** The requests the selected cases may send: each case declares its own ceiling, once for each transport. */
export function plannedRequests(cases, transportNames = REST_AND_GRPC) {
  return cases.reduce(
    (sum, item) =>
      sum +
      item.requests *
        transportNames.filter(
          (name) => item.transports === undefined || item.transports.includes(name),
        ).length,
    0,
  );
}

/** A run that would stop on its budget is not started. */
export function assertBudgetCovers(cases, transportNames, maxRequests) {
  const planned = plannedRequests(cases, transportNames);
  if (planned > maxRequests)
    throw new Error(
      `the selected cases may send ${planned} requests, over --max-requests ${maxRequests}`,
    );
}

export function exitCodeOf(summary) {
  if (
    summary.cleanup.leftover.length > 0 ||
    summary.cleanup.errors.length > 0 ||
    (summary.cleanup.unsettled ?? []).length > 0
  )
    return 1;
  if (summary.stopped !== null) return summary.stopped.includes("budget") ? 4 : 3;
  return 0;
}
