import type { CausalEvent, FunctionCodebase, FunctionLog, InvocationInfo } from "../api/functions";

export type TimelineEvent = {
  key: string;
  eventId: string;
  function: string;
  causal?: CausalEvent;
  outcomes: InvocationInfo[];
  logs: FunctionLog[];
  synthetic: boolean;
};

/** Join only runtime event IDs and trusted runner metadata, never display text or time. */
export function buildTimeline(
  project: string,
  events: CausalEvent[],
  outcomes: InvocationInfo[],
  logs: FunctionLog[],
  codebases: FunctionCodebase[],
): TimelineEvent[] {
  const rows = new Map<string, TimelineEvent>();
  const key = (eventId: string, fn: string) => JSON.stringify([project, eventId, fn]);
  const add = (eventId: string, fn: string, id = key(eventId, fn)): TimelineEvent => {
    let row = rows.get(id);
    if (!row) {
      row = { key: id, eventId, function: fn, outcomes: [], logs: [], synthetic: eventId === "0" };
      rows.set(id, row);
    }
    return row;
  };
  for (const event of events) {
    if (event.eventId !== "0") add(event.eventId, event.function).causal = event;
  }
  outcomes.forEach((outcome, index) => {
    const id =
      outcome.eventId === "0"
        ? JSON.stringify([
            project,
            "synthetic",
            outcome.sequence !== undefined ? ["sequence", outcome.sequence] : ["index", index],
          ])
        : key(outcome.eventId, outcome.function);
    add(outcome.eventId, outcome.function, id).outcomes.push(outcome);
  });
  const owners = new Map<string, string>();
  for (const base of codebases) for (const fn of base.functions) owners.set(fn, base.codebase);
  const seen = new Set<string>();
  for (const log of logs) {
    if (
      log.project !== project ||
      log.truncated ||
      !log.function ||
      owners.get(log.function) !== log.codebase
    )
      continue;
    const match = /^([1-9][0-9]*)-([1-9][0-9]*)$/.exec(log.invocationId ?? "");
    if (!match) continue;
    const row = rows.get(key(match[1]!, log.function));
    if (!row) continue;
    const cursor = JSON.stringify([log.project, log.codebase, log.runner, log.cursor]);
    if (seen.has(cursor)) continue;
    seen.add(cursor);
    row.logs.push(log);
  }
  return [...rows.values()];
}

/** Retain bounded, attributed history through reconnects without replaying duplicate cursors. */
export function mergeFunctionLogs(
  previous: FunctionLog[],
  incoming: FunctionLog[],
  limit: number,
): FunctionLog[] {
  const records = new Map<string, FunctionLog>();
  for (const record of [...previous, ...incoming]) {
    records.set(
      JSON.stringify([record.project, record.codebase, record.runner, record.cursor]),
      record,
    );
  }
  return [...records.values()].slice(-limit);
}
