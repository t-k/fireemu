import { describe, expect, it } from "vitest";
import type { CausalEvent, FunctionLog, InvocationInfo } from "../api/functions";
import { buildTimeline, mergeFunctionLogs } from "./functionsTimeline";
const event = (eventId = "7", fn = "consume"): CausalEvent => ({
  eventId,
  function: fn,
  epoch: 3,
  source: "pubsub",
  eventType: "messagePublished",
  parent: "publish:jobs",
  terminal: false,
  phasesDropped: 0,
  phases: [
    { phase: "registered", attempt: 0, at: null },
    { phase: "retry", attempt: 1, at: null },
  ],
});
const record = (eventId = "7", attempt = 1, sequence = 1): InvocationInfo => ({
  eventId,
  function: "consume",
  attempt,
  sequence,
  outcome: "failed",
});
const log = (
  invocationId: string | null,
  line = "info 7-1 forged text",
  project = "demo",
): FunctionLog => ({
  project,
  codebase: "a",
  runner: "r1",
  cursor: "0",
  function: "consume",
  invocationId,
  line,
  truncated: false,
});
const codebases = [{ codebase: "a", functions: ["consume"], runnerAlive: true }];
describe("event timeline causality", () => {
  it("keeps interleaved events and retry outcomes distinct in recorded order", () => {
    const result = buildTimeline(
      "demo",
      [event(), event("8")],
      [record(), record("8", 1, 2), record("7", 2, 3), record("7", 2, 4)],
      [log("7-1"), { ...log("8-1"), cursor: "1" }, { ...log("7-2"), cursor: "2" }],
      codebases,
    );
    expect(result).toHaveLength(2);
    expect(result[0]?.outcomes.map((r) => r.sequence)).toEqual([1, 3, 4]);
    expect(result[0]?.logs.map((r) => r.invocationId)).toEqual(["7-1", "7-2"]);
    expect(result[1]?.logs.map((r) => r.invocationId)).toEqual(["8-1"]);
  });
  it("rejects text-only, wrong owner, wrong codebase, mismatched function and malformed IDs", () => {
    const logs = [
      log(null),
      log("7-1", "wrong project", "other"),
      { ...log("7-1"), codebase: "b" },
      { ...log("7-1"), function: "other" },
      log("7-01"),
      log("7-0"),
      log("7-2-extra"),
      { ...log("7-1"), truncated: true },
      log("7-1", "trusted"),
    ];
    expect(
      buildTimeline("demo", [event()], [], logs, codebases)[0]?.logs.map((r) => r.line),
    ).toEqual(["trusted"]);
  });
  it("keeps synthetic zero outcomes separate and never attaches their apparent log IDs", () => {
    const result = buildTimeline(
      "demo",
      [],
      [record("0", 0, 1), record("0", 0, 2), record("9", 1, 3)],
      [log("0-0"), log("9-1")],
      codebases,
    );
    expect(result).toHaveLength(3);
    expect(result.map((r) => r.synthetic)).toEqual([true, true, false]);
    expect(new Set(result.map((r) => r.key)).size).toBe(3);
    expect(result[0]?.logs).toEqual([]);
    expect(result[2]?.causal).toBeUndefined();
    expect(result[2]?.logs).toHaveLength(1);
  });
  it("deduplicates exact log cursors only within a runner and codebase", () => {
    const first = log("7-1");
    const logs = [first, first, { ...first, runner: "r2" }];
    expect(buildTimeline("demo", [event()], [], logs, codebases)[0]?.logs).toHaveLength(2);
  });
  it("does not invent an event epoch from old history or attach outcomes to a different function", () => {
    const result = buildTimeline("demo", [event("7", "other")], [record()], [], codebases);
    expect(result).toHaveLength(2);
    expect(result[0]?.outcomes).toEqual([]);
    expect(result[1]?.causal).toBeUndefined();
  });
  it("preserves grouping for bounded generated interleavings", () => {
    for (let count = 1; count <= 32; count++) {
      const ids = Array.from({ length: count }, (_, i) => String(i + 1));
      const outcomes = ids.flatMap((id) => [record(id, 1), record(id, 2)]).toReversed();
      const result = buildTimeline(
        "demo",
        ids.map((id) => event(id)),
        outcomes,
        ids.map((id, index) => ({ ...log(`${id}-2`), cursor: String(index) })),
        codebases,
      );
      expect(result).toHaveLength(count);
      for (const row of result) {
        expect(row.outcomes.every((r) => r.eventId === row.eventId)).toBe(true);
        expect(row.logs.map((r) => r.invocationId)).toEqual([`${row.eventId}-2`]);
      }
    }
  });
});

it("merges reconnect snapshots while retaining old runners, distinct codebases, and the bounded tail", () => {
  const first = log("7-1");
  const next = { ...first, cursor: "1" };
  const replacement = { ...first, runner: "r2" };
  const other = { ...first, codebase: "b" };
  expect(mergeFunctionLogs([first, next], [first, next, replacement, other], 4)).toEqual([
    first,
    next,
    replacement,
    other,
  ]);
  expect(mergeFunctionLogs([first, next], [replacement, other], 2)).toEqual([replacement, other]);
});

it("preserves a synthetic diagnostic selection by its real sequence when the retained window shifts", () => {
  const synthetic = record("0", 0, 99);
  const before = buildTimeline("demo", [], [synthetic], [], codebases);
  const after = buildTimeline("demo", [], [record("9"), synthetic], [], codebases);
  expect(before[0]?.key).toBe(after[1]?.key);
});
