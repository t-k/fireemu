import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { BURST_PROGRAM, PROGRAM, materializeCreate, taskId } from "../corpus.mjs";
import { functionOfRole, functionsOf, queueName } from "../plan.mjs";
import { createGuard } from "./guard.mjs";
import { RUN, go } from "./harness.mjs";
import { readbackRun } from "./readback.mjs";
import { NUMBER, START, SERVICE_ACCOUNT, uriOf } from "./world.mjs";

const fn = functionOfRole(RUN, "tqrate");
const targets = { tqrate: { uri: uriOf(fn), serviceAccountEmail: SERVICE_ACCOUNT } };

test("all 120 named burst creates share an absolute anchor and only selected shapes pass the guard", () => {
  const guard = createGuard(RUN, NUMBER, "burst");
  guard.setTargets(targets);
  assert.equal(BURST_PROGRAM.length, 120);
  const times = new Set();
  for (const [index, step] of BURST_PROGRAM.entries()) {
    assert.equal(step.key, `burst-${String(index + 1).padStart(3, "0")}`);
    assert.deepEqual(step.groups, ["max-dispatches-per-second"]);
    const request = materializeCreate(step, {
      runId: RUN,
      targets,
      now: START + index * 1400,
      anchors: { burst: START },
    });
    assert.equal(request.json.task.name, queueName(fn) + "/tasks/" + taskId(RUN, step.key));
    times.add(request.json.task.scheduleTime);
    assert.equal(guard.allow(request), true);
    request.json.task.name += "-extra";
    assert.equal(guard.allow(request), false);
  }
  assert.deepEqual([...times], [new Date(START + 300_000).toISOString()]);
  const defaultRate = PROGRAM.find((s) => s.key === "rate-a");
  assert.equal(
    guard.allow(materializeCreate(defaultRate, { runId: RUN, targets, now: START })),
    false,
  );
});

test("burst records 100 starts at the anchor and 20 refills, then cleans up only tqrate", async () => {
  const { world, result, journal } = await go({ program: "burst" }, { program: "burst" });
  assert.equal(result.closureReady, true);
  assert.equal(result.judged.observationComplete, true);
  assert.deepEqual(result.judged.findings, []);
  assert.equal(result.burst.starts.length, 120);
  assert.equal(result.burst.firstMs, 0);
  assert.equal(result.burst.countWithin1s, 100);
  assert.equal(result.burst.countWithin5s, 104);
  assert.deepEqual(
    result.burst.starts.map((s) => s.startMs - result.burst.anchorMs),
    [...Array(100).fill(0), ...Array.from({ length: 20 }, (_, i) => (i + 1) * 1000)],
  );
  assert.ok(result.burst.starts.every((s) => s.attempt === 0));
  assert.equal(new Set(result.burst.starts.map((s) => s.id)).size, 120);
  assert.deepEqual(Object.keys(result.readbacks), [fn]);
  assert.deepEqual(result.readbacks[fn].queue.json.rateLimits, {
    maxConcurrentDispatches: 100,
    maxDispatchesPerSecond: 1,
    maxBurstSize: 100,
  });
  assert.equal(world.calls.filter((c) => /^POST cloudtasks.*\/tasks$/.test(c)).length, 120);
  assert.equal(world.calls.filter((c) => /^DELETE cloudtasks.*\/queues\/[^/]+$/.test(c)).length, 1);
  for (const other of functionsOf(RUN).filter((id) => id !== fn))
    assert.ok(
      world.calls.every((c) => !c.includes(other)),
      other,
    );
  assert.equal(world.calls.filter((c) => /^(GET|DELETE) cloudtasks.*\/tasks\//.test(c)).length, 0);
  const cleanupStart = journal.findIndex(
    (r) => r.id === "cleanup-invoker-functions-v2" && r.state === "before-send",
  );
  const cleanup = journal.slice(cleanupStart).filter((r) => r.state === "before-send").length;
  // 120 creates plus setup, queue readback, bounded log reads and cleanup; no default program steps.
  assert.equal(cleanup, 37);
  assert.equal(result.attempted, 120 + 20 + 13 + 37);
  assert.equal(world.calls.length, 190);
  assert.ok(cleanup <= 260);
  const a2Calls = [];
  const a2 = await readbackRun({
    runId: RUN,
    program: "burst",
    projectNumber: NUMBER,
    accessToken: "test-token-abcdefgh",
    save: async () => {},
    send: async (r) => {
      a2Calls.push(r.url);
      return world.send(r);
    },
    baseline: result.inventory.before,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
  });
  assert.equal(a2.allAbsent, true);
  for (const other of functionsOf(RUN).filter((id) => id !== fn))
    assert.ok(
      a2Calls.every((url) => !url.includes(other)),
      other,
    );
});

test("burst stops creating at the anchor when world creates are slow", async () => {
  const { result, world } = await go(
    {
      program: "burst",
      hooks: {
        [`POST cloudtasks.googleapis.com/v2/${queueName(fn)}/tasks`]: ({ w }) => {
          w.advance(10_000);
        },
      },
    },
    { program: "burst" },
  );
  const sent = Object.values(result.program).filter((s) => s.sent);
  assert.ok(sent.length > 0 && sent.length < 120);
  assert.ok(sent.every((s) => s.dispatchedAt < result.burst.anchorMs));
  assert.equal(world.calls.filter((c) => /^POST cloudtasks.*\/tasks$/.test(c)).length, sent.length);
  assert.ok(result.judged.findings.some((f) => f.kind === "burst-late"));
  assert.equal(result.judged.observationComplete, false);
});

test("burst missing one distinct attempt-zero frame stays incomplete at the bound", async () => {
  const { result, journal } = await go(
    {
      program: "burst",
      hooks: {
        "POST logging.googleapis.com/v2/entries:list": ({ w }) => {
          w.entries = w.entries.filter(
            (e) =>
              !(
                e.textPayload?.includes('"case":"burst-120"') &&
                e.textPayload.includes('"kind":"start"')
              ),
          );
        },
      },
    },
    { program: "burst" },
  );
  assert.equal(result.burst.starts.length, 119);
  assert.ok(result.judged.findings.some((f) => f.kind === "burst-missing-start"));
  assert.equal(result.judged.observationComplete, false);
  const polls = journal.filter(
    (r) => /^logs-observe-\d+-frames$/.test(r.id) && r.state === "before-send",
  );
  assert.equal(Date.parse(polls.at(-1).dispatchAt), result.burst.anchorMs + 240_000);
});

test("burst keeps the earlier start when a later duplicate frame appears first in the log", async () => {
  let added = false;
  let earlierStartMs;
  const { result } = await go(
    {
      program: "burst",
      hooks: {
        "POST logging.googleapis.com/v2/entries:list": ({ w }) => {
          if (added) return;
          const original = w.entries.find(
            (entry) =>
              entry.textPayload?.includes('"case":"burst-001"') &&
              entry.textPayload.includes('"kind":"start"') &&
              entry.textPayload.includes('"retryCount":0'),
          );
          if (!original) return;
          added = true;
          earlierStartMs = Date.parse(original.timestamp);
          const later = new Date(Date.parse(original.timestamp) + 1000).toISOString();
          const frame = JSON.parse(original.textPayload.slice(original.textPayload.indexOf("{")));
          frame.at = later;
          const prefix = original.textPayload.slice(0, original.textPayload.indexOf("{"));
          w.entries.unshift({
            ...original,
            insertId: "later-duplicate-start",
            timestamp: later,
            textPayload: prefix + JSON.stringify(frame),
          });
        },
      },
    },
    { program: "burst" },
  );
  const start = result.burst.starts.find((entry) => entry.id === taskId(RUN, "burst-001"));
  assert.ok(start);
  assert.equal(start.startMs, earlierStartMs);
  const any = result.burst.anyAttemptStarts.find((entry) => entry.id === taskId(RUN, "burst-001"));
  assert.ok(any);
  assert.equal(any.startMs, earlierStartMs);
  assert.equal(any.retryCount, 0);
});

test("duplicate starts and retry attempts cannot replace a missing attempt-zero start", async () => {
  let added = false;
  const { result } = await go(
    {
      program: "burst",
      hooks: {
        "POST logging.googleapis.com/v2/entries:list": ({ w }) => {
          const last = w.entries.find(
            (e) =>
              e.textPayload?.includes('"case":"burst-120"') &&
              e.textPayload.includes('"kind":"start"'),
          );
          if (!last || added) return;
          added = true;
          const text = last.textPayload;
          last.textPayload = text.replace('"retryCount":0', '"retryCount":1');
          const previous = w.entries.find(
            (e) =>
              e.textPayload?.includes('"case":"burst-119"') &&
              e.textPayload.includes('"kind":"start"'),
          );
          w.entries.push({ ...previous, insertId: "duplicate-start" });
        },
      },
    },
    { program: "burst" },
  );
  assert.equal(result.burst.starts.length, 119);
  assert.equal(result.judged.observationComplete, false);
  assert.ok(result.judged.findings.some((f) => f.kind === "burst-missing-start"));
});

test("burst-late is caught after the issuance write and before the create is sent", async () => {
  let world;
  let creates = 0;
  const { result, journal } = await go(
    { program: "burst" },
    {
      program: "burst",
      prepareRequest: async (spec) => {
        if (spec.method === "POST" && spec.url.endsWith("/tasks") && ++creates === 4)
          world.advance(300_000);
      },
    },
    (send, w) => {
      world = w;
      return send;
    },
  );
  assert.ok(journal.some((row) => row.id === "issue-task-burst-004" && row.state === "issued"));
  assert.equal(world.calls.filter((c) => /^POST cloudtasks.*\/tasks$/.test(c)).length, 3);
  assert.deepEqual(Object.keys(result.program), ["burst-001", "burst-002", "burst-003"]);
  assert.ok(result.judged.findings.some((f) => f.kind === "burst-late"));
  assert.equal(result.judged.observationComplete, false);
  assert.ok(world.calls.some((c) => /^DELETE cloudtasks.*\/queues\/[^/]+$/.test(c)));
});

test("burst records the first handler start even when the first attempt fails before the handler", async () => {
  const cases = ["burst-001", "burst-002", "burst-003"];
  const { result } = await go({ program: "burst", failBeforeHandler: cases }, { program: "burst" });
  assert.equal(result.burst.starts.length, 117);
  assert.ok(result.judged.findings.some((f) => f.kind === "burst-missing-start"));
  assert.equal(result.burst.anyAttemptStarts.length, 120);
  for (const key of cases)
    assert.equal(
      result.burst.anyAttemptStarts.find((s) => s.id === taskId(RUN, key)).retryCount,
      1,
    );
  assert.ok(
    result.burst.anyAttemptStarts.every(
      (s, i, starts) => i === 0 || starts[i - 1].startMs <= s.startMs,
    ),
  );
});

test("burst checks the last create answer against the anchor", async () => {
  for (const [delay, late] of [
    [300_001, true],
    [299_999, false],
  ]) {
    let creates = 0;
    const { result, world } = await go(
      {
        program: "burst",
        hooks: {
          [`POST cloudtasks.googleapis.com/v2/${queueName(fn)}/tasks`]: ({ w }) => {
            if (++creates === 120) w.advance(delay);
          },
        },
      },
      { program: "burst" },
    );
    assert.equal(world.calls.filter((c) => /^POST cloudtasks.*\/tasks$/.test(c)).length, 120);
    assert.ok(result.program["burst-120"].dispatchedAt < result.burst.anchorMs);
    assert.equal(result.program["burst-120"].answeredAt, result.burst.anchorMs + (late ? 1 : -1));
    assert.equal(
      result.judged.findings.some((f) => f.kind === "burst-late" && f.case === "burst-120"),
      late,
    );
    if (late) assert.equal(result.judged.observationComplete, false);
  }
});
