import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { resourceMatches, runPrograms } from "./functions-events/session.mjs";

const readJson = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url)));
const manifest = readJson("../functions-events/programs.json");
const corpus = readJson("../functions-events/corpus.json");

class FakeCapture {
  frames = [];
  lossCount = 0;
  issues = [];
  async barrier() {
    return {
      cursor: this.frames.length,
      lossCount: this.lossCount,
      issueCount: this.issues.length,
    };
  }
  since(cursor) {
    return this.frames.slice(cursor);
  }
  push(frame) {
    this.frames.push({ sequence: this.frames.length + 1, frame });
  }
}

function fakeDriver(capture, { omit = null, injectUnexpected = null } = {}) {
  let counter = 0;
  const calls = [];
  return {
    calls,
    async runScenario({ scenario, program, role }) {
      counter += 1;
      calls.push({ recipeId: program.recipeId, scenarioId: scenario.id, role });
      const key = `owned-${counter}`;
      const matchKey = { kind: scenario.source, value: key };
      const cursor = (await capture.barrier()).cursor;
      const negative =
        role === "subject" &&
        corpus.cases.some(
          (row) =>
            row.recipeId === program.recipeId &&
            row.scenario === scenario.id &&
            row.delivery === "none-in-window",
        );
      if (!negative && scenario.id !== omit) {
        for (const [generation, handler] of Object.entries(program.handlerExports)) {
          const event =
            scenario.source === "firestore"
              ? { id: `event-${counter}`, time: "2026-09-27T00:00:00Z", data: { path: key } }
              : scenario.source === "storage"
                ? {
                    id: `event-${counter}`,
                    time: "2026-09-27T00:00:00Z",
                    data: { bucket: "bucket", name: key },
                  }
                : scenario.source === "auth"
                  ? { id: `event-${counter}`, time: "2026-09-27T00:00:00Z", data: { uid: key } }
                  : {
                      id: `event-${counter}`,
                      time: "2026-09-27T00:00:00Z",
                      data: { message: { messageId: key } },
                    };
          if (scenario.id === "fs-retry") {
            capture.push({
              handler,
              generation: Number(generation.slice(1)),
              source: scenario.source,
              event: { ...event, data: { path: key, fixtureAttempt: "failed" } },
            });
            capture.push({
              handler,
              generation: Number(generation.slice(1)),
              source: scenario.source,
              event: { ...event, data: { path: key, fixtureAttempt: "succeeded" } },
            });
          } else {
            capture.push({
              handler,
              generation: Number(generation.slice(1)),
              source: scenario.source,
              event,
            });
          }
        }
      }
      if (scenario.id === injectUnexpected) {
        capture.push({
          handler: program.handlerExports.v1 ?? program.handlerExports.v2,
          generation: program.generations[0],
          source: scenario.source,
          event: { data: { path: key } },
        });
      }
      return {
        cursor,
        matchKey,
        sourceResult: scenario.sourceResult,
        readback: { checked: true },
        cleanup: async () => ({ checked: true }),
      };
    },
  };
}

test("all 20 programs run their fixed scenarios and record 109 local aspects", async () => {
  const capture = new FakeCapture();
  const driver = fakeDriver(capture);
  const result = await runPrograms({ manifest, corpus, capture, driver, windowMs: 1 });
  assert.equal(result.status, "LOCAL_OBSERVATION");
  assert.equal(result.programs.length, 20);
  assert.equal(result.programs.flatMap((program) => program.cases).length, 109);
  assert.ok(
    result.programs.every((program) =>
      program.cases.every((row) => row.status === "LOCAL_OBSERVATION"),
    ),
  );
  assert.ok(
    result.programs.every((program) =>
      program.cases.every((row) => row.aspectStatus === "PENDING_LOCAL_COMPARISON"),
    ),
  );
  assert.equal(
    driver.calls.some(({ recipeId }) => recipeId === "functions-events/"),
    false,
  );
});

test("missing positive delivery is incomplete and an unexpected negative delivery is a diff", async () => {
  const capture = new FakeCapture();
  const driver = fakeDriver(capture, { omit: "fs-create" });
  const onlyRecipeIds = ["functions-events/firestore/create"];
  const incomplete = await runPrograms({
    manifest,
    corpus,
    capture,
    driver,
    onlyRecipeIds,
    windowMs: 1,
  });
  assert.ok(incomplete.programs[0].cases.every((row) => row.status === "INCOMPLETE"));
  const otherCapture = new FakeCapture();
  const otherDriver = fakeDriver(otherCapture, { injectUnexpected: "fs-noop" });
  const diff = await runPrograms({
    manifest,
    corpus,
    capture: otherCapture,
    driver: otherDriver,
    onlyRecipeIds: ["functions-events/firestore/noop"],
    windowMs: 1,
  });
  assert.ok(diff.programs[0].cases.every((row) => row.status === "DIFF"));
});

test("capture issues and cleanup failure prevent a local observation claim", async () => {
  const capture = new FakeCapture();
  const driver = fakeDriver(capture);
  const original = driver.runScenario;
  driver.runScenario = async (args) => {
    const result = await original(args);
    capture.lossCount += 1;
    result.cleanup = async () => {
      throw new Error("cleanup failed");
    };
    return result;
  };
  const result = await runPrograms({
    manifest,
    corpus,
    capture,
    driver,
    onlyRecipeIds: ["functions-events/auth/payload"],
    windowMs: 1,
  });
  assert.ok(result.programs[0].cases.every((row) => row.status === "INCOMPLETE"));
  assert.equal(result.status, "INCOMPLETE");
});

test("a bulk Auth negative case correlates every owned user", () => {
  const key = { kind: "auth", values: ["owned-user-a", "owned-user-b"] };
  assert.equal(resourceMatches({ event: { data: { uid: "owned-user-a" } } }, key), true);
  assert.equal(resourceMatches({ event: { data: { uid: "owned-user-b" } } }, key), true);
  assert.equal(resourceMatches({ event: { data: { uid: "unrelated-user" } } }, key), false);
});

test("Pub/Sub frames correlate a publish receipt in both generations", () => {
  const key = { kind: "pubsub", value: "message-123" };
  assert.equal(
    resourceMatches({ event: { context: { eventId: "message-123" }, data: {} } }, key),
    true,
  );
  assert.equal(
    resourceMatches({ event: { data: { message: { messageId: "message-123" } } } }, key),
    true,
  );
  assert.equal(
    resourceMatches({ event: { data: { message: { messageId: "other" } } } }, key),
    false,
  );
});
