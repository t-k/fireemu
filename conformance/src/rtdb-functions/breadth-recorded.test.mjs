import { test } from "node:test";
import assert from "node:assert/strict";
import { compareRecordings } from "./breadth-compare.mjs";
import { isRecordedMember } from "./breadth-frames.mjs";
import { MASKED_NONCE } from "./mask-breadth.mjs";

const frame = (uid, threw) => ({
  handler: "g9WrittenV2Retry",
  generation: 2,
  event: {
    id: Buffer.alloc(20).toString("base64"),
    time: "2026-01-01T00:00:00.000Z",
    params: { group: "ga", id: "a1" },
    authType: "app_user",
    authId: uid,
    data: {
      before: { exists: false, value: null },
      after: { exists: true, value: { value: 1, run: MASKED_NONCE } },
    },
  },
  attempt: { threw },
});
test("masks app user identities and compares retry shape independently of count", () => {
  const production = [frame("one", true), frame("one", true), frame("one", false)];
  const local = [frame("two", true), frame("two", false)];
  assert.equal(compareRecordings({ production, local }).totals.difference, 0);
});
test("accepts only the recorded user context shape", () => {
  const value = {
    type: "object",
    keys: ["auth", "authType", "eventId", "eventType", "params", "resource", "timestamp"],
  };
  assert.equal(isRecordedMember("g9WrittenV2", 2, "context", value), true);
  assert.equal(
    isRecordedMember("g9WrittenV2", 2, "context", { ...value, keys: [...value.keys, "other"] }),
    false,
  );
});

test("replays the masked production and local recordings", async () => {
  const { readFileSync } = await import("node:fs");
  const { judgeRun } = await import("./breadth-judge.mjs");
  const { observe, buildSteps } = await import("./breadth-sequence.mjs");
  const read = (name) =>
    JSON.parse(
      readFileSync(new URL(`./recorded/${name}-rtdb-breadth.json`, import.meta.url), "utf8"),
    );
  const production = read("production");
  const writes = Object.fromEntries(production.steps.map((step) => [step.id, step.write]));
  const report = observe({ writes, frames: production.frames, steps: buildSteps(MASKED_NONCE) });
  assert.deepEqual(
    judgeRun({ report, frames: production.frames, writes, ignored: {}, userUid: "<uid>" }),
    [],
  );
  const strict = compareRecordings({
    production: production.frames,
    local: read("local-strict").frames,
  });
  assert.deepEqual(strict.totals, { rows: 69, match: 69, difference: 0 });
  assert.deepEqual(strict.unattributed, { production: [], local: [] });
  const emulator = compareRecordings({
    production: production.frames,
    local: read("local-emulator").frames,
  });
  assert.deepEqual(
    [
      ...new Set(
        emulator.rows.flatMap((row) => row.differences.map((difference) => difference.path)),
      ),
    ].sort(),
    [
      "$[0].frames[0].event.authType",
      "$[0].frames[0].event.context.eventId",
      "$[0].frames[0].event.context.timestamp",
      "$[0].frames[0].event.datacontenttype",
      "$[0].frames[0].event.eventKeys.datacontenttype",
      "$[0].frames[0].event.eventKeys.traceparent",
      "$[0].frames[0].event.extras.context.keys",
      "$[0].frames[0].event.extras.traceparent",
      "$[0].frames[0].event.id",
      "$[0].frames[0].event.source",
      "$[0].frames[0].event.time",
      "$[0].frames[1].event.authType",
      "$[0].frames[1].event.context.eventId",
      "$[0].frames[1].event.context.timestamp",
      "$[0].frames[1].event.datacontenttype",
      "$[0].frames[1].event.eventKeys.datacontenttype",
      "$[0].frames[1].event.eventKeys.traceparent",
      "$[0].frames[1].event.extras.context.keys",
      "$[0].frames[1].event.extras.traceparent",
      "$[0].frames[1].event.id",
      "$[0].frames[1].event.source",
      "$[0].frames[1].event.time",
    ],
  );
  assert.deepEqual(emulator.unattributed, { production: [], local: [] });
});
