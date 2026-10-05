// The three cases of unknown and ambiguous answers (checklist section 3), end to end for the stage B
// recorder: a recording against the model of the service, then the separate A2 read-back at least ten
// minutes later. Never mixed: an unknown create is never settled by a 404, a confirmed create that reads
// 404 stays open until A2, an unknown delete is closed only by A2.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { MIN_A2_WAIT_MS, main } from "./eventarc-production/record.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";
import { serveWorld } from "./eventarc-production/testing/world-server.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-fireemu-eventarc";
const P1 = `projects/${PROJECT}/locations/us-central1/channels/fe${RUN}-cp-p1`;
const io = () => ({ stdout: { write: () => true }, stderr: { write: () => true } });

async function record(t, options) {
  const world = createWorld({ project: PROJECT, ...options });
  const service = await serveWorld(world);
  t.after(service.close);
  const dir = mkdtempSync(join(tmpdir(), "eventarc-b-a2-"));
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      dir,
      "--only",
      "preconditions,create-probe",
      "--run-id",
      RUN,
    ],
    {},
    io(),
  );
  const first = JSON.parse(readFileSync(join(dir, `summary-${RUN}.json`), "utf8"));
  return { world, service, dir, code, first };
}

/** The A2 read-back: a separate run in the recording's directory, after the ten minutes. */
async function readBack({ dir, service }, { before = 0 } = {}) {
  const code = await main(
    [
      "--target",
      "emulator",
      "--emulator-host",
      service.host,
      "--out",
      dir,
      "--cleanup-only",
      "--run-id",
      RUN,
      "--from-capture",
      join(dir, `capture-${RUN}.jsonl`),
    ],
    {},
    io(),
    { now: () => Date.now() + MIN_A2_WAIT_MS - before + 1000, sleep: async () => {} },
  );
  const name = readdirSync(dir).find((file) => /^summary-.*-a2-.*\.json$/.test(file));
  return { code, summary: name ? JSON.parse(readFileSync(join(dir, name), "utf8")) : null };
}

test("an unknown create is never settled by a 404, not in the run and not at A2: it is reported unconfirmed and the run is not closable", async (t) => {
  const state = await record(t, { createAnswer: "unknown-absent" });
  assert.equal(state.first.closureReady, false);
  assert.deepEqual(state.first.cleanup.unconfirmed, [P1]);
  assert.deepEqual(state.first.cleanup.unsettled, [P1]);
  assert.equal(state.first.cases.at(-1).outcome, "stopped");
  assert.equal(
    state.world.calls.some((call) => call.op === "deleteChannel"),
    false,
    "nothing is deleted on a 404",
  );
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, false);
  assert.deepEqual(a2.summary.cleanup.unconfirmed, [P1], "the A2 404 does not settle it either");
});

test("an unknown create followed by an own positive read settles: the channel is deleted and read back as 404", async (t) => {
  const state = await record(t, { createAnswer: "unknown-appears" });
  assert.deepEqual(state.first.cleanup.unconfirmed, []);
  assert.ok(state.first.cleanup.deleted.includes(P1));
  assert.equal(state.world.channels.has(P1), false);
  assert.equal(state.first.closureReady, false, "the 503 itself is an unknown answer of the run");
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, true);
  assert.deepEqual(a2.summary.cleanup.unsettled, []);
});

test("a confirmed create that reads 404 in the run stays open; only the A2 read-back, ten minutes later, settles it", async (t) => {
  const state = await record(t, { createAnswer: "invisible" });
  assert.deepEqual(state.first.cleanup.unsettled, [P1], "open in the run");
  assert.deepEqual(state.first.cleanup.unconfirmed, [], "confirmed by its operation, so not unconfirmed");
  assert.equal(state.first.closureReady, false);
  assert.equal(
    state.world.calls.some((call) => call.op === "deleteChannel"),
    false,
  );
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, true);
  assert.deepEqual(a2.summary.cleanup.unsettled, []);
  assert.ok(a2.summary.cleanup.alreadyGone.includes(P1));
  // Near miss: a read-back before the ten minutes is refused, and nothing is sent or written by it.
  const sent = state.world.calls.length;
  const early = await readBack(state, { before: 5 * 60 * 1000 });
  assert.equal(early.code, 2);
  assert.equal(state.world.calls.length, sent);
});

test("an unknown delete is sticky in the run (never re-sent) and only the A2 read-back showing 404 closes it", async (t) => {
  const state = await record(t, { deleteAnswer: "unknown-effective" });
  const deletes = state.world.calls.filter((call) => call.op === "deleteChannel");
  assert.equal(deletes.length, 1, "the deletion is not sent again");
  assert.equal(state.first.closureReady, false);
  assert.ok(state.first.cleanup.unsettled.includes(P1));
  const a2 = await readBack(state);
  assert.equal(a2.summary.closureReady, true);
  assert.deepEqual(a2.summary.cleanup.unsettled, []);
  assert.equal(
    state.world.calls.filter((call) => call.op === "deleteChannel").length,
    1,
    "A2 sent nothing: it read 404",
  );
});

test("an unknown delete that did not take effect leaves the channel in place, and the run is not closable", async (t) => {
  const state = await record(t, { deleteAnswer: "unknown-noeffect" });
  assert.equal(state.first.closureReady, false);
  assert.ok(state.world.channels.has(P1), "the channel is still there");
  assert.ok(state.first.cleanup.unsettled.includes(P1));
  assert.equal(state.world.calls.filter((call) => call.op === "deleteChannel").length, 1);
});
