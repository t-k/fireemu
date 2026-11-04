// The local dry run's fixed parts: the golden frames (the fixture's output under fireemu, run marker replaced) judged in
// the local mode, and the dry run's argument parsing. The dry run itself needs a built fireemu and a Python
// environment, so it is run by hand and recorded in the packet's notes, not here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { judge } from "../record/judge.mjs";
import { parseFramesFromText } from "../record/logs.mjs";
import { ALL_FUNCTIONS } from "../record/plan.mjs";
import { parseArgs } from "./dry-run.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const RUN = "0123456789abcdef";
const SENT = Object.fromEntries(
  [
    "fs-create",
    "fs-update",
    "ps-plain",
    "ps-ordered",
    "st-upload",
    "ea-fraction",
    "ea-whole",
    "sched-pcsch",
    "sched-pcschraw",
    "task-pctask",
    "task-pctaskraw",
  ].map((k) => [k, {}]),
);
const golden = () =>
  parseFramesFromText(
    readFileSync(join(here, "golden-frames.txt"), "utf8").replaceAll("pcrun-RUNID", "pcrun-" + RUN),
  );

test("the golden frames parse, with nothing ignored, and cover twelve of the thirteen functions' deliveries", () => {
  const { frames, ignored } = golden();
  assert.equal(ignored, 0);
  assert.equal(frames.length, 16);
  const seen = new Set(frames.map((f) => f.frame.function));
  assert.deepEqual(
    ALL_FUNCTIONS.filter((fn) => !seen.has(fn)),
    [],
    "every function printed a frame",
  );
});

test("the golden frames judge, in the local mode, as the dry run did: twelve as expected, two local differences, one observed", () => {
  const r = judge({ runId: RUN, frames: golden().frames, sent: SENT, mode: "local" });
  assert.deepEqual(r.counts, {
    "as-expected": 12,
    differs: 2,
    observed: 1,
    "not-delivered": 0,
    "not-sent": 0,
  });
  assert.deepEqual(
    r.cases["scheduler-request"].notes,
    ["content-length", "host"],
    "fireemu sends no Content-Length and its own host",
  );
  assert.deepEqual(
    r.cases["tasks-request"].notes,
    ["queue-name-header", "bearer-token"],
    "fireemu names the queue with its own prefix and sends no OIDC bearer",
  );
  assert.equal(r.cases["eventarc-time-whole"].status, "observed");
  assert.equal(r.complete, true);
});

test("the dry run's arguments: pairs of flags, strict by default", () => {
  assert.deepEqual(parseArgs(["--fireemu", "/f", "--venv", "/v", "--out", "/o"]), {
    profile: "strict",
    fireemu: "/f",
    venv: "/v",
    out: "/o",
  });
  assert.equal(parseArgs(["--profile", "emulator"]).profile, "emulator");
  assert.throws(() => parseArgs(["--fireemu"]), /bad arguments/);
  assert.throws(() => parseArgs(["fireemu", "x"]), /bad arguments/);
});
