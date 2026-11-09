// The closure replay of the kinds recordings (RTDB-TRIGGERS-KINDS-20261108-01 and -20261109-02): the strict
// profile of a release binary, run through the two producer runs of kinds-replay-run.mjs (`all`, the 21 steps
// of the first recording, and `v2`, k15 to k26 of the second), compared with the two committed production
// fixtures. What must hold is pinned here: the answers of every write, 43 of 43 rows for the second
// recording, 72 of 76 for the first with only the four rows of k12 apart, and no frame nothing explains.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { compareRecordings } from "./kinds-compare.mjs";
import { MASKED_NONCE, maskLocalRun } from "./kinds-mask.mjs";
import { KINDS_V2_SCENARIO } from "./kinds-scenario.mjs";
import { buildSteps, matchFrame } from "./kinds-sequence.mjs";

const recorded = (name) =>
  JSON.parse(readFileSync(new URL(`./recorded/${name}.json`, import.meta.url), "utf8"));

/** The answer each write of a producer run must have: a status, or "ok" for the SDK's own answer. */
export const KINDS_WRITES = Object.freeze({
  all: Object.freeze([
    ...Array.from({ length: 12 }, (_, i) => [`k${i + 1}`, 200]),
    ["k13", 400],
    ["k14", 200],
    ["k15", 200],
    ["k16", 200],
    ["k17", 200],
    ["k18", "ok"],
    ["k19", "ok"],
    ["k20", "ok"],
    ["k21", "ok"],
  ]),
  v2: Object.freeze([
    ["k15", 200],
    ["k16", 200],
    ["k17", 200],
    ["k18", "ok"],
    ["k19", "ok"],
    ["k20", "ok"],
    ["k21", "ok"],
    ["k22", 200],
    ["k23", 200],
    ["k24", 200],
    ["k25", 400],
    ["k26", 400],
  ]),
});

const readLines = (file) =>
  readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));

const answered = (writes, expected) =>
  writes.length === expected.length &&
  writes.every(
    (write, i) =>
      write.step === expected[i][0] &&
      (expected[i][1] === "ok"
        ? write.outcome === "ok"
        : write.status === expected[i][1] && write.outcome === undefined),
  );

// With k13 refused, k14 deletes the group `gl` that holds l1 and l2 only, which the first recording's plan
// (l1 to l3) does not describe: that one group delivery is the only frame the replay may leave out.
const isK14Group = (frame) =>
  frame.handler === "k9GroupWrittenV2" &&
  frame.event?.params?.group === "gl" &&
  frame.event?.data?.after?.exists === false;

function replay({ production, dir, steps, keep, expected, writes, allowK14 }) {
  const frames = readLines(join(dir, "frames.jsonl"));
  const unplanned = frames.filter((frame) => matchFrame(frame, steps).step === null);
  const explained = allowK14 ? unplanned.length <= 1 && unplanned.every(isK14Group) : false;
  const masked = maskLocalRun({
    frames,
    steps,
    label: "strict",
    dropUnattributed: true,
  });
  const comparison = compareRecordings({
    production,
    local: masked.frames.filter(keep),
    steps,
  });
  const differing = comparison.rows
    .filter((row) => row.verdict !== "MATCH")
    .map((row) => row.row[0])
    .toSorted();
  const writesOk = answered(JSON.parse(readFileSync(join(dir, "writes.json"), "utf8")), writes);
  const result = {
    totals: comparison.totals,
    differing,
    dropped: masked.recording.dropped,
    unattributed: comparison.unattributed,
    writesAnswered: writesOk,
  };
  // The pinned shape, whole: the totals and which steps differ (the totals alone would not say that the
  // four differing rows are those of k12). No frame is unattributed here: the production fixtures are
  // attributed (kinds-recorded.test.mjs) and the local frames were masked with the unplanned ones dropped.
  const match =
    (unplanned.length === 0 || explained) &&
    writesOk &&
    JSON.stringify({ totals: comparison.totals, differing }) ===
      JSON.stringify({ totals: expected.totals, differing: expected.differing });
  return { match, ...result };
}

/**
 * Judges the output directory of kinds-replay-run.mjs. `match` holds only when both runs answered every write
 * as planned and their frames compare as pinned; any other shape, a missing file included, is `match: false`.
 */
export function adjudicateKinds(out) {
  try {
    const first = replay({
      production: recorded("production-rtdb-kinds").frames,
      dir: join(out, "all"),
      steps: buildSteps(MASKED_NONCE),
      keep: (frame) => Number(frame.step.slice(1)) <= 13,
      // k12's 600 KiB create was not delivered once in production (the same shape was, in the second
      // recording): four handlers, one-off and unexplained; fireemu delivers it.
      expected: {
        totals: { rows: 76, match: 72, difference: 4 },
        differing: ["k12", "k12", "k12", "k12"],
      },
      writes: KINDS_WRITES.all,
      allowK14: true,
    });
    const second = replay({
      production: recorded("production-rtdb-kinds-user-ladder").frames,
      dir: join(out, "v2"),
      steps: KINDS_V2_SCENARIO.buildSteps(MASKED_NONCE),
      keep: () => true,
      expected: { totals: { rows: 43, match: 43, difference: 0 }, differing: [] },
      writes: KINDS_WRITES.v2,
      allowK14: false,
    });
    return { match: first.match && second.match, result: { first, second } };
  } catch (error) {
    return { match: false, error: String(error?.message ?? error) };
  }
}
