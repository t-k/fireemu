import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { adjudicateKinds, KINDS_WRITES } from "./kinds-replay.mjs";

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`./recorded/${name}.json`, import.meta.url), "utf8"));
const raw = (frames) => frames.map(({ n: _n, step: _step, ...frame }) => frame);
const writesOf = (expected) =>
  expected.map(([step, status]) =>
    status === "ok" ? { step, outcome: "ok" } : { step, n: 0, status },
  );

/** The output directory of a kinds replay: `all` (the 21 steps of the first recording) and `v2` (k15 to k26). */
function stage(profile = "strict", edit = (dirs) => dirs) {
  const dir = mkdtempSync(join(tmpdir(), "kinds-replay-"));
  const first = fixture(`local-${profile}-rtdb-kinds`).frames;
  const second = fixture(`local-${profile}-rtdb-kinds-user-ladder`).frames;
  const dirs = {
    all: { frames: raw(first), writes: writesOf(KINDS_WRITES.all) },
    v2: { frames: raw(second), writes: writesOf(KINDS_WRITES.v2) },
  };
  for (const [name, content] of Object.entries(edit(dirs))) {
    mkdirSync(join(dir, name));
    writeFileSync(
      join(dir, name, "frames.jsonl"),
      `${content.frames.map((f) => JSON.stringify(f)).join("\n")}\n`,
    );
    writeFileSync(join(dir, name, "writes.json"), JSON.stringify(content.writes));
  }
  return dir;
}
const run = (dir) => {
  try {
    return adjudicateKinds(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};
// the frame fireemu delivers for k14 once k13 was refused: the group `gl` loses l1 and l2, which no step plans
const k14Group = {
  handler: "k9GroupWrittenV2",
  generation: 2,
  event: {
    params: { group: "gl" },
    data: {
      before: { exists: true, key: "gl", value: { items: { l1: { value: 1 } } } },
      after: { exists: false, key: "gl", value: null },
    },
  },
};

test("the planned writes of the two producer runs are pinned", () => {
  assert.equal(KINDS_WRITES.all.length, 21);
  assert.deepEqual(
    KINDS_WRITES.all.filter(([, status]) => status === 400),
    [["k13", 400]],
  );
  assert.deepEqual(
    KINDS_WRITES.v2.map(([step]) => step),
    ["k15", "k16", "k17", "k18", "k19", "k20", "k21", "k22", "k23", "k24", "k25", "k26"],
  );
  assert.deepEqual(
    KINDS_WRITES.v2.filter(([, status]) => status === 400).map(([step]) => step),
    ["k25", "k26"],
  );
});

test("the strict recordings are the closure replay: 43 of 43 rows and 72 of 76 with only k12 apart", () => {
  const result = adjudicateKinds(stage());
  assert.equal(result.match, true, JSON.stringify(result));
  assert.deepEqual(result.result.first.totals, { rows: 76, match: 72, difference: 4 });
  assert.deepEqual(result.result.first.differing, ["k12", "k12", "k12", "k12"]);
  assert.deepEqual(result.result.second.totals, { rows: 43, match: 43, difference: 0 });
  assert.equal(result.result.first.dropped, 0);
});

test("the k14 group delete that follows the refused k13 is dropped, anything else unplanned is not", () => {
  const withK14 = run(
    stage("strict", (d) => ({ ...d, all: { ...d.all, frames: [...d.all.frames, k14Group] } })),
  );
  assert.equal(withK14.match, true);
  assert.equal(withK14.result.first.dropped, 1);
  const twice = run(
    stage("strict", (d) => ({
      ...d,
      all: { ...d.all, frames: [...d.all.frames, k14Group, k14Group] },
    })),
  );
  assert.equal(twice.match, false, "two unplanned frames");
  const stray = structuredClone(k14Group);
  stray.event.params.group = "zz";
  assert.equal(
    run(stage("strict", (d) => ({ ...d, all: { ...d.all, frames: [...d.all.frames, stray] } })))
      .match,
    false,
    "an unplanned frame of another group",
  );
  const other = structuredClone(k14Group);
  other.handler = "k9CreatedV2";
  assert.equal(
    run(stage("strict", (d) => ({ ...d, all: { ...d.all, frames: [...d.all.frames, other] } })))
      .match,
    false,
    "an unplanned frame of another handler",
  );
});

test("a missing, an extra or a changed delivery is not a match", () => {
  const drop = (name, keep) => (d) => ({
    ...d,
    [name]: { ...d[name], frames: d[name].frames.filter(keep) },
  });
  assert.equal(
    run(
      stage(
        "strict",
        drop("v2", (f) => !(f.handler === "k9CreatedV2" && f.event.params.id === "q3")),
      ),
    ).match,
    false,
    "the 1,024,000-byte rung must be delivered",
  );
  assert.equal(
    run(
      stage(
        "strict",
        drop("all", (f) => !(f.handler === "k9CreatedV1" && f.event.context.params.id === "a1")),
      ),
    ).match,
    false,
  );
  // k12 delivered nowhere would make the first comparison 72 rows of 72 plus the k12 rows equal: still not the pinned shape
  assert.equal(
    run(
      stage(
        "strict",
        drop("all", (f) => f.event.params?.id !== "l2" && f.event.context?.params?.id !== "l2"),
      ),
    ).match,
    false,
  );
  const changed = (d) => {
    const copy = structuredClone(d);
    const frame = copy.v2.frames.find((f) => f.handler === "k9UpdatedV2");
    frame.event.authType = "unknown";
    return copy;
  };
  assert.equal(run(stage("strict", changed)).match, false, "a changed member");
});

test("the emulator profile and a refused rung that is delivered are not the strict replay", () => {
  assert.equal(run(stage("emulator")).match, false);
});

test("the producers' answers are checked: a changed status or a missing write is not a match", () => {
  const status = (name, step, to) => (d) => {
    const copy = structuredClone(d);
    copy[name].writes.find((w) => w.step === step).status = to;
    return copy;
  };
  assert.equal(run(stage("strict", status("all", "k13", 200))).match, false, "k13 must be refused");
  assert.equal(run(stage("strict", status("v2", "k25", 200))).match, false);
  assert.equal(run(stage("strict", status("v2", "k24", 400))).match, false);
  const missing = (d) => ({ ...d, v2: { ...d.v2, writes: d.v2.writes.slice(0, -1) } });
  assert.equal(run(stage("strict", missing)).match, false);
  const sdk = (d) => {
    const copy = structuredClone(d);
    copy.v2.writes.find((w) => w.step === "k19").outcome = "failed";
    return copy;
  };
  assert.equal(run(stage("strict", sdk)).match, false, "a transaction that did not commit");
});

test("a replay with a missing directory or file is a failure, not an exception", () => {
  const dir = mkdtempSync(join(tmpdir(), "kinds-replay-empty-"));
  try {
    assert.equal(adjudicateKinds(dir).match, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
