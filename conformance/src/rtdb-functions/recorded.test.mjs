// The production recording of CV14 (recorded/production-rtdb-triggers.json: 28 frames of the run of
// 2026-10-27) judged by the recorder's own judge, and the members that run showed (1st gen `domain`;
// 2nd gen `context`, `change`, `snapshot` and `traceparent`) named exactly as recorded: per generation and
// event type, with the recorded shape, and nothing else.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { RECORDED_MEMBERS } from "./frames.mjs";
import { judgeRun } from "./judge.mjs";
import { buildSteps, observe } from "./sequence.mjs";

const recording = JSON.parse(
  readFileSync(new URL("./recorded/production-rtdb-triggers.json", import.meta.url), "utf8"),
);
const steps = buildSteps(recording.recording.nonce);
const writes = Object.fromEntries(
  recording.steps.map((step) => [
    step.id,
    { outcome: step.outcome, status: step.status, answeredAtMs: 0 },
  ]),
);
const frames = () =>
  recording.frames.map(({ n: _n, step: _step, ...frame }) => structuredClone(frame));
const judge = (list) =>
  judgeRun({ report: observe({ writes, frames: list, steps }), frames: list, writes, ignored: {} });

const kindOf = (frame) =>
  frame.handler
    .replace(/V[12]$/u, "")
    .replace("rtdb", "")
    .toLowerCase();
const holderOf = (frame) => (frame.generation === 1 ? frame.event.context : frame.event);

test("the recording holds 28 frames, each attributed to one write, every documented delivery once and nothing else", () => {
  assert.equal(recording.frames.length, 28);
  const report = observe({ writes, frames: frames(), steps });
  assert.deepEqual(report.totals, { frames: 28, attributed: 28, unattributed: 0 });
  for (const step of report.steps) {
    for (const [handler, seen] of Object.entries(step.handlers)) {
      assert.equal(seen.matchesDocumented, true, `${step.id} ${handler}`);
    }
  }
  assert.deepEqual(
    recording.steps.map((step) => [step.id, step.outcome, step.status]),
    steps.map((step) => [step.id, "ok", 200]),
  );
});

test("with the members named from this recording the judge has nothing left to report", () => {
  assert.deepEqual(judge(frames()), []);
});

test("every recorded member is named for the generation and event types it was recorded on, and cites a recorded frame", () => {
  const seen = new Map();
  for (const frame of recording.frames) {
    const holder = holderOf(frame);
    const keys = frame.generation === 1 ? holder.contextKeys : holder.eventKeys;
    for (const key of keys) {
      if (!(key in (holder.extras ?? {}))) continue;
      const id = `${frame.generation}/${kindOf(frame)}/${key}`;
      seen.set(id, (seen.get(id) ?? 0) + 1);
    }
  }
  const past = { create: "created", update: "updated", delete: "deleted", write: "written" };
  const named = new Set(
    RECORDED_MEMBERS.map((e) => `${e.generation}/${past[e.event]}/${e.member}`),
  );
  assert.deepEqual([...seen.keys()].toSorted(), [...named].toSorted());
  for (const entry of RECORDED_MEMBERS) {
    assert.match(
      entry.source,
      /^recorded\/production-rtdb-triggers\.json frame \d+ \(rtdb\w+ seq \d+, step s\d\)$/u,
    );
    const frame = recording.frames[Number(/frame (\d+)/u.exec(entry.source)[1]) - 1];
    assert.equal(frame.generation, entry.generation);
    assert.ok(entry.member in (holderOf(frame).extras ?? {}), entry.source);
  }
});

test("a member outside the recorded scope is still unnamed: the other event types, the other generation, another shape, another name", () => {
  const unnamedIn = (tweak) => {
    const list = frames();
    tweak(list);
    return judge(list).filter((reason) => /did not name/u.test(reason));
  };
  const find = (list, handler, seq = 1) => list.find((f) => f.handler === handler && f.seq === seq);
  // `snapshot` belongs to created and deleted, `change` to updated and written, only on the 2nd gen
  assert.equal(
    unnamedIn((list) => {
      const f = find(list, "rtdbUpdatedV2");
      f.event.eventKeys = [...f.event.eventKeys, "snapshot"].toSorted();
      f.event.extras.snapshot = { type: "object", keys: ["_data", "_path", "app", "instance"] };
    }).length,
    1,
  );
  assert.equal(
    unnamedIn((list) => {
      const f = find(list, "rtdbCreatedV2");
      f.event.eventKeys = [...f.event.eventKeys, "change"].toSorted();
      f.event.extras.change = { type: "object", keys: ["after", "before"] };
    }).length,
    1,
  );
  // `domain` is a 1st gen context member; on a 2nd gen event it is unnamed
  assert.equal(
    unnamedIn((list) => {
      const f = find(list, "rtdbCreatedV2");
      f.event.eventKeys = [...f.event.eventKeys, "domain"].toSorted();
      f.event.extras.domain = "firebaseio.com";
    }).length,
    1,
  );
  // a 2nd gen member on a 1st gen context
  assert.equal(
    unnamedIn((list) => {
      const f = find(list, "rtdbCreatedV1");
      f.event.context.contextKeys = [...f.event.context.contextKeys, "traceparent"].toSorted();
      f.event.context.extras.traceparent =
        "00-ba24ec84f95950aeca52ade83309684f-70b4120df31afb90-01";
    }).length,
    1,
  );
  // another shape of a recorded name
  for (const [handler, member, value] of [
    ["rtdbCreatedV1", "domain", "example.com"],
    ["rtdbCreatedV1", "domain", { type: "object", keys: [] }],
    ["rtdbWrittenV2", "change", { type: "object", keys: ["after"] }],
    ["rtdbWrittenV2", "context", { type: "object", keys: ["eventId"] }],
    ["rtdbCreatedV2", "snapshot", { type: "object", keys: ["_data"] }],
    ["rtdbCreatedV2", "traceparent", "not-a-traceparent"],
    ["rtdbCreatedV2", "traceparent", 7],
  ]) {
    assert.equal(
      unnamedIn((list) => {
        const f = find(list, handler);
        const holder = holderOf(f);
        holder.extras[member] = value;
      }).length,
      1,
      `${handler} ${member} ${JSON.stringify(value)}`,
    );
  }
  // a member nobody recorded
  assert.equal(
    unnamedIn((list) => {
      const f = find(list, "rtdbWrittenV2");
      f.event.eventKeys = [...f.event.eventKeys, "extension"].toSorted();
      f.event.extras.extension = "x";
    }).length,
    1,
  );
});

test("adding one unknown member to any recorded frame brings the reason back", () => {
  for (let index = 0; index < recording.frames.length; index += 1) {
    const list = frames();
    const holder = holderOf(list[index]);
    const keys = list[index].generation === 1 ? "contextKeys" : "eventKeys";
    holder[keys] = [...holder[keys], "zzz"].toSorted();
    holder.extras = { ...holder.extras, zzz: 1 };
    const reasons = judge(list).filter((reason) => /did not name/u.test(reason));
    assert.equal(reasons.length, 1, `frame ${index + 1}`);
    assert.match(reasons[0], /: zzz$/u);
  }
});
