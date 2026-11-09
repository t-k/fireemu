import test from "node:test";
import assert from "node:assert/strict";
import { FIXTURE_HANDLERS } from "./kinds-frames.mjs";
import { judgeRun } from "./kinds-judge.mjs";
import { buildSteps, matchFrame, observe } from "./kinds-sequence.mjs";
import { perfectFrames } from "./kinds-world.fake.mjs";

// Differential property: drop some of the expected deliveries and repeat some others at random; the judge
// must name exactly the dropped ones on judged steps (missing) and exactly the repeated ones (repeated),
// and nothing else.
const steps = buildSteps("N");
const all = FIXTURE_HANDLERS.map((h) => h.name);
const writes = Object.fromEntries(steps.map((s) => [s.id, { outcome: "ok", status: 200 }]));
const full = perfectFrames(steps);
const observeOnly = new Set(steps.filter((s) => s.observeOnly).map((s) => s.id));

const labelOf = (frame) => {
  const { step } = matchFrame(frame, steps);
  const params = frame.generation === 1 ? frame.event.context.params : frame.event.params;
  return {
    step,
    label: `${step} ${frame.handler} ${params.id === undefined ? params.group : `${params.group}/${params.id}`}`,
  };
};
const labels = full.map(labelOf);

test("random drops and repeats are named exactly, judged steps only", () => {
  let state = 987654321;
  const random = () => (state = (state * 1664525 + 1013904223) >>> 0);
  for (let round = 0; round < 80; round++) {
    const dropped = new Set();
    const repeated = new Set();
    for (let i = 0; i < full.length; i++) {
      const roll = random() % 100;
      if (roll < 6) dropped.add(i);
      else if (roll < 11) repeated.add(i);
    }
    const frames = [];
    full.forEach((frame, i) => {
      if (dropped.has(i)) return;
      frames.push(frame);
      if (repeated.has(i)) frames.push(structuredClone(frame));
    });
    const reasons = judgeRun({
      report: observe({ writes, frames, steps }),
      frames,
      writes,
      ignored: {},
      deployed: all,
    }).toSorted();
    const expected = [
      ...[...dropped]
        .filter((i) => !observeOnly.has(labels[i].step))
        .map((i) => `missing delivery: ${labels[i].label}`),
      ...[...repeated]
        .filter((i) => !dropped.has(i))
        .map((i) => `repeated delivery: ${labels[i].label}`),
    ].toSorted();
    assert.deepEqual(reasons, expected, `round ${round}`);
  }
});

test("a delivery under a second event id is named once per transition, never as a repeat", () => {
  let state = 24680;
  const random = () => (state = (state * 1664525 + 1013904223) >>> 0);
  for (let round = 0; round < 40; round++) {
    const picked = new Set();
    for (let i = 0; i < full.length; i++) if (random() % 100 < 8) picked.add(i);
    const frames = [];
    full.forEach((frame, i) => {
      frames.push(frame);
      if (picked.has(i)) {
        const other = structuredClone(frame);
        if (other.generation === 1) other.event.context.eventId = `other-${i}`;
        else other.event.id = `other-${i}`;
        frames.push(other);
      }
    });
    const reasons = judgeRun({
      report: observe({ writes, frames, steps }),
      frames,
      writes,
      ignored: {},
      deployed: all,
    }).toSorted();
    const expected = [...picked].map((i) => `multiple event ids: ${labels[i].label}`).toSorted();
    assert.deepEqual(reasons, expected, `round ${round}`);
  }
});
