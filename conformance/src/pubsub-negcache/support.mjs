// Test support: a recording over the fake production on virtual time.
import { createRecorder } from "./runner.mjs";
import { createWorld, virtualClock } from "./world.mjs";

export const RUN_ID = "abcdef012345";

export function record({ params, faults, cells, caps, runId = RUN_ID, wrap } = {}) {
  const clock = virtualClock(1_000_000);
  const world = createWorld({ clock, params, faults });
  const rows = [];
  const base = world.send;
  const recorder = createRecorder({
    runId,
    transport: { send: wrap ? (req, meta) => wrap(base, req, meta, clock) : base },
    clock,
    journal: { write: (row) => rows.push(row) },
    ...(cells ? { cells } : {}),
    ...(caps ? { caps } : {}),
  });
  return { recorder, world, clock, rows, run: () => recorder.run() };
}

/** mulberry32: a seeded generator for the property tests. */
export function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
