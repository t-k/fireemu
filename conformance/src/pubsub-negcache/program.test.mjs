import assert from "node:assert/strict";
import test from "node:test";

import { CELLS, MIN_GAP_MS, planned, requestCount } from "./program.mjs";
import { buildRequest, setupRequests } from "./requests.mjs";
import { isOwned } from "./names.mjs";
import { CAPS } from "./runner.mjs";
import { EXPECT } from "./judge.mjs";
import { prng, RUN_ID } from "./support.mjs";

test("the program has the 30 cells and 189 scheduled requests the packet states", () => {
  assert.equal(CELLS.length, 30);
  assert.equal(requestCount(), 189);
  assert.equal(new Set(CELLS.map((c) => c.id)).size, 30);
});

test("the request count plus setup and the cleanup budget fit the hard cap", () => {
  // 2 setup, 189 cells, at most 34 resources deleted once, 3 LISTs, a second round of a few deletes.
  assert.ok(2 + requestCount() + 34 + 3 + 12 + 6 <= CAPS.requests);
});

test("every step builds a request whose targets are owned by the run", () => {
  for (const cell of CELLS)
    for (const step of cell.steps) {
      const request = buildRequest(step, { runId: RUN_ID, cellId: cell.id });
      for (const name of request.targets)
        assert.ok(isOwned(name, RUN_ID), `${cell.id} ${step.op} ${name}`);
    }
  for (const request of setupRequests({ runId: RUN_ID }))
    for (const name of request.targets) assert.ok(isOwned(name, RUN_ID));
});

test("every cell has a judge prerequisite and its arm step exists", () => {
  for (const cell of CELLS) {
    assert.ok(EXPECT[cell.id], cell.id);
    assert.ok(cell.arm >= 0 && cell.arm < cell.steps.length, cell.id);
    assert.ok(["dedicated", "fresh"].includes(cell.conn));
  }
});

test("every since reference points at an earlier step", () => {
  for (const cell of CELLS)
    cell.steps.forEach((step, i) => {
      if (step.since) assert.ok(step.since[0] < i, `${cell.id}/${i}`);
      assert.ok([step.at, step.after, step.since].filter((v) => v !== undefined).length <= 1);
    });
});

test("planned starts respect every constraint and the minimum gap", () => {
  for (const cell of CELLS) {
    const starts = planned(cell);
    starts.forEach((t, i) => {
      if (i > 0) assert.ok(t >= starts[i - 1] + MIN_GAP_MS);
      const s = cell.steps[i];
      if (s.at !== undefined) assert.ok(t >= s.at);
      if (s.since) assert.ok(t >= starts[s.since[0]] + s.since[1]);
      if (s.after !== undefined) assert.ok(t >= starts[i - 1] + s.after);
    });
  }
});

test("property: planned starts of random cells equal the maximum of their constraints", () => {
  const random = prng(7);
  for (let round = 0; round < 300; round += 1) {
    const steps = Array.from({ length: 1 + Math.floor(random() * 8) }, (_, i) => {
      const kind = i === 0 ? 0 : Math.floor(random() * 3);
      const ms = Math.floor(random() * 12000);
      return kind === 0
        ? { op: "getSub", at: ms }
        : kind === 1
          ? { op: "getSub", after: ms }
          : { op: "getSub", since: [Math.floor(random() * i), ms] };
    });
    const starts = planned({ steps });
    steps.forEach((s, i) => {
      const lower = [i === 0 ? 0 : starts[i - 1] + MIN_GAP_MS];
      if (s.at !== undefined) lower.push(s.at);
      if (s.after !== undefined) lower.push(starts[i - 1] + s.after);
      if (s.since) lower.push(starts[s.since[0]] + s.since[1]);
      assert.equal(starts[i], Math.max(...lower));
    });
  }
});

test("the arming steps of the cells are the ones the packet describes", () => {
  const byId = Object.fromEntries(CELLS.map((c) => [c.id, c]));
  assert.equal(byId.E1.steps[1].topic, "M");
  assert.equal(byId.A9.steps[0].from, "M2");
  assert.equal(byId["A6.1"].steps[1].snapshot, "Z");
  assert.equal(byId.N4.steps[1].bodyName, "X");
  assert.equal(byId.N5.steps[2].bodyName, "X");
  assert.equal(byId.N2b.conn, "fresh");
  assert.equal(byId.E4.conn, "fresh");
  // The three exemption cells differ only in the age of the negative after the positive GET.
  assert.deepEqual(
    ["P1", "P3", "P2"].map((id) => byId[id].steps[3].since[1]),
    [4000, 7000, 13000],
  );
});

test("the program is frozen: its canonical JSON has the pinned digest", async () => {
  const { createHash } = await import("node:crypto");
  const digest = createHash("sha256").update(JSON.stringify(CELLS)).digest("hex");
  assert.equal(digest, "54f4124c22a5ec1dca70d7b1d363e34eb0a5cf9e143c56c46d097f2a44fc5c45");
});

test("the minimum gap between two requests is 50 ms", () => {
  assert.equal(MIN_GAP_MS, 50);
});
