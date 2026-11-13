import assert from "node:assert/strict";
import test from "node:test";

import { CELLS, MIN_GAP_MS, planned, requestCount } from "./program.mjs";
import { CELLS_V5, requestCountV5 } from "./program-v5.mjs";
import { buildRequest, setupRequests } from "./requests.mjs";
import { isOwned } from "./names.mjs";
import { CAPS } from "./runner.mjs";
import { EXPECT } from "./judge.mjs";
import { prng, RUN_ID } from "./support.mjs";

test("the program has the 33 cells and 200 scheduled requests the packet states", () => {
  assert.equal(CELLS.length, 33);
  assert.equal(requestCount(), 200);
  assert.equal(new Set(CELLS.map((c) => c.id)).size, 33);
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
  assert.equal(digest, "51088e44d47a67fc7752c8e444d57bbe75bbb505b18b703df09d52445b9c74b5");
});

test("the minimum gap between two requests is 50 ms", () => {
  assert.equal(MIN_GAP_MS, 50);
});

test("v5 keeps only the two calibration cells from v4 and schedules every repeat", () => {
  assert.deepEqual(CELLS_V5.slice(0, 2), CELLS.slice(0, 2));
  const ids = ["C0d", "C0f"];
  for (let i = 1; i <= 8; i++) ids.push(`DA${i}`);
  for (let i = 0; i < 16; i++) ids.push(`N1${String.fromCharCode(97 + i)}`);
  for (const age of [4, 7, 13]) for (const repeat of ["a", "b"]) ids.push(`E200-${age}${repeat}`);
  for (const edge of [25, 30, 35, 40, 45, 50])
    for (const repeat of ["a", "b"]) ids.push(`W${edge}${repeat}`);
  assert.deepEqual(
    CELLS_V5.map((c) => c.id),
    ids,
  );
  assert.equal(new Set(ids).size, 44);
});

test("v5 has exactly one probe per cell, the specified anchors, and a final delete for each created X", () => {
  const neverNames = new Set();
  for (const cell of CELLS_V5.slice(2)) {
    assert.equal(cell.conn, "dedicated");
    const probes = cell.steps.filter((s, i) => s.op === "getSub" && i > cell.arm);
    assert.equal(probes.length, 1, cell.id);
    let expected;
    if (cell.id.startsWith("DA")) {
      const age = [6000, 7500, 9000, 10500][Math.floor((Number(cell.id.slice(2)) - 1) / 2)];
      expected = ["putSub", "deleteSub", "deleteSub", "putSub", "getSub", "deleteSub"];
      assert.equal(cell.arm, 2);
      assert.deepEqual(probes[0].since, [2, age]);
    } else if (cell.id.startsWith("N1")) {
      const age = [3200, 3500, 3800, 4100, 4400, 4700, 5000, 5500][
        Math.floor((cell.id.charCodeAt(2) - 97) / 2)
      ];
      expected = ["getSub", "getSub"];
      assert.equal(cell.arm, 0);
      assert.ok(cell.steps.every((s) => s.target === "M2"));
      assert.deepEqual(probes[0].since, [0, age]);
      neverNames.add(buildRequest(cell.steps[0], { runId: RUN_ID, cellId: cell.id }).path);
    } else if (cell.id.startsWith("E200")) {
      expected = ["putSub", "getSub", "deleteSub", "getSub", "putSub", "getSub", "deleteSub"];
      assert.equal(cell.arm, 3);
      assert.deepEqual(cell.steps[3].since, [1, Number(cell.id.slice(5, -1)) * 1000]);
      assert.equal(probes[0].after, 50);
    } else {
      expected = ["getSub", "putSub", "getSub", "deleteSub"];
      assert.equal(cell.arm, 0);
      assert.deepEqual(probes[0].since, [0, 10000 + Number(cell.id.slice(1, -1)) * 10]);
    }
    assert.deepEqual(
      cell.steps.map((s) => s.op),
      expected,
      cell.id,
    );
    if (!cell.id.startsWith("N1")) {
      assert.deepEqual(cell.steps.at(-1), { op: "deleteSub", target: "X", after: 50 });
      assert.ok(cell.steps.every((s) => s.target === "X"));
    }
    for (const [i, step] of cell.steps.entries()) {
      if (step.since) assert.ok(step.since[0] < i, cell.id);
      assert.ok(!step.op.includes("Snap"));
      const request = buildRequest(step, { runId: RUN_ID, cellId: cell.id });
      for (const name of request.targets) assert.ok(isOwned(name, RUN_ID), name);
      if (step.op === "putSub") assert.equal(step.topic, "T");
    }
  }
  assert.equal(neverNames.size, 16);
});

test("v5 fits the unchanged request reserve, resource budget and 35 minute schedule with 9 s creates and 3 s deletes", () => {
  assert.equal(requestCountV5(), 177);
  assert.ok(requestCountV5() <= 230);
  assert.ok(
    setupRequests({ runId: RUN_ID }).length + requestCountV5() <=
      CAPS.requests - CAPS.cleanupRequests,
  );
  assert.equal(CAPS.requests, 260);
  assert.equal(CAPS.wallMs, 45 * 60 * 1000);
  let duration = 18000; // Conservatively allow two 9 s setup requests.
  let live = 1; // The setup source subscription.
  let maximum = live;
  for (const cell of CELLS_V5) {
    const starts = [];
    let done = 0;
    let created = false;
    for (const [i, step] of cell.steps.entries()) {
      const start = Math.max(
        i ? done + MIN_GAP_MS : 0,
        step.at ?? 0,
        step.after === undefined ? 0 : done + step.after,
        step.since ? starts[step.since[0]] + step.since[1] : 0,
      );
      starts.push(start);
      // Other requests get their full existing timeout, including the calibration pull.
      const latency =
        step.op === "putSub"
          ? 9000
          : step.op === "deleteSub"
            ? 3000
            : step.op === "pullSub"
              ? 25000
              : 10000;
      done = start + latency;
      if (step.op === "putSub") {
        created = true;
        live++;
      }
      maximum = Math.max(maximum, live);
      if (step.op === "deleteSub" && created) {
        created = false;
        live--;
      }
    }
    duration += done;
    assert.equal(live, 1, cell.id);
  }
  assert.ok(maximum <= 26);
  assert.ok(duration <= 35 * 60 * 1000, String(duration));
});
