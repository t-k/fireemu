import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { CANDIDATES, CASE_PLAN, CASE_ROWS } from "./storage-rules-s9/plan-case.mjs";
import { readCase, renderReading } from "./storage-rules-s9/reading.mjs";

const classOf = (allowed) => (allowed ? "allow" : "deny");
const rowsFor = (candidate, recordings = [1, 2]) =>
  recordings.flatMap((recording) =>
    CASE_ROWS.map((row) => ({
      recording,
      program: "case",
      id: row.id,
      class: classOf(row.candidates[candidate]),
    })),
  );
const set = (rows, id, cls, recording) =>
  rows.map((r) => (r.id === id && (recording === undefined || r.recording === recording) ? { ...r, class: cls } : r));
const flip = (rows, id, recording) =>
  rows.map((r) =>
    r.id === id && (recording === undefined || r.recording === recording)
      ? { ...r, class: r.class === "allow" ? "deny" : "allow" }
      : r,
  );

// A small seeded generator, so a failure replays.
function lcg(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

describe("reading a case run against the candidates", () => {
  for (const candidate of CANDIDATES) {
    it(`names ${candidate} when every row is what ${candidate} predicts in both recordings`, () => {
      const reading = readCase(rowsFor(candidate), CASE_PLAN);
      assert.equal(reading.verdict, candidate);
      assert.equal(reading.complete, true);
      assert.equal(reading.controls, "ok");
      assert.deepEqual(reading.disagreeing, []);
      for (const other of CANDIDATES)
        assert.equal(reading.perCandidate[other].consistent, other === candidate, other);
    });
  }

  it("says the controls failed, and reads nothing else, when a control row answers wrongly", () => {
    for (const control of CASE_ROWS.filter((r) => r.control)) {
      const reading = readCase(flip(rowsFor("ascii"), control.id), CASE_PLAN);
      assert.equal(reading.verdict, "controls-failed", control.id);
      assert.deepEqual(reading.failedControls, [control.id]);
    }
  });

  it("says none when a probe row answers what no candidate predicts", () => {
    const reading = readCase(flip(rowsFor("ascii"), "sigma-final"), CASE_PLAN);
    assert.equal(reading.verdict, "none");
    assert.deepEqual(reading.perCandidate.ascii.mismatches.sort(), ["sigma-final"]);
    assert.equal(reading.perCandidate.full.consistent, false);
  });

  it("says none when every probe is refused, as a rule that fails to evaluate would be", () => {
    const rows = rowsFor("ascii").map((r) =>
      CASE_ROWS.find((x) => x.id === r.id).control ? r : { ...r, class: "deny" },
    );
    assert.equal(readCase(rows, CASE_PLAN).verdict, "none");
  });

  it("says none for a runtime that maps Latin-1 and nothing else", () => {
    const latin1 = (row) => {
      const ids = new Set(["acute-lower-mapped", "acute-upper-mapped", "rt-lower-mapped", "rt-res-lower-differs"]);
      return ids.has(row.id) ? true : row.candidates.ascii && !/^acute-(lower|upper)-same$|^rt-lower-same$|^rt-res-lower-same$/.test(row.id);
    };
    const rows = [1, 2].flatMap((recording) =>
      CASE_ROWS.map((row) => ({ recording, program: "case", id: row.id, class: classOf(latin1(row)) })),
    );
    assert.equal(readCase(rows, CASE_PLAN).verdict, "none");
  });

  it("is incomplete, not a verdict, when a probe is unread, other, unknown or not evaluated", () => {
    for (const cls of ["other", "unknown", "not-evaluated", "not-found", "no-release"]) {
      const reading = readCase(set(rowsFor("full"), "sharp-upper-full", cls, 2), CASE_PLAN);
      assert.equal(reading.verdict, "incomplete", cls);
      assert.equal(reading.complete, false);
      assert.deepEqual(reading.unread, ["2/sharp-upper-full"]);
    }
  });

  it("is incomplete when a row is missing from a recording or a recording is missing", () => {
    const missing = rowsFor("ascii").filter((r) => !(r.recording === 2 && r.id === "ctl-upper-true"));
    assert.equal(readCase(missing, CASE_PLAN).verdict, "incomplete");
    assert.equal(readCase(rowsFor("ascii", [1]), CASE_PLAN, { recordings: 2 }).verdict, "incomplete");
    assert.equal(readCase([], CASE_PLAN).verdict, "incomplete");
  });

  it("reads one complete recording when only one is expected", () => {
    assert.equal(readCase(rowsFor("simple", [1]), CASE_PLAN, { recordings: 1 }).verdict, "simple");
  });

  it("says disagree when the two recordings answer a row differently", () => {
    const reading = readCase(flip(rowsFor("ascii"), "acute-lower-same", 2), CASE_PLAN);
    assert.equal(reading.verdict, "disagree");
    assert.deepEqual(reading.disagreeing, ["acute-lower-same"]);
  });

  it("checks the controls before the disagreement and the disagreement before the candidates", () => {
    const both = flip(flip(rowsFor("ascii"), "ctl-upper-true", 2), "acute-lower-same", 2);
    assert.equal(readCase(both, CASE_PLAN).verdict, "controls-failed");
    const incompleteAndDisagree = set(flip(rowsFor("ascii"), "acute-lower-same", 2), "sharp-upper-full", "other", 1);
    assert.equal(readCase(incompleteAndDisagree, CASE_PLAN).verdict, "incomplete");
  });

  it("ignores rows that are not in the plan", () => {
    const extra = [...rowsFor("ascii"), { recording: 1, program: "s9", id: "pub-plain-meta", class: "deny" }];
    assert.equal(readCase(extra, CASE_PLAN).verdict, "ascii");
  });

  it("matches a brute-force reading on random answers, and names a candidate only when it is the only one that fits", () => {
    const next = lcg(20261111);
    for (let trial = 0; trial < 400; trial += 1) {
      const candidate = CANDIDATES[Math.floor(next() * 3)];
      let rows = rowsFor(candidate);
      const flips = Math.floor(next() * 3);
      for (let i = 0; i < flips; i += 1) rows = flip(rows, CASE_ROWS[Math.floor(next() * CASE_ROWS.length)].id);
      const reading = readCase(rows, CASE_PLAN);
      const first = new Map(rows.filter((r) => r.recording === 1).map((r) => [r.id, r.class]));
      const second = new Map(rows.filter((r) => r.recording === 2).map((r) => [r.id, r.class]));
      const disagree = CASE_ROWS.filter((r) => first.get(r.id) !== second.get(r.id));
      const controlWrong = CASE_ROWS.filter((r) => r.control && first.get(r.id) !== classOf(r.candidates.ascii));
      const fits = CANDIDATES.filter((c) =>
        CASE_ROWS.every((r) => first.get(r.id) === classOf(r.candidates[c])),
      );
      if (controlWrong.length > 0) assert.equal(reading.verdict, "controls-failed");
      else if (disagree.length > 0) assert.equal(reading.verdict, "disagree");
      else if (fits.length === 1) assert.equal(reading.verdict, fits[0]);
      else if (fits.length === 0) assert.equal(reading.verdict, "none");
      else assert.equal(reading.verdict, "ambiguous");
    }
  });

  it("prints the verdict, the per-candidate mismatches and one line per probe", () => {
    const text = renderReading(readCase(flip(rowsFor("ascii"), "sigma-final"), CASE_PLAN));
    assert.match(text, /verdict: none/);
    assert.match(text, /ascii: 1 mismatch\(es\): sigma-final/);
    assert.match(text, /full: \d+ mismatch/);
    assert.match(text, /^sigma-final\t/m);
    assert.equal(
      text.split("\n").filter((l) => CASE_ROWS.some((r) => l.startsWith(`${r.id}\t`))).length,
      CASE_ROWS.length,
    );
  });
});
