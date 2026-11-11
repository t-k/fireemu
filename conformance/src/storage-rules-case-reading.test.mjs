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
      program: row.program,
      id: row.id,
      class: classOf(row.candidates[candidate]),
    })),
  );
const set = (rows, id, cls, recording) =>
  rows.map((r) =>
    r.id === id && (recording === undefined || r.recording === recording)
      ? { ...r, class: cls }
      : r,
  );
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
    assert.deepEqual(reading.perCandidate.ascii.mismatches.toSorted(), ["sigma-final"]);
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
      const ids = new Set([
        "acute-lower-mapped",
        "acute-upper-mapped",
        "rt-lower-mapped",
        "rt-res-lower-differs",
      ]);
      return ids.has(row.id)
        ? true
        : row.candidates.ascii &&
            !/^acute-(lower|upper)-same$|^rt-lower-same$|^rt-res-lower-same$/.test(row.id);
    };
    const rows = [1, 2].flatMap((recording) =>
      CASE_ROWS.map((row) => ({
        recording,
        program: "case",
        id: row.id,
        class: classOf(latin1(row)),
      })),
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
    const missing = rowsFor("ascii").filter(
      (r) => !(r.recording === 2 && r.id === "ctl-upper-true"),
    );
    assert.equal(readCase(missing, CASE_PLAN).verdict, "incomplete");
    assert.equal(
      readCase(rowsFor("ascii", [1]), CASE_PLAN, { recordings: 2 }).verdict,
      "incomplete",
    );
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
    const incompleteAndDisagree = set(
      flip(rowsFor("ascii"), "acute-lower-same", 2),
      "sharp-upper-full",
      "other",
      1,
    );
    assert.equal(readCase(incompleteAndDisagree, CASE_PLAN).verdict, "incomplete");
  });

  it("ignores rows that are not in the plan", () => {
    const extra = [
      ...rowsFor("ascii"),
      { recording: 1, program: "s9", id: "pub-plain-meta", class: "deny" },
    ];
    assert.equal(readCase(extra, CASE_PLAN).verdict, "ascii");
  });

  it("matches a brute-force reading on random answers, and names a candidate only when it is the only one that fits", () => {
    const next = lcg(20261111);
    for (let trial = 0; trial < 400; trial += 1) {
      const candidate = CANDIDATES[Math.floor(next() * 3)];
      let rows = rowsFor(candidate);
      const flips = Math.floor(next() * 3);
      for (let i = 0; i < flips; i += 1)
        rows = flip(rows, CASE_ROWS[Math.floor(next() * CASE_ROWS.length)].id);
      const reading = readCase(rows, CASE_PLAN);
      const first = new Map(rows.filter((r) => r.recording === 1).map((r) => [r.id, r.class]));
      const second = new Map(rows.filter((r) => r.recording === 2).map((r) => [r.id, r.class]));
      const disagree = CASE_ROWS.filter((r) => first.get(r.id) !== second.get(r.id));
      const controlWrong = CASE_ROWS.filter(
        (r) => r.control && first.get(r.id) !== classOf(r.candidates.ascii),
      );
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

describe("reading details", () => {
  it("reports the controls as failed in the reading, and ok otherwise", () => {
    assert.equal(readCase(rowsFor("ascii"), CASE_PLAN).controls, "ok");
    const failed = readCase(flip(rowsFor("ascii"), "ctl-lower-true"), CASE_PLAN);
    assert.equal(failed.controls, "failed");
    assert.deepEqual(failed.failedControls, ["ctl-lower-true"]);
  });

  it("marks a missing row `missing` in the table and keeps the answers of the others", () => {
    const rows = rowsFor("ascii").filter((r) => !(r.recording === 2 && r.id === "sigma-final"));
    const reading = readCase(rows, CASE_PLAN);
    assert.deepEqual(reading.table.find((r) => r.id === "sigma-final").classes, [
      "deny",
      "missing",
    ]);
    assert.deepEqual(reading.table.find((r) => r.id === "sigma-same").classes, ["allow", "allow"]);
    assert.equal(reading.table.length, CASE_ROWS.length);
  });

  it("says ambiguous when two candidates fit every row, which a plan that cannot tell them apart allows", () => {
    const rows = ["a", "b"].map((id, index) => ({
      program: "p",
      id,
      control: false,
      group: "g",
      candidates: { ascii: true, full: true, simple: index === 0 },
    }));
    const plan = { rows };
    const answers = [1, 2].flatMap((recording) =>
      rows.map((r) => ({ recording, id: r.id, class: "allow" })),
    );
    const reading = readCase(answers, plan);
    assert.equal(reading.verdict, "ambiguous");
    assert.equal(reading.perCandidate.ascii.consistent, true);
    assert.equal(reading.perCandidate.full.consistent, true);
    assert.equal(reading.perCandidate.simple.consistent, false);
    const none = readCase(
      answers.map((a) => ({ ...a, class: "deny" })),
      plan,
    );
    assert.equal(none.verdict, "none");
  });

  it("prints every line of a reading exactly", () => {
    const rows = ["ctl-upper-true", "acute-lower-same"].length ? rowsFor("ascii") : [];
    const broken = set(
      set(
        flip(flip(rows, "ctl-lower-true", 1), "acute-lower-same", 2),
        "sharp-upper-full",
        "other",
        1,
      ),
      "sigma-final",
      "deny",
      1,
    );
    const lines = renderReading(readCase(broken, CASE_PLAN)).split("\n");
    assert.equal(lines[0], "verdict: controls-failed");
    assert.equal(lines[1], "complete: false; controls: failed (ctl-lower-true)");
    assert.equal(lines[2], "unread: 1/sharp-upper-full");
    assert.equal(lines[3], "disagreeing: ctl-lower-true, acute-lower-same");
    assert.equal(lines[4], "ascii: 2 mismatch(es): ctl-lower-true, acute-lower-same");
    assert.match(lines[5], /^full: \d+ mismatch\(es\): /);
    assert.match(lines[6], /^simple: \d+ mismatch\(es\): /);
    assert.equal(lines[7], "programs: core=controls-failed, wide=ascii");
    assert.equal(lines[8], "");
    assert.equal(lines[9], "row\tgroup\tanswers\tascii\tfull\tsimple");
    assert.equal(lines[10], "ctl-upper-true\tcontrol\tallow,allow\tallow\tallow\tallow");
    assert.ok(lines.includes("acute-lower-same\tacute\tallow,deny\tallow\tdeny\tdeny"));
    assert.ok(lines.includes("sharp-upper-full\tsharp\tother,deny\tdeny\tallow\tdeny"));
    assert.equal(lines.length, 10 + CASE_ROWS.length);
  });

  it("joins several failed controls, unread rows and disagreeing rows with a comma and a space", () => {
    let rows = flip(flip(rowsFor("ascii"), "ctl-lower-true"), "ctl-upper-true");
    rows = set(set(rows, "sharp-upper-full", "other", 1), "sigma-final", "unknown", 2);
    rows = flip(flip(rows, "acute-lower-same", 2), "acute-upper-same", 2);
    const lines = renderReading(readCase(rows, CASE_PLAN)).split("\n");
    assert.equal(lines[1], "complete: false; controls: failed (ctl-upper-true, ctl-lower-true)");
    assert.equal(lines[2], "unread: 1/sharp-upper-full, 2/sigma-final");
    assert.equal(lines[3], "disagreeing: acute-lower-same, acute-upper-same");
  });

  it("prints no unread, disagreeing or failed-control line for a clean reading, and `none` for no mismatch", () => {
    const text = renderReading(readCase(rowsFor("full"), CASE_PLAN));
    assert.ok(text.startsWith("verdict: full\ncomplete: true; controls: ok\nascii: "));
    assert.ok(!/unread|disagreeing|failed/.test(text.split("\n\n")[0].replace("ascii: ", "")));
    assert.match(text, /\nfull: 0 mismatch\(es\)\nsimple: /);
  });
});

describe("the reading per ruleset", () => {
  it("names a candidate for each ruleset alone, and `ambiguous` where its rows cannot tell two apart", () => {
    for (const [candidate, wide] of [
      ["ascii", "ascii"],
      ["full", "ambiguous"],
      ["simple", "ambiguous"],
    ]) {
      const reading = readCase(rowsFor(candidate), CASE_PLAN);
      assert.deepEqual(reading.byProgram, { core: candidate, wide }, candidate);
      assert.equal(reading.verdict, candidate);
    }
  });

  it("still reads the first ruleset when the second was refused at create, and says the second is incomplete", () => {
    const rows = rowsFor("ascii").map((r) =>
      r.program === "wide" ? { ...r, class: "not-evaluated" } : r,
    );
    const reading = readCase(rows, CASE_PLAN);
    assert.equal(reading.verdict, "incomplete");
    assert.deepEqual(reading.byProgram, { core: "ascii", wide: "incomplete" });
    assert.equal(reading.unread.length, 24);
  });

  it("reads each ruleset's own controls: a wrong wide control fails the wide ruleset only", () => {
    const reading = readCase(flip(rowsFor("ascii"), "ctl-wide-upper-true"), CASE_PLAN);
    assert.equal(reading.verdict, "controls-failed");
    assert.deepEqual(reading.byProgram, { core: "ascii", wide: "controls-failed" });
  });

  it("gives a plan with no programs no per-ruleset reading, and prints none", () => {
    const plan = { rows: CASE_PLAN.rows.map((r) => ({ ...r, program: undefined })) };
    assert.deepEqual(readCase(rowsFor("ascii"), plan).byProgram, {});
    assert.ok(!/programs:/.test(renderReading(readCase(rowsFor("ascii"), plan))));
  });

  it("prints the per-ruleset reading between the candidates and the table", () => {
    const lines = renderReading(readCase(rowsFor("ascii"), CASE_PLAN)).split("\n");
    assert.equal(lines[2], "ascii: 0 mismatch(es)");
    assert.equal(lines[5], "programs: core=ascii, wide=ascii");
    assert.equal(lines[6], "");
  });
});
