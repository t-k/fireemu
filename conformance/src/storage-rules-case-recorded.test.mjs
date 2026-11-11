import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { CANDIDATES, CASE_PLAN } from "./storage-rules-s9/plan-case.mjs";
import { readCase } from "./storage-rules-s9/reading.mjs";

// The published production recording of STORAGE-RULES-CASE (two recordings, 2026-11-11) read against
// the plan: production changes ASCII letters only.

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../fixtures/storage/rules-case-production.json", import.meta.url)),
    "utf8",
  ),
);
const rows = fixture.rows;
const answer = (recording, id) => rows.find((r) => r.recording === recording && r.id === id);

describe("the published STORAGE-RULES-CASE recording", () => {
  it("is complete: both recordings, every row of the plan, nothing unknown, no problem", () => {
    assert.deepEqual(fixture.outcome, {
      complete: true,
      closureReady: true,
      unknowns: 0,
      problems: 0,
      rows: 82,
    });
    for (const recording of [1, 2])
      assert.deepEqual(
        rows.filter((r) => r.recording === recording).map((r) => r.id),
        CASE_PLAN.rows.map((r) => r.id),
      );
    for (const row of rows) {
      assert.ok(["allow", "deny"].includes(row.class), row.id);
      assert.equal(row.status, row.class === "allow" ? 200 : 403, row.id);
      assert.equal(
        row.bodyBytes === 73,
        row.class === "deny",
        `${row.id}: a refusal is the 73 byte body`,
      );
    }
  });

  it("holds the program of every row as the plan has it, and no run, project or bucket name", () => {
    for (const row of rows)
      assert.equal(row.program, CASE_PLAN.rows.find((r) => r.id === row.id).program);
    const text = JSON.stringify(fixture);
    assert.ok(
      !/sr-[0-9a-f]{8}/.test(text) && !/firebasestorage\.app/.test(text) && !/AIza/.test(text),
    );
  });

  it("is read by the strict reading as ascii for wide and refuses core only for one control", () => {
    const reading = readCase(rows, CASE_PLAN);
    assert.equal(reading.verdict, "controls-failed");
    assert.deepEqual(reading.failedControls, ["ctl-lower-i"]);
    assert.deepEqual(reading.byProgram, { core: "controls-failed", wide: "ascii" });
    assert.deepEqual(reading.disagreeing, ["ctl-lower-i"]);
    assert.deepEqual(answer(1, "ctl-lower-i").class, "deny");
    assert.deepEqual(answer(2, "ctl-lower-i").class, "allow");
  });

  it("disagrees between the recordings on exactly that control, and it was read inside the propagation window", () => {
    const differ = CASE_PLAN.rows.filter((r) => answer(1, r.id).class !== answer(2, r.id).class);
    assert.deepEqual(
      differ.map((r) => r.id),
      ["ctl-lower-i"],
    );
    // The wide switches of the same run: the previous ruleset was still served up to this long after the release.
    const stale = fixture.wideSwitchPolls.filter((p) => p.marker === "old" && p.status === 200);
    const lingered = Math.max(...stale.map((p) => p.secondsAfterRelease));
    assert.ok(lingered >= 20, `the old ruleset was still served ${lingered} s after a release`);
    assert.ok(answer(1, "ctl-lower-i").secondsAfterRelease < lingered);
  });

  it("reads as ascii under the rule that a 200 in either recording settles a row and a 403 does not", () => {
    const allowedSomewhere = (id) => [1, 2].some((n) => answer(n, id).class === "allow");
    const against = Object.fromEntries(
      CANDIDATES.map((c) => [
        c,
        CASE_PLAN.rows.filter((r) => r.candidates[c] !== allowedSomewhere(r.id)).map((r) => r.id),
      ]),
    );
    assert.deepEqual(against.ascii, []);
    assert.equal(against.full.length, 25);
    assert.equal(against.simple.length, 21);
    // Fifteen rows that full or simple would allow and ascii refuses were refused in both recordings.
    const refusedTwice = CASE_PLAN.rows.filter(
      (r) => (r.candidates.full || r.candidates.simple) && !r.candidates.ascii,
    );
    assert.equal(refusedTwice.length, 15);
    for (const r of refusedTwice)
      assert.deepEqual([answer(1, r.id).class, answer(2, r.id).class], ["deny", "deny"], r.id);
  });
});
