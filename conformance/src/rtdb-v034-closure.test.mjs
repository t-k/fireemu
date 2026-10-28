import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url));
const json = (path) => JSON.parse(read(path));
const sha = (path) => createHash("sha256").update(read(path)).digest("hex");

test("recorded RTDB profile comparisons retain their source, binary and cleanup", () => {
  const closure = json("spec/compatibility/closure/RTDB.json");
  assert.equal(closure.parentStatus, "IMPLEMENTING");
  const regression = closure.integratedRegression;
  const cases = [
    [regression.next4EvidencePath, regression.next4EvidenceSha256, 36, false],
    [regression.rulesV034Evidence.path, regression.rulesV034Evidence.sha256, 56, true],
    [regression.queryrulesV034Evidence.path, regression.queryrulesV034Evidence.sha256, 20, true],
    [regression.queryboundsV034Evidence.path, regression.queryboundsV034Evidence.sha256, 20, true],
  ];
  for (const [path, digest, count, hasCleanup] of cases) {
    assert.equal(sha(path), digest, path);
    const evidence = json(path);
    assert.equal(evidence.sourceCommit, "02d0f10adbfdd26014c0c6b7c10df916a7ca2766");
    assert.equal(
      evidence.binarySha256,
      "238512c0223cd45b9fa218e71282317a724f864fdd9186d4fabab7c3ce940955",
    );
    for (const profile of ["strict", "emulator"]) {
      const run = evidence[profile];
      assert.equal(run.profile, profile);
      assert.equal(run.sourceHead, evidence.sourceCommit);
      assert.equal(run.binarySha256, evidence.binarySha256);
      const rows = run.rounds.flatMap((round) => round.rows);
      assert.equal(rows.length, count);
      assert.ok(rows.every((row) => row.verdict === "MATCH"));
      assert.deepEqual(run.summary, { rows: count, counts: { MATCH: count } });
      if (hasCleanup) {
        assert.equal(run.failure, null);
        assert.deepEqual(run.cleanup, {
          prefix: { status: "restored" },
          rules: { status: "restored" },
        });
      }
    }
  }
});
