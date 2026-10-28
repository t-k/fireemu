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
    assert.equal(evidence.sourceCommit, "81dca801d0f67f002dc7a63e8950f30017f17d9f");
    assert.equal(
      evidence.binarySha256,
      "988a5fce8727bc8c7e1c45a320f4f044aff7753f7d8c54e3c64b0e99ef1b2f52",
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
