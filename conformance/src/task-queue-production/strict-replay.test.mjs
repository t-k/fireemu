// The strict profile against the committed production recordings: the replay needs a fireemu binary (FIREEMU_BIN) and is skipped
// without one. It serves the production program with a real fireemu process (strict, productionExact), shapes the deliveries the
// fixture saw like a recording and compares them with both recordings. Times are never equal twice, so what is required is the
// committed structure verdicts (case by case) and timings within the tolerance, not the committed local projection byte for byte.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { compareStrict } from "./compare-cli.mjs";
import { localProjection } from "./local.mjs";

const binary = process.env.FIREEMU_BIN;
const json = (name) => JSON.parse(readFileSync(new URL(`../../${name}`, import.meta.url), "utf8"));

test(
  "strict fireemu replays the task queue program with no mismatch outside the known differences",
  { skip: binary ? false : "FIREEMU_BIN is not set", timeout: 600_000 },
  async () => {
    const local = await localProjection({
      binary: resolve(binary),
      profile: "strict",
      alias: "strict",
    });
    for (const [pass, committedName] of [
      ["task-queue-production-pass-1.json", "task-queue-production-strict-vs-pass-1.json"],
      ["task-queue-production-pass-2.json", "task-queue-production-strict-vs-pass-2.json"],
    ]) {
      // A loaded runner delays a process start by more than a second, so the replay allows twice the committed tolerance; the
      // committed comparison files are held to the tolerance itself (published.test.mjs).
      const result = compareStrict(local, json(pass), {
        tolerance: { gapMs: 3000, firstMs: 3000 },
      });
      const committed = json(committedName);
      assert.equal(
        result.summary.structure.MISMATCH ?? 0,
        0,
        JSON.stringify(result.rows.filter((r) => r.structure === "MISMATCH").slice(0, 3)),
      );
      assert.equal(result.summary.structure.UNKNOWN ?? 0, 0);
      assert.equal(
        result.summary.timing.OUTSIDE ?? 0,
        0,
        JSON.stringify(
          result.rows.filter((r) => r.timing.verdict === "OUTSIDE").map((r) => [r.case, r.timing]),
        ),
      );
      assert.ok(result.properties.every((p) => p.verdict === "MATCH"));
      assert.deepEqual(
        result.rows.map((r) => [r.case, r.structure]),
        committed.rows.map((r) => [r.case, r.structure]),
        `${committedName} structure verdicts`,
      );
    }
  },
);
