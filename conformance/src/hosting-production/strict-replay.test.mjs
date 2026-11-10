// The strict profile against the committed production recordings: the replay needs a fireemu binary
// (FIREEMU_BIN) and is skipped without one. It serves the production corpus with a real fireemu
// process, compares the answers with both recordings and requires the committed comparison files.
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { comparisons, FILES } from "./closure-evidence.mjs";
import { runLocal } from "./local.mjs";
import { writeFile, readFile } from "node:fs/promises";

const binary = process.env.FIREEMU_BIN;

test(
  "strict fireemu replays the production corpus with no mismatch outside the known differences",
  { skip: binary ? false : "FIREEMU_BIN is not set", timeout: 300_000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), "hosting-replay-"));
    try {
      const local = await runLocal({ binary: resolve(binary), profile: "strict" });
      assert.equal(local.rows.filter((row) => row.outcome !== "answered").length, 0);
      const path = join(directory, "local.json");
      await writeFile(path, JSON.stringify(local));
      const documents = await comparisons(path);
      for (const [name, document] of Object.entries(documents)) {
        const committed = JSON.parse(
          await readFile(new URL(`../../${name}`, import.meta.url), "utf8"),
        );
        assert.equal(document.summary.MISMATCH, 0, name);
        assert.equal(document.summary.UNKNOWN, 0, name);
        assert.deepEqual(document, committed, `${name} equals the committed comparison`);
      }
      assert.deepEqual(
        Object.keys(documents).toSorted(),
        [FILES.runs, FILES.strict1, FILES.strict2].toSorted(),
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
