import assert from "node:assert/strict";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { prepareRunDir } from "./auth-fs-cross/stage2-run.mjs";

test("each local run gets its own private directory, and earlier runs are kept", async () => {
  const root = await mkdtemp(join(tmpdir(), "afc2-runs-"));
  try {
    // An earlier run's rows and a comparison made from them.
    const earlier = join(root, "2026-09-28T02-00-00.000Z");
    await mkdir(earlier);
    await writeFile(join(earlier, "rows.json"), "earlier rows");
    await writeFile(join(root, "comparison.json"), "earlier comparison");
    const at = new Date("2026-09-28T07:05:00.000Z");
    const first = await prepareRunDir({ root, now: at, program: { steps: [] }, config: { a: 1 } });
    const second = await prepareRunDir({ root, now: at, program: { steps: [] }, config: { a: 1 } });
    assert.notEqual(first.dir, second.dir);
    assert.equal(await readFile(join(earlier, "rows.json"), "utf8"), "earlier rows");
    assert.equal(await readFile(join(root, "comparison.json"), "utf8"), "earlier comparison");
    assert.deepEqual((await readdir(root)).toSorted(), [
      "2026-09-28T02-00-00.000Z",
      "2026-09-28T07-05-00.000Z",
      "2026-09-28T07-05-00.000Z-2",
      "comparison.json",
    ]);
    for (const { dir, paths } of [first, second]) {
      assert.equal((await stat(dir)).mode & 0o777, 0o700);
      assert.deepEqual(JSON.parse(await readFile(paths.in, "utf8")), { steps: [] });
      assert.deepEqual(JSON.parse(await readFile(paths.config, "utf8")), { a: 1 });
      assert.deepEqual(JSON.parse(await readFile(paths.firebase, "utf8")), {
        firestore: [{ database: "(default)" }],
      });
      assert.equal(paths.out, join(dir, "fireemu.json"));
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
