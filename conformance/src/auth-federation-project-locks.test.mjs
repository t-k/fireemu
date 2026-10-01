import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { replaceFile } from "./test-replace-file.mjs";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

import {
  projectLockPath,
  releaseProjectLocks,
  takeProjectLocks,
  withProjectLocks,
} from "./auth-federation/project-locks.mjs";

const HOLDER = {
  taskId: "AUTH-FEDERATION-SANDBOX",
  packetId: "record-oidc",
  run: "a1b2c3",
  sourceCommit: "abc",
};

async function ledgerDir() {
  const dir = await mkdtemp(join(tmpdir(), "fed-plock-"));
  return join(dir, "sandbox-ledger.jsonl");
}

test("a project's lock stops a run on it but not on another project", async () => {
  const ledger = await ledgerDir();
  const held = await takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER);
  const path = projectLockPath(ledger, "fireemu-oracle-idp");
  const body = JSON.parse(await readFile(path, "utf8"));
  assert.deepEqual(Object.keys(body).toSorted(), [
    "acquiredAt",
    "packetId",
    "pid",
    "run",
    "sourceCommit",
    "taskId",
  ]);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal((await stat(join(ledger, "..", "sandbox-locks"))).mode & 0o777, 0o700);
  await assert.rejects(takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER), /is locked/);
  const other = await takeProjectLocks(ledger, ["fireemu-oracle-query"], HOLDER);
  await releaseProjectLocks(other);
  await releaseProjectLocks(held);
  assert.ok(!existsSync(path));
});

test("the legacy shared lock stops a run before and after taking", async () => {
  const ledger = await ledgerDir();
  await writeFile(`${ledger}.lock`, "FS-RULES pid 1\n");
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER),
    /legacy shared lock .* exists/,
  );
  assert.ok(!existsSync(projectLockPath(ledger, "fireemu-oracle-idp")));
  await rm(`${ledger}.lock`);
  // It appears while the project locks are being taken: they are released and nothing starts.
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-query", "fireemu-oracle-idp"], HOLDER, {
      afterEach: async (project) => {
        if (project === "fireemu-oracle-query") await writeFile(`${ledger}.lock`, "late\n");
      },
    }),
    /legacy shared lock .* appeared/,
  );
  assert.ok(!existsSync(projectLockPath(ledger, "fireemu-oracle-idp")));
  assert.ok(!existsSync(projectLockPath(ledger, "fireemu-oracle-query")));
});

test("several projects are taken in ascending order, all or none", async () => {
  const ledger = await ledgerDir();
  // The later project is held: the earlier one taken first is released again.
  const heldQuery = await takeProjectLocks(ledger, ["fireemu-oracle-query"], HOLDER);
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-query", "fireemu-oracle-idp"], HOLDER),
    /fireemu-oracle-query is locked/,
  );
  assert.ok(!existsSync(projectLockPath(ledger, "fireemu-oracle-idp")));
  await releaseProjectLocks(heldQuery);
  const both = await takeProjectLocks(
    ledger,
    ["fireemu-oracle-query", "fireemu-oracle-idp"],
    HOLDER,
  );
  assert.deepEqual(
    both.taken.map(({ path }) => path.split("/").at(-1)),
    ["fireemu-oracle-idp.lock", "fireemu-oracle-query.lock"],
  );
  await releaseProjectLocks(both);
  assert.throws(() => projectLockPath(ledger, "../escape"), /not a project ID/);
});

test("locks stay after a failure once something was sent, and another's lock is never removed", async () => {
  const ledger = await ledgerDir();
  const path = projectLockPath(ledger, "fireemu-oracle-idp");
  // A failure before sending releases.
  await assert.rejects(
    withProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, async () => {
      throw new Error("ADC expired");
    }),
    /ADC expired/,
  );
  assert.ok(!existsSync(path));
  // After sending it stays, as does a result that needs recovery.
  await assert.rejects(
    withProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, async (state) => {
      state.sent = true;
      throw new Error("fetch failed");
    }),
    /fetch failed/,
  );
  assert.ok(existsSync(path));
  await rm(path);
  await withProjectLocks(
    ledger,
    ["fireemu-oracle-idp"],
    HOLDER,
    async () => ({ outcome: "needs-recovery" }),
    {
      keep: (result) => result.outcome === "needs-recovery",
    },
  );
  assert.ok(existsSync(path));
  await rm(path);
  // A lock replaced by another holder (another inode or text) is left alone.
  const handle = await takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER);
  await replaceFile(path, '{"taskId":"OTHER"}\n');
  await releaseProjectLocks(handle);
  assert.equal(await readFile(path, "utf8"), '{"taskId":"OTHER"}\n');
  await rm(path);
  // Rewritten in place (the same inode, another text): left alone.
  const inPlace = await takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER);
  await writeFile(path, '{"taskId":"OTHER"}\n');
  await releaseProjectLocks(inPlace);
  assert.ok(existsSync(path));
  await rm(path);
  // Recreated with the very same text (another inode): left alone.
  const recreated = await takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER);
  const text = await readFile(path, "utf8");
  await replaceFile(path, text);
  await releaseProjectLocks(recreated);
  assert.ok(existsSync(path));
});

test("a recovery adopts only this run's lock whose process is gone", async () => {
  const ledger = await ledgerDir();
  const path = projectLockPath(ledger, "fireemu-oracle-idp");
  const adopt = (body) => body.taskId === HOLDER.taskId && body.run === HOLDER.run;
  const leave = async (pid, extra = {}) => {
    await rm(path, { force: true });
    await takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER);
    await writeFile(path, `${JSON.stringify({ ...HOLDER, pid, ...extra })}\n`);
  };
  const gone = spawnSync(process.execPath, ["-e", "0"]).pid;
  // A lock whose recording still runs (this process) is not adopted.
  await leave(process.pid);
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, { adopt }),
    /is locked/,
  );
  // Another run's or another task's lock is not adopted, even with its process gone.
  await leave(gone, { run: "d4e5f6" });
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, { adopt }),
    /is locked/,
  );
  await leave(gone, { taskId: "OTHER" });
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, { adopt }),
    /is locked/,
  );
  await leave("not-a-pid");
  await assert.rejects(
    takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, { adopt }),
    /is locked/,
  );
  // Without adopt nothing is taken over.
  await leave(gone);
  await assert.rejects(takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER), /is locked/);
  // This run's lock with its process gone is adopted, rewritten, and released by its new holder.
  const adopted = await takeProjectLocks(ledger, ["fireemu-oracle-idp"], HOLDER, { adopt });
  assert.equal(JSON.parse(await readFile(path, "utf8")).pid, process.pid);
  await releaseProjectLocks(adopted);
  assert.ok(!existsSync(path));
});
