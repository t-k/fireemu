import assert from "node:assert/strict";
import { lstat, mkdtemp, mkdir, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { replaceFile } from "./test-replace-file.mjs";
import { join } from "node:path";
import test from "node:test";

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), "storage-rules-lock-"));
  const lockDir = join(root, "sandbox-locks");
  const legacyLockPath = join(root, "sandbox-ledger.jsonl.lock");
  const options = {
    projects: ["fireemu-oracle-query"],
    lockDir,
    legacyLockPath,
    taskId: "STORAGE-RULES",
    packetId: "local-packet",
    sourceCommit: "a".repeat(40),
    pid: process.pid,
    acquiredAt: "2026-09-28T00:00:00Z",
  };
  try {
    return await run({ root, lockDir, legacyLockPath, options });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("an existing lock for the same project prevents entry without changing its owner", async () => {
  await fixture(async ({ lockDir, options }) => {
    await mkdir(lockDir, { mode: 0o700 });
    const path = join(lockDir, "fireemu-oracle-query.lock");
    const foreign = '{"taskId":"OTHER"}\n';
    await writeFile(path, foreign, { mode: 0o600 });
    const module = await import("./storage-rules/project-locks.mjs").catch(() => ({}));
    assert.equal(typeof module.withProjectLocks, "function");
    let entered = false;
    await assert.rejects(() => module.withProjectLocks(options, async () => { entered = true; }), /project lock exists/);
    assert.equal(entered, false);
    assert.equal(await readFile(path, "utf8"), foreign);
  });
});

test("another project's lock permits an owned mode-600 lock and normal release", async () => {
  await fixture(async ({ lockDir, options }) => {
    await mkdir(lockDir, { mode: 0o700 });
    const other = join(lockDir, "fireemu-oracle-idp.lock");
    const own = join(lockDir, "fireemu-oracle-query.lock");
    await writeFile(other, '{"taskId":"OTHER"}\n', { mode: 0o600 });
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    const result = await withProjectLocks(options, async () => {
      const lock = JSON.parse(await readFile(own, "utf8"));
      assert.deepEqual(Object.keys(lock).sort(), ["acquiredAt", "packetId", "pid", "sourceCommit", "taskId"]);
      assert.equal(lock.taskId, options.taskId);
      assert.equal((await lstat(own)).mode & 0o777, 0o600);
      assert.equal((await lstat(lockDir)).mode & 0o777, 0o700);
      return "done";
    });
    assert.equal(result, "done");
    await assert.rejects(lstat(own), { code: "ENOENT" });
    assert.equal(await readFile(other, "utf8"), '{"taskId":"OTHER"}\n');
  });
});

test("a legacy shared lock prevents acquisition before any project lock is created", async () => {
  await fixture(async ({ legacyLockPath, lockDir, options }) => {
    await writeFile(legacyLockPath, "legacy\n", { mode: 0o600 });
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let entered = false;
    await assert.rejects(() => withProjectLocks(options, async () => { entered = true; }), /legacy shared lock exists/);
    assert.equal(entered, false);
    await assert.rejects(lstat(join(lockDir, "fireemu-oracle-query.lock")), { code: "ENOENT" });
  });
});

test("a legacy lock appearing after project acquisition releases only the new lock", async () => {
  await fixture(async ({ legacyLockPath, lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () => withProjectLocks(options, async () => { entered = true; }, {
        afterAcquire: async () => writeFile(legacyLockPath, "legacy\n", { mode: 0o600 }),
      }),
      /legacy shared lock exists/,
    );
    assert.equal(entered, false);
    assert.equal(await readFile(legacyLockPath, "utf8"), "legacy\n");
    await assert.rejects(lstat(join(lockDir, "fireemu-oracle-query.lock")), { code: "ENOENT" });
  });
});

test("multi-project acquisition is sorted and rolls back owned locks on a later conflict", async () => {
  await fixture(async ({ lockDir, options }) => {
    await mkdir(lockDir, { mode: 0o700 });
    const idp = join(lockDir, "fireemu-oracle-idp.lock");
    const query = join(lockDir, "fireemu-oracle-query.lock");
    const foreign = '{"taskId":"OTHER"}\n';
    await writeFile(query, foreign, { mode: 0o600 });
    const seen = [];
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () => withProjectLocks({ ...options, projects: ["fireemu-oracle-query", "fireemu-oracle-idp"] }, async () => { entered = true; }, {
        onLockCreated: async (project) => { seen.push(project); },
      }),
      /project lock exists/,
    );
    assert.deepEqual(seen, ["fireemu-oracle-idp"]);
    assert.equal(entered, false);
    await assert.rejects(lstat(idp), { code: "ENOENT" });
    assert.equal(await readFile(query, "utf8"), foreign);
  });
});

test("a failed outbound attempt keeps every acquired project lock", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    const projects = ["fireemu-oracle-idp", "fireemu-oracle-query"];
    await assert.rejects(
      () => withProjectLocks({ ...options, projects }, async (lease) => {
        await lease.dispatch(async () => { throw new Error("outbound result unknown"); });
      }),
      /outbound result unknown/,
    );
    for (const project of projects) {
      const lock = JSON.parse(await readFile(join(lockDir, `${project}.lock`), "utf8"));
      assert.equal(lock.taskId, "STORAGE-RULES");
    }
  });
});

test("catching a transport failure cannot turn the run into a normal lock release", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    await assert.rejects(
      () => withProjectLocks(options, async (lease) => {
        await assert.rejects(lease.dispatch(async () => { throw new Error("uncertain send"); }), /uncertain send/);
        return "incorrect-success";
      }),
      /outbound attempt failed/,
    );
    assert.equal(JSON.parse(await readFile(join(lockDir, "fireemu-oracle-query.lock"), "utf8")).taskId, "STORAGE-RULES");
  });
});

test("an application failure after a successful dispatch retains the project lock", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    await assert.rejects(
      () => withProjectLocks(options, async (lease) => {
        await lease.dispatch(async () => ({ status: 403 }));
        throw new Error("response or cleanup rejected");
      }),
      /response or cleanup rejected/,
    );
    assert.equal(JSON.parse(await readFile(join(lockDir, "fireemu-oracle-query.lock"), "utf8")).taskId, "STORAGE-RULES");
  });
});

test("a sent run cannot release its lock without explicit closure confirmation", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    await assert.rejects(
      () => withProjectLocks(options, async (lease) => lease.dispatch(async () => ({ status: 200 }))),
      /closure not confirmed/,
    );
    assert.equal(JSON.parse(await readFile(join(lockDir, "fireemu-oracle-query.lock"), "utf8")).taskId, "STORAGE-RULES");
  });
});

test("a sent run releases its lock after explicit closure confirmation", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    const result = await withProjectLocks(options, async (lease) => {
      await lease.dispatch(async () => ({ status: 200 }));
      lease.confirmClosed();
      return "closed";
    });
    assert.equal(result, "closed");
    await assert.rejects(lstat(join(lockDir, "fireemu-oracle-query.lock")), { code: "ENOENT" });
  });
});

test("closure is rejected while an outbound dispatch remains pending", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let finish;
    const pending = new Promise((resolve) => { finish = resolve; });
    await assert.rejects(
      () => withProjectLocks(options, async (lease) => {
        const dispatch = lease.dispatch(async () => pending);
        assert.throws(() => lease.confirmClosed(), /dispatch still pending/);
        finish({ status: 200 });
        await dispatch;
      }),
      /closure not confirmed/,
    );
    assert.equal(JSON.parse(await readFile(join(lockDir, "fireemu-oracle-query.lock"), "utf8")).taskId, "STORAGE-RULES");
  });
});

test("incomplete lock metadata is rejected before acquisition", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    await assert.rejects(() => withProjectLocks({ ...options, packetId: undefined }, async () => {}), /invalid lock metadata/);
    await assert.rejects(lstat(join(lockDir, "fireemu-oracle-query.lock")), { code: "ENOENT" });
  });
});

test("release refuses a same-body lock replaced by another inode", async () => {
  await fixture(async ({ lockDir, options }) => {
    const own = join(lockDir, "fireemu-oracle-query.lock");
    const replacement = join(lockDir, "replacement.tmp");
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let body;
    await assert.rejects(
      () => withProjectLocks(options, async () => {
        body = await readFile(own, "utf8");
        await writeFile(replacement, body, { mode: 0o600 });
        await unlink(own);
        await rename(replacement, own);
      }),
      /project lock ownership changed/,
    );
    assert.equal(await readFile(own, "utf8"), body);
  });
});

test("a project ID cannot escape the lock directory", async () => {
  await fixture(async ({ root, lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () => withProjectLocks({ ...options, projects: ["../foreign"] }, async () => { entered = true; }),
      /invalid project ID/,
    );
    assert.equal(entered, false);
    await assert.rejects(lstat(join(root, "foreign.lock")), { code: "ENOENT" });
    await assert.rejects(lstat(join(lockDir, "foreign.lock")), { code: "ENOENT" });
  });
});

test("one replaced lock prevents releasing any lock in the multi-project set", async () => {
  await fixture(async ({ lockDir, options }) => {
    const idp = join(lockDir, "fireemu-oracle-idp.lock");
    const query = join(lockDir, "fireemu-oracle-query.lock");
    const replacement = join(lockDir, "replacement.tmp");
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    await assert.rejects(
      () => withProjectLocks({ ...options, projects: ["fireemu-oracle-idp", "fireemu-oracle-query"] }, async () => {
        await writeFile(replacement, await readFile(idp), { mode: 0o600 });
        await unlink(idp);
        await rename(replacement, idp);
      }),
      /project lock ownership changed/,
    );
    assert.equal(JSON.parse(await readFile(idp, "utf8")).taskId, "STORAGE-RULES");
    assert.equal(JSON.parse(await readFile(query, "utf8")).taskId, "STORAGE-RULES");
  });
});

test("verifyHeld proves each owned lock is still this run's and refuses once one changed", async () => {
  await fixture(async ({ lockDir, legacyLockPath, options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    const projects = ["fireemu-oracle-idp", "fireemu-oracle-query"];
    const own = (project) => join(lockDir, `${project}.lock`);
    // The run body records what it proved; an inner failure leaves a proof missing, so the counts are checked outside.
    const proven = [];
    const inRun = (opts, body) => assert.rejects(() => withProjectLocks(opts, async (lease) => { await body(lease); }), Error);
    await inRun({ ...options, projects }, async (lease) => {
      assert.equal(typeof lease.verifyHeld, "function");
      assert.equal(await lease.verifyHeld(), true);
      proven.push("held");
      // A replaced file (same body, different inode) is not this run's lock.
      const body = await readFile(own(projects[1]), "utf8");
      await replaceFile(own(projects[1]), body, { mode: 0o600 });
      await assert.rejects(() => lease.verifyHeld(), /ownership changed/);
      proven.push("replaced");
      await unlink(own(projects[1]));
      await assert.rejects(() => lease.verifyHeld(), { code: "ENOENT" });
      proven.push("missing");
    });
    await rm(lockDir, { recursive: true, force: true });
    await inRun(options, async (lease) => {
      await writeFile(own(options.projects[0]), '{"taskId":"OTHER"}\n');
      await assert.rejects(() => lease.verifyHeld(), /ownership changed/);
      proven.push("body");
    });
    await rm(lockDir, { recursive: true, force: true });
    await withProjectLocks(options, async (lease) => {
      await writeFile(legacyLockPath, "legacy\n", { mode: 0o600 });
      await assert.rejects(() => lease.verifyHeld(), /legacy shared lock exists/);
      proven.push("legacy");
      await unlink(legacyLockPath);
      await lease.dispatch(async () => "sent");
      lease.confirmClosed();
    });
    assert.deepEqual(proven, ["held", "replaced", "missing", "body", "legacy"]);
  });
});

test("verifyHeld is refused once the run is closed", async () => {
  await fixture(async ({ options }) => {
    const { withProjectLocks } = await import("./storage-rules/project-locks.mjs");
    let held;
    await withProjectLocks(options, async (lease) => {
      held = lease;
      await lease.dispatch(async () => "sent");
      lease.confirmClosed();
    });
    await assert.rejects(() => held.verifyHeld(), /already closed|released/);
  });
});
