import assert from "node:assert/strict";
import { lstat, mkdtemp, mkdir, readFile, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import fsPromises from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), "storage-object-lock-"));
  const lockDir = join(root, "sandbox-locks");
  const legacyLockPath = join(root, "sandbox-ledger.jsonl.lock");
  const options = {
    projects: ["example-query"],
    lockDir,
    legacyLockPath,
    taskId: "STORAGE-OBJECT",
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
    const path = join(lockDir, "example-query.lock");
    const foreign = '{"taskId":"OTHER"}\n';
    await writeFile(path, foreign, { mode: 0o600 });
    const module = await import("./storage-object/project-locks.mjs").catch(() => ({}));
    assert.equal(typeof module.withProjectLocks, "function");
    let entered = false;
    await assert.rejects(
      () =>
        module.withProjectLocks(options, async () => {
          entered = true;
        }),
      /project lock exists/,
    );
    assert.equal(entered, false);
    assert.equal(await readFile(path, "utf8"), foreign);
  });
});

test("another project's lock permits an owned mode-600 lock and normal release", async () => {
  await fixture(async ({ lockDir, options }) => {
    await mkdir(lockDir, { mode: 0o700 });
    const other = join(lockDir, "example-idp.lock");
    const own = join(lockDir, "example-query.lock");
    await writeFile(other, '{"taskId":"OTHER"}\n', { mode: 0o600 });
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    const result = await withProjectLocks(options, async () => {
      const lock = JSON.parse(await readFile(own, "utf8"));
      assert.deepEqual(Object.keys(lock).toSorted(), [
        "acquiredAt",
        "packetId",
        "pid",
        "sourceCommit",
        "taskId",
      ]);
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
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () =>
        withProjectLocks(options, async () => {
          entered = true;
        }),
      /legacy shared lock exists/,
    );
    assert.equal(entered, false);
    await assert.rejects(lstat(join(lockDir, "example-query.lock")), { code: "ENOENT" });
  });
});

test("a legacy lock appearing after project acquisition releases only the new lock", async () => {
  await fixture(async ({ legacyLockPath, lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () =>
        withProjectLocks(
          options,
          async () => {
            entered = true;
          },
          {
            afterAcquire: async () => writeFile(legacyLockPath, "legacy\n", { mode: 0o600 }),
          },
        ),
      /legacy shared lock exists/,
    );
    assert.equal(entered, false);
    assert.equal(await readFile(legacyLockPath, "utf8"), "legacy\n");
    await assert.rejects(lstat(join(lockDir, "example-query.lock")), { code: "ENOENT" });
  });
});

test("multi-project acquisition is sorted and rolls back owned locks on a later conflict", async () => {
  await fixture(async ({ lockDir, options }) => {
    await mkdir(lockDir, { mode: 0o700 });
    const idp = join(lockDir, "example-idp.lock");
    const query = join(lockDir, "example-query.lock");
    const foreign = '{"taskId":"OTHER"}\n';
    await writeFile(query, foreign, { mode: 0o600 });
    const seen = [];
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () =>
        withProjectLocks(
          { ...options, projects: ["example-query", "example-idp"] },
          async () => {
            entered = true;
          },
          {
            onLockCreated: async (project) => {
              seen.push(project);
            },
          },
        ),
      /project lock exists/,
    );
    assert.deepEqual(seen, ["example-idp"]);
    assert.equal(entered, false);
    await assert.rejects(lstat(idp), { code: "ENOENT" });
    assert.equal(await readFile(query, "utf8"), foreign);
  });
});

test("a failed outbound attempt keeps every acquired project lock", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    const projects = ["example-idp", "example-query"];
    await assert.rejects(
      () =>
        withProjectLocks({ ...options, projects }, async (lease) => {
          await lease.dispatch(async () => {
            throw new Error("outbound result unknown");
          });
        }),
      /outbound result unknown/,
    );
    for (const project of projects) {
      const lock = JSON.parse(await readFile(join(lockDir, `${project}.lock`), "utf8"));
      assert.equal(lock.taskId, "STORAGE-OBJECT");
    }
  });
});

test("catching a transport failure cannot turn the run into a normal lock release", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    await assert.rejects(
      () =>
        withProjectLocks(options, async (lease) => {
          await assert.rejects(
            lease.dispatch(async () => {
              throw new Error("uncertain send");
            }),
            /uncertain send/,
          );
          return "incorrect-success";
        }),
      /outbound attempt failed/,
    );
    assert.equal(
      JSON.parse(await readFile(join(lockDir, "example-query.lock"), "utf8")).taskId,
      "STORAGE-OBJECT",
    );
  });
});

test("an application failure after a successful dispatch retains the project lock", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    await assert.rejects(
      () =>
        withProjectLocks(options, async (lease) => {
          await lease.dispatch(async () => ({ status: 403 }));
          throw new Error("response or cleanup rejected");
        }),
      /response or cleanup rejected/,
    );
    assert.equal(
      JSON.parse(await readFile(join(lockDir, "example-query.lock"), "utf8")).taskId,
      "STORAGE-OBJECT",
    );
  });
});

test("a sent run cannot release its lock without explicit closure confirmation", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    await assert.rejects(
      () =>
        withProjectLocks(options, async (lease) => lease.dispatch(async () => ({ status: 200 }))),
      /closure not confirmed/,
    );
    assert.equal(
      JSON.parse(await readFile(join(lockDir, "example-query.lock"), "utf8")).taskId,
      "STORAGE-OBJECT",
    );
  });
});

test("a sent run releases its lock after explicit closure confirmation", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    const result = await withProjectLocks(options, async (lease) => {
      await lease.dispatch(async () => ({ status: 200 }));
      lease.confirmClosed();
      return "closed";
    });
    assert.equal(result, "closed");
    await assert.rejects(lstat(join(lockDir, "example-query.lock")), { code: "ENOENT" });
  });
});

test("closure is rejected while an outbound dispatch remains pending", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    let finish;
    const pending = new Promise((resolve) => {
      finish = resolve;
    });
    await assert.rejects(
      () =>
        withProjectLocks(options, async (lease) => {
          const dispatch = lease.dispatch(async () => pending);
          assert.throws(() => lease.confirmClosed(), /dispatch still pending/);
          finish({ status: 200 });
          await dispatch;
        }),
      /closure not confirmed/,
    );
    assert.equal(
      JSON.parse(await readFile(join(lockDir, "example-query.lock"), "utf8")).taskId,
      "STORAGE-OBJECT",
    );
  });
});

test("incomplete lock metadata is rejected before acquisition", async () => {
  await fixture(async ({ lockDir, options }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    await assert.rejects(
      () => withProjectLocks({ ...options, packetId: undefined }, async () => {}),
      /invalid lock metadata/,
    );
    await assert.rejects(lstat(join(lockDir, "example-query.lock")), { code: "ENOENT" });
  });
});

test("release refuses a same-body lock replaced by another inode", async () => {
  await fixture(async ({ lockDir, options }) => {
    const own = join(lockDir, "example-query.lock");
    const replacement = join(lockDir, "replacement.tmp");
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    let body;
    await assert.rejects(
      () =>
        withProjectLocks(options, async () => {
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
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    let entered = false;
    await assert.rejects(
      () =>
        withProjectLocks({ ...options, projects: ["../foreign"] }, async () => {
          entered = true;
        }),
      /invalid project ID/,
    );
    assert.equal(entered, false);
    await assert.rejects(lstat(join(root, "foreign.lock")), { code: "ENOENT" });
    await assert.rejects(lstat(join(lockDir, "foreign.lock")), { code: "ENOENT" });
  });
});

test("one replaced lock prevents releasing any lock in the multi-project set", async () => {
  await fixture(async ({ lockDir, options }) => {
    const idp = join(lockDir, "example-idp.lock");
    const query = join(lockDir, "example-query.lock");
    const replacement = join(lockDir, "replacement.tmp");
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    await assert.rejects(
      () =>
        withProjectLocks({ ...options, projects: ["example-idp", "example-query"] }, async () => {
          await writeFile(replacement, await readFile(idp), { mode: 0o600 });
          await unlink(idp);
          await rename(replacement, idp);
        }),
      /project lock ownership changed/,
    );
    assert.equal(JSON.parse(await readFile(idp, "utf8")).taskId, "STORAGE-OBJECT");
    assert.equal(JSON.parse(await readFile(query, "utf8")).taskId, "STORAGE-OBJECT");
  });
});

test("release refuses a foreign body even when its inode remains the same", async () => {
  await fixture(async ({ lockDir, options }) => {
    const path = join(lockDir, "example-query.lock");
    const foreign = '{"taskId":"OTHER"}\n';
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    await assert.rejects(
      () =>
        withProjectLocks(options, async () => {
          const before = await lstat(path);
          await writeFile(path, foreign);
          assert.equal((await lstat(path)).ino, before.ino);
        }),
      /project lock ownership changed/,
    );
    assert.equal(await readFile(path, "utf8"), foreign);
  });
});

test("a retained lease cannot dispatch after release or after callback failure", async () => {
  for (const callbackFails of [false, true])
    await fixture(async ({ options }) => {
      const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
      let retained,
        dispatched = false;
      const run = () =>
        withProjectLocks(options, async (lease) => {
          retained = lease;
          if (callbackFails) throw new Error("pre-send callback failed");
        });
      if (callbackFails) await assert.rejects(run(), /pre-send callback/);
      else await run();
      await assert.rejects(
        retained.dispatch(async () => {
          dispatched = true;
        }),
        /inactive|closed/,
      );
      assert.equal(dispatched, false);
    });
});

test("a lock replaced while another project's release is checked is never deleted", async () => {
  await fixture(async ({ options, lockDir }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    const idp = join(lockDir, "example-idp.lock"),
      query = join(lockDir, "example-query.lock");
    const replacement = join(lockDir, "foreign.tmp"),
      foreign = '{"taskId":"FOREIGN"}\n';
    const original = fsPromises.readFile;
    let replaced = false;
    fsPromises.readFile = async function (path, ...args) {
      const body = await original.call(this, path, ...args);
      if (path === query && !replaced) {
        replaced = true;
        await writeFile(replacement, foreign, { mode: 0o600 });
        await rename(replacement, idp);
      }
      return body;
    };
    syncBuiltinESMExports();
    try {
      await assert.rejects(
        withProjectLocks(
          { ...options, projects: ["example-idp", "example-query"] },
          async () => {},
        ),
        /ownership changed/,
      );
      assert.equal(await readFile(idp, "utf8"), foreign);
    } finally {
      fsPromises.readFile = original;
      syncBuiltinESMExports();
    }
  });
});

test("an acquisition fsync failure rolls back its owned lock before any dispatch", async () => {
  await fixture(async ({ options, lockDir, root }) => {
    const { withProjectLocks } = await import("./storage-object/project-locks.mjs");
    const handle = await fsPromises.open(join(root, "probe.tmp"), "wx", 0o600);
    const prototype = Object.getPrototypeOf(handle),
      original = prototype.sync;
    await handle.close();
    prototype.sync = async () => {
      throw new Error("fsync failed");
    };
    let entered = false;
    try {
      await assert.rejects(
        withProjectLocks(options, async () => {
          entered = true;
        }),
        /fsync failed/,
      );
      assert.equal(entered, false);
      await assert.rejects(lstat(join(lockDir, "example-query.lock")), { code: "ENOENT" });
    } finally {
      prototype.sync = original;
    }
  });
});
