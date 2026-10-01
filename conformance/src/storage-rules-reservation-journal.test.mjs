import { tmpdir } from "node:os";
import assert from "node:assert/strict";
import { constants } from "node:fs";
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { createStage3RequestCounter } from "./storage-rules/request-counter.mjs";

const runId = "journal-test";
const sourceCommit = "ab".repeat(20);
const manifestDigest = "cd".repeat(32);
const preflightIds = ["preflight/owner", "preflight/keys"];
const requestIds = [...preflightIds, "case/example/subject/get", "recovery/case/example/get"];
const start = () => ({
  runId,
  maxRequests: 6648,
  recoveryReserve: 2000,
  preflightIds: [...preflightIds],
});
const reserve = (attempt = 1, operationId = preflightIds[0], phase = "preflight") => ({
  attempt,
  operationId,
  phase,
});
const terminal = (outcome = "preflight-failed", requests = 0, normal = 0, recovery = 0) => ({
  outcome,
  requests,
  normal,
  recovery,
  maxRequests: 6648,
});

async function fixture(t, { delta = {}, hooks = {}, before = null } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "storage-rules-journal-"));
  const path = join(directory, "reservations.jsonl");
  const trace = [];
  const handles = [];
  let journal;
  t.after(async () => {
    if (journal) await journal.close().catch(() => {});
    for (const handle of handles) await handle.close().catch(() => {});
    await rm(directory, { recursive: true, force: true });
  });
  if (before) await before({ directory, path });
  const io = {
    lstat,
    open: async (name, flags, mode) => {
      trace.push({ event: "open", name, flags, mode });
      const handle = await open(name, flags, mode);
      handles.push(handle);
      const isDirectory = name === directory;
      const kind = isDirectory ? "directory" : "file";
      return {
        stat: (...args) => handle.stat(...args),
        write: async (...args) => {
          trace.push({ event: "write", kind });
          return hooks.write ? hooks.write(handle, args) : handle.write(...args);
        },
        sync: async () => {
          trace.push({ event: "sync", kind });
          return hooks.sync ? hooks.sync(handle, kind) : handle.sync();
        },
        close: async () => {
          trace.push({ event: "close", kind });
          return hooks.close ? hooks.close(handle, kind) : handle.close();
        },
      };
    },
  };
  const module = await import("./storage-rules/reservation-journal.mjs").catch((error) => {
    if (error.code === "ERR_MODULE_NOT_FOUND") return {};
    throw error;
  });
  assert.equal(typeof module.createReservationJournal, "function");
  journal = await module.createReservationJournal({
    directory,
    runId,
    sourceCommit,
    manifestDigest,
    requestIds,
    preflightIds,
    io,
    ...delta,
  });
  return {
    journal,
    directory,
    path,
    trace,
    rows: async () =>
      (await readFile(path, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line)),
  };
}

test("exclusive journal creation writes a bound header and syncs file then directory", async (t) => {
  const ctx = await fixture(t);
  assert.equal((await lstat(ctx.directory)).mode & 0o777, 0o700);
  assert.equal((await lstat(ctx.path)).mode & 0o777, 0o600);
  const file = ctx.trace.find((row) => row.event === "open" && row.name === ctx.path);
  assert.equal(file.flags & constants.O_EXCL, constants.O_EXCL);
  assert.equal(file.flags & constants.O_APPEND, constants.O_APPEND);
  assert.equal(file.flags & constants.O_NOFOLLOW, constants.O_NOFOLLOW);
  assert.deepEqual(
    ctx.trace.filter((row) => row.event === "sync").map((row) => row.kind),
    ["file", "directory"],
  );
  const [row] = await ctx.rows();
  assert.equal(row.event, "opened");
  assert.equal(row.runId, runId);
  assert.equal(row.sourceCommit, sourceCommit);
  assert.equal(row.manifestDigest, manifestDigest);
  assert.equal(row.sequence, 1);
  assert.equal(row.data.requestIds.length, requestIds.length);
  assert.deepEqual(ctx.journal.snapshot(), {
    state: "opened",
    busy: false,
    uncertain: false,
    closed: false,
    requests: 0,
    normal: 0,
    recovery: 0,
    sendAuthorized: false,
  });
});

test("the real counter dispatches only after its reservation is completely written and synced", async (t) => {
  const ctx = await fixture(t);
  const { onStarted, onReserve, onTerminal } = ctx.journal;
  const counter = createStage3RequestCounter({ preflightIds, onStarted, onReserve, onTerminal });
  await counter.start({ runId });
  for (const id of preflightIds)
    await counter.sendPreflight(
      id,
      async () => {
        assert.equal(ctx.trace.at(-1).event, "sync");
        const last = (await ctx.rows()).at(-1);
        assert.equal(last.event, "reserved");
        assert.equal(last.data.operationId, id);
        return true;
      },
      (result) => result,
    );
  counter.admit();
  await counter.send(requestIds[2], async () => true);
  counter.enterRecovery();
  await counter.send(requestIds[3], async () => true);
  await counter.finish("finished");
  const rows = await ctx.rows();
  assert.deepEqual(
    rows.map((row) => row.event),
    ["opened", "started", "reserved", "reserved", "reserved", "reserved", "terminal"],
  );
  assert.deepEqual(rows.at(-1).data, terminal("finished", 4, 3, 1));
  assert.equal(ctx.journal.snapshot().state, "terminal");
  assert.equal(ctx.journal.snapshot().sendAuthorized, false);
  await assert.rejects(
    ctx.journal.onReserve(reserve(5, requestIds[3], "recovery")),
    /journal event refused/,
  );
});

for (const label of ["existing file", "symlink"]) {
  test(`a ${label} is not appended or replaced`, async (t) => {
    let saved;
    await assert.rejects(
      fixture(t, {
        before: async ({ directory, path }) => {
          saved = join(directory, "saved.txt");
          await writeFile(saved, "existing-content");
          if (label === "symlink") await symlink(saved, path);
          else await writeFile(path, "existing-content");
        },
      }),
      /journal creation failed/,
    );
    assert.equal(await readFile(saved, "utf8"), "existing-content");
  });
}

test("a permissive journal directory is refused before creating a file", async (t) => {
  await assert.rejects(
    fixture(t, { before: async ({ directory }) => chmod(directory, 0o755) }),
    /journal creation failed/,
  );
});

for (const delta of [
  { runId: "../other" },
  { sourceCommit: "short" },
  { manifestDigest: "short" },
  { requestIds: [preflightIds[0]] },
  { preflightIds: [] },
  { requestIds: [...requestIds, requestIds[0]] },
  { token: "synthetic-secret" },
]) {
  test(`invalid journal option ${Object.keys(delta)[0]} is refused`, async (t) => {
    await assert.rejects(fixture(t, { delta }), /invalid reservation journal input/);
  });
}

test("input arrays are copied and getters are refused without invocation", async (t) => {
  const ids = [...requestIds];
  const beforeIds = [...preflightIds];
  const ctx = await fixture(t, { delta: { requestIds: ids, preflightIds: beforeIds } });
  ids[0] = "changed";
  beforeIds[0] = "changed";
  await ctx.journal.onStarted(start());
  await ctx.journal.onReserve(reserve());
  let touched = false;
  const row = start();
  Object.defineProperty(row, "runId", {
    enumerable: true,
    get() {
      touched = true;
      throw new Error("synthetic-secret");
    },
  });
  const other = await fixture(t);
  await assert.rejects(other.journal.onStarted(row), /journal event refused/);
  assert.equal(touched, false);
});

for (const delta of [
  { runId: "other-run" },
  { maxRequests: 6649 },
  { recoveryReserve: 1999 },
  { preflightIds: [...preflightIds].reverse() },
  { token: "synthetic-secret" },
]) {
  test(`a mismatched started field ${Object.keys(delta)[0]} cannot be recorded`, async (t) => {
    const ctx = await fixture(t);
    await assert.rejects(ctx.journal.onStarted({ ...start(), ...delta }), /journal event refused/);
    assert.equal((await ctx.rows()).length, 1);
  });
}

test("started must be recorded exactly once before any reservation", async (t) => {
  const ctx = await fixture(t);
  await assert.rejects(ctx.journal.onReserve(reserve()), /journal event refused/);
  await ctx.journal.onStarted(start());
  await assert.rejects(ctx.journal.onStarted(start()), /journal event refused/);
});

for (const row of [
  reserve(2),
  reserve(1, "unknown/id"),
  reserve(1, preflightIds[0], "other"),
  reserve(1, requestIds[2], "preflight"),
  { ...reserve(), headers: { authorization: "synthetic-secret" } },
]) {
  test("an invalid reservation cannot alter the file or counters", async (t) => {
    const ctx = await fixture(t);
    await ctx.journal.onStarted(start());
    await assert.rejects(ctx.journal.onReserve(row), /journal event refused/);
    assert.equal((await ctx.rows()).length, 2);
    assert.equal(ctx.journal.snapshot().requests, 0);
  });
}

test("duplicate requests and phase regressions cannot be recorded", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.onStarted(start());
  await ctx.journal.onReserve(reserve());
  await assert.rejects(ctx.journal.onReserve(reserve(2)), /journal event refused/);
  await assert.rejects(
    ctx.journal.onReserve(reserve(2, requestIds[2], "normal")),
    /journal event refused/,
  );
  await ctx.journal.onReserve(reserve(2, preflightIds[1]));
  await ctx.journal.onReserve(reserve(3, requestIds[3], "recovery"));
  await assert.rejects(
    ctx.journal.onReserve(reserve(4, requestIds[2], "normal")),
    /journal event refused/,
  );
});

test("unknown IDs and phases remain forbidden after completed preflight", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.onStarted(start());
  await ctx.journal.onReserve(reserve());
  await ctx.journal.onReserve(reserve(2, preflightIds[1]));
  await assert.rejects(
    ctx.journal.onReserve(reserve(3, "unknown/subject/get", "normal")),
    /journal event refused/,
  );
  await assert.rejects(
    ctx.journal.onReserve(reserve(3, requestIds[2], "unknown")),
    /journal event refused/,
  );
});

for (const delta of [
  { requests: 2 },
  { normal: 0 },
  { recovery: 1 },
  { maxRequests: 6649 },
  { outcome: "unknown" },
  { body: "synthetic-secret" },
]) {
  test(`terminal field ${Object.keys(delta)[0]} must match durable counters`, async (t) => {
    const ctx = await fixture(t);
    await ctx.journal.onStarted(start());
    await ctx.journal.onReserve(reserve());
    await assert.rejects(
      ctx.journal.onTerminal({ ...terminal("preflight-failed", 1, 1), ...delta }),
      /journal event refused/,
    );
  });
}

test("a finished terminal requires every declared preflight and cannot be repeated", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.onStarted(start());
  await assert.rejects(ctx.journal.onTerminal(terminal("finished")), /journal event refused/);
  await ctx.journal.onReserve(reserve());
  await ctx.journal.onTerminal(terminal("preflight-failed", 1, 1));
  await assert.rejects(
    ctx.journal.onTerminal(terminal("preflight-failed", 1, 1)),
    /journal event refused/,
  );
});

test("short writes finish every JSON line before sync acknowledgement", async (t) => {
  const ctx = await fixture(t, {
    hooks: {
      write: (handle, [bytes, offset, length, position]) =>
        handle.write(bytes, offset, Math.min(length, 7), position),
    },
  });
  await ctx.journal.onStarted(start());
  await ctx.journal.onReserve(reserve());
  assert.equal((await ctx.rows()).at(-1).data.operationId, preflightIds[0]);
  assert.ok(ctx.trace.filter((row) => row.event === "write").length > 3);
});

for (const kind of ["file", "directory"]) {
  test(`initial ${kind} fsync failure refuses creation and closes handles`, async (t) => {
    const closed = [];
    await assert.rejects(
      fixture(t, {
        hooks: {
          sync: async (handle, name) => {
            if (name === kind) throw new Error("synthetic-secret");
            await handle.sync();
          },
          close: async (handle, name) => {
            closed.push(name);
            await handle.close();
          },
        },
      }),
      (error) => error.message === "reservation journal creation failed",
    );
    assert.deepEqual(closed, ["file", "directory"]);
  });
}

for (const failure of ["zero", "throw", "sync"]) {
  test(`reservation ${failure} failure prevents HTTP and permanently stops events`, async (t) => {
    let failed = false;
    const ctx = await fixture(t, {
      hooks: {
        write: (handle, args) => {
          if (failed && failure === "zero") return { bytesWritten: 0 };
          if (failed && failure === "throw") throw new Error("synthetic-secret");
          return handle.write(...args);
        },
        sync: (handle) => {
          if (failed && failure === "sync") throw new Error("synthetic-secret");
          return handle.sync();
        },
      },
    });
    const counter = createStage3RequestCounter({
      preflightIds,
      onStarted: ctx.journal.onStarted,
      onReserve: ctx.journal.onReserve,
      onTerminal: ctx.journal.onTerminal,
    });
    await counter.start({ runId });
    failed = true;
    let sent = false;
    await assert.rejects(
      counter.sendPreflight(
        preflightIds[0],
        async () => {
          sent = true;
          return true;
        },
        (value) => value,
      ),
      (error) => error.message === "reservation journal uncertain",
    );
    assert.equal(sent, false);
    assert.equal(ctx.journal.snapshot().uncertain, true);
    assert.equal(counter.snapshot().mode, "journal-uncertain");
    failed = false;
    await assert.rejects(ctx.journal.onReserve(reserve()), /journal event refused/);
  });
}

for (const changed of ["inode", "mode", "size", "link"]) {
  test(`a changed journal ${changed} stops acknowledgement`, async (t) => {
    const ctx = await fixture(t);
    await ctx.journal.onStarted(start());
    if (changed === "inode") {
      const bytes = await readFile(ctx.path);
      await rename(ctx.path, `${ctx.path}.old`);
      await writeFile(ctx.path, bytes, { mode: 0o600 });
    }
    if (changed === "mode") await chmod(ctx.path, 0o644);
    if (changed === "size") await writeFile(ctx.path, "external", { flag: "a" });
    if (changed === "link") await link(ctx.path, `${ctx.path}.linked`);
    await assert.rejects(ctx.journal.onReserve(reserve()), /reservation journal uncertain/);
    assert.equal(ctx.journal.snapshot().uncertain, true);
    if (changed === "inode")
      assert.equal((await readFile(`${ctx.path}.old`)).length, (await readFile(ctx.path)).length);
  });
}

test("a same-byte inode replacement immediately after fsync cannot acknowledge a reservation", async (t) => {
  let changed = false;
  let path;
  const ctx = await fixture(t, {
    hooks: {
      sync: async (handle, kind) => {
        await handle.sync();
        if (changed && kind === "file") {
          changed = false;
          const bytes = await readFile(path);
          await rename(path, `${path}.old`);
          await writeFile(path, bytes, { mode: 0o600 });
        }
      },
    },
  });
  path = ctx.path;
  const counter = createStage3RequestCounter({
    preflightIds,
    onStarted: ctx.journal.onStarted,
    onReserve: ctx.journal.onReserve,
    onTerminal: ctx.journal.onTerminal,
  });
  await counter.start({ runId });
  changed = true;
  let sent = false;
  await assert.rejects(
    counter.sendPreflight(
      preflightIds[0],
      async () => {
        sent = true;
        return true;
      },
      (value) => value,
    ),
    /reservation journal uncertain/,
  );
  assert.equal(sent, false);
  assert.equal(ctx.journal.snapshot().requests, 0);
  assert.equal(counter.snapshot().mode, "journal-uncertain");
  await assert.rejects(ctx.journal.onReserve(reserve()), /journal event refused/);
});

test("a pending append blocks concurrent events and close", async (t) => {
  let enter;
  let resume;
  let paused = false;
  const entered = new Promise((resolve) => {
    enter = resolve;
  });
  const resumed = new Promise((resolve) => {
    resume = resolve;
  });
  const ctx = await fixture(t, {
    hooks: {
      write: async (handle, args) => {
        if (paused) {
          paused = false;
          enter();
          await resumed;
        }
        return handle.write(...args);
      },
    },
  });
  await ctx.journal.onStarted(start());
  paused = true;
  const first = ctx.journal.onReserve(reserve());
  await entered;
  try {
    await assert.rejects(ctx.journal.onReserve(reserve()), /journal event refused/);
    await assert.rejects(ctx.journal.close(), /journal event refused/);
  } finally {
    resume();
    await first;
  }
  assert.equal(ctx.journal.snapshot().requests, 1);
});

test("close releases both handles, preserves the file and refuses later events", async (t) => {
  const ctx = await fixture(t);
  await ctx.journal.close();
  assert.deepEqual(
    ctx.trace.filter((row) => row.event === "close").map((row) => row.kind),
    ["file", "directory"],
  );
  assert.equal((await ctx.rows()).length, 1);
  assert.equal(ctx.journal.snapshot().closed, true);
  await assert.rejects(ctx.journal.onStarted(start()), /journal event refused/);
  await ctx.journal.close();
});

test("a failed close stays uncertain and an explicit close retry releases the remaining handle", async (t) => {
  let failed = true;
  let attempts = 0;
  const ctx = await fixture(t, {
    hooks: {
      close: async (handle, kind) => {
        if (kind === "file") {
          attempts++;
          if (failed) throw new Error("synthetic-secret");
        }
        await handle.close();
      },
    },
  });
  await assert.rejects(
    ctx.journal.close(),
    (error) => error.message === "reservation journal uncertain",
  );
  assert.equal(ctx.journal.snapshot().uncertain, true);
  await assert.rejects(ctx.journal.onStarted(start()), /journal event refused/);
  failed = false;
  await ctx.journal.close();
  assert.equal(attempts, 2);
});

test("a partial reservation write followed by error preserves evidence and cannot dispatch", async (t) => {
  let failed = false;
  let first = true;
  const ctx = await fixture(t, {
    hooks: {
      write: async (handle, [bytes, offset, length, position]) => {
        if (failed) {
          if (!first) throw new Error("synthetic-secret");
          first = false;
          return handle.write(bytes, offset, 7, position);
        }
        return handle.write(bytes, offset, length, position);
      },
    },
  });
  const counter = createStage3RequestCounter({
    preflightIds,
    onStarted: ctx.journal.onStarted,
    onReserve: ctx.journal.onReserve,
    onTerminal: ctx.journal.onTerminal,
  });
  await counter.start({ runId });
  const size = (await lstat(ctx.path)).size;
  failed = true;
  let sent = false;
  await assert.rejects(
    counter.sendPreflight(
      preflightIds[0],
      async () => {
        sent = true;
      },
      () => true,
    ),
    /reservation journal uncertain/,
  );
  assert.equal(sent, false);
  assert.equal((await lstat(ctx.path)).size, size + 7);
  assert.equal(ctx.journal.snapshot().requests, 0);
  assert.equal(ctx.journal.snapshot().uncertain, true);
});

test("an impossible bytesWritten count is refused even when all bytes reached the file", async (t) => {
  let failed = false;
  const ctx = await fixture(t, {
    hooks: {
      write: async (handle, args) => {
        const result = await handle.write(...args);
        return failed ? { bytesWritten: result.bytesWritten + 1 } : result;
      },
    },
  });
  await ctx.journal.onStarted(start());
  failed = true;
  await assert.rejects(ctx.journal.onReserve(reserve()), /reservation journal uncertain/);
  assert.equal(ctx.journal.snapshot().requests, 0);
});

test("the supplied IO methods are copied before caller mutation", async (t) => {
  const methods = { open, lstat };
  const ctx = await fixture(t, { delta: { io: methods } });
  methods.lstat = async () => {
    throw new Error("synthetic-secret");
  };
  methods.open = async () => {
    throw new Error("synthetic-secret");
  };
  await ctx.journal.onStarted(start());
  assert.equal(ctx.journal.snapshot().state, "started");
});

test("a request ID array getter is refused without invocation", async (t) => {
  let touched = false;
  const ids = [...requestIds];
  Object.defineProperty(ids, "0", {
    enumerable: true,
    get() {
      touched = true;
      throw new Error("synthetic-secret");
    },
  });
  await assert.rejects(
    fixture(t, { delta: { requestIds: ids } }),
    /invalid reservation journal input/,
  );
  assert.equal(touched, false);
});

async function memoryJournal(t, ids) {
  let size = 0;
  const directory = "/synthetic/run";
  const stats = (isDirectory) => ({
    dev: 1,
    ino: isDirectory ? 1 : 2,
    mode: isDirectory ? 0o40700 : 0o100600,
    nlink: 1,
    size: isDirectory ? 0 : size,
    isDirectory: () => isDirectory,
    isFile: () => !isDirectory,
  });
  const io = {
    lstat: async (path) => stats(path === directory),
    open: async (path) => ({
      stat: async () => stats(path === directory),
      sync: async () => {},
      close: async () => {},
      write: async (_bytes, _offset, length) => {
        size += length;
        return { bytesWritten: length };
      },
    }),
  };
  const { createReservationJournal } = await import("./storage-rules/reservation-journal.mjs");
  const journal = await createReservationJournal({
    directory,
    runId,
    sourceCommit,
    manifestDigest,
    requestIds: [...preflightIds, ...ids],
    preflightIds,
    io,
  });
  t.after(() => journal.close());
  await journal.onStarted(start());
  await journal.onReserve(reserve());
  await journal.onReserve(reserve(2, preflightIds[1]));
  return journal;
}

for (const [phase, cap, used] of [
  ["normal", 4648, 2],
  ["recovery", 2000, 0],
]) {
  test(`the ${phase} cap cannot be consumed beyond its durable bound`, async (t) => {
    const ids = Array.from(
      { length: cap - used + 1 },
      (_, index) => `${phase}/attempt-${index + 1}`,
    );
    const journal = await memoryJournal(t, ids);
    for (let index = 0; index < cap - used; index++)
      await journal.onReserve(reserve(index + 3, ids[index], phase));
    const total = cap - used + 2;
    await assert.rejects(
      journal.onReserve(reserve(total + 1, ids.at(-1), phase)),
      /journal event refused/,
    );
    assert.equal(journal.snapshot().requests, total);
  });
}

async function admittedJournal(t, { recoveryRequests = 0, normalRequests = 0 } = {}) {
  const ctx = await fixture(t);
  await ctx.journal.onStarted(start());
  await ctx.journal.onReserve(reserve(1, preflightIds[0], "preflight"));
  await ctx.journal.onReserve(reserve(2, preflightIds[1], "preflight"));
  let attempt = 3;
  if (normalRequests) await ctx.journal.onReserve(reserve(attempt++, requestIds[2], "normal"));
  if (recoveryRequests) await ctx.journal.onReserve(reserve(attempt++, requestIds[3], "recovery"));
  return { ctx, requests: attempt - 1 };
}

test("a stopped-no-mutation terminal is durable only in the normal phase with no recovery request", async (t) => {
  const { ctx, requests } = await admittedJournal(t, { normalRequests: 1 });
  await assert.rejects(
    ctx.journal.onTerminal(terminal("stopped-no-mutation", requests + 1, requests + 1, 0)),
    /journal event refused/,
  );
  await ctx.journal.onTerminal(terminal("stopped-no-mutation", requests, requests, 0));
  assert.equal((await ctx.rows()).at(-1).data.outcome, "stopped-no-mutation");
});

test("a stopped-no-mutation terminal is refused before admission and after a recovery request", async (t) => {
  const early = await fixture(t);
  await early.journal.onStarted(start());
  await early.journal.onReserve(reserve(1, preflightIds[0], "preflight"));
  await assert.rejects(
    early.journal.onTerminal(terminal("stopped-no-mutation", 1, 1, 0)),
    /journal event refused/,
  );
  const { ctx, requests } = await admittedJournal(t, { normalRequests: 1, recoveryRequests: 1 });
  await assert.rejects(
    ctx.journal.onTerminal(terminal("stopped-no-mutation", requests, requests - 1, 1)),
    /journal event refused/,
  );
});

test("a recovered terminal needs the recovery phase and at least one recovery request", async (t) => {
  const normalOnly = await admittedJournal(t, { normalRequests: 1 });
  await assert.rejects(
    normalOnly.ctx.journal.onTerminal(
      terminal("recovered", normalOnly.requests, normalOnly.requests, 0),
    ),
    /journal event refused/,
  );
  const { ctx, requests } = await admittedJournal(t, { normalRequests: 1, recoveryRequests: 1 });
  await ctx.journal.onTerminal(terminal("recovered", requests, requests - 1, 1));
  assert.equal((await ctx.rows()).at(-1).data.outcome, "recovered");
});
