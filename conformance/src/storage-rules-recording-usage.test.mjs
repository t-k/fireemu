import assert from "node:assert/strict";
import { chmod, link, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

// The record of which recordings an approval has already started: one durable line per started run.
const packetSha256 = "a".repeat(64);
const load = async () => {
  const module = await import("./storage-rules/recording-usage.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createRecordingUsage, "function");
  return module;
};
async function scratch(t) {
  const directory = await mkdtemp("/private/tmp/storage-rules-usage-");
  t.after(() => rm(directory, { recursive: true, force: true }));
  return { directory, path: join(directory, "usage.jsonl") };
}

test("a fresh ledger holds no run, marking a run makes it durable and private, and the same run is marked once", async (t) => {
  const { createRecordingUsage } = await load();
  const { path } = await scratch(t);
  const usage = createRecordingUsage({ path, packetSha256 });
  assert.deepEqual(await usage.startedRunIds(), []);
  await usage.markStarted("run-one");
  assert.deepEqual(await usage.startedRunIds(), ["run-one"]);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  await usage.markStarted("run-two");
  assert.deepEqual(await usage.startedRunIds(), ["run-one", "run-two"]);
  await assert.rejects(usage.markStarted("run-one"), /recording usage refused/);
  assert.deepEqual((await readFile(path, "utf8")).split("\n").filter(Boolean).map((line) => JSON.parse(line)), [{ packetSha256, runId: "run-one" }, { packetSha256, runId: "run-two" }]);
});

test("only the lines of this packet count, and a line that is not exactly a usage line refuses the whole ledger", async (t) => {
  const { createRecordingUsage } = await load();
  const { path } = await scratch(t);
  await writeFile(path, `${JSON.stringify({ packetSha256: "b".repeat(64), runId: "other-packet-run" })}\n${JSON.stringify({ packetSha256, runId: "mine" })}\n`, { mode: 0o600 });
  const usage = createRecordingUsage({ path, packetSha256 });
  assert.deepEqual(await usage.startedRunIds(), ["mine"]);
  for (const bad of ["not json\n", `${JSON.stringify({ packetSha256, runId: "x", extra: 1 })}\n`, `${JSON.stringify({ packetSha256, runId: "Bad Id!" })}\n`, `${JSON.stringify({ packetSha256: "zz", runId: "x" })}\n`, `${JSON.stringify([packetSha256, "x"])}\n`, `${JSON.stringify({ packetSha256, runId: "x" })}`, `${JSON.stringify({ packetSha256, runId: "d" })}\n${JSON.stringify({ packetSha256, runId: "d" })}\n`, `\n`]) {
    const file = await scratch(t);
    await writeFile(file.path, bad, { mode: 0o600 });
    await assert.rejects(createRecordingUsage({ path: file.path, packetSha256 }).startedRunIds(), /recording usage refused/, JSON.stringify(bad).slice(0, 40));
  }
});

test("a ledger file that is group or world accessible, a link, a directory or foreign-owned is refused for reading and marking", async (t) => {
  const { createRecordingUsage } = await load();
  const cases = {
    "group readable": async ({ path }) => { await writeFile(path, "", { mode: 0o600 }); await chmod(path, 0o640); return path; },
    "world writable": async ({ path }) => { await writeFile(path, "", { mode: 0o600 }); await chmod(path, 0o602); return path; },
    "symlink": async ({ directory, path }) => { await writeFile(path, "", { mode: 0o600 }); await symlink(path, join(directory, "link")); return join(directory, "link"); },
    "hard link": async ({ directory, path }) => { await writeFile(path, "", { mode: 0o600 }); await link(path, join(directory, "hard")); return path; },
    "directory": async ({ directory }) => directory,
  };
  for (const [name, prepare] of Object.entries(cases)) {
    const dir = await scratch(t);
    const path = await prepare(dir);
    const usage = createRecordingUsage({ path, packetSha256 });
    await assert.rejects(usage.startedRunIds(), /recording usage refused/, name);
    await assert.rejects(usage.markStarted("run-x"), /recording usage refused/, name);
  }
  const { path } = await scratch(t);
  await writeFile(path, "", { mode: 0o600 });
  await assert.rejects(createRecordingUsage({ path, packetSha256, uid: process.getuid() + 1 }).startedRunIds(), /recording usage refused/);
});

test("the options are a closed record and the run ID has one shape", async (t) => {
  const { createRecordingUsage } = await load();
  const { path } = await scratch(t);
  for (const bad of [undefined, null, {}, { path }, { path, packetSha256: "x" }, { path: "relative", packetSha256 }, { path, packetSha256, extra: 1 }, { path: 1, packetSha256 }]) assert.throws(() => createRecordingUsage(bad), /invalid recording usage options/);
  const usage = createRecordingUsage({ path, packetSha256 });
  for (const bad of ["", "UPPER", "a b", "x".repeat(49), 5, null, undefined, "-lead", "a/b"]) await assert.rejects(usage.markStarted(bad), /recording usage refused/, String(bad));
  await usage.markStarted("a1-b2");
});

// Cases that separate each guard from the others.
test("an empty ledger is a valid ledger, and a last line without its newline is refused whatever it holds", async (t) => {
  const { createRecordingUsage } = await load();
  const empty = await scratch(t);
  await writeFile(empty.path, "", { mode: 0o600 });
  assert.deepEqual(await createRecordingUsage({ path: empty.path, packetSha256 }).startedRunIds(), []);
  const line = JSON.stringify({ packetSha256, runId: "one" });
  for (const body of [`${line} `, `${line}\n${line.replace("one", "two")} `, `${line}\n ${line.replace("one", "two")}\n `]) {
    const file = await scratch(t);
    await writeFile(file.path, body, { mode: 0o600 });
    await assert.rejects(createRecordingUsage({ path: file.path, packetSha256 }).startedRunIds(), /recording usage refused/, JSON.stringify(body).slice(0, 30));
  }
});

test("a ledger over its size limit is refused whole even when every line is valid", async (t) => {
  const { createRecordingUsage } = await load();
  const file = await scratch(t);
  const lines = Array.from({ length: 1200 }, (_, index) => `${JSON.stringify({ packetSha256, runId: `run-${index}` })}\n`).join("");
  assert.ok(lines.length > 64 * 1024);
  await writeFile(file.path, lines, { mode: 0o600 });
  await assert.rejects(createRecordingUsage({ path: file.path, packetSha256 }).startedRunIds(), /recording usage refused/);
  await assert.rejects(createRecordingUsage({ path: file.path, packetSha256 }).markStarted("another"), /recording usage refused/);
});

test("a named pipe or another special file is refused without blocking", async (t) => {
  const { createRecordingUsage } = await load();
  const { execFileSync } = await import("node:child_process");
  const file = await scratch(t);
  execFileSync("mkfifo", ["-m", "600", file.path]);
  const usage = createRecordingUsage({ path: file.path, packetSha256 });
  await assert.rejects(Promise.race([usage.startedRunIds(), new Promise((_, reject) => setTimeout(() => reject(new Error("blocked")), 3000).unref())]), /recording usage refused/);
  await assert.rejects(Promise.race([usage.markStarted("run-x"), new Promise((_, reject) => setTimeout(() => reject(new Error("blocked")), 3000).unref())]), /recording usage refused/);
});

test("a marker is synced before the handle closes, and a file that changed under the append is refused", async (t) => {
  const { createRecordingUsage } = await load();
  const file = await scratch(t);
  const { open } = await import("node:fs/promises");
  const events = [];
  const io = { open: async (path, flags, mode) => {
    const handle = await open(path, flags, mode);
    return { stat: (...a) => handle.stat(...a), readFile: (...a) => handle.readFile(...a), writeFile: async (...a) => { events.push("write"); return handle.writeFile(...a); }, sync: async () => { events.push("sync"); return handle.sync(); }, close: async () => { events.push("close"); return handle.close(); } };
  } };
  await createRecordingUsage({ path: file.path, packetSha256, io }).markStarted("run-one");
  const at = (name) => events.lastIndexOf(name);
  assert.ok(at("write") < at("sync") && at("sync") < at("close"), events.join());
  // A handle whose file is group writable when the append starts is refused before anything is written.
  const other = await scratch(t);
  const { constants } = await import("node:fs");
  const racing = { open: async (path, flags, mode) => {
    const handle = await open(path, flags, mode);
    const writing = (flags & constants.O_WRONLY) !== 0;
    return { stat: async () => (writing ? { ...(await handle.stat()), isFile: () => true, mode: 0o100664, uid: process.getuid(), nlink: 1, size: 0 } : handle.stat()), readFile: (...a) => handle.readFile(...a), writeFile: async (...a) => { events.push("late-write"); return handle.writeFile(...a); }, sync: () => handle.sync(), close: () => handle.close() };
  } };
  events.length = 0;
  await assert.rejects(createRecordingUsage({ path: other.path, packetSha256, io: racing }).markStarted("run-two"), /recording usage refused/);
  assert.equal(events.includes("late-write"), false);
  assert.equal(await readFile(other.path, "utf8"), "");
});

test("both opens refuse symbolic links and never block on a special file, and the append creates a private file", async (t) => {
  const { createRecordingUsage } = await load();
  const file = await scratch(t);
  const { open } = await import("node:fs/promises");
  const { constants } = await import("node:fs");
  const opens = [];
  const io = { open: async (path, flags, mode) => { opens.push({ flags, mode }); return open(path, flags, mode); } };
  await createRecordingUsage({ path: file.path, packetSha256, io }).markStarted("run-one");
  assert.equal(opens.length, 2);
  const [read, write] = opens;
  for (const flag of ["O_NOFOLLOW", "O_NONBLOCK"]) assert.ok((read.flags & constants[flag]) !== 0 && (write.flags & constants[flag]) !== 0, flag);
  assert.ok((read.flags & constants.O_ACCMODE) === constants.O_RDONLY);
  for (const flag of ["O_WRONLY", "O_APPEND", "O_CREAT"]) assert.ok((write.flags & constants[flag]) !== 0, flag);
  assert.equal(write.mode, 0o600);
});

test("the uid option is an integer, and the io option is a closed record of functions", async (t) => {
  const { createRecordingUsage } = await load();
  const { path } = await scratch(t);
  for (const uid of ["501", 1.5, null, NaN, undefined]) assert.throws(() => createRecordingUsage({ path, packetSha256, uid }), /invalid recording usage options/, String(uid));
  for (const io of [null, {}, { open: 1 }, { open() {}, extra: 1 }, "x"]) assert.throws(() => createRecordingUsage({ path, packetSha256, io }), /invalid recording usage options/, JSON.stringify(io));
});
