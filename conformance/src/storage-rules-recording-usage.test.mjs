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
