import assert from "node:assert/strict";
import { test } from "node:test";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  cleanEnvironment,
  readSource,
  newPrivateDirectory,
  publish,
  runProcess,
  snapshotBinary,
} from "../io.mjs";
import { parseArgs, buildExecArgs } from "../pilot.mjs";

async function area(fn) {
  const root = await fs.mkdtemp(join(tmpdir(), "prod-diff-"));
  try {
    return await fn(root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}
test("only an explicit small environment crosses the process boundary", () => {
  const e = cleanEnvironment("/private/home");
  for (const key of [
    "NODE_OPTIONS",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "FIRESTORE_PROBE_TOKEN",
    "FIRESTORE_PROBE_TARGET",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "GIT_CONFIG_COUNT",
  ])
    assert.equal(e[key], undefined);
  assert.equal(e.HOME, "/private/home");
  assert.equal(e.GIT_NO_REPLACE_OBJECTS, "1");
  assert.equal(e.GIT_OPTIONAL_LOCKS, "0");
});
test("output is outside the repo, private and never reused", () =>
  area(async (root) => {
    const repo = join(root, "repo");
    await fs.mkdir(repo);
    await assert.rejects(newPrivateDirectory(join(repo, "out"), repo), /outside/);
    const out = await newPrivateDirectory(join(root, "out"), repo);
    assert.equal((await fs.stat(out)).mode & 0o777, 0o700);
    await assert.rejects(newPrivateDirectory(out, repo));
  }));
test("result publication does not overwrite files", () =>
  area(async (root) => {
    const p = join(root, "result.json");
    await publish(p, "one");
    await assert.rejects(publish(p, "two"));
    assert.equal(await fs.readFile(p, "utf8"), "one");
    assert.deepEqual(await fs.readdir(root), ["result.json"]);
  }));
test("result publication does not follow a symlink", () =>
  area(async (root) => {
    const actual = join(root, "keep");
    await fs.writeFile(actual, "keep");
    await fs.symlink(actual, join(root, "result"));
    await assert.rejects(publish(join(root, "result"), "overwrite"));
    assert.equal(await fs.readFile(actual, "utf8"), "keep");
  }));
test("readSource rejects file and directory symlink traversal", () =>
  area(async (root) => {
    await fs.mkdir(join(root, "repo"));
    await fs.mkdir(join(root, "external"));
    await fs.writeFile(join(root, "external/x.json"), "{}");
    await fs.symlink(join(root, "external"), join(root, "repo/link"));
    await fs.symlink(join(root, "external/x.json"), join(root, "repo/file.json"));
    await assert.rejects(readSource(join(root, "repo"), "link/x.json"), /symlink/);
    await assert.rejects(readSource(join(root, "repo"), "file.json"), /symlink/);
  }));
for (const p of ["../x", "/etc/passwd", "a/../x", "a//x", "a\\x"])
  test(`unsafe input path ${p}`, () => assert.rejects(readSource("/tmp", p), /unsafe-source-path/));
test("readSource bounds input size and supports spaces/Japanese", () =>
  area(async (root) => {
    const dir = join(root, "作業 space");
    await fs.mkdir(dir);
    await fs.writeFile(join(dir, "sample.json"), "1234");
    assert.equal((await readSource(dir, "sample.json")).toString(), "1234");
    await assert.rejects(readSource(dir, "sample.json", 3), /size/);
  }));
test("shell scripts cannot be presented as a native fireemu binary", () =>
  area(async (root) => {
    const f = join(root, "fake");
    await fs.writeFile(f, "#!/bin/sh\nexit 0\n");
    await assert.rejects(snapshotBinary(f, join(root, "copy")), /native-binary/);
  }));
test("CLI does not provide a production backend or a server endpoint", () => {
  assert.throws(() => parseArgs(["observe"]), /unknown-mode/);
  assert.throws(
    () => parseArgs(["replay", "--endpoint", "https://firestore.googleapis.com"]),
    /arguments/,
  );
  assert.throws(() => parseArgs(["replay", "--binary", "/x"]), /replay-arguments/);
});
test("CLI rejects duplicate flags, case drift and unbounded runtime", () => {
  assert.throws(() => parseArgs(["plan", "--repo", "/a", "--repo", "/b"]), /arguments/);
  assert.throws(() => parseArgs(["plan", "--case", "other"]), /unknown-case/);
  assert.throws(() => parseArgs(["plan", "--timeout", "0"]), /timeout/);
  assert.throws(() => parseArgs(["plan", "--timeout", "9999"]), /timeout/);
});
test("exec uses argument arrays, private config and OS-assigned ports", () => {
  const c = buildExecArgs("/binary", "/a b/日本語", "/entry with spaces.mjs", "/node");
  assert.equal(c.command, "/binary");
  assert.equal(c.args.at(-1), "/entry with spaces.mjs");
  for (const flag of [
    "--firestore-port",
    "--http-port",
    "--ui-port",
    "--hub-port",
    "--logging-port",
  ])
    assert.equal(c.args[c.args.indexOf(flag) + 1], "0");
  assert.ok(c.args.includes("/a b/日本語/fireemu.json"));
  assert.ok(!c.args.includes("sh"));
});
test("bounded process captures an ordinary completion", async () => {
  const p = await runProcess(process.execPath, ["-e", 'console.log("ok")'], {
    env: cleanEnvironment("/tmp"),
    timeoutMs: 2000,
  });
  assert.equal(p.code, 0);
  assert.equal(p.reason, null);
  assert.equal(p.state, "stopped");
  assert.equal(p.log.toString().trim(), "ok");
});
test("bounded process exposes the actual owned PID before child completion", async () => {
  let spawned;
  const p = await runProcess(process.execPath, ["-e", "process.exit(0)"], {
    env: cleanEnvironment("/tmp"),
    timeoutMs: 2000,
    onSpawn: (info) => {
      spawned = info;
    },
  });
  assert.equal(p.code, 0);
  assert.equal(p.state, "stopped");
  assert.equal(spawned.command, process.execPath);
  assert.deepEqual(spawned.args, ["-e", "process.exit(0)"]);
  assert.equal(p.pid, spawned.pid);
  assert.ok(Number.isInteger(spawned.pid) && spawned.pid > 0);
});
test("process timeout is an error and the owned group is stopped", async () => {
  const p = await runProcess(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
    env: cleanEnvironment("/tmp"),
    timeoutMs: 100,
  });
  assert.equal(p.reason, "process-timeout");
  assert.notEqual(p.code, 0);
  assert.equal(p.state, "stopped");
});
test("oversized logs stop the process", async () => {
  const p = await runProcess(
    process.execPath,
    ["-e", 'console.log("x".repeat(20000));setInterval(()=>{},1000)'],
    { env: cleanEnvironment("/tmp"), maxLogBytes: 100, timeoutMs: 2000 },
  );
  assert.equal(p.reason, "process-log-limit");
  assert.ok(p.log.length <= 100);
});
test("missing executable is not a pass", async () => {
  const p = await runProcess("/nonexistent-fireemu-pilot-binary", [], {
    env: cleanEnvironment("/tmp"),
    timeoutMs: 100,
  });
  assert.equal(p.reason, "spawn-failed");
  assert.notEqual(p.code, 0);
});
