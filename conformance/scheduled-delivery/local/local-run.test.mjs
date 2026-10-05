// `runLocal` against a fake `fireemu` (a script that records how it was called and prints handler lines), so that the
// command line, the copy of the fixture, the config, the environment and the clean-up are checked without a daemon.
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { runLocal } from "./local-run.mjs";

function fake(dir, body = "") {
  const path = join(dir, "fake-fireemu.mjs");
  writeFileSync(
    path,
    `#!${process.execPath}
import { existsSync, readFileSync, lstatSync } from "node:fs";
import { join } from "node:path";
const args = process.argv.slice(2);
const at = (flag) => args[args.indexOf(flag) + 1];
const fixture = at("--functions");
console.log("ARGS " + JSON.stringify(args));
console.log("CONFIG " + readFileSync(at("--config"), "utf8"));
console.log("INDEX " + JSON.stringify(readFileSync(join(fixture, "index.js"), "utf8")));
console.log("MODULES " + lstatSync(join(fixture, "node_modules")).isSymbolicLink());
console.log("WORK " + JSON.stringify({ fixture, config: at("--config"), home: process.env.HOME }));
console.log("ENV " + JSON.stringify(Object.fromEntries(Object.entries(process.env).filter(([k]) => k.startsWith("LOCAL_") || k === "PATH"))));
console.log("HOMEDIR " + existsSync(process.env.HOME));
${body}
`,
  );
  chmodSync(path, 0o755);
  return path;
}
function fixtureDir(dir) {
  const fixture = join(dir, "fixture-src");
  mkdirSync(fixture);
  writeFileSync(join(fixture, "index.js"), "setTimeout(resolve, 100_000);\n");
  writeFileSync(join(fixture, "package.json"), "{}");
  return fixture;
}
const field = (output, name) =>
  output
    .split("\n")
    .find((l) => l.startsWith(name + " "))
    ?.slice(name.length + 1);

test("it copies the fixture, links the dependencies, writes the pinned-clock config and runs the daemon once", async () => {
  const dir = mkdtempSync(join(tmpdir(), "local-run-test-"));
  try {
    const deps = join(dir, "deps");
    mkdirSync(deps);
    const result = await runLocal({
      fireemu: fake(
        dir,
        'console.log("PROBE " + JSON.stringify({ handler: "h", scheduleTime: "t" }));\nconsole.log("STEP 2026-10-05T08:40:31Z");\nconsole.log("STATE {\\"pending\\":0}");',
      ),
      node: "/usr/local/bin/node22",
      depsDir: deps,
      fixtureDir: fixtureDir(dir),
      profile: "emulator",
      start: "2026-10-05T08:40:30Z",
      seconds: 7,
      manual: ["a", "b"],
      awaitIdle: false,
      pauseMs: 150,
      patch: (source) => source.replace("100_000", "100"),
    });
    assert.equal(result.exitCode, 0);
    const args = JSON.parse(field(result.output, "ARGS"));
    assert.deepEqual(args.slice(0, 5), ["exec", "--project", "demo-sched", "--only", "functions"]);
    assert.equal(args[args.indexOf("--") + 1], "/usr/local/bin/node22");
    assert.match(args.at(-1), /local-child\.mjs$/);
    for (const name of [
      "functions",
      "firestore",
      "storage",
      "eventarc",
      "tasks",
      "pubsub",
      "ui",
      "hub",
      "logging",
    ])
      assert.equal(args[args.indexOf("--" + name + "-port") + 1], "0", name);
    assert.match(args[args.indexOf("--http-port") + 1], /^[1-9]\d{3,4}$/);
    assert.deepEqual(JSON.parse(field(result.output, "CONFIG")), {
      schemaVersion: 1,
      profile: "emulator",
      daemon: { clockStart: "2026-10-05T08:40:30Z" },
    });
    assert.equal(
      JSON.parse(field(result.output, "INDEX")),
      "setTimeout(resolve, 100);\n",
      "the patch is applied to the copy",
    );
    assert.equal(field(result.output, "MODULES"), "true");
    assert.equal(field(result.output, "HOMEDIR"), "true");
    const env = JSON.parse(field(result.output, "ENV"));
    assert.deepEqual(env, {
      PATH: "/usr/local/bin:/usr/bin:/bin",
      LOCAL_START: "2026-10-05T08:40:30Z",
      LOCAL_SECONDS: "7",
      LOCAL_AWAIT_IDLE: "0",
      LOCAL_PAUSE_MS: "150",
      LOCAL_MANUAL: "a,b",
    });
    assert.deepEqual(result.lines, [
      { at: "2026-10-05T08:40:31Z", kind: "PROBE", value: { handler: "h", scheduleTime: "t" } },
    ]);
    assert.deepEqual(result.state, { pending: 0 });
    // the work directory is gone, and the source fixture is untouched
    const work = JSON.parse(field(result.output, "WORK"));
    assert.equal(existsSync(work.config), false);
    assert.equal(existsSync(work.home), false);
    assert.equal(
      readFileSync(join(dir, "fixture-src", "index.js"), "utf8"),
      "setTimeout(resolve, 100_000);\n",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the defaults: the source is copied as it is, the runtime is waited for after each step, and the pause is 40 ms", async () => {
  const dir = mkdtempSync(join(tmpdir(), "local-run-test-"));
  try {
    const deps = join(dir, "deps");
    mkdirSync(deps);
    const result = await runLocal({
      fireemu: fake(dir),
      node: "/usr/local/bin/node22",
      depsDir: deps,
      fixtureDir: fixtureDir(dir),
      profile: "strict",
      start: "2026-10-05T08:40:30Z",
      seconds: 3,
    });
    assert.equal(JSON.parse(field(result.output, "INDEX")), "setTimeout(resolve, 100_000);\n");
    const env = JSON.parse(field(result.output, "ENV"));
    assert.equal(env.LOCAL_AWAIT_IDLE, "1");
    assert.equal(env.LOCAL_PAUSE_MS, "40");
    assert.equal(env.LOCAL_MANUAL, "");
    assert.equal(JSON.parse(field(result.output, "CONFIG")).profile, "strict");
    assert.deepEqual(result.lines, []);
    assert.equal(result.state, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a daemon that exits non-zero is reported with its output, and the work directory is still removed", async () => {
  const dir = mkdtempSync(join(tmpdir(), "local-run-test-"));
  try {
    const deps = join(dir, "deps");
    mkdirSync(deps);
    const result = await runLocal({
      fireemu: fake(dir, 'console.error("boom");\nprocess.exit(3);'),
      node: "/usr/local/bin/node22",
      depsDir: deps,
      fixtureDir: fixtureDir(dir),
      profile: "strict",
      start: "2026-10-05T08:40:30Z",
      seconds: 1,
    });
    assert.equal(result.exitCode, 3);
    assert.match(result.output, /boom/);
    assert.equal(existsSync(JSON.parse(field(result.output, "WORK")).config), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
