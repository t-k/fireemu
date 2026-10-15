import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { SANDBOX_PROJECT } from "./fs-rules/harness.mjs";
import { TASK_ID, TASK_ID_BAD_PATH } from "./fs-rules-v1/judge.mjs";
import { assertCleanTree, productionDeps, RECORDING_SIGNALS } from "./fs-rules-v1/run.mjs";

const RUN = join(import.meta.dirname, "fs-rules-v1/run.mjs");
const CLEAN_ENV = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  NODE_OPTIONS: "",
};

/** Runs the real entry point with nothing production-related in the environment. */
const run = (args, env = {}) =>
  spawnSync(process.execPath, [RUN, ...args], {
    env: { ...CLEAN_ENV, ...env },
    encoding: "utf8",
    timeout: 20_000,
  });

test("an unknown command prints the usage and exits 2", () => {
  const result = run(["frobnicate"]);
  assert.equal(result.status, 2);
  assert.match(
    result.stderr,
    /usage: run\.mjs preflight\|record-production\|check\|local\|official/,
  );
});

test("record-production refuses to start without its ledger and private directory", () => {
  const result = run(["record-production"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FIREEMU_SANDBOX_LEDGER and FIREEMU_FS3_PRIVATE_DIR are required/);
  const half = run(["record-production"], { FIREEMU_SANDBOX_LEDGER: "/nonexistent/ledger" });
  assert.notEqual(half.status, 0);
  assert.match(half.stderr, /FIREEMU_FS3_PRIVATE_DIR are required/);
});

test("preflight refuses to start without the sandbox web config, before any request", () => {
  const result = run(["preflight"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required/);
});

test("export-comparison needs an output path", () => {
  const result = run(["export-comparison"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /usage: export-comparison <output\.json>/);
});

// ---- the clean-tree check -------------------------------------------------------------------

const git = (cwd, ...args) => {
  const done = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8" });
  assert.equal(done.status, 0, done.stderr);
  return done.stdout;
};

test("the clean-tree check refuses a change anywhere in the worktree, not only in the recorder's files", async () => {
  const root = mkdtempSync(join(tmpdir(), "fs3-tree-"));
  try {
    git(root, "init", "-q");
    git(root, "config", "user.email", "t@example.com");
    git(root, "config", "user.name", "t");
    mkdirSync(join(root, "conformance/src/auth-fs-cross"), { recursive: true });
    writeFileSync(join(root, "conformance/src/auth-fs-cross/listen-grpc.mjs"), "export {};\n");
    writeFileSync(join(root, "README"), "x\n");
    git(root, "add", ".");
    git(root, "commit", "-q", "-m", "init");
    const cwd = join(root, "conformance");
    await assertCleanTree(cwd);
    for (const file of ["conformance/src/auth-fs-cross/listen-grpc.mjs", "README"]) {
      writeFileSync(join(root, file), "changed\n");
      await assert.rejects(assertCleanTree(cwd), /needs a clean tree/, file);
      git(root, "checkout", "-q", "--", file);
    }
    writeFileSync(join(root, "conformance/untracked.mjs"), "x\n");
    await assert.rejects(assertCleanTree(cwd), /needs a clean tree/);
    rmSync(join(root, "conformance/untracked.mjs"));
    await assertCleanTree(cwd);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a closed terminal stops a recording like an interrupt does", () => {
  assert.deepEqual([...RECORDING_SIGNALS].toSorted(), ["SIGHUP", "SIGINT", "SIGTERM"]);
});

// ---- the corpus family reaches the preflight --------------------------------------------------

test("preflight names the corpus family before it asks for the web config", () => {
  const result = run(["preflight"], { FS3_CORPUS: "nonsense" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FS3_CORPUS must be v1 or bad-path, not nonsense/);
  assert.doesNotMatch(result.stderr, /FIREEMU_AUTH_SANDBOX_WEB_CONFIG/);
  const mixed = run(["preflight"], { FS3_CORPUS: "bad-path", FS3_PROGRAMS: "fs-rules-v1/path" });
  assert.match(mixed.stderr, /no program matches FS3_PROGRAMS/);
});

test("the production preflight hands the run's task id on, so a run is not its own other lane", async () => {
  const { preflight } = productionDeps();
  const now = Date.now();
  const line = (taskId) =>
    JSON.stringify({
      ts: new Date(now - 5 * 60_000).toISOString(),
      project: SANDBOX_PROJECT,
      taskId,
      event: "started",
    });
  const ledgerText = `${line(TASK_ID)}\n${line(TASK_ID_BAD_PATH)}\n`;
  const answer = (url) => {
    const text = String(url);
    const body = text.includes("/releases")
      ? { releases: [] }
      : text.includes("/rulesets")
        ? {}
        : text.endsWith("/databases")
          ? { databases: [{ name: `projects/${SANDBOX_PROJECT}/databases/(default)` }] }
          : text.includes(":runQuery")
            ? [{}]
            : text.includes("accounts:query")
              ? { recordsCount: "0" }
              : { signIn: { anonymous: { enabled: true } } };
    return { status: 200, json: async () => body };
  };
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => answer(url);
  try {
    const target = { adminToken: "ya29.owner-test-token" };
    const bad = await preflight(target, ledgerText, TASK_ID_BAD_PATH);
    assert.deepEqual(bad.report.otherLanesRecently, [TASK_ID]);
    assert.deepEqual(bad.report.openRuns, [TASK_ID]);
    const v1 = await preflight(target, ledgerText, TASK_ID);
    assert.deepEqual(v1.report.otherLanesRecently, [TASK_ID_BAD_PATH]);
    // No task id: the FS-3 id, as before the FS-8 corpus existed.
    const none = await preflight(target, ledgerText);
    assert.deepEqual(none.report.otherLanesRecently, [TASK_ID_BAD_PATH]);
  } finally {
    globalThis.fetch = real;
  }
});
