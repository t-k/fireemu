import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";

const moduleUrl = new URL("../pubsub-production/capture.mjs", import.meta.url);
const common = execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
  encoding: "utf8",
}).trim();
const base = join(dirname(common), "docs.local/runs/codex-lane7");
async function withCapture(run) {
  assert.ok(existsSync(moduleUrl), "concrete private capture adapter is missing");
  const { capturePreflight } = await import(moduleUrl.href);
  await mkdir(base, { recursive: true });
  const parent = await mkdtemp(join(base, "capture-test-"));
  try {
    await run(capturePreflight, join(parent, "attempt"));
  } finally {
    await rm(parent, { recursive: true });
  }
}

test("capture persists a before-send receipt before the transport and never saves credentials", async () => {
  await withCapture(async (capture, directory) => {
    let calls = 0;
    const result = await capture({
      directory,
      projectNumber: "123456789012",
      accessToken: "test-secret-token",
      send: async () => {
        const rows = (await readFile(join(directory, "requests.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map(JSON.parse);
        assert.equal(rows.at(-1).state, "before-send");
        assert.equal(rows.filter(({ state }) => state === "before-send").length, ++calls);
        return new Response('{"unobservedShape":true}', { status: 403 });
      },
    });
    assert.equal(result.outcome, "recorded-preflight");
    assert.equal(result.attempted, 13);
    assert.equal(result.completed, 13);
    assert.equal(result.unknown, 0);
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    for (const name of await readdir(directory)) {
      assert.equal((await stat(join(directory, name))).mode & 0o777, 0o600);
      assert.ok(!(await readFile(join(directory, name), "utf8")).includes("test-secret-token"));
    }
    assert.equal(JSON.parse(await readFile(join(directory, "identity.json"), "utf8")).status, 403);
  });
});

test("failed transport consumes its slot and persists uncertainty without its secret-bearing error", async () => {
  await withCapture(async (capture, directory) => {
    let calls = 0;
    const result = await capture({
      directory,
      projectNumber: "123456789012",
      accessToken: "test-secret-token",
      send: async () => {
        if (++calls === 2) {
          const error = new Error("test-secret-token");
          error.name = "test-secret-token";
          throw error;
        }
        return new Response("{}");
      },
    });
    assert.equal(calls, 2);
    assert.equal(result.outcome, "incomplete-read-only");
    assert.equal(result.attempted, 2);
    assert.equal(result.completed, 1);
    assert.equal(result.unknown, 1);
    const summary = await readFile(join(directory, "summary.json"), "utf8");
    assert.ok(!summary.includes("test-secret-token"));
    assert.deepEqual(JSON.parse(summary), result);
  });
});

test("capture refuses an existing directory without overwriting previous evidence", async () => {
  await withCapture(async (capture, directory) => {
    await mkdir(directory);
    await assert.rejects(
      capture({
        directory,
        projectNumber: "123456789012",
        accessToken: "test-secret-token",
        send: async () => assert.fail("no request"),
      }),
      /EEXIST/,
    );
    assert.deepEqual(await readdir(directory), []);
  });
});

test("capture rejects public output paths before calling the transport", async () => {
  await withCapture(async (capture) => {
    await assert.rejects(
      capture({
        directory: join(dirname(common), "conformance/forbidden-output"),
        projectNumber: "123456789012",
        accessToken: "test-secret-token",
        send: async () => assert.fail("no request"),
      }),
      /private run directory/,
    );
  });
});

test("new run directory is durable before any send and failed parent sync prevents sending", async () => {
  await withCapture(async (capture, directory) => {
    let called = false;
    await assert.rejects(
      capture({
        directory,
        projectNumber: "123456789012",
        accessToken: "test-secret-token",
        syncParent: async (parent) => {
          called = true;
          assert.equal(parent, dirname(directory));
          assert.ok((await stat(directory)).isDirectory());
          assert.deepEqual(await readdir(directory), []);
          throw new Error("simulated parent fsync failure");
        },
        send: async () => assert.fail("no request before durable directory"),
      }),
      /parent fsync failure/,
    );
    assert.ok(called);
  });
});
