import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const moduleUrl = new URL("../pubsub-production/baseline-capture.mjs", import.meta.url);
const runId = "0123456789abcdef0123456789abcdef";
async function fixture(run) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "lane7-baseline-capture-")));
  const base = join(root, "docs.local/runs/codex-lane7");
  await mkdir(base, { recursive: true });
  try {
    const { captureBaseline } = await import(moduleUrl.href);
    await run(captureBaseline, {
      root,
      base,
      directory: join(base, `fixture-baseline-002-${runId}`),
    });
  } finally {
    await rm(root, { recursive: true });
  }
}

test("baseline capture preserves fixed read-only POST and durable raw receipts before declaring capture", async () => {
  await fixture(async (capture, { root, directory }) => {
    let calls = 0,
      guards = 0;
    const result = await capture({
      root,
      runId,
      projectNumber: "123456789012",
      accessToken: "synthetic-secret",
      guard: async () => {
        guards++;
      },
      send: async (request) => {
        const rows = (await readFile(join(directory, "requests.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map(JSON.parse);
        assert.equal(rows.at(-1).state, "before-send");
        assert.equal(rows.filter((row) => row.state === "before-send").length, ++calls);
        if (calls === 2) {
          assert.equal(request.method, "POST");
          assert.equal(request.body, '{"options":{"requestedPolicyVersion":3}}');
          assert.equal(request.readOnly, true);
        }
        return new Response('{"unobserved":true}', { status: 403 });
      },
    });
    assert.deepEqual(result, {
      outcome: "captured-read-only-baseline",
      attempted: 3,
      completed: 3,
      unknown: 0,
    });
    assert.equal(guards, 6);
    assert.equal((await stat(directory)).mode & 0o777, 0o700);
    const rows = (await readFile(join(directory, "requests.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.equal(rows.length, 9);
    for (const id of ["identity", "project-iam", "pubsub-service-identity"]) {
      const raw = JSON.parse(await readFile(join(directory, `${id}.json`), "utf8"));
      assert.equal(raw.body, '{"unobserved":true}');
      assert.equal(Buffer.from(raw.bodyBase64, "base64").toString(), raw.body);
      assert.equal(raw.bodyBytes, Buffer.byteLength(raw.body));
      assert.equal(raw.status, 403);
    }
    for (const name of await readdir(directory)) {
      assert.equal((await stat(join(directory, name))).mode & 0o777, 0o600);
      assert.ok(!(await readFile(join(directory, name), "utf8")).includes("synthetic-secret"));
    }
    assert.deepEqual(JSON.parse(await readFile(join(directory, "summary.json"), "utf8")), result);
  });
});

test("baseline capture retains uncertain WAL without secret-bearing exceptions or later sends", async () => {
  await fixture(async (capture, { root, directory }) => {
    let calls = 0;
    const result = await capture({
      root,
      runId,
      projectNumber: "123456789012",
      accessToken: "synthetic-secret",
      guard: async () => {},
      send: async () => {
        if (++calls === 2) throw new Error("synthetic-secret");
        return new Response("{}");
      },
    });
    assert.equal(calls, 2);
    assert.deepEqual(result, {
      outcome: "incomplete-read-only-baseline",
      attempted: 2,
      completed: 1,
      unknown: 1,
    });
    assert.ok(
      !(await readFile(join(directory, "summary.json"), "utf8")).includes("synthetic-secret"),
    );
  });
});

test("baseline capture refuses replay and linked private roots without any sends", async () => {
  await fixture(async (capture, { root, directory, base }) => {
    const options = {
      root,
      runId,
      projectNumber: "123456789012",
      accessToken: "synthetic-secret",
      guard: async () => {},
      send: async () => assert.fail("no send"),
    };
    await mkdir(directory);
    await assert.rejects(capture(options), /EEXIST/);
    await rm(directory, { recursive: true });
    const external = join(root, "external");
    await mkdir(external);
    await rm(base, { recursive: true });
    await symlink(external, base);
    await assert.rejects(capture(options), /canonical private/);
    assert.deepEqual(await readdir(external), []);
  });
});

test("baseline capture requires a live guard and durable directory before transport", async () => {
  await fixture(async (capture, { root, directory }) => {
    const options = {
      root,
      runId,
      projectNumber: "123456789012",
      accessToken: "synthetic-secret",
      send: async () => assert.fail("no send"),
    };
    await assert.rejects(capture(options), /live admission/);
    await assert.rejects(
      capture({
        ...options,
        guard: async () => {},
        syncParent: async () => {
          assert.deepEqual(await readdir(directory), []);
          throw new Error("parent sync failed");
        },
      }),
      /parent sync failed/,
    );
  });
});
