import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
const target = new URL("../pubsub-production/shape-capture.mjs", import.meta.url);
const common = execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
  encoding: "utf8",
}).trim();
const base = join(dirname(common), "docs.local/runs/codex-lane7");
const runId = "12".repeat(16);
async function withProbe(run) {
  assert.ok(existsSync(target), "owned shape capture is missing");
  const module = await import(target.href);
  await mkdir(base, { recursive: true });
  const parent = await mkdtemp(join(base, "shape-test-"));
  try {
    await run(module, join(parent, "capture"));
  } finally {
    await rm(parent, { recursive: true });
  }
}
function fakeBackend() {
  const resources = new Map();
  const calls = [];
  return {
    resources,
    calls,
    async send(request) {
      calls.push({ id: request.id, method: request.method, url: request.url });
      const name = new URL(request.url).pathname.slice("/v1/".length);
      if (request.id.includes("list")) return new Response("{}");
      if (request.method === "PUT") {
        if (resources.has(name)) return new Response("collision", { status: 409 });
        resources.set(name, true);
        return new Response('{"shapeWasNotAssumed":true}');
      }
      if (request.method === "DELETE") {
        resources.delete(name);
        return new Response("{}");
      }
      if (resources.has(name)) return new Response('{"differentGetShape":[true]}');
      return new Response(JSON.stringify({ unobservedError: { name, code: "missing" } }), {
        status: 404,
      });
    },
  };
}
const options = (directory, send) => ({
  directory,
  runId,
  accessToken: "test-secret-token",
  send,
  baseline: { topics: { status: 200, body: "{}" }, subscriptions: { status: 200, body: "{}" } },
});
test("shape manifest is16fixed requests with fresh owned names and no publications", async () => {
  await withProbe(async ({ shapeRequests }) => {
    const rows = shapeRequests(runId);
    assert.equal(rows.length, 16);
    assert.deepEqual(
      rows.slice(0, 6).map((r) => r.method),
      Array(6).fill("GET"),
    );
    assert.deepEqual(
      rows.filter((r) => r.method === "PUT").map((r) => r.id),
      ["topic-create", "subscription-create"],
    );
    assert.equal(rows.filter((r) => r.method === "DELETE").length, 2);
    for (const r of rows) {
      assert.ok(!r.url.includes(":publish"));
      if (!r.id.includes("list")) assert.ok(r.url.includes(`fireemu-lane7-${runId}-`));
    }
    assert.throws(() => shapeRequests("../foreign"));
  });
});
test("unknown created bodies are captured; ownership WAL precedes writes and cleanup returns baseline", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const backend = fakeBackend();
    const result = await captureShape(
      options(directory, async (request) => {
        const rows = (await readFile(join(directory, "requests.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map(JSON.parse);
        assert.equal(rows.at(-1).id, request.id);
        assert.equal(rows.at(-1).state, "before-send");
        if (request.method === "PUT") {
          assert.equal(rows.at(-1).ownership, "fresh-absent-before-create");
          const name =
            request.id === "topic-create" ? "topic-before-get" : "subscription-before-get";
          assert.equal(
            JSON.parse(await readFile(join(directory, `${name}.json`), "utf8")).status,
            404,
          );
        }
        return backend.send(request);
      }),
    );
    assert.equal(result.outcome, "exploration-recorded");
    assert.equal(result.sandboxAtBaseline, true);
    assert.equal(result.attempted, 16);
    assert.equal(result.unknown, 0);
    assert.equal(backend.resources.size, 0);
    for (const file of await readdir(directory))
      assert.ok(!(await readFile(join(directory, file), "utf8")).includes("test-secret-token"));
    const blob = JSON.parse(await readFile(join(directory, "topic-create.json"), "utf8"));
    assert.equal(blob.body, '{"shapeWasNotAssumed":true}');
    assert.match(blob.bodySha256, /^[a-f0-9]{64}$/);
  });
});
test("changed recorded list baseline prevents all writes without treating resource bodies as known", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const result = await captureShape(
      options(directory, async (request) => {
        assert.equal(request.method, "GET");
        return new Response('{"topics":[{"name":"foreign"}]}');
      }),
    );
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(result.sandboxAtBaseline, false);
    assert.equal(result.mutationAttempts, 0);
  });
});
test("a409collision is never adopted or deleted", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const backend = fakeBackend();
    const result = await captureShape(
      options(directory, async (request) =>
        request.id === "topic-create"
          ? new Response("foreign collision", { status: 409 })
          : backend.send(request),
      ),
    );
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(result.sandboxAtBaseline, false);
    assert.ok(!backend.calls.some((r) => r.method === "DELETE"));
  });
});
test("an unknown create is counted and bounded cleanup uses only its journaled run name", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const backend = fakeBackend();
    const result = await captureShape(
      options(directory, async (request) => {
        const reply = await backend.send(request);
        if (request.id === "topic-create") throw new Error("test-secret-token");
        return reply;
      }),
    );
    assert.equal(result.outcome, "exploration-inconclusive");
    assert.equal(result.sandboxAtBaseline, true);
    assert.equal(result.unknown, 1);
    assert.equal(backend.resources.size, 0);
    assert.ok(!backend.calls.some((r) => r.id === "subscription-create"));
    assert.deepEqual(
      backend.calls.filter((r) => r.method === "DELETE").map((r) => r.id),
      ["topic-delete"],
    );
  });
});
test("failed absence proof never claims baseline even after deletion returned success", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const backend = fakeBackend();
    const result = await captureShape(
      options(directory, async (request) =>
        request.id === "topic-after-get"
          ? new Response('{"stillExists":true}')
          : backend.send(request),
      ),
    );
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(result.sandboxAtBaseline, false);
  });
});
test("each transport fault before or after dispatch preserves the16request bound and never deletes unjournaled names", async () => {
  for (let index = 0; index < 16; index++)
    for (const mode of ["before", "after"]) {
      await withProbe(async ({ captureShape }, directory) => {
        const backend = fakeBackend();
        let count = 0;
        const result = await captureShape(
          options(directory, async (request) => {
            const fault = count++ === index;
            if (fault && mode === "before") throw new Error("test-secret-token");
            const response = await backend.send(request);
            if (fault && mode === "after") throw new Error("test-secret-token");
            return response;
          }),
        );
        assert.ok(result.attempted <= 16);
        assert.equal(result.unknown, result.attempted - result.completed);
        const rows = (await readFile(join(directory, "requests.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map(JSON.parse);
        for (const call of backend.calls.filter((r) => r.method === "DELETE")) {
          const create = call.id === "topic-delete" ? "topic-create" : "subscription-create";
          assert.ok(
            rows.some((r) => r.id === create && r.ownership === "fresh-absent-before-create"),
          );
        }
        if (result.sandboxAtBaseline) assert.equal(backend.resources.size, 0);
      });
    }
});

test("a409header followed by a failed body read cannot turn a foreign collision into cleanup ownership", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const backend = fakeBackend();
    const result = await captureShape(
      options(directory, async (request) => {
        if (request.id === "topic-create")
          return new Response(
            new ReadableStream({
              start(controller) {
                controller.error(new Error("test-secret-token"));
              },
            }),
            { status: 409 },
          );
        return backend.send(request);
      }),
    );
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(result.sandboxAtBaseline, false);
    assert.equal(result.unknown, 1);
    assert.ok(!backend.calls.some((r) => r.method === "DELETE"));
  });
});

test("authority withdrawn during capture forbids further sends including cleanup", async () => {
  await withProbe(async ({ captureShape }, directory) => {
    const backend = fakeBackend();
    let stopped = false;
    const result = await captureShape({
      ...options(directory, async (request) => {
        const reply = await backend.send(request);
        if (request.id === "topic-create") stopped = true;
        return reply;
      }),
      guard: async () => {
        if (stopped) throw new Error("withdrawn");
      },
    });
    assert.equal(result.outcome, "needs-recovery");
    assert.equal(result.sandboxAtBaseline, false);
    assert.equal(backend.calls.at(-1).id, "topic-create");
    assert.equal(result.attempted, 7);
  });
});
