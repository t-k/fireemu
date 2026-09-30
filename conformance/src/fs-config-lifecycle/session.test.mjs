import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext } from "./harness.mjs";
import { runCorpus } from "./session.mjs";

/** A local context whose fetch is a stub that answers from `respond(method, path)`. */
function stubbed(respond) {
  const ctx = createContext({
    run: "1790000000",
    target: {
      kind: "local",
      origin: "http://127.0.0.1:1",
      storageOrigin: "http://127.0.0.1:2",
      grpcHost: "127.0.0.1",
      grpcPort: 1,
    },
  });
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const { pathname } = new URL(url);
    calls.push(`${init.method} ${decodeURIComponent(pathname)}`);
    const [status, body] = respond(init.method, decodeURIComponent(pathname));
    return new Response(body === undefined ? "" : JSON.stringify(body), { status });
  };
  return { ctx, calls, restore: () => (globalThis.fetch = original) };
}

const program = {
  id: "fs-config/test/cleanup",
  ordinal: 0,
  slug: "test-cleanup",
  databases: ["a", "b"],
  steps: [],
};

test("cleanup attempts every database and names every one that may remain", async () => {
  const stuck = "cfg1790000000-00a";
  const { ctx, calls, restore } = stubbed((_method, path) => {
    // Database a never goes away; b is already absent.
    if (path.endsWith(`/${stuck}`)) return [200, {}];
    if (path.endsWith("/databases")) return [200, { databases: [] }];
    return [404, {}];
  });
  try {
    await assert.rejects(
      runCorpus([program], ctx, { bucket: false, pollScale: 0 }),
      (error) =>
        error.fatal && /cfg1790000000-00a/.test(error.message) && !/00b/.test(error.message),
    );
    assert.ok(
      calls.some((c) => c.endsWith("cfg1790000000-00b")),
      "b was still attempted",
    );
  } finally {
    restore();
  }
});

test("the final sweep fails the run when a database of the run is still listed", async () => {
  const leftover = `projects/fireemu-oracle-query/databases/cfg1790000000-07q`;
  const { ctx, restore } = stubbed((_method, path) =>
    path.endsWith("/databases") ? [200, { databases: [{ name: leftover }] }] : [404, {}],
  );
  try {
    await assert.rejects(
      runCorpus([program], ctx, { bucket: false, pollScale: 0 }),
      (error) =>
        error.fatal &&
        /cfg1790000000-07q/.test(error.message) &&
        error.partial?.context?.run === "1790000000",
    );
  } finally {
    restore();
  }
});

test("a failed token refresh at cleanup is retried and every database is still deleted", async () => {
  const deleted = new Set();
  const { calls, restore } = stubbed(() => [404, {}]);
  restore();
  const ctx = createContext({
    run: "1790000000",
    target: {
      kind: "production",
      token: "t0",
      quotaProject: "fireemu-oracle-query",
      bucket: "fireemu-oracle-query-cfg-1790000000",
    },
  });
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const path = decodeURIComponent(new URL(url).pathname);
    calls.push(`${init.method} ${path}`);
    const id = path.split("/").at(-1);
    if (path.endsWith("/databases"))
      return new Response(JSON.stringify({ databases: [] }), { status: 200 });
    if (init.method === "DELETE") deleted.add(id);
    return new Response("{}", { status: deleted.has(id) ? 404 : 200 });
  };
  let refreshes = 0;
  try {
    await runCorpus([program], ctx, {
      bucket: false,
      pollScale: 0,
      refreshToken: async () => {
        refreshes += 1;
        if (refreshes === 1) throw new Error("gcloud failed once");
        return `t${refreshes}`;
      },
    });
    assert.deepEqual([...deleted].toSorted(), ["cfg1790000000-00a", "cfg1790000000-00b"]);
    assert.ok(refreshes >= 2);
  } finally {
    globalThis.fetch = original;
  }
});

test("a 401 is retried once with a fresh token and never recorded", async () => {
  const ctx = createContext({
    run: "1790000000",
    target: {
      kind: "production",
      token: "stale",
      quotaProject: "fireemu-oracle-query",
      bucket: "fireemu-oracle-query-cfg-1790000000",
    },
  });
  const seen = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push(init.headers.authorization);
    const path = decodeURIComponent(new URL(url).pathname);
    if (path.endsWith("/databases"))
      return new Response(JSON.stringify({ databases: [] }), { status: 200 });
    if (init.headers.authorization === "Bearer stale") return new Response("{}", { status: 401 });
    return new Response("{}", { status: 404 });
  };
  const readProgram = {
    ...program,
    databases: [],
    steps: [{ id: "get", path: "v1/{project}/locations" }],
  };
  try {
    const out = await runCorpus([readProgram], ctx, {
      bucket: false,
      pollScale: 0,
      refreshToken: async () => "fresh",
    });
    assert.equal(out.results[readProgram.id].steps.get.status, 404);
    assert.deepEqual(seen.slice(0, 2), ["Bearer stale", "Bearer fresh"]);
  } finally {
    globalThis.fetch = original;
  }
});

test("a rate-limited answer is retried and never recorded; another 429 is behavior", async () => {
  const ctx = createContext({
    run: "1790000000",
    target: {
      kind: "production",
      token: "t",
      quotaProject: "fireemu-oracle-query",
      bucket: "fireemu-oracle-query-cfg-1790000000",
    },
  });
  let calls = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const path = decodeURIComponent(new URL(url).pathname);
    if (path.endsWith("/databases"))
      return new Response(JSON.stringify({ databases: [] }), { status: 200 });
    if (path.endsWith("/locations")) {
      calls += 1;
      if (calls === 1)
        return new Response(
          JSON.stringify({
            error: {
              code: 429,
              status: "RESOURCE_EXHAUSTED",
              details: [{ reason: "RATE_LIMIT_EXCEEDED" }],
            },
          }),
          { status: 429 },
        );
      return new Response("{}", { status: 200 });
    }
    return new Response(
      JSON.stringify({
        error: { code: 429, status: "RESOURCE_EXHAUSTED", message: "at most '1' field(s)" },
      }),
      { status: 429 },
    );
  };
  const readProgram = {
    ...program,
    databases: [],
    steps: [
      { id: "limited", path: "v1/{project}/locations" },
      { id: "quota", path: "v1/{project}/locations/x" },
    ],
  };
  try {
    const out = await runCorpus([readProgram], ctx, {
      bucket: false,
      pollScale: 0,
      rateLimitDelayMs: 0,
    });
    assert.equal(calls, 2);
    assert.equal(out.results[readProgram.id].steps.limited.status, 200);
    assert.equal(out.results[readProgram.id].steps.quota.status, 429);
  } finally {
    globalThis.fetch = original;
  }
});

test("a concurrent-change refusal is retried unless an etag asked for it; persisting, it is transient", async () => {
  const { isTransient } = await import("./harness.mjs");
  const ctx = createContext({
    run: "1790000000",
    target: {
      kind: "production",
      token: "t",
      quotaProject: "fireemu-oracle-query",
      bucket: "fireemu-oracle-query-cfg-1790000000",
    },
  });
  const aborted = () =>
    new Response(
      JSON.stringify({
        error: {
          code: 409,
          status: "ABORTED",
          message: "There are concurrent database changes, please try again.",
        },
      }),
      { status: 409 },
    );
  let raced = 0;
  let stuck = 0;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const parsed = new URL(url);
    if (init?.method !== "DELETE") {
      // The listing is empty and every database of the program reads back absent.
      return parsed.pathname.endsWith("/databases")
        ? new Response(JSON.stringify({ databases: [] }), { status: 200 })
        : new Response("{}", { status: 404 });
    }
    if (parsed.searchParams.has("etag")) return aborted();
    if (parsed.pathname.endsWith("a")) {
      raced += 1;
      return raced === 1 ? aborted() : new Response("{}", { status: 200 });
    }
    // b stays contended for the step's three attempts; cleanup then finds it gone.
    stuck += 1;
    return stuck <= 3 ? aborted() : new Response("{}", { status: 404 });
  };
  const deleting = {
    ...program,
    databases: ["a", "b"],
    steps: [
      { id: "raced", method: "DELETE", path: "v1/{project}/databases/{db:a}" },
      { id: "stale", method: "DELETE", path: "v1/{project}/databases/{db:a}", query: { etag: "e30=" } },
      { id: "stuck", method: "DELETE", path: "v1/{project}/databases/{db:b}" },
    ],
  };
  try {
    const out = await runCorpus([deleting], ctx, {
      bucket: false,
      pollScale: 0,
      rateLimitDelayMs: 0,
      concurrentChangeDelayMs: 0,
      concurrentChangeRetries: 2,
    });
    const steps = out.results[deleting.id].steps;
    assert.equal(steps.raced.status, 200, "a race is retried until the delete goes through");
    assert.equal(steps.stale.status, 409, "a stale etag is behavior");
    assert.ok(!isTransient(steps.stale));
    assert.equal(steps.stuck.status, 409);
    assert.ok(isTransient(steps.stuck), "a race that never clears is not an observation");
  } finally {
    globalThis.fetch = original;
  }
});
