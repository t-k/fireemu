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
