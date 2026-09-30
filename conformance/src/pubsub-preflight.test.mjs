import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";

const moduleUrl = new URL("../pubsub-production/preflight.mjs", import.meta.url);
async function load() {
  assert.ok(existsSync(moduleUrl), "bounded read-only preflight collector is missing");
  return import(moduleUrl.href);
}

test("preflight has exactly thirteen sandbox GETs and no publish or writes", async () => {
  const { preflightRequests } = await load();
  const requests = preflightRequests("123456789012");
  assert.equal(requests.length, 13);
  assert.equal(new Set(requests.map(({ id }) => id)).size, 13);
  assert.ok(requests.every(({ method, url }) => method === "GET" && url.startsWith("https://")));
  assert.ok(
    requests.some(({ url }) => url.endsWith("/services/eventarcpublishing.googleapis.com")),
  );
  assert.ok(
    requests.every(({ url }) => /projects\/(fireemu-oracle-idp|123456789012)\//.test(`${url}/`)),
  );
  assert.ok(
    requests.every(
      ({ url }) =>
        !/publish|:enable|:disable|iamPolicy/.test(url.replace("eventarcpublishing", "service")),
    ),
  );
  assert.throws(() => preflightRequests("unexpected/project"), /project number/);
});

test("unrecorded API bodies are captured without inventing success predicates", async () => {
  const { collectPreflight } = await load();
  const sent = [],
    saved = [];
  await collectPreflight({
    projectNumber: "123456789012",
    accessToken: "test-only-token",
    send: async (request) => {
      sent.push(request);
      return new Response(JSON.stringify({ unexpected: { value: "record-only" } }), {
        status: 403,
      });
    },
    save: async (row) => saved.push(row),
  });
  assert.equal(sent.length, 13);
  assert.equal(saved.length, 13);
  assert.ok(
    saved.every(
      ({ status, body }) => status === 403 && JSON.parse(body).unexpected.value === "record-only",
    ),
  );
  assert.ok(!JSON.stringify(saved).includes("test-only-token"));
  assert.ok(
    sent.every(
      ({ redirect, headers }) =>
        redirect === "manual" && headers["x-goog-user-project"] === "fireemu-oracle-idp",
    ),
  );
});

test("preflight stops on transport uncertainty without retry or later requests", async () => {
  const { collectPreflight } = await load();
  let calls = 0;
  const rows = [];
  await assert.rejects(
    collectPreflight({
      projectNumber: "123456789012",
      accessToken: "test-only-token",
      send: async () => {
        calls++;
        if (calls === 2) throw new Error("connection lost");
        return new Response("{}");
      },
      save: async (row) => rows.push(row),
    }),
    /connection lost/,
  );
  assert.equal(calls, 2);
  assert.equal(rows.length, 1);
});

test("preflight stops after a persistence failure and rejects response overflow", async () => {
  const { collectPreflight } = await load();
  let calls = 0;
  await assert.rejects(
    collectPreflight({
      projectNumber: "123456789012",
      accessToken: "test-only-token",
      send: async () => {
        calls++;
        return new Response("{}");
      },
      save: async () => {
        throw new Error("disk full");
      },
    }),
    /disk full/,
  );
  assert.equal(calls, 1);
  await assert.rejects(
    collectPreflight({
      projectNumber: "123456789012",
      accessToken: "test-only-token",
      send: async () => new Response("x".repeat(1024 * 1024 + 1)),
      save: async () => {
        assert.fail("oversized response is not a complete blob");
      },
    }),
    /response byte limit/,
  );
});

test("redirect is never followed and wall-clock limit prevents further sends", async () => {
  const { collectPreflight } = await load();
  await assert.rejects(
    collectPreflight({
      projectNumber: "123456789012",
      accessToken: "test-only-token",
      send: async () =>
        new Response("redirect", { status: 302, headers: { location: "https://other.invalid" } }),
      save: async () => {},
    }),
    /redirect/,
  );
  let ticks = 0,
    calls = 0;
  await assert.rejects(
    collectPreflight({
      projectNumber: "123456789012",
      accessToken: "test-only-token",
      clock: () => (ticks++ === 0 ? 0 : 600001),
      send: async () => {
        calls++;
        return new Response("{}");
      },
      save: async () => {},
    }),
    /elapsed-time limit/,
  );
  assert.equal(calls, 0);
});
