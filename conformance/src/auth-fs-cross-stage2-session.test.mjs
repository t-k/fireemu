import assert from "node:assert/strict";
import { test } from "node:test";

import { createContext } from "./fs-rules/harness.mjs";
import { createSession } from "./auth-fs-cross/stage2-session.mjs";

test("harness calls stop at their ceiling, and cleanup stops at its own", async () => {
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    sent.push([init?.method, new URL(url).pathname]);
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  const ctx = createContext({
    run: "1790000000000",
    target: {
      kind: "local",
      firestoreOrigin: "http://127.0.0.1:1",
      authOrigin: "http://127.0.0.1:2",
      grpcHost: "127.0.0.1",
      grpcPort: 1,
      control: { url: "http://127.0.0.1:3", token: "t" },
    },
  });
  const session = createSession(ctx, { maxHarnessRequests: 2, maxCleanupRequests: 3 });
  try {
    await session.wipe();
    await session.wipe();
    await assert.rejects(session.wipe(), /harness request ceiling 2 reached/);
    session.beginCleanup();
    for (let i = 0; i < 3; i += 1) await session.wipe();
    await assert.rejects(session.wipe(), /cleanup request ceiling 3 reached/);
    assert.equal(sent.length, 5);
    assert.deepEqual(session.counts(), {
      requests: 0,
      harnessRequests: 5,
      cleanupRequests: 3,
      foreignRequests: 0,
    });
  } finally {
    globalThis.fetch = realFetch;
    await session.close();
  }
});

test("a harness URL the destination check refuses is never sent", async () => {
  const sent = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    sent.push(url);
    return new Response("{}", { status: 200 });
  };
  const ctx = createContext({
    run: "1790000000000",
    target: {
      kind: "local",
      firestoreOrigin: "http://127.0.0.1:1",
      authOrigin: "http://127.0.0.1:2",
      grpcHost: "127.0.0.1",
      grpcPort: 1,
      control: { url: "http://127.0.0.1:3", token: "t" },
    },
  });
  const session = createSession(ctx, { destinationProblem: () => "undeclared host x" });
  try {
    await assert.rejects(session.wipe(), /undeclared host x; not sent/);
    assert.deepEqual(sent, []);
    assert.deepEqual(session.counts().harnessRequests, 0);
  } finally {
    globalThis.fetch = realFetch;
    await session.close();
  }
});
