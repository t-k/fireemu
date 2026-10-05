import assert from "node:assert/strict";
import test from "node:test";
import { paging } from "./pubsub-production/cases/lifecycle.mjs";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { plannedRequests, runCases } from "./pubsub-production/runner.mjs";

test("paging reaches all four previously truncated requests and recreates once with 90s on both transports", async () => {
  assert.equal(paging.requests, 28);
  assert.equal(plannedRequests([paging]), 56);
  const ownership = createOwnership({ project: "demo-project", runId: "0123456789ab" });
  const capture = createCapture({ journal: { write() {} } });
  const calls = { rest: [], grpc: [] };
  const transports = Object.fromEntries(
    ["rest", "grpc"].map((name) => {
      const send = async (call) => {
        calls[name].push(call);
        capture.record({ case: call.label.case, op: call.op });
        const body = call.op.startsWith("list") ? { nextPageToken: "cursor" } : {};
        return name === "rest"
          ? { status: 200, body, unknown: false }
          : { code: "OK", body, unknown: false };
      };
      return [name, name === "rest" ? { name, request: send } : { name, call: send }];
    }),
  );
  const cleanupRest = createClient({
    ownership,
    pushState: newPushState(),
    caseId: "cleanup",
    transport: { name: "rest", request: async () => ({ status: 200, body: {}, unknown: false }) },
  });
  const summary = await runCases({
    cases: [paging],
    transports,
    cleanupRest,
    ownership,
    pushState: newPushState(),
    capture,
    options: {},
    sleep: async () => {},
  });
  assert.deepEqual(
    summary.cases.map((c) => [c.outcome, c.requests]),
    [
      ["completed", 27],
      ["completed", 27],
    ],
  );
  for (const name of ["rest", "grpc"]) {
    const tail = calls[name].slice(-6);
    assert.deepEqual(
      tail.map((c) => c.op),
      [
        "listSnapshots",
        "listTopicSnapshots",
        "listTopicSubscriptions",
        "listTopicSnapshots",
        "deleteTopic",
        "createTopic",
      ],
    );
    assert.equal(
      tail[0].request?.pageToken ??
        new URL(`http://x${tail[0].path}`).searchParams.get("pageToken"),
      "garbage",
    );
    assert.equal(tail.at(-1).timeoutMs, 90_000);
    assert.equal(calls[name].filter((c) => c.op === "createTopic").length, 2);
    assert.equal(
      calls[name].filter((c) => c.op === "deleteSubscription").length,
      0,
      "all three subscriptions remain attached when the topic is deleted",
    );
  }
});

test("the paging meter refuses the 29th request before either transport dispatches it", async () => {
  const ownership = createOwnership({ project: "demo-project", runId: "0123456789ab" });
  const capture = createCapture({ journal: { write() {} } });
  let sends = 0;
  const transport = {
    name: "rest",
    request: async (call) => {
      sends += 1;
      capture.record({ case: call.label.case });
      return { status: 200, body: {}, unknown: false };
    },
  };
  const client = createClient({
    transport,
    ownership,
    pushState: newPushState(),
    caseId: "cleanup",
  });
  const item = {
    ...paging,
    run: async (ctx) => {
      for (let i = 0; i < 29; i += 1) await ctx.client.getTopic(ctx.name("topics", "meter"));
    },
  };
  const report = await runCases({
    cases: [item],
    transportNames: ["rest"],
    transports: { rest: transport },
    cleanupRest: client,
    ownership,
    pushState: newPushState(),
    capture,
    options: {},
    sleep: async () => {},
  });
  assert.equal(report.cases[0].requests, 28);
  assert.equal(report.cases[0].outcome, "limit");
  assert.equal(sends, 31, "28 case requests and three cleanup list calls");
});
