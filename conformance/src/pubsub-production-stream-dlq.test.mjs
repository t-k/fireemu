import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { channel } from "node:diagnostics_channel";
import { createBudget, createCapture } from "./pubsub-production/capture.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { createRest } from "./pubsub-production/rest.mjs";
import * as record from "./pubsub-production/record.mjs";
import { plannedRequests, runCases, selectCases } from "./pubsub-production/runner.mjs";
import { createPhaseLimit } from "./pubsub-production/limits.mjs";
import * as streamDlq from "./pubsub-production/cases/stream-dlq.mjs";

const IDS = [
  "stream-push-open",
  "stream-invalid-ack",
  "stream-invalid-deadline",
  "stream-invalid-initial",
  "deleted-cursor",
  "dlq-no-grant",
  "dlq-grant-prerequisite",
];
const PROJECT = "demo-project";
const RUN = "0123456789ab";
const notes = (lines, kind) => lines.filter((line) => line.note === kind);

function world({
  source = [],
  sink = [],
  cursor = "opaque-cursor",
  badCursor = false,
  foreignCursor = false,
} = {}) {
  const live = new Map();
  const lines = [];
  const requests = [];
  const streams = [];
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const pushState = newPushState();
  const capture = createCapture({ journal: { write: (line) => lines.push(line) } });
  const rest = createRest({
    base: "http://127.0.0.1:1",
    budget: createBudget(200),
    capture,
    fetchImpl: async (url, options) => {
      const parsed = new URL(url);
      const path = parsed.pathname.slice(4);
      const body = options.body === undefined ? undefined : JSON.parse(options.body);
      requests.push({ method: options.method, path, query: parsed.search, body });
      let reply = {};
      let status = 200;
      if (options.method === "PUT") {
        if (path.includes("/subscriptions/")) assert.equal(typeof body.topic, "string");
        live.set(path, { name: path, ...body });
        reply = live.get(path);
      } else if (options.method === "DELETE") live.delete(path);
      else if (path.endsWith(":publish")) {
        assert.ok(body.messages[0].data);
        reply = { messageIds: ["published-id"] };
      } else if (path.endsWith(":pull")) {
        assert.equal(body.maxMessages, 1);
        const queue = path.includes("-sink") ? sink : source;
        reply = queue.shift() ?? {};
      } else if (path.endsWith(":modifyAckDeadline")) {
        assert.deepEqual(Object.keys(body).toSorted(), ["ackDeadlineSeconds", "ackIds"]);
        assert.equal(body.ackDeadlineSeconds, 0);
      } else if (path.endsWith(":acknowledge")) assert.ok(body.ackIds.length);
      else if (path.endsWith("/topics") && parsed.searchParams.get("pageSize") === "1") {
        reply = parsed.searchParams.has("pageToken")
          ? { topics: [] }
          : {
              topics: [
                {
                  name: foreignCursor
                    ? "projects/other-project/topics/foreign"
                    : [...live.keys()].find((name) => name.includes("/topics/")),
                },
              ],
              nextPageToken: badCursor ? 42 : cursor,
            };
      } else if (/\/(topics|subscriptions|snapshots)$/.test(path)) {
        const kind = path.split("/").at(-1);
        reply = { [kind]: [...live.values()].filter((item) => item.name.includes(`/${kind}/`)) };
      } else if (options.method === "GET") {
        reply = live.get(path);
        if (!reply) {
          status = 404;
          reply = { error: { status: "NOT_FOUND" } };
        }
      }
      const text = ` \n${JSON.stringify(reply)}\n `;
      return new Response(text, {
        status,
        headers: { "content-length": String(Buffer.byteLength(text)) },
      });
    },
  });
  const grpc = {
    name: "grpc",
    async call({ request, method, label, op, service }) {
      if (request.name !== undefined) live.set(request.name, request);
      const body = method === "Publish" ? { messageIds: ["stream-published"] } : request;
      capture.record({
        ...label,
        transport: "grpc",
        op,
        request: { rpc: `${service}/${method}`, body: request },
        response: { code: "OK", body },
      });
      return { code: "OK", body };
    },
    async stream(call) {
      streams.push(call);
      capture.record({
        ...call.label,
        transport: "grpc",
        op: "streamingPull",
        response: { code: "INVALID_ARGUMENT" },
      });
      return {
        code: "INVALID_ARGUMENT",
        unknown: false,
        inboundFrames: 0,
        outboundFrames: call.frames.length,
        followUpSent: call.afterReceive !== undefined,
      };
    },
  };
  const cleanupRest = createClient({
    transport: rest,
    ownership,
    ledger,
    pushState,
    caseId: "cleanup",
  });
  return {
    lines,
    requests,
    streams,
    ownership,
    ledger,
    capture,
    rest,
    grpc,
    pushState,
    cleanupRest,
  };
}
async function run(ids, fixture = world()) {
  const sleeps = [];
  const summary = await runCases({
    cases: selectCases(ids, "stream-dlq"),
    transportNames: ["rest", "grpc"],
    transports: { rest: fixture.rest, grpc: fixture.grpc },
    ...fixture,
    options: { production: true, suite: "stream-dlq" },
    sleep: async (ms) => sleeps.push(ms),
  });
  return { ...fixture, sleeps, summary };
}

test("stream-dlq is an opt-in suite with exact transport and request ceilings", () => {
  const cases = selectCases(undefined, "stream-dlq");
  assert.deepEqual(
    cases.map((item) => item.id),
    IDS,
  );
  assert.equal(plannedRequests(cases), 116);
  assert.equal(
    cases.reduce((sum, item) => sum + item.resources, 0),
    15,
  );
  assert.ok(selectCases().every((item) => !IDS.includes(item.id)));
  assert.throws(() => selectCases(["lifecycle"], "stream-dlq"), /unknown case/);
});

test("the real recorder prepare guard loads the suite and returns before any credential or wire path", async () => {
  let output = "";
  const io = {
    stdout: { write: (text) => (output += text) },
    stderr: { write: (text) => assert.fail(text) },
  };
  const code = await record.main(
    [
      "--target",
      "production",
      "--project",
      PROJECT,
      "--out",
      "unused",
      "--suite",
      "stream-dlq",
      "--max-requests",
      "116",
      "--prepare",
    ],
    {},
    io,
    { now: Date.now, noWire: true },
  );
  assert.equal(code, 0);
  const plan = JSON.parse(output);
  assert.deepEqual(
    plan.cases.map((item) => item.id),
    IDS,
  );
  assert.equal(plan.noWire, true);
  assert.equal(plan.requests, 116);
  assert.equal(plan.cleanupRequests, 600);
  assert.equal(plan.a2Requests, 600);
  assert.equal(plan.iamFiniteUpperBoundMs, null);
});

test("four native stream cases keep their exact invalid frames and never publish to push", async () => {
  const result = await run(IDS.slice(0, 4));
  assert.deepEqual(
    result.summary.cases.map((item) => item.transport),
    ["grpc", "grpc", "grpc", "grpc"],
  );
  assert.equal(result.streams.length, 4);
  assert.deepEqual(
    result.streams.map((call) => call.frames.length),
    [1, 2, 1, 1],
  );
  assert.ok(result.streams[0].frames[0].subscription.includes("stream"));
  assert.deepEqual(result.streams[1].frames[1], { ackIds: ["invalid-ack-for-stream-observation"] });
  assert.deepEqual(result.streams[2].afterReceive, { modifyDeadlineSeconds: -1 });
  assert.equal(result.streams[3].frames[0].streamAckDeadlineSeconds, 0);
  const publishes = result.requests.filter((request) => request.path.endsWith(":publish"));
  assert.equal(publishes.length, 1);
  assert.ok(publishes[0].path.includes("-sd-g-stream-topic"));
  assert.equal(
    typeof result.lines.find((entry) => entry.op === "publish" && entry.transport === "rest")
      .response.bodyBytes,
    "number",
  );
  assert.equal(
    result.lines.find(
      (entry) => entry.case === "stream-push-open/grpc" && entry.op === "createSubscription",
    ).request.body.pushConfig.pushEndpoint,
    "https://example.invalid/pubsub-never-published",
  );
  assert.equal(notes(result.lines, "stream-result").length, 4);
  assert.deepEqual(result.summary.cleanup.outstandingActions, []);
});

test("deleted cursor deletes the actual first-page owned topic and reuses only its opaque token", async () => {
  const result = await run(["deleted-cursor"]);
  const lists = result.requests.filter(
    (request) => new URLSearchParams(request.query).get("pageSize") === "1",
  );
  assert.equal(lists.length, 2);
  assert.equal(new URLSearchParams(lists[1].query).get("pageToken"), "opaque-cursor");
  const deletion = result.requests.find((request) => request.method === "DELETE");
  assert.equal(deletion.path, notes(result.lines, "deleted-cursor")[0].deletedName);
  assert.equal(result.summary.cases[0].requests, 6);
});

test("deleted cursor refuses malformed tokens and foreign first-page items before deletion", async () => {
  for (const config of [
    { badCursor: true },
    { foreignCursor: true },
    { cursor: "" },
    { cursor: "x".repeat(4097) },
  ]) {
    const result = await run(["deleted-cursor"], world(config));
    assert.equal(result.summary.cases[0].outcome, "aborted");
    assert.equal(
      result.requests.filter(
        (request) => new URLSearchParams(request.query).get("pageSize") === "1",
      ).length,
      1,
    );
    assert.equal(
      result.requests.some(
        (request) => request.method === "DELETE" && request.path.includes("foreign"),
      ),
      false,
    );
  }
});

test("DLQ B records actual source attempts, every sink poll, and forwarded payload identity", async () => {
  const payload = Buffer.from("actual-forwarded-payload").toString("base64");
  const result = await run(
    ["dlq-no-grant"],
    world({
      source: [
        {
          receivedMessages: [
            { ackId: "a1", deliveryAttempt: 9, message: { messageId: "source-id", data: payload } },
          ],
        },
        {
          receivedMessages: [
            { ackId: "a2", deliveryAttempt: 2, message: { messageId: "source-id", data: payload } },
          ],
        },
      ],
      sink: [
        {},
        {},
        {
          receivedMessages: [
            {
              ackId: "sink-ack",
              message: {
                messageId: "forwarded-id",
                data: payload,
                attributes: { source: "source-id" },
              },
            },
          ],
        },
      ],
    }),
  );
  assert.equal(
    result.requests.some((request) => request.path.includes("IamPolicy")),
    false,
  );
  assert.deepEqual(
    notes(result.lines, "dlq-source-poll")
      .slice(0, 2)
      .map((entry) => entry.messages[0].deliveryAttempt),
    [9, 2],
  );
  assert.equal(notes(result.lines, "dlq-sink-poll").length, 36);
  assert.equal(notes(result.lines, "dlq-source-poll").length, 9);
  assert.equal(notes(result.lines, "dlq-forwarded")[0].messageId, "forwarded-id");
  assert.equal(
    notes(result.lines, "dlq-forwarded")[0].dataBytes,
    Buffer.from(payload, "base64").length,
  );
  assert.equal(notes(result.lines, "dlq-forwarded")[0].dataSha256.length, 64);
  assert.equal(result.sleeps.filter((ms) => ms === 5000).length, 35);
  for (const line of result.lines.filter(
    (entry) => entry.transport === "rest" && entry.response !== undefined,
  )) {
    assert.equal(typeof line.response.bodyBytes, "number");
    assert.equal(Number(line.response.contentLength), line.response.bodyBytes);
  }
});

test("DLQ A stops before resources, IAM grants or publish because no finite propagation bound exists", async () => {
  const result = await run(["dlq-grant-prerequisite"]);
  assert.equal(result.summary.cases[0].requests, 0);
  assert.equal(result.summary.cases[0].outcome, "stopped");
  assert.match(result.summary.stopped, /finite.*IAM.*upper bound/);
  assert.equal(
    result.requests.some((request) => request.method !== "GET"),
    false,
  );
  assert.equal(result.ownership.issued().length, 0);
});

test("phase time bounds reject non-finite or non-positive limits", () => {
  for (const value of [0, -1, NaN, Infinity, undefined, 1.5])
    assert.throws(() => createPhaseLimit(value), /positive integer/);
});

test("phase deadlines follow a monotonic reference model and include sleeps", async () => {
  for (const origin of [0, 7200000, 2147483647]) {
    let now = origin;
    const phase = createPhaseLimit(100, () => now);
    const calls = [];
    const wrapped = phase.transport({ request: async (call) => calls.push(call) });
    for (let delta = 0; delta < 100; delta += 7) {
      now = origin + delta;
      await wrapped.request({ timeoutMs: 80 });
      assert.equal(calls.at(-1).timeoutMs, Math.min(80, 100 - delta));
    }
    now = origin + 100;
    assert.throws(() => wrapped.request({}), /time budget/);
    await assert.rejects(
      phase.sleep(async () => assert.fail("expired sleep was called"))(1),
      /time budget/,
    );
  }
});

test("prepare refuses missing required transports and invalid project identity without wire", async () => {
  const base = [
    "--target",
    "production",
    "--project",
    PROJECT,
    "--out",
    "unused",
    "--suite",
    "stream-dlq",
    "--max-requests",
    "116",
    "--prepare",
  ];
  for (const args of [
    [...base, "--transports", "rest"],
    [...base, "--project", "invalid".repeat(10)],
    [...base, "--iam-propagation-ms", "420000"],
  ]) {
    let error = "";
    assert.equal(
      await record.main(
        args,
        {},
        {
          stdout: { write: () => assert.fail("unusable plan accepted") },
          stderr: { write: (text) => (error += text) },
        },
        { now: Date.now, noWire: true },
      ),
      2,
    );
    assert.match(error, /transport|project|unknown option/);
  }
});

test("native context refuses foreign frames and resource ceilings before dispatch", async () => {
  const fixture = world();
  const subscription = fixture.ownership.resource("subscriptions", "own");
  const item = {
    id: "guards",
    short: "gg",
    requests: 1,
    resources: 1,
    transports: ["grpc"],
    async run(ctx) {
      assert.throws(
        () => ctx.stream(subscription, [{ subscription: "projects/foreign/subscriptions/s" }], 10),
        /foreign subscription/,
      );
      ctx.name("topics", "a");
      assert.throws(() => ctx.name("topics", "b"), /limit/);
    },
  };
  const summary = await runCases({
    cases: [item],
    transportNames: ["grpc"],
    transports: { rest: fixture.rest, grpc: fixture.grpc },
    ...fixture,
    options: {},
    sleep: async () => {},
  });
  assert.equal(summary.cases[0].outcome, "completed");
  assert.equal(fixture.streams.length, 0);
});

test("message identity compares exact data bytes and preserves all source metadata without interpreting wrappers", () => {
  const { observedMessageIdentity } = streamDlq;
  assert.equal(typeof observedMessageIdentity, "function");
  for (const bytes of [
    Buffer.alloc(0),
    Buffer.from("λ\n"),
    Buffer.from([0, 255, 128]),
    Buffer.alloc(300, "z"),
  ]) {
    const expected = {
      data: bytes.toString("base64"),
      attributes: { recorderRun: RUN },
      sourceSubscription: "projects/demo-project/subscriptions/source",
    };
    const identity = observedMessageIdentity(
      {
        message: {
          data: expected.data,
          attributes: { source: expected.sourceSubscription, extra: "untouched" },
        },
        deliveryAttempt: 3,
      },
      expected,
    );
    assert.equal(identity.dataBytes, bytes.length);
    assert.equal(identity.dataSha256, createHash("sha256").update(bytes).digest("hex"));
    assert.equal(identity.outerDataMatchesPublished, true);
    assert.equal(identity.dataBase64, expected.data);
    assert.deepEqual(identity.sourceSubscriptionExactAttributeKeys, ["source"]);
    assert.deepEqual(identity.attributes, {
      source: expected.sourceSubscription,
      extra: "untouched",
    });
    assert.equal(identity.wrapperInterpretation, "needs-review");
    assert.equal(identity.publishedAttributesEqualOuter, false);
    const matched = observedMessageIdentity(
      { message: { data: expected.data, attributes: expected.attributes } },
      expected,
    );
    assert.equal(matched.publishedAttributesEqualOuter, true);
    const miss = observedMessageIdentity(
      {
        message: {
          data: Buffer.concat([bytes, Buffer.from("x")]).toString("base64"),
          attributes: { source: expected.sourceSubscription + "x" },
        },
      },
      expected,
    );
    assert.equal(miss.outerDataMatchesPublished, false);
    assert.deepEqual(miss.sourceSubscriptionExactAttributeKeys, []);
  }
});

test("native case meter counts each stream once and refuses a second dispatch over its ceiling", async () => {
  const fixture = world();
  const item = {
    id: "stream-meter",
    short: "sm",
    requests: 1,
    resources: 1,
    transports: ["grpc"],
    async run(ctx) {
      const subscription = ctx.name("subscriptions", "owned");
      await ctx.stream(subscription, [{ subscription }], 10);
      await ctx.stream(subscription, [{ subscription }], 10);
    },
  };
  const summary = await runCases({
    cases: [item],
    transportNames: ["grpc"],
    transports: { rest: fixture.rest, grpc: fixture.grpc },
    ...fixture,
    options: {},
    sleep: async () => {},
  });
  assert.equal(summary.cases[0].outcome, "limit");
  assert.equal(fixture.streams.length, 1);
});

test("native case phase refuses a dispatch after its monotonic deadline", async () => {
  const fixture = world();
  let now = 0;
  const item = {
    id: "stream-time",
    short: "st",
    requests: 2,
    resources: 1,
    timeoutMs: 10,
    transports: ["grpc"],
    async run(ctx) {
      const subscription = ctx.name("subscriptions", "owned");
      await ctx.stream(subscription, [{ subscription }], 10);
      now = 10;
      await ctx.stream(subscription, [{ subscription }], 10);
    },
  };
  const summary = await runCases({
    cases: [item],
    transportNames: ["grpc"],
    transports: { rest: fixture.rest, grpc: fixture.grpc },
    ...fixture,
    options: { monotonicNow: () => now },
    sleep: async () => {},
  });
  assert.equal(summary.cases[0].outcome, "budget");
  assert.equal(fixture.streams.length, 1);
});

test("independent no-wire test guard refuses the actual recorder path before constructing transports", async () => {
  const out = mkdtempSync(join(tmpdir(), "stream-no-wire-"));
  let connections = 0;
  const connection = channel("undici:client:beforeConnect");
  const observe = () => {
    connections += 1;
  };
  connection.subscribe(observe);
  try {
    await assert.rejects(
      record.main(
        [
          "--target",
          "emulator",
          "--emulator-host",
          "127.0.0.1:1",
          "--out",
          out,
          "--suite",
          "stream-dlq",
          "--only",
          "dlq-grant-prerequisite",
          "--transports",
          "rest",
        ],
        {},
        { stdout: { write() {} }, stderr: { write() {} } },
        { now: Date.now, noWire: true },
      ),
      /no-wire test guard/,
    );
  } finally {
    connection.unsubscribe(observe);
    console.log(JSON.stringify({ noWireConnectionAttempts: connections, target: "127.0.0.1:1" }));
    assert.equal(connections, 0);
    rmSync(out, { recursive: true });
  }
});
