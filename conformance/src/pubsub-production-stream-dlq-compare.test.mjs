import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tempDir } from "./test-tmpdir.mjs";

import * as core from "./pubsub-production/stream-dlq-compare-core.mjs";
import * as cli from "./pubsub-production/stream-dlq-compare.mjs";
import { protos } from "@google-cloud/pubsub";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const exchange = (body, extra = {}) => ({
  n: 1,
  transport: "rest",
  op: "pull",
  response: { status: 200, body, bodyBytes: 12 },
  ...extra,
});

test("comparison preserves exact gRPC status across all generated status pairs", () => {
  assert.equal(typeof core.judgeRow, "function");
  for (let source = 0; source < 17; source += 1)
    for (let local = 0; local < 17; local += 1) {
      const expected = exchange(undefined, { transport: "grpc", response: { code: source } });
      const actual = { response: { code: local } };
      const verdict = core.judgeRow(expected, actual).verdict;
      if (
        [1, 2, 4, 10, 12, 13, 14, 15].includes(source) ||
        [1, 2, 4, 10, 12, 13, 14, 15].includes(local)
      )
        assert.equal(verdict, "NOT_COMPARABLE");
      else assert.equal(verdict, source === local ? "MATCH" : "DIVERGES");
    }
});

test("body masks preserve user maps, timestamp precision and identifier width", () => {
  assert.equal(typeof core.judgeRow, "function");
  const body = {
    receivedMessages: [
      {
        ackId: "abcDEF_123",
        message: {
          messageId: "12345",
          publishTime: "2026-10-05T00:00:00.123Z",
          data: "dGVzdA==",
          attributes: { messageId: "12345", publishTime: "literal" },
        },
      },
    ],
  };
  const changed = structuredClone(body);
  changed.receivedMessages[0].message.messageId = "98765";
  changed.receivedMessages[0].ackId = "xyzABC_456";
  assert.equal(core.judgeRow(exchange(body), exchange(changed)).verdict, "MATCH");
  for (const mutate of [
    (b) => (b.receivedMessages[0].message.attributes.messageId = "98765"),
    (b) => (b.receivedMessages[0].message.publishTime += "x"),
    (b) => (b.receivedMessages[0].message.messageId += "1"),
    (b) => (b.receivedMessages[0].ackId += "!"),
  ]) {
    const near = structuredClone(changed);
    mutate(near);
    assert.equal(core.judgeRow(exchange(body), exchange(near)).verdict, "DIVERGES");
  }
  assert.notDeepEqual(core.normalizeBody({ ackId: "abc=" }), core.normalizeBody({ ackId: "abcd" }));
  assert.notDeepEqual(core.normalizeBody({ ackId: "ab!d" }), core.normalizeBody({ ackId: "ab?d" }));
});

test("native details and timestamp wire precision are preserved in comparison", () => {
  assert.equal(
    core.judgeRow(
      exchange(undefined, {
        transport: "grpc",
        response: { code: "INVALID_ARGUMENT", message: "first" },
      }),
      { response: { code: "INVALID_ARGUMENT", message: "second" } },
    ).verdict,
    "DIVERGES",
  );
  assert.deepEqual(
    core.normalizeBody({ publishTime: { seconds: "1700000000", nanos: 123000000 } }),
    core.normalizeBody({ publishTime: { seconds: "1800000000", nanos: 456000000 } }),
  );
  assert.notDeepEqual(
    core.normalizeBody({ publishTime: { seconds: "1700000000", nanos: 123000000 } }),
    core.normalizeBody({ publishTime: { seconds: "1800000000", nanos: 456789000 } }),
  );
});

test("byte layout uses recorded wire length rather than reserialized body", () => {
  assert.equal(typeof core.judgeRow, "function");
  const expected = exchange({});
  assert.equal(
    core.judgeRow(expected, exchange({}, { response: { status: 200, body: {}, bodyBytes: 2 } }))
      .verdict,
    "DIVERGES",
  );
  assert.equal(
    core.judgeRow(expected, exchange({}, { response: { status: 200, body: {} } })).verdict,
    "NOT_COMPARABLE",
  );
  assert.equal(core.judgeRow(expected, exchange({})).layout, "length-match-only");
});

test("causal bindings refuse missing, conflicting and ambiguous identities against a reference model", () => {
  assert.equal(typeof core.createBindings, "function");
  for (let seed = 0; seed < 64; seed += 1) {
    const binding = core.createBindings();
    const reference = new Map();
    for (let step = 0; step < 12; step += 1) {
      const original = `id-${seed}-${step}`,
        local = `local-${seed}-${step}`;
      reference.set(original, local);
      binding.bind("message", original, local);
      assert.equal(binding.get("message", original), reference.get(original));
    }
    binding.bind("message", `id-${seed}-0`, "conflict");
    assert.throws(() => binding.get("message", `id-${seed}-0`), /binding/);
    assert.throws(() => binding.get("ack", "missing"), /binding/);
  }
  const binding = core.createBindings();
  binding.linkPublish(
    { messages: [{ data: "MQ==" }] },
    { messageIds: ["1"] },
    { messageIds: ["9"] },
  );
  binding.linkReceive(
    { receivedMessages: [{ ackId: "source-ack", message: { messageId: "1", data: "MQ==" } }] },
    { receivedMessages: [{ ackId: "local-ack", message: { messageId: "9", data: "MQ==" } }] },
  );
  assert.equal(binding.get("ack", "source-ack"), "local-ack");
  const fresh = core.createBindings();
  fresh.bind("message", "1", "9");
  assert.throws(
    () =>
      fresh.linkReceive(
        {
          receivedMessages: [
            { ackId: "fresh-source-ack", message: { messageId: "1", data: "MQ==" } },
          ],
        },
        {
          receivedMessages: [
            { ackId: "fresh-local-ack", message: { messageId: "8", data: "MQ==" } },
          ],
        },
      ),
    /binding/,
  );
  assert.throws(
    () => fresh.linkPublish({ messages: [] }, { messageIds: ["1"] }, { messageIds: ["9"] }),
    /binding/,
  );
  assert.deepEqual(
    binding.request({
      request: { body: { ackIds: ["source-ack"], attributes: { ackIds: "source-ack" } } },
    }),
    { body: { ackIds: ["local-ack"], attributes: { ackIds: "source-ack" } } },
  );
  assert.throws(
    () =>
      binding.linkPublish(
        { messages: [{ data: "MQ==" }] },
        { messageIds: ["1", "1"] },
        { messageIds: ["9", "9"] },
      ),
    /binding/,
  );
  assert.throws(
    () =>
      binding.linkReceive(
        {
          receivedMessages: [
            {
              ackId: "a",
              message: { messageId: "1", data: "MQ==", attributes: { key: "original" } },
            },
          ],
        },
        {
          receivedMessages: [
            { ackId: "b", message: { messageId: "9", data: "MQ==", attributes: { key: "wrong" } } },
          ],
        },
      ),
    /binding/,
  );
  assert.throws(
    () =>
      binding.linkReceive(
        { receivedMessages: [{ ackId: "a", message: { messageId: "unknown" } }] },
        { receivedMessages: [{ ackId: "b", message: { messageId: "9" } }] },
      ),
    /binding/,
  );
});

test("list judgments ignore item order but cursor binding requires the identical ordered page", () => {
  assert.equal(typeof core.createBindings, "function");
  const expected = { topics: [{ name: "a" }, { name: "b" }], nextPageToken: "abcdefgh" };
  const actual = { topics: [{ name: "b" }, { name: "a" }], nextPageToken: "ijklmnop" };
  assert.equal(core.judgeRow(exchange(expected), exchange(actual)).verdict, "MATCH");
  const binding = core.createBindings();
  assert.throws(() => binding.linkCursor(expected, actual), /ordered/);
  actual.topics.reverse();
  binding.linkCursor(expected, actual);
  assert.equal(binding.get("cursor", "abcdefgh"), "ijklmnop");
  const rewritten = binding.request({
    request: { method: "GET", path: "/v1/projects/demo-v2/topics?pageToken=abcdefgh&pageSize=1" },
  });
  assert.equal(
    new URL(rewritten.path, "http://127.0.0.1").searchParams.get("pageToken"),
    "ijklmnop",
  );
});

test("IAM recorded get/set routes remain structural needs-review without any local dispatch", async () => {
  assert.equal(typeof core.compareRecording, "function");
  const fixture = JSON.parse(
    readFileSync(new URL("./pubsub-production/fixtures/recorded-v2-iam.json", import.meta.url)),
  );
  let dispatched = 0;
  const capture = [
    { note: "run-start", suite: "stream-dlq-v2", project: "demo-v2", runId: "0123456789ab" },
    ...fixture.map((r, i) => ({
      ...r,
      transport: "rest",
      n: i + 1,
      case: "dlq-grant-window/rest",
    })),
  ];
  const report = await core.compareRecording(
    { capture, issued: [], iam: [] },
    {
      replay: async () => {
        dispatched += 1;
        throw new Error("IAM dispatch forbidden");
      },
    },
  );
  assert.equal(dispatched, 0);
  assert.equal(report.cases.length, 8);
  assert.ok(report.rows.every((r) => r.verdict === "NOT_COMPARABLE" && r.reason.includes("IAM")));
});

test("missing case boundaries and journal answers cannot produce an eight-case MATCH", async () => {
  assert.equal(typeof core.compareRecording, "function");
  const report = await core.compareRecording(
    { capture: [], issued: [], iam: [] },
    { replay: async () => exchange({}) },
  );
  assert.deepEqual(
    report.cases.map((r) => r.verdict),
    Array(8).fill("NOT_COMPARABLE"),
  );
});

test("closed input verification rejects tampering before parsing any capture", () => {
  assert.equal(typeof cli.readPinnedJsonl, "function");
  const path = join(tempDir("pubsub-compare-"), "capture.jsonl");
  const text = '{"note":"fixture"}\n';
  writeFileSync(path, text);
  const sha = createHash("sha256").update(text).digest("hex");
  assert.deepEqual(cli.readPinnedJsonl(path, sha), [{ note: "fixture" }]);
  writeFileSync(path, '{"note":"tampered"}\n');
  assert.throws(() => cli.readPinnedJsonl(path, sha), /digest/);
  assert.throws(() => cli.readPinnedJsonl(path, "bad"), /SHA256/);
});

test("runtime admission accepts only loopback endpoints and a strict release build pin", () => {
  assert.equal(typeof cli.validateRuntime, "function");
  const pin = {
    profile: "release",
    rustcWrapper: "",
    sha256: "a".repeat(64),
    head: "b".repeat(40),
    command: ["cargo", "build", "--release"],
    path: "/fixture/target/release/fireemu",
  };
  const env = {
    PUBSUB_EMULATOR_HOST: "127.0.0.1:12345",
    FIREEMU_CONTROL_URL: "http://127.0.0.1:12346/v1/",
    FIREEMU_CONTROL_TOKEN: "local-only",
  };
  assert.doesNotThrow(() => cli.validateRuntime(pin, env));
  for (const patch of [
    { profile: "debug" },
    { rustcWrapper: "sccache" },
    { sha256: "bad" },
    { command: ["cargo", "check"] },
    { command: ["cargo", "build"] },
  ])
    assert.throws(() => cli.validateRuntime({ ...pin, ...patch }, env), /release|pin|wrapper/);
  for (const patch of [
    { PUBSUB_EMULATOR_HOST: "pubsub.googleapis.com:443" },
    { FIREEMU_CONTROL_URL: "https://127.0.0.1/v1/" },
    { FIREEMU_CONTROL_URL: "http://user@127.0.0.1:12346/v1/" },
  ])
    assert.throws(() => cli.validateRuntime(pin, { ...env, ...patch }), /loopback/);
});

test("native receive guard binds an actual local ACK only to the published original identity", () => {
  assert.equal(typeof cli.guardReceived, "function");
  const bindings = core.createBindings();
  bindings.bind("message", "1", "9");
  const expected = {
    receivedMessages: [{ ackId: "original-ack", message: { messageId: "1", data: "MQ==" } }],
  };
  const actual = {
    receivedMessages: [{ ackId: "actual-local-ack", message: { messageId: "9", data: "MQ==" } }],
  };
  assert.doesNotThrow(() => cli.guardReceived(expected, actual, bindings));
  assert.equal(bindings.get("ack", "original-ack"), "actual-local-ack");
  for (const wrong of [
    { receivedMessages: [] },
    { receivedMessages: [...actual.receivedMessages, ...actual.receivedMessages] },
    { receivedMessages: [{ ackId: "invented", message: { messageId: "8", data: "MQ==" } }] },
  ])
    assert.throws(() => cli.guardReceived(expected, wrong, bindings), /binding|receive/);
});

function layoutInput() {
  const name = (kind) => `projects/demo-v2/${kind}/fe0123456789ab-rl-r-own`;
  const topic = name("topics"),
    subscription = name("subscriptions"),
    snapshot = name("snapshots");
  const id = "rest-layout-routes/rest",
    at = "2026-10-05T00:00:01.000Z";
  const requests = [
    ["createTopic", "PUT", `/v1/${topic}`, {}, { name: topic }],
    [
      "createSubscription",
      "PUT",
      `/v1/${subscription}`,
      { topic, retainAckedMessages: true },
      { name: subscription, topic },
    ],
    [
      "publish",
      "POST",
      `/v1/${topic}:publish`,
      { messages: [{ data: "MQ==" }] },
      { messageIds: ["1"] },
    ],
    ["createSnapshot", "PUT", `/v1/${snapshot}`, { subscription }, { name: snapshot, topic }],
    [
      "pull",
      "POST",
      `/v1/${subscription}:pull`,
      { maxMessages: 1, returnImmediately: false },
      { receivedMessages: [{ ackId: "source-ack", message: { messageId: "1", data: "MQ==" } }] },
    ],
    ["acknowledge", "POST", `/v1/${subscription}:acknowledge`, { ackIds: ["source-ack"] }, {}],
    ["seek", "POST", `/v1/${subscription}:seek`, { snapshot }, {}],
  ];
  const capture = [
    {
      note: "run-start",
      suite: "stream-dlq-v2",
      target: "fixture",
      project: "demo-v2",
      runId: "0123456789ab",
      at,
    },
    { note: "case-start", case: id, at },
  ];
  const issued = [];
  requests.forEach(([op, method, path, body, response], i) => {
    const label = { case: id, step: String(i + 1) };
    capture.push({ note: "request-dispatch", ...label, op, transport: "rest", at });
    capture.push({
      ...label,
      n: i + 1,
      op,
      transport: "rest",
      at,
      ms: 0,
      request: { method, path, body },
      response: { status: 200, body: response, bodyBytes: 12 },
    });
    if (op.startsWith("create")) {
      const entry = {
        name: path.slice(4),
        action: "create",
        transport: "rest",
        requestId: `${path}#1`,
        at,
      };
      issued.push({ ...entry, phase: "sent" }, { ...entry, phase: "answered", kind: "ok" });
    }
  });
  capture.push({ note: "case-end", case: id, outcome: "completed", at }, { note: "run-end", at });
  return { capture, issued, iam: [] };
}
const echoReplay = async (original, request) => {
  void request;
  return structuredClone(original);
};

test("complete layout trace is comparable while reordered boundaries and missing dispatch stay incomplete", async () => {
  const input = layoutInput();
  const baseline = await core.compareRecording(input, { replay: echoReplay });
  assert.equal(baseline.cases.find((r) => r.case === "rest-layout-routes").verdict, "MATCH");
  for (const alter of [
    (data) => (data.capture = data.capture.filter((r) => r.note !== "request-dispatch")),
    (data) => data.capture.unshift(data.capture.splice(-2, 1)[0]),
    (data) => (data.issued[1].kind = "unknown"),
    (data) => (data.issued[1].kind = "error"),
    (data) => {
      const extra = {
        ...data.issued[0],
        name: "projects/demo-v2/topics/fe0123456789ab-unrecorded",
        requestId: "unrecorded#1",
      };
      data.issued.push(extra, { ...extra, phase: "answered", kind: "ok" });
    },
    (data) => (data.issued[0].at = "2026-10-05T00:00:02.000Z"),
    (data) => (data.capture = data.capture.filter((r) => r.op !== "acknowledge")),
  ]) {
    const near = structuredClone(input);
    alter(near);
    const report = await core.compareRecording(near, { replay: echoReplay });
    assert.equal(
      report.cases.find((r) => r.case === "rest-layout-routes").verdict,
      "NOT_COMPARABLE",
    );
  }
});

test("native receiver allows empty frames before the causal followup and refuses a second identity", () => {
  assert.equal(typeof cli.createReceiveGuard, "function");
  const bindings = core.createBindings();
  bindings.bind("message", "1", "9");
  const expected = {
    receivedMessages: [{ ackId: "source-ack", message: { messageId: "1", data: "MQ==" } }],
  };
  const guard = cli.createReceiveGuard(
    [
      { direction: "in", body: {} },
      { direction: "in", body: expected },
    ],
    bindings,
  );
  assert.doesNotThrow(() => guard({}));
  assert.doesNotThrow(() =>
    guard({
      receivedMessages: [{ ackId: "actual-ack", message: { messageId: "9", data: "MQ==" } }],
    }),
  );
  assert.equal(bindings.get("ack", "source-ack"), "actual-ack");
  assert.throws(
    () =>
      guard({
        receivedMessages: [{ ackId: "actual-ack", message: { messageId: "9", data: "MQ==" } }],
      }),
    /second|binding/,
  );
});

test("public CLI refuses direct worker invocation before any input or daemon access", async () => {
  await assert.rejects(
    cli.main(
      [
        "--worker",
        "unused",
        "--capture",
        "unused",
        "--capture-sha256",
        "a".repeat(64),
        "--issued",
        "unused",
        "--issued-sha256",
        "a".repeat(64),
        "--iam",
        "unused",
        "--iam-sha256",
        "a".repeat(64),
        "--build-pin",
        "unused",
        "--out",
        "unused",
      ],
      {},
    ),
    /expected|inputs|internal/,
  );
});

test("native followup ACK masks preserve equality classes without literal source ACK reuse", () => {
  assert.deepEqual(
    core.normalizeBody({ modifyDeadlineAckIds: ["source-ack"], modifyDeadlineSeconds: [-1] }),
    core.normalizeBody({ modifyDeadlineAckIds: ["actual-ack"], modifyDeadlineSeconds: [-1] }),
  );
  assert.notDeepEqual(
    core.normalizeBody({ messageIds: ["111", "222"] }),
    core.normalizeBody({ messageIds: ["999", "999"] }),
  );
});

test("DLQ trace validates the nine source polls, thirty-six sink polls and final source in order", () => {
  const source = "/v1/projects/demo-v2/subscriptions/fe0123456789ab-dl-r-source";
  const sink = source.replace("-source", "-sink");
  const pull = (path) => ({
    op: "pull",
    request: { path: `${path}:pull`, body: { maxMessages: 1, returnImmediately: path === sink } },
    response: { status: 200, body: {} },
  });
  const requests = [
    "createTopic",
    "createTopic",
    "createSubscription",
    "createSubscription",
    "getSubscription",
    "publish",
  ].map((op) => ({ op }));
  requests.push(
    ...Array.from({ length: 9 }, () => pull(source)),
    ...Array.from({ length: 36 }, () => pull(sink)),
    pull(source),
  );
  assert.equal(core.completeTrace("dlq-no-grant", requests), true);
  [requests[6], requests[16]] = [requests[16], requests[6]];
  assert.equal(core.completeTrace("dlq-no-grant", requests), false);
});

test("native unknown terminal status cannot become a frame-layout divergence", async () => {
  const source = {
    n: 1,
    at: "2026-10-05T00:00:00Z",
    case: "stream-invalid-initial/grpc",
    step: "stream",
    op: "streamingPull",
    transport: "grpc",
    unknown: true,
    request: { rpc: "Subscriber/StreamingPull", frames: [{}] },
    response: { code: "DEADLINE_EXCEEDED", unknown: true },
  };
  const capture = [
    { note: "run-start", suite: "stream-dlq-v2", project: "demo-v2", runId: "0123456789ab" },
    {
      note: "request-dispatch",
      case: source.case,
      step: source.step,
      op: source.op,
      transport: source.transport,
    },
    {
      note: "stream-frame",
      case: source.case,
      step: source.step,
      direction: "out",
      body: {},
      bodyBytes: 0,
    },
    source,
  ];
  const report = await core.compareRecording(
    { capture, issued: [], iam: [] },
    { frameVerified: () => true, replay: async () => ({ response: { code: "OK" }, frames: [] }) },
  );
  assert.equal(report.rows[0].verdict, "NOT_COMPARABLE");
});

test("native raw initial request and causal followup must agree with their captured frames", () => {
  assert.equal(typeof cli.validateStreamFrames, "function");
  const body = {
    subscription: "projects/demo-v2/subscriptions/fe0123456789ab-stream-own",
    streamAckDeadlineSeconds: 10,
  };
  const Request = protos.google.pubsub.v1.StreamingPullRequest;
  const sha256 = createHash("sha256")
    .update(Request.encode(Request.fromObject(body)).finish())
    .digest("hex");
  const original = {
    request: { frames: [body], afterReceive: { modifyDeadlineSeconds: -1 } },
    response: { followUpSent: true },
  };
  const frames = [
    { direction: "out", frame: 1, sha256, body },
    {
      direction: "in",
      frame: 1,
      body: { receivedMessages: [{ ackId: "own-ack", message: { messageId: "1" } }] },
    },
    {
      direction: "out",
      frame: 2,
      causedByInboundFrame: 1,
      body: { modifyDeadlineAckIds: ["own-ack"], modifyDeadlineSeconds: [-1] },
    },
  ];
  assert.doesNotThrow(() => cli.validateStreamFrames(original, frames));
  for (const alter of [
    (data) => (data[0].sha256 = "a".repeat(64)),
    (data) => (data[2].body.modifyDeadlineAckIds = ["other-ack"]),
    (data) => (data[2].causedByInboundFrame = 2),
    (data) => (data[2].body.modifyDeadlineSeconds = [0]),
  ]) {
    const near = structuredClone(frames);
    alter(near);
    assert.throws(() => cli.validateStreamFrames(original, near), /native|causal/);
  }
});

test(
  "pinned release CLI replays all eight fixture cases through its own strict exec lifecycle",
  {
    skip:
      !process.env.FIREEMU_PUBSUB_COMPARE_BUILD_PIN || !process.env.FIREEMU_PUBSUB_COMPARE_FIXTURE,
  },
  () => {
    const fixture = process.env.FIREEMU_PUBSUB_COMPARE_FIXTURE;
    const pins = JSON.parse(readFileSync(join(fixture, "pins.json")));
    const args = [];
    for (const kind of ["capture", "issued", "iam"])
      args.push(`--${kind}`, join(fixture, `${kind}.jsonl`), `--${kind}-sha256`, pins[kind]);
    // The optional integration input must be explicitly synthetic, never an active production run.
    const input = cli.readPinnedJsonl(join(fixture, "capture.jsonl"), pins.capture);
    assert.equal(input.find((row) => row.note === "run-start")?.target, "fixture");
    const out = join(tempDir("pubsub-compare-release-"), "output");
    args.push("--build-pin", process.env.FIREEMU_PUBSUB_COMPARE_BUILD_PIN, "--out", out);
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./pubsub-production/stream-dlq-compare.mjs", import.meta.url)),
        ...args,
      ],
      { encoding: "utf8", timeout: 150000 },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const report = JSON.parse(readFileSync(join(out, "comparison.json")));
    assert.equal(report.cases.length, 8);
    assert.ok(report.cases.every((row) => row.comparedRows > 0));
    assert.equal(report.runtime.pinnedExecParent, true);
    assert.equal(report.sourceEvidence, "fixture");
    assert.equal(report.compatibilityPromotion, false);
    const native = report.rows.filter((row) => row.op === "streamingPull");
    assert.equal(native.length, 4);
    assert.ok(
      native.every(
        (row) => !/raw frame|native request|causal followup provenance/.test(row.reason),
      ),
    );
    assert.equal(report.iam.localRequests, 0);
    assert.ok(
      report.rows
        .filter((row) => row.op.endsWith("IamPolicy"))
        .every((row) => row.verdict === "NOT_COMPARABLE"),
    );
  },
);

test("unknown HTTP answers and omitted local responses remain not comparable", () => {
  assert.equal(core.judgeRow(exchange({ raw: "HTML" }), exchange({})).verdict, "NOT_COMPARABLE");
  for (const status of [199, 302, 499, 500, null])
    assert.equal(
      core.judgeRow(exchange({}, { response: { status, body: {}, bodyBytes: 12 } }), exchange({}))
        .verdict,
      "NOT_COMPARABLE",
    );
  for (const actual of [
    null,
    { notReplayed: true },
    exchange({}, { unknown: true }),
    exchange({}, { response: { status: 200, body: { raw: "HTML" }, bodyBytes: 12 } }),
  ])
    assert.equal(core.judgeRow(exchange({}), actual).verdict, "NOT_COMPARABLE");
  assert.equal(
    core.judgeRow(exchange({}, { unknown: true }), exchange({})).verdict,
    "NOT_COMPARABLE",
  );
  assert.equal(
    core.judgeRow(
      exchange({}),
      exchange({}, { response: { status: 404, body: {}, bodyBytes: 12 } }),
    ).verdict,
    "DIVERGES",
  );
});

test("case gaps retain precedence while journal and boundary debt remains visible", async () => {
  const input = layoutInput();
  const near = structuredClone(input);
  near.capture = near.capture.filter((row) => row.note !== "case-end");
  const report = await core.compareRecording(near, {
    replay: async (original) =>
      original.op === "seek"
        ? { response: { status: 404, body: {}, bodyBytes: 12 } }
        : echoReplay(original),
  });
  const layout = report.cases.find((row) => row.case === "rest-layout-routes");
  assert.equal(layout.verdict, "DIVERGES");
  assert.ok(layout.reasons.some((reason) => reason.includes("boundary")));
  for (const alter of [
    (data) => data.issued.splice(1, 1),
    (data) => (data.capture.find((row) => row.op === "seek" && row.response).n = 1),
    (data) => (data.capture = data.capture.filter((row) => row.note !== "case-end")),
  ]) {
    const changed = structuredClone(input);
    alter(changed);
    const result = await core.compareRecording(changed, { replay: echoReplay });
    assert.equal(
      result.cases.find((row) => row.case === "rest-layout-routes").verdict,
      "NOT_COMPARABLE",
    );
  }
});

test("raw frame verification rejects altered bytes and metadata before native replay", () => {
  const directory = tempDir("pubsub-compare-frames-");
  mkdirSync(join(directory, "capture.jsonl.frames"));
  const Type = protos.google.pubsub.v1.StreamingPullRequest;
  const bytes = Buffer.from(
    Type.encode(Type.fromObject({ streamAckDeadlineSeconds: 10 })).finish(),
  );
  const frame = {
    note: "stream-frame",
    direction: "out",
    blob: "capture.jsonl.frames/frame-000001.pb",
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bodyBytes: bytes.length,
    body: Type.toObject(Type.decode(bytes), { longs: String, enums: String, bytes: String }),
  };
  const path = join(directory, "capture.jsonl");
  writeFileSync(join(directory, frame.blob), bytes);
  assert.equal(cli.verifyFrames([frame], path).has(frame), true);
  const near = { ...frame, body: { streamAckDeadlineSeconds: 0 } };
  assert.equal(cli.verifyFrames([near], path).size, 0);
  writeFileSync(join(directory, frame.blob), Buffer.from([1, 2, 3]));
  assert.equal(cli.verifyFrames([frame], path).size, 0);
});

test("generated binding histories agree with a functional relation model including reverse conflicts", () => {
  for (let seed = 1; seed <= 64; seed += 1) {
    let random = seed;
    const bindings = core.createBindings(),
      accepted = [],
      invalid = new Set();
    for (let step = 0; step < 128; step += 1) {
      random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
      const source = `source-${random % 8}`,
        local = `local-${(random >>> 8) % 8}`;
      const prior = accepted.find((pair) => pair.source === source);
      const owner = accepted.find((pair) => pair.local === local);
      const conflict = (prior && prior.local !== local) || (owner && owner.source !== source);
      if (conflict) {
        invalid.add(source);
        if (owner) invalid.add(owner.source);
      } else if (!invalid.has(source) && !prior) accepted.push({ source, local });
      assert.equal(bindings.bind("message", source, local), !conflict && !invalid.has(source));
      for (let n = 0; n < 8; n += 1) {
        const name = `source-${n}`,
          pair = accepted.find((entry) => entry.source === name);
        if (invalid.has(name) || !pair)
          assert.throws(() => bindings.get("message", name), /binding/);
        else assert.equal(bindings.get("message", name), pair.local);
      }
    }
  }
});
