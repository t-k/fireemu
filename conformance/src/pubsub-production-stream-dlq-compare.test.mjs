import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tempDir } from "./test-tmpdir.mjs";

import * as core from "./pubsub-production/stream-dlq-compare-core.mjs";
import * as cli from "./pubsub-production/stream-dlq-compare.mjs";
import { protos } from "@google-cloud/pubsub";
import { spawnSync, spawn, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const exchange = (body, extra = {}) => ({
  n: 1,
  transport: "rest",
  op: "pull",
  response: { status: 200, body, bodyBytes: 12 },
  ...extra,
});

function readRuntimeStart(path) {
  try {
    const receipt = JSON.parse(readFileSync(path));
    if (
      !receipt ||
      !Number.isSafeInteger(receipt.serverPid) ||
      receipt.serverPid <= 0 ||
      !Number.isSafeInteger(receipt.workerPid) ||
      receipt.workerPid <= 0 ||
      receipt.serverPid === receipt.workerPid ||
      typeof receipt.strictConfigSha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(receipt.strictConfigSha256)
    )
      return undefined;
    return receipt;
  } catch (error) {
    // The other process can create the receipt before writing its complete JSON.
    if (error.code === "ENOENT" || error instanceof SyntaxError) return undefined;
    throw error;
  }
}

test("worker readiness waits for complete receipt bytes and valid process identities", () => {
  const dir = tempDir("pubsub-compare-receipt-");
  const path = join(dir, "runtime-start.json");
  const receipt = { serverPid: 123, workerPid: 456, strictConfigSha256: "a".repeat(64) };
  assert.equal(readRuntimeStart(path), undefined);
  const text = JSON.stringify(receipt);
  for (let length = 0; length < text.length; length += 1) {
    writeFileSync(path, text.slice(0, length));
    assert.equal(readRuntimeStart(path), undefined, `incomplete prefix ${length}`);
  }
  writeFileSync(path, text);
  assert.deepEqual(readRuntimeStart(path), receipt);
  for (const malformed of [
    {},
    null,
    [],
    { ...receipt, serverPid: 0 },
    { ...receipt, serverPid: 1.5 },
    { ...receipt, serverPid: Number.MAX_SAFE_INTEGER + 1 },
    { ...receipt, workerPid: "456" },
    { ...receipt, workerPid: receipt.serverPid },
    { ...receipt, strictConfigSha256: "partial" },
    { ...receipt, strictConfigSha256: [receipt.strictConfigSha256] },
  ]) {
    writeFileSync(path, JSON.stringify(malformed));
    assert.equal(readRuntimeStart(path), undefined);
  }
  assert.throws(() => readRuntimeStart(dir), { code: "EISDIR" });
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

test("list judgments and cursor bindings preserve exact page membership independent of order", () => {
  assert.equal(typeof core.createBindings, "function");
  const expected = { topics: [{ name: "a" }, { name: "b" }], nextPageToken: "abcdefgh" };
  const actual = { topics: [{ name: "b" }, { name: "a" }], nextPageToken: "ijklmnop" };
  assert.equal(core.judgeRow(exchange(expected), exchange(actual)).verdict, "MATCH");
  const binding = core.createBindings();
  assert.doesNotThrow(() => binding.linkCursor(expected, actual));
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
    {
      note: "run-start",
      suite: "stream-dlq-v2",
      project: "demo-v2",
      runId: "0123456789ab",
      at: "2026-10-05T00:00:00Z",
    },
    ...fixture.map((r, i) => ({
      ...r,
      transport: "rest",
      n: i + 1,
      case: "dlq-grant-window/rest",
      at: "2026-10-05T00:00:00Z",
      ms: 0,
    })),
    { note: "run-end", at: "2026-10-05T00:00:00Z" },
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

test("closed run boundaries and valid chronology gate replay and MATCH", async () => {
  for (const alter of [
    (data) => data.capture.unshift(data.capture.pop()),
    (data) => data.capture.splice(-2, 0, data.capture.pop()),
    (data) => data.capture.splice(-1, 0, data.capture.shift()),
    (data) =>
      (data.capture.find((r) => r.note === "request-dispatch").at = "2026-10-06T00:00:01.000Z"),
    (data) =>
      (data.capture.find((r) => r.op === "seek" && r.response).at = "2020-01-01T00:00:00.000Z"),
    (data) => (data.capture.find((r) => r.op === "seek" && r.response).ms = -1000),
    (data) => (data.capture.find((r) => r.op === "seek" && r.response).ms = Infinity),
    (data) => (data.capture.find((r) => r.op === "seek" && r.response).ms = 1000),
    (data) => {
      data.capture[0].at = data.capture[1].at = "2026-10-05T00:00:00.000Z";
      data.capture.find((r) => r.op === "seek" && r.response).ms = 500;
    },
    (data) => (data.capture.find((r) => r.op === "seek" && r.response).at = "invalid"),
  ]) {
    const input = layoutInput();
    alter(input);
    let replayed = 0;
    const report = await core.compareRecording(input, {
      replay: async (row) => {
        replayed++;
        return row;
      },
    });
    assert.equal(
      report.cases.find((r) => r.case === "rest-layout-routes").verdict,
      "NOT_COMPARABLE",
    );
    assert.equal(replayed, 0, "invalid provenance must be refused before local dispatch");
  }
});

test("measured request duration must fit inside its case without inventing a dispatch tolerance", async () => {
  for (const boundarySuffix of ["/rest", ""])
    for (const [dispatchSeconds, endSeconds, ms] of [
      [10, 11, 5000],
      [100, 101, 100000],
    ]) {
      const input = layoutInput();
      const at = (seconds) => new Date(Date.UTC(2026, 9, 5) + seconds * 1000).toISOString();
      input.capture.forEach((row) => {
        row.at = at(endSeconds);
      });
      input.capture[0].at = at(0);
      input.capture[1].at = at(10);
      input.capture[1].case = `rest-layout-routes${boundarySuffix}`;
      input.capture.at(-2).case = input.capture[1].case;
      input.capture[2].at = at(dispatchSeconds);
      input.capture[3].ms = ms;
      input.issued.forEach((row) => {
        row.at = at(endSeconds);
      });
      input.issued[0].at = at(dispatchSeconds);
      const report = await core.compareRecording(input, { replay: echoReplay });
      assert.equal(
        report.cases.find((r) => r.case === "rest-layout-routes").verdict,
        "NOT_COMPARABLE",
      );
      assert.match(
        report.cases.find((r) => r.case === "rest-layout-routes").reasons.join(";"),
        /case.*time/,
      );
    }
});

test("a delayed request retains its measured duration and replays its dispatch instant", async () => {
  for (let seed = 0; seed < 64; seed++) {
    const start = Date.UTC(2026, 9, 5) + seed * 3_600_000;
    const duration = (seed * 37100) % 900_001;
    assert.equal(
      core.recordedRequestInstant({ at: new Date(start + duration).toISOString(), ms: duration }),
      start,
    );
  }
  for (const ms of [-1, Infinity, NaN, 0.5, undefined])
    assert.throws(
      () => core.recordedRequestInstant({ at: "2026-10-05T00:00:00Z", ms }),
      /invalid recorded/,
    );
  assert.throws(() => core.recordedRequestInstant({ at: "invalid", ms: 0 }), /invalid recorded/);
  const input = layoutInput();
  const dispatch = input.capture.find((r) => r.op === "seek" && r.note === "request-dispatch");
  const seek = input.capture.find((r) => r.op === "seek" && r.response);
  dispatch.at = "2026-10-05T00:00:02.001Z";
  seek.at = "2026-10-05T00:00:04.000Z";
  seek.ms = 2000;
  input.capture.slice(-2).forEach((r) => {
    r.at = seek.at;
  });
  assert.equal(core.recordedRequestInstant(seek), Date.parse("2026-10-05T00:00:02.000Z"));
  const report = await core.compareRecording(input, { replay: echoReplay });
  assert.equal(report.cases.find((r) => r.case === "rest-layout-routes").verdict, "MATCH");
});

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
    ms: 0,
    unknown: true,
    request: { rpc: "Subscriber/StreamingPull", frames: [{}] },
    response: { code: "DEADLINE_EXCEEDED", unknown: true },
  };
  const capture = [
    {
      note: "run-start",
      suite: "stream-dlq-v2",
      project: "demo-v2",
      runId: "0123456789ab",
      at: source.at,
    },
    {
      note: "request-dispatch",
      case: source.case,
      step: source.step,
      op: source.op,
      transport: source.transport,
      at: source.at,
    },
    {
      note: "stream-frame",
      case: source.case,
      step: source.step,
      direction: "out",
      body: {},
      bodyBytes: 0,
      at: source.at,
    },
    source,
    { note: "run-end", at: source.at },
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
    assert.equal(report.clock.basis, "recorded request-dispatch at");
    for (const actual of report.clock.requests.filter((row) => row.n !== null)) {
      const source = input.find((row) => row.n === actual.n);
      const dispatch = input.find(
        (row) =>
          row.note === "request-dispatch" &&
          row.case === source.case &&
          row.step === source.step &&
          row.op === source.op &&
          row.transport === source.transport,
      );
      assert.equal(actual.instant, dispatch.at);
    }
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

test(
  "interrupting the comparison launcher stops its pinned exec and worker",
  {
    skip:
      !process.env.FIREEMU_PUBSUB_COMPARE_BUILD_PIN || !process.env.FIREEMU_PUBSUB_COMPARE_FIXTURE,
  },
  async () => {
    const fixture = process.env.FIREEMU_PUBSUB_COMPARE_FIXTURE;
    const pins = JSON.parse(readFileSync(join(fixture, "pins.json")));
    const pin = JSON.parse(readFileSync(process.env.FIREEMU_PUBSUB_COMPARE_BUILD_PIN));
    const out = join(tempDir("pubsub-compare-interrupt-"), "output");
    const args = [];
    for (const kind of ["capture", "issued", "iam"])
      args.push(`--${kind}`, join(fixture, `${kind}.jsonl`), `--${kind}-sha256`, pins[kind]);
    args.push("--build-pin", process.env.FIREEMU_PUBSUB_COMPARE_BUILD_PIN, "--out", out);
    const child = spawn(
      process.execPath,
      [
        fileURLToPath(new URL("./pubsub-production/stream-dlq-compare.mjs", import.meta.url)),
        ...args,
      ],
      { stdio: "ignore" },
    );
    const exited = new Promise((resolveExit) => child.once("exit", (code) => resolveExit(code)));
    const delay = (ms) => new Promise((done) => setTimeout(done, ms));
    const alive = (pid) => {
      try {
        process.kill(pid, 0);
        return true;
      } catch (error) {
        if (error.code === "ESRCH") return false;
        throw error;
      }
    };
    const until = async (predicate, ms) => {
      const end = Date.now() + ms;
      while (!predicate() && Date.now() < end) await delay(10);
      return predicate();
    };
    let runtime;
    try {
      assert.ok(
        await until(() => {
          runtime = readRuntimeStart(join(out, "runtime-start.json"));
          return runtime !== undefined;
        }, 5000),
        "worker startup receipt required",
      );
      const identity = execFileSync(
        "ps",
        ["-ww", "-p", String(runtime.serverPid), "-o", "ppid=,comm=,args="],
        { encoding: "utf8" },
      );
      assert.ok(
        identity.trim().startsWith(String(child.pid)) &&
          identity.includes(`${pin.path} exec --config`),
      );
      assert.ok(alive(runtime.workerPid));
      child.kill("SIGTERM");
      assert.ok(
        await until(() => child.exitCode !== null || child.signalCode !== null, 5000),
        "launcher must settle after interruption",
      );
      assert.equal(
        await exited,
        143,
        "launcher must forward SIGTERM and retain the supervised child status",
      );
      assert.ok(
        await until(() => !alive(runtime.serverPid) && !alive(runtime.workerPid), 1500),
        "owned exec and worker must both stop",
      );
    } finally {
      if (alive(child.pid)) child.kill("SIGTERM");
      // A failing regression also cleans only the still-owned, identity-checked exec PID.
      if (runtime && alive(runtime.serverPid)) {
        const identity = execFileSync(
          "ps",
          ["-ww", "-p", String(runtime.serverPid), "-o", "comm=,args="],
          { encoding: "utf8" },
        );
        assert.ok(identity.includes(`${pin.path} exec --config`), "cleanup exec identity changed");
        process.kill(runtime.serverPid, "SIGTERM");
        assert.ok(await until(() => !alive(runtime.serverPid) && !alive(runtime.workerPid), 12000));
      }
      assert.ok(await until(() => !alive(child.pid), 12000));
    }
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

test("a contradictory issued answer also marks the individual exchange not comparable", async () => {
  const input = layoutInput();
  input.issued[1].kind = "error";
  const report = await core.compareRecording(input, { replay: echoReplay });
  assert.equal(report.rows[0].verdict, "NOT_COMPARABLE");
  assert.match(report.rows[0].reason, /contradictory/);
});

test("cleanup journal answers must agree with their captured exchange too", async () => {
  const input = layoutInput(),
    at = "2026-10-05T00:00:01.000Z";
  const name = "projects/demo-v2/topics/fe0123456789ab-rl-r-own";
  input.capture.splice(-1, 0, {
    n: 8,
    at,
    ms: 0,
    case: "cleanup",
    step: "01",
    op: "deleteTopic",
    transport: "rest",
    request: { method: "DELETE", path: `/v1/${name}` },
    response: { status: 200, body: {}, bodyBytes: 12 },
  });
  const entry = { at, name, action: "delete", transport: "rest", requestId: "cleanup#1" };
  input.issued.push({ ...entry, phase: "sent" }, { ...entry, phase: "answered", kind: "ok" });
  const baseline = await core.compareRecording(input, { replay: echoReplay });
  assert.equal(baseline.cases.find((row) => row.case === "rest-layout-routes").verdict, "MATCH");
  input.issued.at(-1).kind = "error";
  const report = await core.compareRecording(input, { replay: echoReplay });
  assert.equal(
    report.cases.find((row) => row.case === "rest-layout-routes").verdict,
    "NOT_COMPARABLE",
  );
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

const silenceProbe = () => {
  const first = {
    subscription: "projects/demo-v2/subscriptions/fe0123456789ab-sa-g-stream-sub",
    streamAckDeadlineSeconds: 10,
    maxOutstandingMessages: "1",
    maxOutstandingBytes: "1024",
  };
  const second = { ackIds: ["invalid-ack-for-stream-observation"] };
  const expected = {
    case: "stream-invalid-ack/grpc",
    op: "streamingPull",
    transport: "grpc",
    ms: 30002,
    request: { rpc: "Subscriber/StreamingPull", frames: [first, second] },
    response: {
      code: "DEADLINE_EXCEEDED",
      unknown: true,
      inboundFrames: 0,
      outboundFrames: 2,
      followUpSent: false,
    },
  };
  return {
    expected,
    frames: [first, second].map((body) => ({
      note: "stream-frame",
      direction: "out",
      body,
      verified: true,
    })),
    actual: {
      response: { code: "CANCELLED", unknown: true, inboundFrames: 0, outboundFrames: 2 },
      nativeObservation: {
        durationMs: 30000,
        inboundMessages: 0,
        outboundWrites: 2,
        terminalBeforeWindow: false,
        completedWindow: true,
        cancelledByObserver: true,
      },
    },
  };
};
test("recorded invalid ACK window has independent observation while its response stays unknown", () => {
  const { expected, actual, frames } = silenceProbe();
  const r = core.judgeRow(expected, actual, { frames, frameVerified: (f) => f.verified });
  assert.equal(r.verdict, "NOT_COMPARABLE");
  assert.equal(expected.response.unknown, true);
  assert.equal(r.observation?.criterion, "no-reply-during-30000ms");
  assert.equal(r.observation?.assessment, "PASS");
});
test("early native data or terminal status cannot pass the recorded silence window", () => {
  for (const change of [
    (o) => (o.durationMs = 29999),
    (o) => (o.inboundMessages = 1),
    (o) => (o.terminalBeforeWindow = true),
    (o) => (o.completedWindow = false),
    (o) => (o.outboundWrites = 1),
    (o) => (o.cancelledByObserver = false),
  ]) {
    const { expected, actual, frames } = silenceProbe();
    change(actual.nativeObservation);
    const r = core.judgeRow(expected, actual, { frames, frameVerified: (f) => f.verified });
    assert.equal(r.verdict, "NOT_COMPARABLE");
    assert.notEqual(r.observation?.assessment, "PASS");
    assert.ok(r.observation);
  }
});
test("silence observation does not accept other unknown ACK frames or missing raw provenance", () => {
  for (const change of [
    (p) => (p.expected.case = "stream-invalid-deadline/grpc"),
    (p) => p.expected.request.frames[1].ackIds.push("other"),
    (p) => (p.expected.request.frames[1].modifyDeadlineSeconds = [0]),
    (p) => (p.expected.response.code = "UNKNOWN"),
    (p) => (p.expected.ms = 29999),
    (p) => (p.frames[1].verified = false),
    (p) => p.frames.push({ direction: "in", body: {}, verified: true }),
  ]) {
    const p = silenceProbe();
    change(p);
    const r = core.judgeRow(p.expected, p.actual, {
      frames: p.frames,
      frameVerified: (f) => f.verified,
    });
    assert.equal(r.verdict, "NOT_COMPARABLE");
    assert.equal(r.observation, undefined);
  }
});

test("native silence observer waits a full monotonic window and cancels only its own RPC", () => {
  assert.equal(typeof cli.createNativeSilenceObserver, "function");
  for (const age of [0, 3600000]) {
    let time = age,
      cancelled = 0;
    const listeners = new Map(),
      pending = new Map();
    let sequence = 0;
    const rpc = {
      on: (event, fn) => {
        listeners.set(event, [...(listeners.get(event) ?? []), fn]);
        return rpc;
      },
      cancel: () => {
        cancelled += 1;
      },
      write: () => true,
    };
    const observer = cli.createNativeSilenceObserver(rpc, {
      now: () => time,
      schedule: (fn, delay) => {
        pending.set(++sequence, { fn, at: time + delay });
        return sequence;
      },
      clear: (id) => pending.delete(id),
    });
    rpc.write(Buffer.from([1]));
    rpc.write(Buffer.from([2]));
    time += 29999;
    assert.equal(cancelled, 0);
    assert.equal(observer.snapshot().completedWindow, false);
    time += 1;
    for (const [id, job] of pending)
      if (job.at <= time) {
        pending.delete(id);
        job.fn();
      }
    const o = observer.snapshot();
    assert.equal(o.completedWindow, true);
    assert.equal(o.durationMs, 30000);
    assert.equal(o.outboundWrites, 2);
    assert.equal(cancelled, 1);
    observer.close();
    assert.equal(pending.size, 0);
  }
});
test("native silence observer preserves early server events and clears pending timers", () => {
  assert.equal(typeof cli.createNativeSilenceObserver, "function");
  for (const event of ["data", "status", "error", "close"]) {
    let time = 0,
      cancelled = 0;
    const listeners = new Map(),
      pending = new Map();
    const rpc = {
      on: (e, fn) => {
        listeners.set(e, [...(listeners.get(e) ?? []), fn]);
        return rpc;
      },
      cancel: () => {
        cancelled += 1;
      },
      write: () => true,
    };
    const o = cli.createNativeSilenceObserver(rpc, {
      now: () => time,
      schedule: (fn, delay) => {
        pending.set(1, { fn, delay });
        return 1;
      },
      clear: (id) => pending.delete(id),
    });
    rpc.write(Buffer.from([1]));
    rpc.write(Buffer.from([2]));
    assert.equal(pending.size, 1, "the timer must be live before testing cleanup");
    time = 25;
    for (const fn of listeners.get(event) ?? []) fn({});
    assert.equal(o.snapshot().completedWindow, false);
    assert.equal(o.snapshot().inboundMessages, event === "data" ? 1 : 0);
    if (event !== "data") assert.equal(pending.size, 0);
    o.close();
    assert.equal(cancelled, 0);
    assert.equal(pending.size, 0);
  }
});

test("seeded silence-window decisions preserve the bounded reference model", () => {
  let seed = 0x20d10020;
  for (let i = 0; i < 512; i += 1) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const p = silenceProbe(),
      o = p.actual.nativeObservation;
    o.durationMs = 29000 + (seed % 2001);
    o.inboundMessages = (seed >>> 12) % 2;
    o.terminalBeforeWindow = Boolean((seed >>> 15) % 2);
    o.completedWindow = Boolean((seed >>> 18) % 2);
    o.cancelledByObserver = Boolean((seed >>> 21) % 2);
    o.outboundWrites = (seed >>> 24) % 4;
    const expected =
      o.durationMs >= 30000 &&
      o.inboundMessages === 0 &&
      !o.terminalBeforeWindow &&
      o.completedWindow &&
      o.cancelledByObserver &&
      o.outboundWrites === 2;
    const r = core.judgeRow(p.expected, p.actual, {
      frames: p.frames,
      frameVerified: (f) => f.verified,
    });
    assert.equal(r.verdict, "NOT_COMPARABLE");
    assert.equal(r.observation.assessment === "PASS", expected);
  }
});
test("early timer re-arms the remaining window at an aged monotonic origin", () => {
  let time = 7200000,
    cancelled = 0;
  const pending = new Map();
  let seq = 0;
  const rpc = {
    on: () => rpc,
    cancel: () => {
      cancelled += 1;
    },
    write: () => true,
  };
  const o = cli.createNativeSilenceObserver(rpc, {
    now: () => time,
    schedule: (fn, delay) => {
      pending.set(++seq, { fn, delay });
      return seq;
    },
    clear: (id) => pending.delete(id),
  });
  rpc.write(Buffer.from([1]));
  time += 17;
  rpc.write(Buffer.from([2]));
  time += 29999;
  const first = pending.get(1);
  pending.delete(1);
  first.fn();
  assert.equal(cancelled, 0);
  assert.equal(o.snapshot().completedWindow, false);
  assert.equal(pending.get(2).delay, 1);
  time += 1;
  const second = pending.get(2);
  pending.delete(2);
  second.fn();
  assert.equal(cancelled, 1);
  assert.equal(o.snapshot().durationMs, 30000);
  o.close();
  assert.equal(pending.size, 0);
});

test("DLQ empty production windows remain observation debt without masking status or shape gaps", () => {
  for (const caseId of ["dlq-no-grant/rest", "dlq-grant-window/rest"]) {
    const source = exchange({}, { case: caseId, op: "pull" });
    const local = exchange({ receivedMessages: [{ ackId: "a", message: { data: "eA==" } }] });
    const result = core.judgeRow(source, local);
    assert.equal(result.verdict, "NOT_COMPARABLE");
    assert.equal(result.reason, "本番の配送が観測窓内に起きなかった。IAM反映の時間は未記録");
    assert.equal(
      core.judgeRow({ ...source, response: { ...source.response, status: 403 } }, local).verdict,
      "DIVERGES",
    );
    assert.equal(
      core.judgeRow({ ...source, response: { ...source.response, unknown: true } }, local).reason,
      "unknown response",
    );
    assert.equal(
      core.judgeRow({ ...source, case: "rest-layout-routes/rest" }, local).verdict,
      "DIVERGES",
    );
    assert.equal(
      core.judgeRow(
        { ...source, response: { ...source.response, body: { unexpected: true } } },
        local,
      ).verdict,
      "DIVERGES",
    );
    assert.equal(core.judgeRow(source, exchange({})).verdict, "MATCH");
  }
});

test("cursor binding compares exact member multiset and cardinality independent of order", () => {
  for (let seed = 0; seed < 64; seed += 1) {
    const names = Array.from(
      { length: 2 + (seed % 8) },
      (_, i) => `projects/demo/topics/topic${i}`,
    );
    const source = { topics: names.map((name) => ({ name })), nextPageToken: `source${seed}` };
    const local = {
      topics: names.toReversed().map((name) => ({ name })),
      nextPageToken: `local${seed}`,
    };
    const bindings = core.createBindings();
    bindings.linkCursor(source, local);
    assert.equal(bindings.get("cursor", source.nextPageToken), local.nextPageToken);
    for (const topics of [
      local.topics.slice(1),
      [...local.topics, local.topics[0]],
      [{ name: "projects/demo/topics/different" }, ...local.topics.slice(1)],
    ])
      assert.throws(() => core.createBindings().linkCursor(source, { ...local, topics }), /cursor/);
  }
});

test("two-run field normalization requires equal shapes and retains format and producer bindings", () => {
  assert.equal(typeof core.createFieldNormalization, "function");
  for (let seed = 0; seed < 64; seed += 1) {
    const runs = [seed.toString(16).padStart(12, "0"), (seed + 100).toString(16).padStart(12, "0")];
    const make = (run, width = 196) => [
      { note: "run-start", suite: "stream-dlq-v2", runId: run, project: "demo-project" },
      {
        n: 99,
        case: "dlq-grant-window/rest",
        step: 12,
        op: "publish",
        transport: "rest",
        response: { status: 200 },
        request: {
          body: {
            messages: [
              {
                data: Buffer.from(`dlq-${run}-identity`).toString("base64"),
                attributes: { recorderRun: run, identity: "original" },
              },
            ],
          },
        },
      },
      {
        n: 100,
        case: "dlq-grant-window/rest",
        step: 13,
        op: "pull",
        transport: "rest",
        request: { path: `/v1/projects/demo-project/subscriptions/fe${run}-da-r-source:pull` },
        response: {
          status: 200,
          bodyBytes: 537,
          body: {
            receivedMessages: [
              {
                ackId: "a".repeat(width),
                message: {
                  messageId: "1".repeat(17),
                  data: Buffer.from(`dlq-${run}-identity`).toString("base64"),
                  attributes: { recorderRun: run, identity: "original" },
                },
              },
            ],
          },
        },
      },
    ];
    const [a, b] = runs.map((r) => make(r));
    const policy = core.createFieldNormalization(a, b);
    const row = a[2];
    assert.deepEqual(
      policy.normalize(row.response.body, row),
      policy.normalize(b[2].response.body, b[2]),
    );
    assert.ok(policy.evidence.some((e) => e.path.endsWith("/data")));
    assert.ok(policy.evidence.some((e) => e.path.endsWith("/attributes/recorderRun")));
    const near = structuredClone(row.response.body);
    near.receivedMessages[0].message.data = Buffer.from(`dlq-${runs[0]}-changed!`).toString(
      "base64",
    );
    assert.notDeepEqual(policy.normalize(row.response.body, row), policy.normalize(near, row));
    const changedShape = make(runs[1], 195);
    const shaped = core.createFieldNormalization(a, changedShape);
    assert.notDeepEqual(
      core.normalizeBody(shaped.normalize(row.response.body, row)),
      core.normalizeBody(shaped.normalize(changedShape[2].response.body, changedShape[2])),
    );
    const wrong = make(runs[1]);
    wrong[2].response.body.receivedMessages[0].message.attributes.recorderRun = "f".repeat(12);
    const refused = core.createFieldNormalization(a, wrong);
    assert.ok(!refused.evidence.some((e) => e.path.endsWith("/attributes/recorderRun")));
  }
});

test("field normalization replays redacted actual two-run bodies and format near misses", () => {
  const fixture = JSON.parse(
    readFileSync(
      new URL(
        "./pubsub-production/fixtures/stream-dlq-normalization-recorded.json",
        import.meta.url,
      ),
    ),
  );
  const [a, b] = fixture.captures;
  const policy = core.createFieldNormalization(a, b);
  const paths = new Set(policy.evidence.map((e) => e.path));
  for (const suffix of [
    "/data",
    "/attributes/recorderRun",
    "/attributes/CloudPubSubDeadLetterSourceSubscription",
    "/attributes/CloudPubSubDeadLetterSourceTopicPublishTime",
  ])
    assert.ok(
      [...paths].some((path) => path.endsWith(suffix)),
      suffix,
    );
  for (const n of [26, 28, 30, 32, 34, 36, 38, 40, 42, 80]) {
    const first = a.find((r) => r.n === n),
      second = b.find((r) => r.n === n);
    assert.equal(
      core.judgeRow(first, second, { fieldNormalization: policy }).verdict,
      "MATCH",
      `n=${n}`,
    );
  }
  for (const n of [85, 100, 102, 104, 106, 108, 114]) {
    const first = a.find((r) => r.n === n),
      second = b.find((r) => r.n === n);
    assert.equal(
      core.judgeRow(first, second, { fieldNormalization: policy }).verdict,
      "DIVERGES",
      `ACK format n=${n}`,
    );
  }
  const row = a.find((r) => r.n === 114),
    body = row.response.body;
  const normalized = policy.normalize(body, row);
  for (const change of [
    (m) => (m.data = Buffer.from("other-payload").toString("base64")),
    (m) => (m.data = m.data.replace(/==$/, "=")),
    (m) => (m.attributes.recorderRun = "F".repeat(12)),
    (m) => (m.attributes.recorderRun = "a".repeat(13)),
    (m) => (m.attributes.identity = "changed"),
    (m) => (m.attributes.extra = "unexpected"),
    (m) => delete m.attributes.recorderRun,
    (m) => (m.attributes.CloudPubSubDeadLetterSourceSubscription += "x"),
    (m) =>
      (m.attributes.CloudPubSubDeadLetterSourceTopicPublishTime =
        m.attributes.CloudPubSubDeadLetterSourceTopicPublishTime.replace("+00:00", "Z")),
    (m) =>
      (m.attributes.CloudPubSubDeadLetterSourceTopicPublishTime =
        m.attributes.CloudPubSubDeadLetterSourceTopicPublishTime.replace(/\.\d{3}/, ".123456")),
    (m) =>
      (m.attributes.CloudPubSubDeadLetterSourceTopicPublishTime = "2026-02-31T03:04:05.123+00:00"),
  ]) {
    const changed = structuredClone(body);
    change(changed.receivedMessages[0].message);
    assert.notDeepEqual(policy.normalize(changed, row), normalized);
  }
  const first = a.find((r) => r.n === 4),
    second = b.find((r) => r.n === 4);
  assert.equal(
    core.judgeRow(first, second, { fieldNormalization: policy }).verdict,
    "DIVERGES",
    "different page members remain a proposal",
  );
  const frames = a.filter((r) => r.note === "stream-frame" && r.direction === "in");
  assert.equal(frames.length, 1);
  assert.deepEqual(
    core.normalizeBody(
      policy.normalize(
        frames[0].body,
        a.find((r) => r.n === 16),
      ),
    ),
    core.normalizeBody(
      policy.normalize(
        b.find((r) => r.note === "stream-frame" && r.direction === "in").body,
        b.find((r) => r.n === 16),
      ),
    ),
  );
});

test("normalization cannot exchange the peer producer identity within a local response", () => {
  const [a, b] = JSON.parse(
    readFileSync(
      new URL(
        "./pubsub-production/fixtures/stream-dlq-normalization-recorded.json",
        import.meta.url,
      ),
    ),
  ).captures;
  const policy = core.createFieldNormalization(a, b);
  const expected = a.find((r) => r.n === 26),
    peer = b.find((r) => r.n === 26);
  const actual = structuredClone(expected);
  actual.response.body.receivedMessages[0].message.data =
    peer.response.body.receivedMessages[0].message.data;
  assert.equal(core.judgeRow(expected, actual, { fieldNormalization: policy }).verdict, "DIVERGES");
  const attrs = structuredClone(expected);
  attrs.response.body.receivedMessages[0].message.attributes.recorderRun =
    peer.response.body.receivedMessages[0].message.attributes.recorderRun;
  assert.equal(core.judgeRow(expected, attrs, { fieldNormalization: policy }).verdict, "DIVERGES");
});

test("string list layouts preserve exact membership and cardinality independently of permutation", () => {
  for (const key of ["subscriptions", "snapshots"]) {
    const expected = exchange({
      [key]: ["projects/demo/subscriptions/a", "projects/demo/subscriptions/b"],
    });
    assert.equal(
      core.judgeRow(expected, exchange({ [key]: expected.response.body[key].toReversed() }))
        .verdict,
      "MATCH",
    );
    for (const list of [
      ["projects/demo/subscriptions/a"],
      ["projects/demo/subscriptions/a", "projects/demo/subscriptions/a"],
      ["projects/demo/subscriptions/a", "projects/demo/subscriptions/c"],
    ])
      assert.equal(core.judgeRow(expected, exchange({ [key]: list })).verdict, "DIVERGES");
  }
});
