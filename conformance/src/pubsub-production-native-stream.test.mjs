import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { createBudget, createCapture, createFileJournal } from "./pubsub-production/capture.mjs";
import { createGrpc } from "./pubsub-production/grpc.mjs";

const Request = protos.google.pubsub.v1.StreamingPullRequest;
const Response = protos.google.pubsub.v1.StreamingPullResponse;
const encode = (Type, value) => Buffer.from(Type.encode(Type.fromObject(value)).finish());
const frame = {
  subscription: "projects/demo-project/subscriptions/fe0123456789ab-stream",
  streamAckDeadlineSeconds: 10,
  maxOutstandingMessages: "1",
  maxOutstandingBytes: "1024",
};
async function server(handler) {
  const instance = new grpc.Server();
  const calls = [];
  instance.addService(
    {
      StreamingPull: {
        path: "/google.pubsub.v1.Subscriber/StreamingPull",
        requestStream: true,
        responseStream: true,
        requestSerialize: (value) => encode(Request, value),
        requestDeserialize: (bytes) => Request.toObject(Request.decode(bytes), { longs: String }),
        responseSerialize: (value) => (Buffer.isBuffer(value) ? value : encode(Response, value)),
        responseDeserialize: (bytes) => Response.decode(bytes),
      },
    },
    {
      StreamingPull: (call) => {
        calls.push(call);
        call.on("error", () => {});
        handler(call);
      },
    },
  );
  const port = await new Promise((resolve, reject) =>
    instance.bindAsync("127.0.0.1:0", grpc.ServerCredentials.createInsecure(), (error, bound) =>
      error ? reject(error) : resolve(bound),
    ),
  );
  return { calls, target: `127.0.0.1:${port}`, close: () => instance.forceShutdown() };
}
function setup(t, target, max = 2) {
  const lines = [];
  const dir = mkdtempSync(join(tmpdir(), "pubsub-native-frames-"));
  const journal = createFileJournal(join(dir, "capture.jsonl"));
  t.after(() => {
    journal.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const budget = createBudget(max);
  const transport = createGrpc({
    target,
    secure: false,
    budget,
    capture: createCapture({
      journal: {
        write: (line) => {
          journal.write(line);
          lines.push(line);
        },
        writeFrame: journal.writeFrame,
      },
    }),
  });
  t.after(transport.close);
  return { transport, lines, budget, rawFrame: (line) => readFileSync(join(dir, line.blob)) };
}
const call = (transport, extra = {}) =>
  transport.stream({
    label: { case: "native/grpc", step: "01" },
    frames: [frame],
    timeoutMs: 300,
    ...extra,
  });

test("native StreamingPull exchanges real protobuf frames and actual terminal status", async (t) => {
  const s = await server((stream) =>
    stream.on("data", () => {
      stream.write({
        receivedMessages: [
          {
            ackId: "a",
            deliveryAttempt: 7,
            message: { data: Buffer.from("wire"), messageId: "m" },
          },
        ],
      });
      stream.end();
    }),
  );
  t.after(s.close);
  const { transport, lines, budget } = setup(t, s.target);
  assert.equal(typeof transport.stream, "function");
  const reply = await call(transport);
  assert.equal(reply.code, "OK");
  assert.equal(reply.unknown, false);
  assert.equal(reply.inboundFrames, 1);
  assert.equal(budget.used(), 1);
  const frames = lines.filter((line) => line.note === "stream-frame");
  assert.deepEqual(
    frames.map((line) => line.direction),
    ["out", "in"],
  );
  assert.equal(frames[0].bodyBytes, encode(Request, frame).length);
  assert.equal(frames[0].sha256, createHash("sha256").update(encode(Request, frame)).digest("hex"));
  assert.equal(frames[1].body.receivedMessages[0].deliveryAttempt, 7);
  assert.equal(
    frames[1].body.receivedMessages[0].message.data,
    Buffer.from("wire").toString("base64"),
  );
  assert.equal(lines.find((line) => line.op === "streamingPull").response.code, "OK");
});

test("native stream captures INVALID_ARGUMENT without inventing a frame or successful answer", async (t) => {
  const s = await server((stream) =>
    stream.once("data", () =>
      stream.emit("error", { code: grpc.status.INVALID_ARGUMENT, details: "invalid frame" }),
    ),
  );
  t.after(s.close);
  const { transport, lines } = setup(t, s.target);
  assert.equal(typeof transport.stream, "function");
  const reply = await call(transport, { frames: [frame, { ackIds: ["bad"] }] });
  assert.equal(reply.code, "INVALID_ARGUMENT");
  assert.equal(reply.unknown, false);
  assert.equal(reply.inboundFrames, 0);
  assert.equal(
    lines.filter((line) => line.note === "stream-frame" && line.direction === "out").length,
    2,
  );
});

test("native stream deadline is unknown and closes the stream without retry", async (t) => {
  const s = await server(() => {});
  t.after(s.close);
  const { transport, lines } = setup(t, s.target);
  assert.equal(typeof transport.stream, "function");
  const reply = await call(transport, { timeoutMs: 80 });
  assert.equal(reply.unknown, true);
  assert.ok(["CANCELLED", "DEADLINE_EXCEEDED"].includes(reply.code));
  assert.equal(s.calls.length, 1);
  assert.equal(lines.filter((line) => line.op === "streamingPull").length, 1);
});

test("native stream rejects frame counts, encoded bytes and time bounds before dispatch", async (t) => {
  const s = await server(() => {});
  t.after(s.close);
  const { transport, budget } = setup(t, s.target);
  assert.equal(typeof transport.stream, "function");
  for (const extra of [
    { frames: [] },
    { frames: [frame, frame, frame] },
    { frames: [{ ackIds: ["x".repeat(16384)] }] },
    { timeoutMs: 0 },
    { timeoutMs: 30001 },
    ...[-2, 0, 1, 600, 601, 602].map((modifyDeadlineSeconds) => ({
      afterReceive: { modifyDeadlineSeconds },
    })),
    { frames: [frame, frame], afterReceive: { modifyDeadlineSeconds: -1 } },
  ])
    await assert.rejects(call(transport, extra), /stream.*bound/);
  assert.equal(budget.used(), 0);
  assert.equal(s.calls.length, 0);
});

test("native stream caps received frame count and preserves ambiguity on overflow", async (t) => {
  const s = await server((stream) =>
    stream.on("data", () => {
      for (let n = 0; n < 8; n += 1) stream.write({});
    }),
  );
  t.after(s.close);
  const { transport, lines } = setup(t, s.target);
  assert.equal(typeof transport.stream, "function");
  const reply = await call(transport);
  assert.equal(reply.unknown, true);
  assert.equal(reply.reason, "inbound-frame-limit");
  assert.equal(
    lines.filter((line) => line.note === "stream-frame" && line.direction === "in").length,
    4,
  );
});

test("native oversized response is unreadable and unknown even with RESOURCE_EXHAUSTED status", async (t) => {
  const s = await server((stream) =>
    stream.on("data", () =>
      stream.write({ receivedMessages: [{ message: { data: Buffer.alloc(20000, "x") } }] }),
    ),
  );
  t.after(s.close);
  const { transport, lines } = setup(t, s.target);
  const reply = await call(transport);
  assert.equal(reply.unknown, true);
  assert.equal(reply.inboundFrames, 0);
  assert.equal(
    lines.filter((line) => line.note === "stream-frame" && line.direction === "in").length,
    0,
  );
});

test("native deadline followup sends the documented negative value with an ACK actually received on this stream", async (t) => {
  const seen = [];
  const s = await server((stream) =>
    stream.on("data", (request) => {
      seen.push(request);
      if (seen.length === 1)
        stream.write({
          receivedMessages: [{ ackId: "actual-wire-ack", message: { data: Buffer.from("one") } }],
        });
      else stream.end();
    }),
  );
  t.after(s.close);
  const { transport, lines } = setup(t, s.target);
  const reply = await call(transport, { afterReceive: { modifyDeadlineSeconds: -1 } });
  assert.equal(reply.followUpSent, true);
  assert.equal(
    lines.find(
      (line) => line.note === "stream-frame" && line.direction === "out" && line.frame === 2,
    ).causedByInboundFrame,
    1,
  );
  assert.deepEqual(seen[1].modifyDeadlineAckIds, ["actual-wire-ack"]);
  assert.deepEqual(seen[1].modifyDeadlineSeconds, [-1]);
  assert.equal(
    lines.filter((line) => line.note === "stream-frame" && line.direction === "out").length,
    2,
  );
});

test("native deadline followup never fabricates an ACK when no message arrived", async (t) => {
  const s = await server((stream) => stream.on("data", () => stream.end()));
  t.after(s.close);
  const { transport } = setup(t, s.target);
  const reply = await call(transport, { afterReceive: { modifyDeadlineSeconds: -1 } });
  assert.equal(reply.followUpSent, false);
  assert.equal(reply.outboundFrames, 1);
});

test("native raw frames round-trip long ACK bytes and unknown protobuf fields without re-encoding", async (t) => {
  const ackId = "actual-ack-".repeat(500);
  const known = encode(Response, {
    receivedMessages: [{ ackId, message: { data: Buffer.alloc(5000, 0xff) } }],
  });
  const inbound = Buffer.concat([Buffer.from([0xf8, 0x07, 0x96, 0x01]), known]);
  let n = 0;
  const s = await server((stream) =>
    stream.on("data", () => {
      n += 1;
      if (n === 1) stream.write(inbound);
      else stream.end();
    }),
  );
  t.after(s.close);
  const { transport, lines, rawFrame } = setup(t, s.target);
  const reply = await call(transport, { afterReceive: { modifyDeadlineSeconds: -1 } });
  assert.equal(reply.code, "OK");
  assert.equal(reply.followUpSent, true);
  const recorded = lines.filter((line) => line.note === "stream-frame");
  assert.deepEqual(rawFrame(recorded[0]), encode(Request, frame));
  assert.deepEqual(rawFrame(recorded[1]), inbound);
  assert.notDeepEqual(
    rawFrame(recorded[1]),
    known,
    "unknown field and original field order survive",
  );
  assert.deepEqual(
    rawFrame(recorded[2]),
    encode(Request, { modifyDeadlineAckIds: [ackId], modifyDeadlineSeconds: [-1] }),
  );
  assert.ok(
    recorded[1].body?.receivedMessages?.[0]?.ackId?.omitted,
    "inbound ACK metadata must be sanitized",
  );
  assert.ok(
    recorded[2].body?.modifyDeadlineAckIds?.[0]?.omitted,
    "outbound ACK metadata must be sanitized",
  );
  assert.equal(recorded[1].body.receivedMessages[0].ackId.omitted.length, ackId.length);
  assert.equal(recorded[2].body.modifyDeadlineAckIds[0].omitted.length, ackId.length);
  for (const line of recorded) {
    const bytes = rawFrame(line);
    assert.equal(line.bodyBytes, bytes.length);
    assert.equal(line.sha256, createHash("sha256").update(bytes).digest("hex"));
  }
});

test("native unreadable bounded protobuf frame remains replayable and unknown", async (t) => {
  const malformed = Buffer.from([0x0a, 0xff]);
  const s = await server((stream) => stream.once("data", () => stream.write(malformed)));
  t.after(s.close);
  const { transport, lines, rawFrame } = setup(t, s.target);
  const reply = await call(transport);
  assert.equal(reply.unknown, true);
  assert.equal(reply.reason, "unreadable-frame");
  assert.equal(reply.inboundFrames, 1);
  const line = lines.find((entry) => entry.note === "stream-frame" && entry.direction === "in");
  assert.ok(line, "unreadable raw frame metadata must be retained");
  assert.equal(line.unreadable, true);
  assert.deepEqual(rawFrame(line), malformed);
});
