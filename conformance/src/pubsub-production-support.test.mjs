import assert from "node:assert/strict";
import test from "node:test";
import { protos } from "@google-cloud/pubsub";
import {
  CaseAbort,
  StopClean,
  ackIds,
  messageSize,
  messagesOfRequestSize,
  must,
  payload,
  pullMessages,
  timeoutForBytes,
} from "./pubsub-production/cases/support.mjs";

const types = protos.google.pubsub.v1;
const TOPIC = "projects/demo-project/topics/t";

test("a step that did not succeed names itself, and an unknown answer says so", () => {
  assert.equal(must({ ok: true }, "x").ok, true);
  assert.throws(
    () => must({ ok: false, code: "NOT_FOUND" }, "getTopic"),
    (error) => {
      return error instanceof CaseAbort && error.message === "getTopic did not succeed (NOT_FOUND)";
    },
  );
  assert.throws(
    () => must({ ok: false, code: "UNKNOWN", unknown: true }, "publish"),
    /publish did not succeed \(UNKNOWN, unknown\)/,
  );
  assert.throws(() => must(undefined, "x"), /no answer/);
  assert.equal(new StopClean("r").name, "StopClean");
});

test("the messages of a request size encode to exactly that many bytes, whatever the length prefix", () => {
  const sizes = [
    10_000_000, 10_000_001, 10_485_760, 10_485_761, 4_000_100, 4_000_130, 4_200_000, 6_000_000,
  ];
  for (const total of sizes) {
    const messages = messagesOfRequestSize(TOPIC, total);
    const request = types.PublishRequest.fromObject({
      topic: TOPIC,
      messages: messages.map(({ data }) => ({ data: Buffer.from(data, "base64") })),
    });
    assert.equal(types.PublishRequest.encode(request).finish().length, total, String(total));
    assert.ok(
      messages.every(({ data }) => typeof data === "string"),
      "the data is already base64 text",
    );
  }
});

test("a request size too small for the fixed chunk is refused rather than approximated", () => {
  assert.throws(() => messagesOfRequestSize(TOPIC, 1000));
});

test("the sizes of a payload and its message, and the time allowed for a request", () => {
  assert.equal(payload(5).toString(), "xxxxx");
  assert.equal(payload(0).length, 0);
  assert.equal(messageSize(payload(10_000_000)), 10_000_005);
  assert.equal(messageSize(payload(100)), 102);
  assert.equal(timeoutForBytes(0), 30_000);
  assert.equal(timeoutForBytes(1), 31_000);
  assert.equal(timeoutForBytes(10_000_000), 130_000);
  assert.equal(timeoutForBytes(10_485_760 * 1.4), 30_000 + 147 * 1000);
});

function fakeContext(replies) {
  const calls = [];
  const sleeps = [];
  const pull = async (subscription, body) => {
    calls.push({ subscription, body });
    return replies.shift() ?? { ok: true, body: {} };
  };
  const client = {
    pull,
    with: (options) => ({ pull: (...args) => (calls.push({ options }), pull(...args)) }),
  };
  return { calls, sleeps, ctx: { client, sleep: async (ms) => sleeps.push(ms) } };
}
const got = (...ids) => ({ ok: true, body: { receivedMessages: ids.map((ackId) => ({ ackId })) } });

test("pulling collects messages across pulls until the count is reached, and asks for what is missing", async () => {
  const { ctx, calls } = fakeContext([got("a"), { ok: true, body: {} }, got("b", "c")]);
  const received = await pullMessages(ctx, "s", 3);
  assert.deepEqual(ackIds(received), ["a", "b", "c"]);
  const bodies = calls.filter((call) => call.body).map((call) => call.body);
  assert.deepEqual(bodies, [
    { maxMessages: 3, returnImmediately: false },
    { maxMessages: 2, returnImmediately: false },
    { maxMessages: 2, returnImmediately: false },
  ]);
  assert.ok(
    calls.some((call) => call.options?.timeoutMs === 20_000),
    "a waiting pull has a time limit",
  );
});

test("pulling stops at the attempt limit and at the first failure, and an immediate pull waits between pulls", async () => {
  const none = fakeContext([]);
  assert.deepEqual(await pullMessages(none.ctx, "s", 1, { attempts: 3 }), []);
  assert.equal(none.calls.filter((call) => call.body).length, 3);
  const failing = fakeContext([{ ok: false, code: "NOT_FOUND" }, got("never")]);
  assert.deepEqual(await pullMessages(failing.ctx, "s", 1), []);
  assert.equal(failing.calls.filter((call) => call.body).length, 1);
  const immediate = fakeContext([]);
  await pullMessages(immediate.ctx, "s", 1, { attempts: 3, immediately: true });
  assert.deepEqual(immediate.sleeps, [1000, 1000, 1000]);
  assert.ok(
    immediate.calls.every((call) => call.options === undefined),
    "no time limit change when immediate",
  );
  assert.ok(immediate.calls.every((call) => call.body.returnImmediately === true));
});
