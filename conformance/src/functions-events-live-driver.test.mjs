import assert from "node:assert/strict";
import { test } from "node:test";
import {
  advanceLocalClock,
  createLiveDriver,
  ensureLocalTopic,
  runPubsubScenario,
} from "./functions-events/live-driver.mjs";

const required = [
  "FIRESTORE_EMULATOR_HOST",
  "FIREBASE_STORAGE_EMULATOR_HOST",
  "FIREBASE_AUTH_EMULATOR_HOST",
  "PUBSUB_EMULATOR_HOST",
];

test("every live driver refuses missing or remote SDK hosts before initialization", async () => {
  const previous = Object.fromEntries(
    [...required, "STORAGE_EMULATOR_HOST"].map((name) => [name, process.env[name]]),
  );
  try {
    for (const name of required) process.env[name] = "127.0.0.1:1";
    process.env.STORAGE_EMULATOR_HOST = "http://127.0.0.1:1";
    for (const name of required) {
      for (const bad of [undefined, "firestore.googleapis.com:443", "localhost.evil.com:443"]) {
        if (bad === undefined) delete process.env[name];
        else process.env[name] = bad;
        await assert.rejects(
          createLiveDriver({ projectId: "demo-conformance" }),
          /loopback emulator/,
        );
        process.env[name] = "127.0.0.1:1";
      }
    }
    process.env.STORAGE_EMULATOR_HOST = "https://storage.googleapis.com";
    await assert.rejects(createLiveDriver({ projectId: "demo-conformance" }), /loopback emulator/);
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test("retry clock control is loopback-only and never exposes its token in a result", async () => {
  const calls = [];
  const request = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200 };
  };
  await assert.rejects(
    advanceLocalClock({
      controlUrl: "https://firestore.googleapis.com",
      token: "synthetic-secret",
      seconds: 5,
      request,
    }),
    /loopback control URL/,
  );
  assert.equal(calls.length, 0);
  await advanceLocalClock({
    controlUrl: "http://127.0.0.1:1234",
    token: "synthetic-secret",
    seconds: 5,
    request,
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:1234/v1/sessions/default/clock:advance");
  assert.deepEqual(JSON.parse(calls[0].init.body), { seconds: 5 });
  assert.equal(calls[0].init.headers.authorization, "Bearer synthetic-secret");
});

test("a trigger-owned primary topic is reused and a missing control topic is created", async () => {
  const calls = [];
  const primary = {
    exists: async () => [true],
    create: async () => {
      calls.push("primary-create");
    },
  };
  const control = {
    exists: async () => [false],
    create: async () => {
      calls.push("control-create");
    },
  };
  assert.deepEqual(await ensureLocalTopic(primary), { created: false, existed: true });
  assert.deepEqual(await ensureLocalTopic(control), { created: true, existed: false });
  assert.deepEqual(calls, ["control-create"]);
});

function fakePubsub() {
  const published = [];
  const topics = new Map();
  return {
    published,
    topic(name, options) {
      const topic = {
        name,
        options,
        exists: async () => [true],
        publishMessage: async (message) => {
          published.push({ topic: name, ...message });
          return String(published.length);
        },
      };
      topics.set(name, topic);
      return topic;
    },
  };
}

test("the local Pub/Sub scenarios publish what the production script publishes", async () => {
  const capture = { barrier: async () => ({ cursor: 7 }) };
  for (const [id, resource, topic, orderingKey] of [
    ["pubsub-publish", "topic-primary", "fe-events-primary", undefined],
    ["pubsub-other-topic", "topic-control", "fe-events-control", undefined],
    ["pubsub-ordering", "topic-primary", "fe-events-primary", "fe-events-order"],
  ]) {
    const pubsub = fakePubsub();
    const result = await runPubsubScenario({ scenario: { id, resource }, capture, pubsub });
    assert.equal(pubsub.published.length, 1);
    const [message] = pubsub.published;
    assert.equal(message.topic, topic);
    const text = message.data.toString("utf8");
    assert.match(text, /^e[0-9a-f]{24}m\d+$/);
    assert.deepEqual(message.attributes, { probe: text });
    assert.equal(message.orderingKey, orderingKey);
    assert.equal(result.cursor, 7);
    assert.deepEqual(result.matchKey, { kind: "pubsub", value: "1", topic, probe: text });
    assert.equal(result.readback.topicName, topic);
  }
});
