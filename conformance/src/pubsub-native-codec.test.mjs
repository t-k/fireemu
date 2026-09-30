import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { test } from "node:test";
const target = new URL("../pubsub-corpus/native-codec.mjs", import.meta.url);
const root = dirname(
  execFileSync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
    encoding: "utf8",
  }).trim(),
);
const require = createRequire(join(root, "conformance/package.json"));
const protobuf = require("protobufjs");
const descriptor = JSON.parse(
  readFileSync(require.resolve("@google-cloud/pubsub/build/protos/protos.json"), "utf8"),
);
async function codec() {
  assert.ok(existsSync(target), "canonical native wire codec is missing");
  const { createNativeCodec } = await import(target.href);
  return createNativeCodec(protobuf.Root.fromJSON(descriptor).resolveAll());
}
test("native publish encodes actual bytes and camel-case members through the pinned descriptor", async () => {
  const c = await codec();
  const bytes = Buffer.from([0, 255, 10]);
  const wire = c.serialize("PublishRequest", {
    topic: "projects/demo/topics/owned",
    messages: [
      { data: bytes.toString("base64"), orderingKey: "key", attributes: { region: "local" } },
    ],
  });
  const decoded = c.deserialize("PublishRequest", wire);
  assert.deepEqual(Buffer.from(decoded.messages[0].data), bytes);
  assert.equal(decoded.messages[0].orderingKey, "key");
  assert.equal(decoded.messages[0].attributes.region, "local");
  assert.equal(c.fieldType("PublishRequest", "messages.data"), "bytes");
});
test("invalid base64 is a client representation refusal and is never serialized as a fabricated service request", async () => {
  const c = await codec();
  assert.throws(
    () =>
      c.serialize("PublishRequest", {
        topic: "projects/demo/topics/owned",
        messages: [{ data: "%%%not-base64" }],
      }),
    (error) => error.code === "CLIENT_INPUT_UNREPRESENTABLE",
  );
});
test("duration, retained-acked and nested retry configuration do not vanish during native serialization", async () => {
  const c = await codec();
  const wire = c.serialize("Subscription", {
    name: "projects/demo/subscriptions/owned",
    topic: "projects/demo/topics/owned",
    messageRetentionDuration: "600.000000001s",
    retainAckedMessages: true,
    retryPolicy: { minimumBackoff: "-0.100s", maximumBackoff: "600s" },
  });
  const result = c.deserialize("Subscription", wire);
  assert.equal(result.messageRetentionDuration.seconds.toString(), "600");
  assert.equal(result.messageRetentionDuration.nanos, 1);
  assert.equal(result.retainAckedMessages, true);
  assert.equal(result.retryPolicy.minimumBackoff.nanos, -100000000);
});
test("field masks and timestamps retain their precise native members", async () => {
  const c = await codec();
  const patch = c.deserialize(
    "UpdateSubscriptionRequest",
    c.serialize("UpdateSubscriptionRequest", {
      subscription: { name: "projects/demo/subscriptions/owned", ackDeadlineSeconds: 60 },
      updateMask: "ackDeadlineSeconds,retryPolicy.minimumBackoff",
    }),
  );
  assert.deepEqual(patch.updateMask.paths, [
    "ack_deadline_seconds",
    "retry_policy.minimum_backoff",
  ]);
  const seek = c.deserialize(
    "SeekRequest",
    c.serialize("SeekRequest", {
      subscription: "projects/demo/subscriptions/owned",
      time: "2026-09-30T00:00:00.123456789Z",
    }),
  );
  assert.equal(seek.time.nanos, 123456789);
  assert.equal(seek.time.seconds.toString(), String(Date.parse("2026-09-30T00:00:00Z") / 1000));
});
test("unknown fields, conflicting oneofs and wrong primitive types cannot silently change the observed request", async () => {
  const c = await codec();
  for (const request of [
    { name: "owned", unknownConfig: true },
    { name: "owned", retainAckedMessages: "false" },
    { name: "owned", ackDeadlineSeconds: 1.5 },
  ])
    assert.throws(() => c.serialize("Subscription", request));
  assert.throws(() =>
    c.serialize("SeekRequest", {
      subscription: "owned",
      time: { seconds: "1" },
      snapshot: "owned-snapshot",
    }),
  );
});
test("empty response types resolve by full protobuf name and canonical input supports snake-case native fields", async () => {
  const c = await codec();
  assert.equal(c.serialize("google.protobuf.Empty", {}).length, 0);
  const decoded = c.deserialize(
    "Subscription",
    c.serialize("Subscription", { name: "owned", ack_deadline_seconds: 60 }),
  );
  assert.equal(decoded.ackDeadlineSeconds, 60);
});

test("native int64 values are range-checked before coercion and exact signed boundaries survive", async () => {
  const c = await codec();
  for (const duration of ["18446744073709551616s", "9223372036854775808s", "-9223372036854775809s"])
    assert.throws(
      () => c.serialize("Subscription", { messageRetentionDuration: duration }),
      (error) => error.code === "CLIENT_INPUT_UNREPRESENTABLE",
    );
  for (const seconds of ["9223372036854775807", "-9223372036854775808"])
    assert.equal(
      c
        .deserialize(
          "Subscription",
          c.serialize("Subscription", { messageRetentionDuration: { seconds, nanos: 0 } }),
        )
        .messageRetentionDuration.seconds.toString(),
      seconds,
    );
});

test("invalid calendar dates cannot silently normalize into a different native timestamp", async () => {
  const c = await codec();
  assert.throws(
    () =>
      c.serialize("SeekRequest", {
        subscription: "projects/demo/subscriptions/owned",
        time: "2026-02-29T00:00:00Z",
      }),
    { code: "CLIENT_INPUT_UNREPRESENTABLE" },
  );
  assert.throws(
    () =>
      c.serialize("SeekRequest", {
        subscription: "projects/demo/subscriptions/owned",
        time: "2026-04-31T00:00:00Z",
      }),
    { code: "CLIENT_INPUT_UNREPRESENTABLE" },
  );
});

test("unsigned wire integers reject overflow and negative values before protobuf coercion", async () => {
  const c = await codec();
  for (const value of ["18446744073709551616", "-1"])
    assert.throws(
      () => c.serialize(".google.protobuf.UninterpretedOption", { positiveIntValue: value }),
      { code: "CLIENT_INPUT_UNREPRESENTABLE" },
    );
  for (const value of ["0", "18446744073709551615"])
    assert.equal(
      c
        .deserialize(
          ".google.protobuf.UninterpretedOption",
          c.serialize(".google.protobuf.UninterpretedOption", { positiveIntValue: value }),
        )
        .positiveIntValue.toString(),
      value,
    );
});
test("service-invalid but representable duration is encoded unchanged for actual service observation", async () => {
  const c = await codec(),
    wire = c.serialize("Subscription", {
      name: "projects/demo/subscriptions/owned",
      messageRetentionDuration: "1000000000000s",
    });
  assert.equal(
    c.deserialize("Subscription", wire).messageRetentionDuration.seconds.toString(),
    "1000000000000",
  );
});

test("invalid RFC3339 time components are never normalized into another native timestamp", async () => {
  const c = await codec();
  for (const time of ["2026-09-30T24:00:00Z", "2026-09-30T00:60:00Z", "2026-09-30T00:00:60Z"])
    assert.throws(
      () => c.serialize("SeekRequest", { subscription: "projects/demo/subscriptions/owned", time }),
      { code: "CLIENT_INPUT_UNREPRESENTABLE" },
    );
});
