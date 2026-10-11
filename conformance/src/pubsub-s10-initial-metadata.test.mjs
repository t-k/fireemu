import test from "node:test";
import assert from "node:assert/strict";
import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";

const endpoint = process.env.PUBSUB_S10_NATIVE_ENDPOINT;
const profile = process.env.PUBSUB_S10_NATIVE_PROFILE;
const pb = protos.google.pubsub.v1;
const details =
  "A service error has occurred. Please retry your request. If the error persists, please report it. [code=e8c0]";

// The finite local fixture supplies an owned loopback endpoint; default CI has no server.
test(
  "S10 native initial metadata precedes strict zero-opener terminal without changing other openers",
  { skip: !endpoint },
  async () => {
    assert.match(endpoint, /^127\.0\.0\.1:[0-9]+$/);
    assert.ok(["strict", "emulator"].includes(profile));
    const client = new grpc.Client(endpoint, grpc.credentials.createInsecure(), {
      "grpc.enable_retries": 0,
    });
    const nonce = `${process.pid}-${Date.now()}`;
    const topic = `projects/s10-local/topics/topic-${nonce}`;
    const subscription = `projects/s10-local/subscriptions/sub-${nonce}`;
    const unary = (service, method, Request, Response, body) =>
      new Promise((resolve, reject) => {
        client.makeUnaryRequest(
          `/google.pubsub.v1.${service}/${method}`,
          (value) => Buffer.from(Request.encode(value).finish()),
          (bytes) => Response.decode(bytes),
          body,
          new grpc.Metadata(),
          { deadline: new Date(Date.now() + 5000) },
          (error, reply) => (error ? reject(error) : resolve(reply)),
        );
      });
    const observe = (deadline, expectDelivery) =>
      new Promise((resolve, reject) => {
        const events = [],
          messages = [];
        const rpc = client.makeBidiStreamRequest(
          "/google.pubsub.v1.Subscriber/StreamingPull",
          (value) => Buffer.from(pb.StreamingPullRequest.encode(value).finish()),
          (bytes) => pb.StreamingPullResponse.decode(bytes),
          new grpc.Metadata(),
          { deadline: new Date(Date.now() + 5000) },
        );
        let timer = setTimeout(() => {
          rpc.cancel();
          reject(Error("native lifecycle bound exceeded"));
        }, 6000);
        rpc.on("metadata", () => events.push({ event: "metadata" }));
        rpc.on("data", (body) => {
          messages.push(...body.receivedMessages);
          events.push({ event: "data" });
          if (expectDelivery) rpc.cancel();
        });
        rpc.on("error", (error) =>
          events.push({ event: "error", code: error.code, details: error.details }),
        );
        rpc.on("status", (status) =>
          events.push({ event: "status", code: status.code, details: status.details }),
        );
        rpc.on("end", () => {
          clearTimeout(timer);
          timer = null;
          events.push({ event: "end" });
          resolve({ events, messages });
        });
        rpc.write({
          subscription,
          streamAckDeadlineSeconds: deadline,
          maxOutstandingMessages: "1",
          maxOutstandingBytes: "1024",
        });
      });
    try {
      await unary("Publisher", "CreateTopic", pb.Topic, pb.Topic, { name: topic });
      await unary("Subscriber", "CreateSubscription", pb.Subscription, pb.Subscription, {
        name: subscription,
        topic,
        ackDeadlineSeconds: 10,
      });
      const published = await unary("Publisher", "Publish", pb.PublishRequest, pb.PublishResponse, {
        topic,
        messages: [{ data: Buffer.from("s10-local-marker") }],
      });
      if (profile === "strict") {
        const zero = await observe(0, false);
        assert.equal(zero.messages.length, 0);
        assert.deepEqual(
          zero.events.map((event) => event.event),
          ["metadata", "error", "status", "end"],
        );
        for (const event of zero.events.filter((event) =>
          ["error", "status"].includes(event.event),
        )) {
          assert.equal(event.code, 13);
          assert.equal(event.details, details);
        }
      } else {
        const zero = await observe(0, true);
        assert.equal(zero.messages.length, 1);
        assert.equal(zero.messages[0].message.messageId, published.messageIds[0]);
        assert.equal(Buffer.from(zero.messages[0].message.data).toString(), "s10-local-marker");
        await unary(
          "Subscriber",
          "ModifyAckDeadline",
          pb.ModifyAckDeadlineRequest,
          protos.google.protobuf.Empty,
          { subscription, ackIds: [zero.messages[0].ackId], ackDeadlineSeconds: 0 },
        );
      }
      const valid = await observe(10, true);
      assert.equal(valid.messages.length, 1);
      assert.equal(valid.messages[0].message.messageId, published.messageIds[0]);
      assert.equal(Buffer.from(valid.messages[0].message.data).toString(), "s10-local-marker");
    } finally {
      client.close();
    }
  },
);
