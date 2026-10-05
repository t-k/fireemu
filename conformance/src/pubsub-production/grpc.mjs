// The gRPC transport of a recording: unary calls to the Pub/Sub services, with the messages of the
// protos the Pub/Sub client library ships. A request is written in the REST (proto3 JSON) form and
// converted; a response is converted back to that form, so that both transports are read the same way.
// One attempt for each call, counted against the budget before it is sent and captured as it happens;
// a deadline or a transport error is an unknown answer, never retried.

import grpcLib from "@grpc/grpc-js";
import { protos as pubsubProtos } from "@google-cloud/pubsub";
import { createStreamingPull } from "./stream.mjs";

const DURATION_FIELDS = new Set([
  "messageRetentionDuration",
  "ttl",
  "minimumBackoff",
  "maximumBackoff",
  "topicMessageRetentionDuration",
]);
// Maps of user data: their keys are not field names, whatever they are called.
const USER_MAPS = new Set(["labels", "attributes", "tags"]);
const TIMESTAMP_FIELDS = new Set(["time", "publishTime", "expireTime"]);

/** The services and methods of a recording: the wire path, the request type and the response type. */
export const SERVICES = Object.freeze({
  Publisher: {
    path: "/google.pubsub.v1.Publisher",
    methods: {
      CreateTopic: ["Topic", "Topic"],
      GetTopic: ["GetTopicRequest", "Topic"],
      ListTopics: ["ListTopicsRequest", "ListTopicsResponse"],
      ListTopicSubscriptions: ["ListTopicSubscriptionsRequest", "ListTopicSubscriptionsResponse"],
      ListTopicSnapshots: ["ListTopicSnapshotsRequest", "ListTopicSnapshotsResponse"],
      DeleteTopic: ["DeleteTopicRequest", "Empty"],
      Publish: ["PublishRequest", "PublishResponse"],
    },
  },
  Subscriber: {
    path: "/google.pubsub.v1.Subscriber",
    methods: {
      CreateSubscription: ["Subscription", "Subscription"],
      GetSubscription: ["GetSubscriptionRequest", "Subscription"],
      UpdateSubscription: ["UpdateSubscriptionRequest", "Subscription"],
      ListSubscriptions: ["ListSubscriptionsRequest", "ListSubscriptionsResponse"],
      DeleteSubscription: ["DeleteSubscriptionRequest", "Empty"],
      ModifyAckDeadline: ["ModifyAckDeadlineRequest", "Empty"],
      Acknowledge: ["AcknowledgeRequest", "Empty"],
      Pull: ["PullRequest", "PullResponse"],
      ModifyPushConfig: ["ModifyPushConfigRequest", "Empty"],
      GetSnapshot: ["GetSnapshotRequest", "Snapshot"],
      CreateSnapshot: ["CreateSnapshotRequest", "Snapshot"],
      ListSnapshots: ["ListSnapshotsRequest", "ListSnapshotsResponse"],
      DeleteSnapshot: ["DeleteSnapshotRequest", "Empty"],
      Seek: ["SeekRequest", "SeekResponse"],
    },
  },
});

const snake = (text) => text.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);

/** `"600s"` or `"1.500s"` as the `{ seconds, nanos }` of the wire. */
export function durationToWire(text) {
  const match = /^(-?\d+)(?:\.(\d{1,9}))?s$/.exec(text);
  if (!match) throw new Error(`not a duration: ${String(text)}`);
  return {
    seconds: match[1],
    nanos: match[2] ? Number(match[2].padEnd(9, "0")) * (match[1].startsWith("-") ? -1 : 1) : 0,
  };
}

/** An RFC 3339 time as the `{ seconds, nanos }` of the wire. */
export function timestampToWire(text) {
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(text);
  if (!match) throw new Error(`not a time: ${String(text)}`);
  return {
    seconds: String(Math.floor(Date.parse(`${match[1]}Z`) / 1000)),
    nanos: match[2] ? Number(match[2].padEnd(9, "0")) : 0,
  };
}

const fraction = (nanos) => {
  if (nanos === 0) return "";
  const padded = String(Math.abs(nanos)).padStart(9, "0");
  const width = padded.endsWith("000000") ? 3 : padded.endsWith("000") ? 6 : 9;
  return `.${padded.slice(0, width)}`;
};

/** The proto3 JSON text of a wire duration. */
export function durationFromWire({ seconds = "0", nanos = 0 }) {
  const negative = String(seconds).startsWith("-") || nanos < 0;
  const whole = String(seconds).replace(/^-/, "");
  return `${negative ? "-" : ""}${whole}${fraction(nanos)}s`;
}

/** The proto3 JSON text of a wire timestamp. */
export function timestampFromWire({ seconds = "0", nanos = 0 }) {
  const iso = new Date(Number(seconds) * 1000).toISOString().slice(0, 19);
  return `${iso}${fraction(nanos)}Z`;
}

/** A request in the REST form, as the object the wire message is made from. */
export function requestToWire(value, key = "") {
  if (USER_MAPS.has(key)) return value;
  if (Array.isArray(value)) return value.map((item) => requestToWire(item, key));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([name, item]) => [name, requestToWire(item, name)]),
    );
  if (typeof value === "string" && DURATION_FIELDS.has(key)) return durationToWire(value);
  if (typeof value === "string" && TIMESTAMP_FIELDS.has(key)) return timestampToWire(value);
  return value;
}

/** A response object of the wire in the REST form: durations and times as text. */
export function responseFromWire(value, key = "") {
  if (USER_MAPS.has(key)) return value;
  if (Array.isArray(value)) return value.map((item) => responseFromWire(item, key));
  if (value !== null && typeof value === "object") {
    if (DURATION_FIELDS.has(key) && "seconds" in value) return durationFromWire(value);
    if (TIMESTAMP_FIELDS.has(key) && "seconds" in value) return timestampFromWire(value);
    return Object.fromEntries(
      Object.entries(value).map(([name, item]) => [name, responseFromWire(item, name)]),
    );
  }
  return value;
}

const UNSURE_CODES = new Set([
  "DEADLINE_EXCEEDED",
  "UNAVAILABLE",
  "INTERNAL",
  "UNKNOWN",
  "CANCELLED",
]);
const STATUS_NAMES = Object.fromEntries(
  Object.entries(grpcLib.status).map(([name, code]) => [code, name]),
);

export function createGrpc({
  target,
  secure,
  budget,
  capture,
  getToken = null,
  quotaProject = null,
  grpc = grpcLib,
  protos = pubsubProtos,
  defaultTimeoutMs = 30_000,
  now = Date.now,
}) {
  if (typeof target !== "string" || !/^[^/]+:\d+$/.test(target))
    throw new Error("the gRPC target must be host:port");
  const types = protos.google.pubsub.v1;
  const typeOf = (name) => (name === "Empty" ? protos.google.protobuf.Empty : types[name]);
  const client = new grpc.Client(
    target,
    secure ? grpc.credentials.createSsl() : grpc.credentials.createInsecure(),
  );
  const streaming = createStreamingPull({
    target,
    secure,
    budget,
    capture,
    getToken,
    quotaProject,
    grpc,
    protos,
    now,
  });
  return Object.freeze({
    name: "grpc",
    close: () => {
      client.close();
      streaming.close();
    },
    stream: streaming.stream,
    /** Sends one unary call. `request` is in the REST form; `token` is "default", "none" or "invalid". */
    async call({
      label,
      op,
      service,
      method,
      request,
      token = "default",
      timeoutMs = defaultTimeoutMs,
    }) {
      const definition = SERVICES[service]?.methods[method];
      if (!definition) throw new Error(`unknown method ${service}/${method}`);
      const [requestName, responseName] = definition;
      const Request = typeOf(requestName);
      const Response = typeOf(responseName);
      budget.consume();
      const body = requestToWire(request);
      if (request.updateMask !== undefined)
        body.updateMask = { paths: String(request.updateMask).split(",").map(snake) };
      const metadata = new grpc.Metadata();
      if (token === "invalid")
        metadata.add("authorization", "Bearer invalid-token-for-the-recording");
      else if (token === "default" && getToken !== null)
        metadata.add("authorization", `Bearer ${await getToken()}`);
      if (quotaProject !== null && token !== "none")
        metadata.add("x-goog-user-project", quotaProject);
      const started = now();
      const entry = {
        ...label,
        transport: "grpc",
        op,
        request: { rpc: `${service}/${method}`, body: request },
      };
      const response = await new Promise((resolve) => {
        client.makeUnaryRequest(
          `${SERVICES[service].path}/${method}`,
          (message) => Buffer.from(Request.encode(Request.fromObject(message)).finish()),
          (buffer) => Response.decode(buffer),
          body,
          metadata,
          { deadline: new Date(now() + timeoutMs) },
          (error, message) => {
            if (!error)
              return resolve({
                code: "OK",
                body: responseFromWire(
                  Response.toObject(message, { longs: String, enums: String, bytes: String }),
                ),
              });
            const code = STATUS_NAMES[error.code] ?? "UNKNOWN";
            // A deadline, an unavailable server and an internal or unknown error do not say whether the
            // call was applied.
            resolve({
              code,
              message: error.details ?? "",
              ...(UNSURE_CODES.has(code) ? { unknown: true } : {}),
            });
          },
        );
      });
      entry.response = response;
      entry.ms = now() - started;
      if (response.unknown) entry.unknown = true;
      capture.record(entry);
      return {
        code: response.code,
        message: response.message,
        body: response.body,
        unknown: response.unknown === true,
      };
    },
  });
}
