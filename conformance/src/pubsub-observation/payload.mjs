import { protos } from "@google-cloud/pubsub";
import { CAPS } from "./plan.mjs";
const types = protos.google.pubsub.v1;
const field = (length) => 1 + varint(length) + length;
const varint = (value) => {
  let bytes = 1;
  while (value >= 128) {
    value = Math.floor(value / 128);
    bytes++;
  }
  return bytes;
};
const messageLength = (data, padding) => field(data) + field(field(1) + field(padding));
const requestLength = (topic, message) => field(Buffer.byteLength(topic)) + field(message);
export function encodedSizes(topic, messages) {
  const request = { topic, messages };
  return {
    json: Buffer.byteLength(JSON.stringify({ messages })),
    protobuf: types.PublishRequest.encode(types.PublishRequest.fromObject(request)).finish().length,
    message: types.PubsubMessage.encode(types.PubsubMessage.fromObject(messages[0])).finish()
      .length,
    payload: messages.reduce(
      (sum, item) =>
        sum +
        Buffer.byteLength(item.data ?? "") +
        Object.entries(item.attributes ?? {}).reduce(
          (n, [k, v]) => n + Buffer.byteLength(k) + Buffer.byteLength(v),
          0,
        ),
      0,
    ),
  };
}
export function boundaryPayload({ topic, transport, target, kind }) {
  if (
    !["rest", "grpc"].includes(transport) ||
    !["request", "message"].includes(kind) ||
    !Number.isSafeInteger(target) ||
    target < 256 ||
    target > 10485761
  )
    throw new Error("undeclared boundary");
  let data, padding;
  if (transport === "rest" && kind === "request") {
    const fixed = Buffer.byteLength(
      JSON.stringify({ messages: [{ data: "", attributes: { p: "" } }] }),
    );
    const base64 = Math.floor((target - fixed) / 4) * 4;
    data = (base64 / 4) * 3;
    padding = target - fixed - base64;
  } else {
    for (let candidate = 0; candidate <= 128 && data === undefined; candidate++) {
      let low = 0,
        high = target;
      while (low <= high) {
        const middle = Math.floor((low + high) / 2);
        const message = messageLength(middle, candidate);
        const size = kind === "message" ? message : requestLength(topic, message);
        if (size === target) {
          data = middle;
          padding = candidate;
          break;
        }
        if (size < target) low = middle + 1;
        else high = middle - 1;
      }
    }
  }
  if (data === undefined || data < 0) throw new Error("boundary has no exact encoding");
  const messages = [
    { data: Buffer.alloc(data, 0x78).toString("base64"), attributes: { p: "p".repeat(padding) } },
  ];
  const sizes = encodedSizes(topic, messages);
  const actual =
    kind === "message" ? sizes.message : sizes[transport === "rest" ? "json" : "protobuf"];
  if (actual !== target || sizes.payload > CAPS.largeEncodedPayloadBytes)
    throw new Error("boundary encoding contract failed");
  return { messages, sizes, target, kind, transport };
}
