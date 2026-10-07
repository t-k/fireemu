import { normalizeOutcome } from "../pubsub-production/outcome.mjs";
import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { SERVICES, requestToWire, responseFromWire } from "../pubsub-production/grpc.mjs";
import { sha256 } from "../pubsub-production/admission.mjs";
import { CAPS, PROJECT, minimumCallMs } from "./plan.mjs";
import { encodedSizes } from "./payload.mjs";
import { openStream } from "./stream.mjs";
import { metadataBytes, FRAMING_RESERVE } from "./metadata.mjs";

const statusNames = Object.fromEntries(
  Object.entries(grpc.status).map(([key, value]) => [value, key]),
);
const unsure = new Set([
  "UNKNOWN",
  "INTERNAL",
  "UNAVAILABLE",
  "DEADLINE_EXCEEDED",
  "CANCELLED",
  "DATA_LOSS",
  "RESOURCE_EXHAUSTED",
]);
const types = protos.google.pubsub.v1;
// This reservation is for framing overhead, not an assertion about TCP retransmissions.
const headerBytes = (headers) =>
  [...(headers?.entries?.() ?? [])].reduce(
    (sum, [name, value]) => sum + Buffer.byteLength(name) + Buffer.byteLength(value) + 4,
    0,
  );
export const typeOf = (name) => (name === "Empty" ? protos.google.protobuf.Empty : types[name]);
export const decode = (Type, raw) =>
  responseFromWire(
    Type.toObject(Type.decode(raw), {
      longs: String,
      enums: String,
      bytes: String,
      defaults: false,
    }),
  );
export function encodeRequest(service, method, request) {
  const definition = SERVICES[service]?.methods[method];
  if (!definition) throw new Error("unlisted unary method");
  const body = requestToWire(request);
  if (request.name !== undefined) {
    if (["GetTopic", "DeleteTopic"].includes(method)) body.topic = request.name;
    if (["GetSubscription", "DeleteSubscription"].includes(method))
      body.subscription = request.name;
  }
  if (request.updateMask !== undefined)
    body.updateMask = {
      paths: String(request.updateMask)
        .split(",")
        .map((name) => name.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`)),
    };
  return Buffer.from(typeOf(definition[0]).encode(typeOf(definition[0]).fromObject(body)).finish());
}
function route(method, request, routeName) {
  const name =
    routeName ??
    request.name ??
    request.topic ??
    request.subscription?.name ??
    request.subscription;
  if (typeof name !== "string" || !/^projects\/[^/]+\/(topics|subscriptions)\/[^/]+$/.test(name))
    throw new Error("invalid REST resource route");
  const url = `https://pubsub.googleapis.com/v1/${name}`;
  if (method.startsWith("Create")) return { url, verb: "PUT", body: request };
  if (method.startsWith("Get")) return { url, verb: "GET" };
  if (method.startsWith("Delete")) return { url, verb: "DELETE" };
  if (method === "Publish")
    return { url: `${url}:publish`, verb: "POST", body: { messages: request.messages } };
  if (method === "UpdateSubscription")
    return {
      url: `https://pubsub.googleapis.com/v1/${request.subscription.name}`,
      verb: "PATCH",
      body: request,
    };
  const suffix = {
    Pull: "pull",
    Acknowledge: "acknowledge",
    ModifyAckDeadline: "modifyAckDeadline",
  }[method];
  if (!suffix) throw new Error("unlisted REST route");
  const { subscription: _subscription, ...body } = request;
  return { url: `${url}:${suffix}`, verb: "POST", body };
}
export async function readResponse(response) {
  const cap = CAPS.metadataBytesEachDirection - headerBytes(response.headers) - FRAMING_RESERVE;
  if (cap < 0) throw new Error("response byte cap");
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > cap) {
        await reader.cancel();
        throw new Error("response byte cap");
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, length);
  } finally {
    reader.releaseLock();
  }
}
export function createWire({
  meter,
  journal,
  getToken,
  beforeDispatch = () => {},
  fetch = globalThis.fetch,
  client = new grpc.Client("pubsub.googleapis.com:443", grpc.credentials.createSsl(), {
    "grpc.enable_retries": 0,
    "grpc.max_receive_message_length": CAPS.metadataBytesEachDirection,
    "grpc.max_send_message_length": CAPS.largeEncodedPayloadBytes + CAPS.metadataBytesEachDirection,
  }),
  now = Date.now,
} = {}) {
  let sequence = 0;
  const controllers = new Map();
  let sourceStopped = false,
    activeStream;
  const controllerFor = (maintenance) => {
    if (sourceStopped && !maintenance) throw new Error("source stopped");
    const controller = new AbortController();
    controllers.set(controller, maintenance);
    return controller;
  };
  const credential = async (maintenance) => {
    const timeout = Math.min(30000, meter.remaining(maintenance));
    let timer;
    const controller = controllerFor(maintenance);
    try {
      return await Promise.race([
        new Promise((_, reject) =>
          controller.signal.addEventListener(
            "abort",
            () => reject(new Error("credential aborted")),
            { once: true },
          ),
        ),
        getToken({ timeoutMs: timeout, signal: controller.signal }),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error("credential time cap"));
          }, timeout);
        }),
      ]);
    } finally {
      clearTimeout(timer);
      controllers.delete(controller);
    }
  };
  const api = {
    client,
    meter,
    journal,
    credential,
    beforeDispatch,
    now,
    close: () => client.close(),
    abortSource() {
      sourceStopped = true;
      for (const [controller, maintenance] of controllers) if (!maintenance) controller.abort();
      activeStream?.cancel("source-signal");
    },
    async call(call) {
      const { category, transport, service, method, request, routeName, cellId } = call;
      const maintenance =
        category.startsWith("cleanup") || ["resourceRead", "unknownDeleteRead"].includes(category);
      if (sourceStopped && !maintenance) throw new Error("source stopped");
      meter.start(category, transport);
      if (meter.remaining(maintenance) < minimumCallMs(method))
        throw new Error("recorded latency margin unavailable");
      let raw, address;
      if (transport === "rest") {
        address = route(method, request, routeName);
        raw = Buffer.from(address.body === undefined ? "" : JSON.stringify(address.body));
      } else raw = encodeRequest(service, method, request);
      if (method === "Publish")
        meter.payload(encodedSizes(request.topic, request.messages).payload);
      else if (raw.length > CAPS.metadataBytesEachDirection)
        throw new Error("request metadata byte cap");
      const token = await credential(maintenance);
      if (meter.remaining(maintenance) < minimumCallMs(method))
        throw new Error("recorded latency margin unavailable after credentials");
      const metadataBytesOut = Buffer.byteLength(token) + 256 + FRAMING_RESERVE;
      const payloadBytes =
        method === "Publish" ? encodedSizes(request.topic, request.messages).payload : 0;
      if (
        Math.max(0, raw.length - payloadBytes) + metadataBytesOut >
        CAPS.metadataBytesEachDirection
      )
        throw new Error("outbound metadata byte cap");
      const timeoutMs = Math.min(
        method.startsWith("Create") ? 80000 : 30000,
        meter.remaining(maintenance),
      );
      const started = now(),
        monotonicStarted = meter.clock(),
        requestId = ++sequence;
      journal.write({
        event: "request-dispatch",
        cellId,
        requestId,
        transport,
        category,
        method,
        request,
        ...(routeName ? { routeName } : {}),
        requestBodyBytes: raw.length,
        metadataBytesOut,
        requestSha256: sha256(raw),
        requestDeadlineAt: new Date(started + timeoutMs).toISOString(),
      });
      let reply;
      const controller = controllerFor(maintenance);
      let requestTimer;
      try {
        beforeDispatch();
        const available = Math.min(
          timeoutMs - (meter.clock() - monotonicStarted),
          meter.remaining(maintenance),
        );
        if (available < minimumCallMs(method))
          throw new Error("durable dispatch latency margin unavailable");
        requestTimer = setTimeout(() => controller.abort(), available);
        if (transport === "rest") {
          const response = await fetch(address.url, {
            method: address.verb,
            redirect: "manual",
            headers: {
              authorization: `Bearer ${token}`,
              "content-type": "application/json",
              "x-goog-user-project": PROJECT,
            },
            ...(address.body === undefined ? {} : { body: raw }),
            signal: controller.signal,
          });
          const bytes = await readResponse(response);
          let body;
          try {
            body = bytes.length === 0 ? {} : JSON.parse(bytes);
            if (body === null || typeof body !== "object" || Array.isArray(body))
              throw new Error("unreadable response object");
          } catch {
            throw new Error("unreadable response");
          }
          reply = {
            ok: response.status >= 200 && response.status < 300,
            status: response.status,
            code: body?.error?.status ?? (response.ok ? "OK" : "UNKNOWN"),
            body,
            bodyBytes: bytes.length,
            metadataBytesIn: headerBytes(response.headers) + FRAMING_RESERVE,
            bodySha256: sha256(bytes),
            unknown:
              response.status < 200 ||
              (response.status >= 300 && response.status < 400) ||
              response.status >= 500 ||
              response.status === 499,
          };
        } else {
          const definition = SERVICES[service].methods[method];
          const metadata = new grpc.Metadata();
          metadata.add("authorization", `Bearer ${token}`);
          metadata.add("x-goog-user-project", PROJECT);
          let metadataBytesIn = FRAMING_RESERVE;
          let candidate = {
            ok: false,
            code: "UNKNOWN",
            unknown: true,
            body: {},
            bodyBytes: null,
            layoutVerdict: "NOT_COMPARABLE",
          };
          reply = await new Promise((resolve) => {
            const rpc = client.makeUnaryRequest(
              `${SERVICES[service].path}/${method}`,
              (value) => value,
              (value) => value,
              raw,
              metadata,
              { deadline: new Date(started + timeoutMs) },
              (error, bytes) => {
                if (error) {
                  const code = statusNames[error.code] ?? "UNKNOWN";
                  const details =
                    typeof error.details === "string" &&
                    Buffer.byteLength(error.details) + metadataBytesIn <=
                      CAPS.metadataBytesEachDirection
                      ? error.details
                      : null;
                  candidate = {
                    ok: false,
                    code,
                    unknown: unsure.has(code) || details === null,
                    body: details === null ? {} : { error: { status: code, message: details } },
                    bodyBytes: null,
                    layoutVerdict: "NOT_COMPARABLE_NATIVE_ERROR_BODY_NOT_CAPTURED",
                  };
                } else {
                  try {
                    if (
                      !Buffer.isBuffer(bytes) ||
                      bytes.length + metadataBytesIn > CAPS.metadataBytesEachDirection
                    )
                      throw new Error("native response byte cap");
                    candidate = {
                      ok: true,
                      code: "OK",
                      unknown: false,
                      body: decode(typeOf(definition[1]), bytes),
                      bodyBytes: bytes.length,
                      metadataBytesIn,
                      bodySha256: sha256(bytes),
                    };
                  } catch {
                    candidate = {
                      ok: false,
                      code: "UNKNOWN",
                      unknown: true,
                      body: {},
                      bodyBytes: null,
                      layoutVerdict: "NOT_COMPARABLE",
                    };
                  }
                }
              },
            );
            rpc.on("metadata", (value) => {
              metadataBytesIn += metadataBytes(value);
              if (metadataBytesIn > CAPS.metadataBytesEachDirection) rpc.cancel();
            });
            rpc.on("status", (status) => {
              metadataBytesIn += metadataBytes(status.metadata, status.details);
              if (metadataBytesIn + (candidate.bodyBytes ?? 0) > CAPS.metadataBytesEachDirection) {
                rpc.cancel();
                resolve({
                  ok: false,
                  code: "UNKNOWN",
                  unknown: true,
                  body: {},
                  bodyBytes: null,
                  metadataBytesIn,
                  layoutVerdict: "NOT_COMPARABLE_METADATA_OVERFLOW",
                });
              } else
                resolve({
                  ...candidate,
                  metadataBytesIn,
                  unknown: candidate.unknown || statusNames[status.code] !== candidate.code,
                });
            });
            controller.signal.addEventListener("abort", () => rpc.cancel(), { once: true });
          });
        }
      } catch {
        reply = { ok: false, code: "UNKNOWN", unknown: true, body: {} };
      } finally {
        clearTimeout(requestTimer);
        controllers.delete(controller);
      }
      reply = normalizeOutcome(reply, { method, request });
      if (reply.unknown && !maintenance) sourceStopped = true;
      reply.durationMs = meter.clock() - monotonicStarted;
      journal.write({
        event: "response",
        cellId,
        requestId,
        transport,
        method,
        durationMs: reply.durationMs,
        reply,
      });
      try {
        meter.remaining(maintenance);
      } catch {
        reply.budgetOverrun = true;
        journal.write({ event: "request-budget-overrun", cellId, requestId, transport, method });
      }
      return reply;
    },
    async open(options) {
      if (sourceStopped) throw new Error("source stopped");
      activeStream = await openStream({ ...api, ...options });
      if (sourceStopped) activeStream.cancel("source-signal");
      return activeStream;
    },
  };
  return api;
}
