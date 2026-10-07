import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { SERVICES, requestToWire, responseFromWire } from "../pubsub-production/grpc.mjs";
import { sha256 } from "../pubsub-production/admission.mjs";
import { CAPS, PROJECT } from "./plan.mjs";
import { encodedSizes } from "./payload.mjs";
import { openStream } from "./stream.mjs";

const statusNames = Object.fromEntries(
  Object.entries(grpc.status).map(([key, value]) => [value, key]),
);
const unsure = new Set(["UNKNOWN", "INTERNAL", "UNAVAILABLE", "DEADLINE_EXCEEDED", "CANCELLED"]);
const types = protos.google.pubsub.v1;
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
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > CAPS.metadataBytesEachDirection) {
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
  fetch = globalThis.fetch,
  client = new grpc.Client("pubsub.googleapis.com:443", grpc.credentials.createSsl(), {
    "grpc.enable_retries": 0,
    "grpc.max_receive_message_length": CAPS.metadataBytesEachDirection,
    "grpc.max_send_message_length": CAPS.largeEncodedPayloadBytes + CAPS.metadataBytesEachDirection,
  }),
  now = Date.now,
} = {}) {
  let sequence = 0;
  const credential = async (maintenance) => {
    const timeout = Math.min(30000, meter.remaining(maintenance));
    let timer;
    const controller = new AbortController();
    try {
      return await Promise.race([
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
    }
  };
  const api = {
    client,
    meter,
    journal,
    credential,
    now,
    close: () => client.close(),
    async call(call) {
      const { category, transport, service, method, request, routeName, cellId } = call;
      const maintenance =
        category.startsWith("cleanup") || ["resourceRead", "unknownDeleteRead"].includes(category);
      meter.start(category, transport);
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
      const timeoutMs = Math.min(
        method.startsWith("Create") ? 80000 : 30000,
        meter.remaining(maintenance),
      );
      const started = now(),
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
        requestSha256: sha256(raw),
        requestDeadlineAt: new Date(started + timeoutMs).toISOString(),
      });
      let reply;
      try {
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
            signal: AbortSignal.timeout(timeoutMs),
          });
          const bytes = await readResponse(response);
          let body;
          try {
            body = bytes.length === 0 ? {} : JSON.parse(bytes);
          } catch {
            throw new Error("unreadable response");
          }
          reply = {
            ok: response.status >= 200 && response.status < 300,
            status: response.status,
            code: body?.error?.status ?? (response.ok ? "OK" : "UNKNOWN"),
            body,
            bodyBytes: bytes.length,
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
          reply = await new Promise((resolve) =>
            client.makeUnaryRequest(
              `${SERVICES[service].path}/${method}`,
              (value) => value,
              (value) => value,
              raw,
              metadata,
              { deadline: new Date(started + timeoutMs) },
              (error, bytes) => {
                if (error) {
                  const code = statusNames[error.code] ?? "UNKNOWN";
                  resolve({ ok: false, code, unknown: unsure.has(code), body: {} });
                } else {
                  try {
                    resolve({
                      ok: true,
                      code: "OK",
                      unknown: false,
                      body: decode(typeOf(definition[1]), bytes),
                      bodyBytes: bytes.length,
                      bodySha256: sha256(bytes),
                    });
                  } catch {
                    resolve({ ok: false, code: "UNKNOWN", unknown: true, body: {} });
                  }
                }
              },
            ),
          );
        }
      } catch {
        reply = { ok: false, code: "UNKNOWN", unknown: true, body: {} };
      }
      journal.write({
        event: "response",
        cellId,
        requestId,
        transport,
        method,
        durationMs: now() - started,
        reply,
      });
      return reply;
    },
    open: (options) => openStream({ ...api, ...options }),
  };
  return api;
}
