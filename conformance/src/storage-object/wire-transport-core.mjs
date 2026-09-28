import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { once } from "node:events";
import { types } from "node:util";
import { createStage3WireBudget } from "./wire-budget.mjs";
import { HTTP_RESPONSE_READ_UNIT_BYTES, MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const PINNED_NODE_VERSION = "v24.14.0";
const FAILURE_CODES = new Set([
  "WIRE_ABORTED",
  "WIRE_ABORTED_BEFORE_DISPATCH",
  "WIRE_PREDISPATCH_REJECTED",
  "WIRE_TRUNCATED",
  "WIRE_REQUEST_SERIALIZATION_DIFFERED",
  "WIRE_TIMEOUT",
  "WIRE_CAPTURE_FAILED",
  "WIRE_RESPONSE_CAP_EXCEEDED",
  "WIRE_TLS_VALIDATION_FAILED",
  "WIRE_CONNECTION_FAILED",
  "WIRE_UNSUPPORTED_ENCODING",
  "WIRE_RESPONSE_BODY_CAP_EXCEEDED",
  "WIRE_RESPONSE_FAILED",
  "WIRE_UNEXPECTED_UPGRADE",
  "WIRE_REQUEST_FAILED",
  "WIRE_REQUEST_CREATION_FAILED",
]);

function safeFailure(error) {
  let message = "";
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, "message");
    if (descriptor && Object.hasOwn(descriptor, "value") && typeof descriptor.value === "string")
      message = descriptor.value;
  } catch {
    /* Unknown accessors and traps are never used as failure text. */
  }
  if (FAILURE_CODES.has(message)) return new Error(message);
  if (message === "request wire cap exhausted") return new Error("WIRE_REQUEST_CAP_EXHAUSTED");
  if (message === "response wire cap exhausted") return new Error("WIRE_RESPONSE_CAP_EXHAUSTED");
  if (message === "wire budget is halted") return new Error("WIRE_BUDGET_HALTED");
  return new Error("WIRE_PREDISPATCH_OR_CAPTURE_FAILED");
}

function requireSynchronousCaptureCompletion(value) {
  if (types.isPromise(value)) void Promise.prototype.then.call(value, undefined, () => {});
  if (value !== undefined) throw new Error("WIRE_CAPTURE_FAILED");
}

/** Factories supply closed serialization, capture and TLS policies to this shared byte meter/socket core. */
export function createWireTransportCore({
  limits,
  onByteReserve,
  serializeRequest,
  createCapture,
  tlsConnectionOptions,
  timeoutMs = 30_000,
}) {
  if (
    process.version !== PINNED_NODE_VERSION ||
    typeof onByteReserve !== "function" ||
    typeof serializeRequest !== "function" ||
    typeof createCapture !== "function" ||
    typeof tlsConnectionOptions !== "function" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000
  )
    throw new Error("invalid wire transport core configuration");
  let context = null;
  const meter = createStage3WireBudget(limits, {
    onReserve: (event) => onByteReserve({ ...event, phase: context.phase }),
  });
  let busy = false;
  let closed = false;
  let abortActive = null;
  let activePromise = null;
  let activeCall = null;

  async function dispatch(value, init = {}) {
    if (closed) throw new Error("WIRE_CLOSED");
    if (busy) throw new Error("WIRE_CONCURRENT_DISPATCH");
    if (!["subject", "cleanup", "recovery"].includes(init.accountingPhase))
      throw new Error("WIRE_INVALID_PHASE");
    let serialized;
    try {
      serialized = serializeRequest(value, init);
    } catch (error) {
      throw safeFailure(error);
    }
    busy = true;
    context = { phase: init.accountingPhase };
    let attempt = null;
    let capture = null;
    let result = null;
    let failure = null;
    let responseReturn = null;
    try {
      attempt = await meter.reserve(init.operationId, serialized.wire.length);
      const createdCapture = createCapture({
        sequence: attempt.sequence,
        serialized,
        metadata: {
          operationId: init.operationId,
          phase: init.accountingPhase,
          url: serialized.url.href,
          nodeVersion: process.version,
          boundary: "HTTP_PLAINTEXT_DELIVERED_TO_ONREAD",
        },
      });
      if (types.isPromise(createdCapture)) {
        void Promise.prototype.then.call(createdCapture, undefined, () => {});
        throw new Error("WIRE_CAPTURE_FAILED");
      }
      if (
        !createdCapture ||
        Object.getPrototypeOf(createdCapture) !== Object.prototype ||
        !Object.isFrozen(createdCapture) ||
        Object.hasOwn(createdCapture, "then")
      )
        throw new Error("WIRE_CAPTURE_FAILED");
      for (const name of ["appendResponse", "finish"]) {
        const descriptor = Object.getOwnPropertyDescriptor(createdCapture, name);
        if (
          !descriptor ||
          !Object.hasOwn(descriptor, "value") ||
          typeof descriptor.value !== "function" ||
          Object.getPrototypeOf(descriptor.value) !== Function.prototype
        )
          throw new Error("WIRE_CAPTURE_FAILED");
      }
      capture = createdCapture;
      if (closed || init.signal?.aborted) throw new Error("WIRE_ABORTED_BEFORE_DISPATCH");
      try {
        init.verifyBeforeDispatch?.();
      } catch {
        throw new Error("WIRE_PREDISPATCH_REJECTED");
      }
      activePromise = execute(serialized, init, attempt, capture);
      result = await activePromise;
      if (result.reason) throw new Error(result.reason);
      const body = result.body;
      responseReturn = {
        status: result.status,
        headers: new Headers(result.headers),
        arrayBuffer: async () => body,
      };
    } catch (error) {
      failure = safeFailure(error);
    } finally {
      abortActive = null;
      activePromise = null;
      try {
        if (capture)
          requireSynchronousCaptureCompletion(
            capture.finish({
              complete: failure === null,
              reason: result?.reason ?? failure?.message ?? null,
              status: result?.status ?? null,
              finishConfirmed: result?.finishConfirmed ?? false,
              socketReportedWrittenBytes: result?.socketReportedWrittenBytes ?? 0,
              requestReservedBytes: serialized.wire.length,
              responseObservedBytes: attempt.snapshot().responseObservedBytes,
              rawResponseHeaders: result?.rawHeaders ?? [],
              responseBodyBase64: result?.body?.toString("base64") ?? null,
            }),
          );
      } catch {
        failure = new Error("WIRE_CAPTURE_FAILED");
      } finally {
        attempt?.finish();
        busy = false;
        context = null;
      }
    }
    if (failure) throw failure;
    return responseReturn;
  }

  function execute(serialized, init, attempt, capture) {
    return new Promise((resolve) => {
      let request = null;
      let socket = null;
      let response = null;
      let bodyBytes = 0;
      const chunks = [];
      let reason = null;
      let responseEnded = false;
      let finishConfirmed = false;
      let settled = false;
      const secure = serialized.url.protocol === "https:";
      const agent = secure
        ? new https.Agent({ keepAlive: false, maxSockets: 1 })
        : new http.Agent({ keepAlive: false, maxSockets: 1 });
      const fail = (code) => {
        reason ??= code;
        request?.destroy();
        socket?.destroy();
      };
      abortActive = () => fail("WIRE_ABORTED");
      const timer = setTimeout(() => fail("WIRE_TIMEOUT"), timeoutMs);
      const onAbort = () => fail("WIRE_ABORTED");
      init.signal?.addEventListener("abort", onAbort, { once: true });
      const settle = async () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        init.signal?.removeEventListener("abort", onAbort);
        agent.destroy();
        if (socket && !socket.closed) {
          try {
            await once(socket, "close");
          } catch {
            /* The sanitized reason is already retained. */
          }
        }
        if (!responseEnded && !reason) reason = "WIRE_TRUNCATED";
        if (finishConfirmed && socket?.bytesWritten !== serialized.wire.length && !reason)
          reason = "WIRE_REQUEST_SERIALIZATION_DIFFERED";
        const headers = [];
        for (let i = 0; i < (response?.rawHeaders.length ?? 0); i += 2)
          headers.push([response.rawHeaders[i], response.rawHeaders[i + 1]]);
        resolve({
          reason,
          status: response?.statusCode ?? null,
          headers,
          rawHeaders: response?.rawHeaders ?? [],
          body: Buffer.concat(chunks, bodyBytes),
          finishConfirmed,
          socketReportedWrittenBytes: socket?.bytesWritten ?? 0,
        });
      };
      // A dedicated agent is necessary: agent:false would bypass a supplied createConnection.
      agent.createConnection = () => {
        const options = {
          host: serialized.url.hostname.replace(/^\[|\]$/g, ""),
          port: Number(serialized.url.port || (secure ? 443 : 80)),
          highWaterMark: HTTP_RESPONSE_READ_UNIT_BYTES,
          onread: {
            buffer: Buffer.alloc(HTTP_RESPONSE_READ_UNIT_BYTES),
            callback(nread, buffer) {
              let accountingError = null;
              try {
                attempt.receive(nread);
              } catch (error) {
                accountingError = error;
              }
              try {
                requireSynchronousCaptureCompletion(
                  capture.appendResponse(buffer.subarray(0, nread)),
                );
              } catch {
                fail("WIRE_CAPTURE_FAILED");
                return false;
              }
              if (accountingError) {
                fail("WIRE_RESPONSE_CAP_EXCEEDED");
                return false;
              }
              if (reason || socket.destroyed) return false;
              // Copy the reused onread buffer before the standard HTTP parser consumes it.
              return socket.push(Buffer.from(buffer.subarray(0, nread)));
            },
          },
        };
        socket = secure
          ? tls.connect({
              ...options,
              ...tlsConnectionOptions(serialized.url),
              ALPNProtocols: ["http/1.1"],
            })
          : net.connect(options);
        if (secure)
          socket.once("secureConnect", () => {
            if (!socket.authorized || (socket.alpnProtocol && socket.alpnProtocol !== "http/1.1"))
              fail("WIRE_TLS_VALIDATION_FAILED");
          });
        socket.on("error", () => fail("WIRE_CONNECTION_FAILED"));
        return socket;
      };
      try {
        request = (secure ? https : http).request(
          serialized.url,
          {
            method: serialized.method,
            headers: serialized.headers,
            setDefaultHeaders: false,
            setHost: false,
            agent,
            maxHeaderSize: 16 * 1024,
          },
          (incoming) => {
            response = incoming;
            if (reason) {
              incoming.destroy();
              return;
            }
            if (
              incoming.headers["content-encoding"] &&
              incoming.headers["content-encoding"] !== "identity"
            )
              fail("WIRE_UNSUPPORTED_ENCODING");
            incoming.on("data", (chunk) => {
              if (reason) return;
              if (chunk.length > MAX_RESPONSE_BODY_BYTES - bodyBytes) {
                fail("WIRE_RESPONSE_BODY_CAP_EXCEEDED");
                return;
              }
              bodyBytes += chunk.length;
              chunks.push(Buffer.from(chunk));
            });
            incoming.once("end", () => {
              responseEnded = true;
            });
            incoming.once("aborted", () => fail("WIRE_TRUNCATED"));
            incoming.once("error", () => fail("WIRE_RESPONSE_FAILED"));
          },
        );
        request.once("finish", () => {
          finishConfirmed = true;
        });
        request.once("upgrade", () => fail("WIRE_UNEXPECTED_UPGRADE"));
        request.once("error", () => fail("WIRE_REQUEST_FAILED"));
        request.once("close", () => {
          void settle();
        });
        request.end(serialized.body);
      } catch {
        fail("WIRE_REQUEST_CREATION_FAILED");
        void settle();
      }
    });
  }

  return Object.freeze({
    fetch(value, init) {
      if (activeCall) return Promise.reject(new Error("WIRE_CONCURRENT_DISPATCH"));
      const call = dispatch(value, init);
      activeCall = call;
      const finished = () => {
        if (activeCall === call) activeCall = null;
      };
      void call.then(finished, finished);
      return call;
    },
    snapshot: () => ({ ...meter.snapshot(), busy, closed, nodeVersion: process.version }),
    async close() {
      closed = true;
      abortActive?.();
      if (activeCall) {
        try {
          await activeCall;
        } catch {
          /* The caller receives the sanitized attempt failure. */
        }
      }
    },
  });
}
