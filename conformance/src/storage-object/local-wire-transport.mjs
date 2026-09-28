import { createWireTransportCore } from "./wire-transport-core.mjs";
import { createPrivateWireAttempt } from "./private-wire-capture.mjs";
import { loopbackHttpOrigin, serializeLocalHttpRequest } from "./wire-serialization.mjs";

/** Exact local HTTP plaintext captures. This facade accepts only explicit loopback origins. */
export function createLocalWireTransport({
  origins,
  limits,
  captureDirectory,
  onByteReserve,
  localCa,
  timeoutMs = 30_000,
}) {
  if (
    process.version !== "v24.14.0" ||
    !Array.isArray(origins) ||
    origins.length < 1 ||
    origins.length > 4 ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30_000 ||
    (localCa !== undefined && !Buffer.isBuffer(localCa)) ||
    typeof onByteReserve !== "function"
  )
    throw new Error("invalid local wire transport configuration");
  const allowed = origins.map(loopbackHttpOrigin);
  return createWireTransportCore({
    limits,
    onByteReserve,
    timeoutMs,
    serializeRequest: (value, init) => serializeLocalHttpRequest(value, init, allowed),
    createCapture: ({ sequence, serialized, metadata }) =>
      createPrivateWireAttempt({
        directory: captureDirectory,
        sequence,
        request: serialized.wire,
        metadata,
      }),
    tlsConnectionOptions: (url) => ({
      servername: url.hostname === "localhost" ? "localhost" : undefined,
      ...(localCa === undefined ? {} : { ca: localCa }),
    }),
  });
}
