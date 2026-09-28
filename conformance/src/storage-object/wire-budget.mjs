import { HTTP_RESPONSE_READ_UNIT_BYTES } from "./wire-limits.mjs";

/** One shared plaintext byte meter; the transport must enforce the fixed receive unit. */
export function createStage3WireBudget(limits, { onReserve } = {}) {
  const { maxRequestBytes, maxResponseBytes, maxPerResponseWireBytes, responseReadUnitBytes } =
    limits;
  if (
    typeof onReserve !== "function" ||
    [maxRequestBytes, maxResponseBytes, maxPerResponseWireBytes].some(
      (value) => !Number.isSafeInteger(value) || value <= 0 || value > 2 ** 40,
    ) ||
    responseReadUnitBytes !== HTTP_RESPONSE_READ_UNIT_BYTES
  )
    throw new Error("invalid wire budget bound");
  let pending = false;
  let active = null;
  let halted = false;
  let attempts = 0;
  let requestReservedBytes = 0;
  let responseObservedBytes = 0;
  let largestResponseReadBytes = 0;
  let readAfterHaltBytes = 0;

  return {
    async reserve(operationId, requestBytes) {
      if (halted) throw new Error("wire budget is halted");
      if (pending || active) throw new Error("wire attempt is active");
      if (
        typeof operationId !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(operationId) ||
        !Number.isSafeInteger(requestBytes) ||
        requestBytes <= 0
      )
        throw new Error("invalid wire budget bound");
      if (requestBytes > maxRequestBytes - requestReservedBytes)
        throw new Error("request wire cap exhausted");
      const responseReservedBytes = maxPerResponseWireBytes + responseReadUnitBytes;
      if (responseReservedBytes > maxResponseBytes - responseObservedBytes)
        throw new Error("response wire cap exhausted");
      pending = true;
      try {
        await onReserve({
          sequence: attempts + 1,
          operationId,
          requestReservedBytes: requestBytes,
          responseReservedBytes,
        });
        attempts++;
        requestReservedBytes += requestBytes;
        const token = {};
        active = token;
        let responseBytes = 0;
        const requireActive = () => {
          if (active !== token) throw new Error("wire attempt is inactive");
        };
        return Object.freeze({
          sequence: attempts,
          receive(bytes) {
            requireActive();
            if (!Number.isSafeInteger(bytes) || bytes <= 0 || bytes > 2 ** 30)
              throw new Error("invalid received byte count");
            if (halted) readAfterHaltBytes += bytes;
            responseBytes += bytes;
            responseObservedBytes += bytes;
            largestResponseReadBytes = Math.max(largestResponseReadBytes, bytes);
            if (halted) throw new Error("wire budget is halted");
            if (bytes > responseReadUnitBytes) {
              halted = true;
              throw new Error("response read-unit bound violated");
            }
            if (
              responseBytes > maxPerResponseWireBytes ||
              responseObservedBytes > maxResponseBytes
            ) {
              halted = true;
              throw new Error("response attempt cap exceeded");
            }
          },
          finish() {
            requireActive();
            active = null;
          },
          snapshot: () => ({ responseObservedBytes: responseBytes }),
        });
      } finally {
        pending = false;
      }
    },
    snapshot() {
      return {
        attempts,
        requestReservedBytes,
        responseObservedBytes,
        largestResponseReadBytes,
        readAfterHaltBytes,
        active: pending || active !== null,
        halted,
        boundary: "HTTP_PLAINTEXT_DELIVERED_TO_ONREAD",
      };
    },
  };
}
