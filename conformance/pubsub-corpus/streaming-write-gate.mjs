// Injected outbound admission only; no connection, peer status or process-quiescence proof.
import { createHash } from "node:crypto";
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const byteLengthOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength").get;
const byteOffsetOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset").get;
const bufferOf = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer").get;

export function createStreamingWriteGate({
  maxFrames,
  maxFrameBytes,
  maxOutgoingBytes,
  maxActions,
  wallMs,
  deadlineAt,
  guard,
  liveCheck,
  persist,
  issue,
  contain,
  signal,
  credential,
}) {
  for (const bound of [maxFrames, maxFrameBytes, maxOutgoingBytes, maxActions, wallMs])
    if (!Number.isSafeInteger(bound) || bound <= 0)
      throw new Error("finite positive bounds required");
  if (wallMs > 2147483647 || maxFrameBytes > 4294967295)
    throw new Error("finite timer/wire bounds required");
  for (const callback of [guard, liveCheck, persist, issue, contain])
    if (typeof callback !== "function")
      throw new Error("reviewed synchronous issue/live check and owned callbacks required");
  if (
    credential !== undefined &&
    (typeof credential !== "string" || !credential || Buffer.byteLength(credential) > 16384)
  )
    throw new Error("bounded credential required");
  const secret = credential === undefined ? undefined : Buffer.from(credential);
  const startedAt = performance.now(),
    deadline = deadlineAt === undefined ? startedAt + wallMs : deadlineAt;
  if (!Number.isFinite(deadline) || deadline <= startedAt || deadline > startedAt + wallMs)
    throw new Error("live bounded monotonic deadline required");
  const controller = new AbortController(),
    pending = new Map();
  let attemptedActions = 0,
    issuedActions = 0,
    completedActions = 0,
    openingReservations = 0,
    frameReservations = 0,
    outgoingBytes = 0,
    active = false,
    direction = "NEW",
    stopOrigin,
    containmentSettled = false,
    containmentFailed = false,
    unsettledObserved = false,
    synchronousContractFailed = false,
    issueFailed = false;
  const origins = new Set([
    "peer-terminal",
    "client-cancel",
    "revocation",
    "abort",
    "deadline",
    "local-close",
    "uncertain",
  ]);
  let timer;
  function tracked(id, callback) {
    let resolve, reject;
    const work = new Promise((r, j) => {
      resolve = r;
      reject = j;
    });
    const observed = work.then(
      (value) => {
        pending.delete(id);
        return value;
      },
      (error) => {
        pending.delete(id);
        throw error;
      },
    );
    pending.set(id, observed);
    try {
      resolve(callback());
    } catch (error) {
      reject(error);
    }
    return observed;
  }
  function stop(origin = "uncertain") {
    if (stopOrigin) return;
    stopOrigin = origins.has(origin) ? origin : "uncertain";
    controller.abort();
    tracked("containment", () => contain({ signal: controller.signal, origin: stopOrigin })).then(
      () => {
        if (performance.now() >= deadline) unsettledObserved = true;
        else containmentSettled = true;
      },
      () => {
        containmentFailed = true;
      },
    );
  }
  const onAbort = () => stop("abort");
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) stop("abort");
  timer = setTimeout(() => stop("deadline"), Math.max(0, deadline - performance.now()));
  timer.unref();
  function check() {
    if (performance.now() >= deadline) stop("deadline");
    if (stopOrigin) throw new Error("streaming admission stopped");
  }
  async function bounded(id, callback) {
    check();
    const remaining = deadline - performance.now();
    let cutoff;
    const expired = new Promise((_, reject) => {
      cutoff = setTimeout(
        () => {
          stop("deadline");
          reject(new Error("streaming admission stopped"));
        },
        Math.max(0, remaining),
      );
    });
    try {
      return await Promise.race([
        tracked(id, () => {
          check();
          return callback();
        }),
        expired,
      ]);
    } finally {
      clearTimeout(cutoff);
    }
  }
  function rejectAsync(id, result) {
    if (result?.then) {
      synchronousContractFailed = true;
      tracked(id, () => result).catch(() => {});
      stop("uncertain");
      throw new Error("streaming admission stopped");
    }
  }
  function action(kind, input) {
    check();
    if (active) throw new Error("concurrent streaming actions forbidden");
    if (kind === "open" && openingReservations) throw new Error("one opening required");
    if (kind !== "open" && direction === "NEW") throw new Error("opening required");
    if ((kind === "frame" || kind === "half-close") && direction !== "OPEN")
      throw new Error("write direction is closed");
    if (kind === "frame" && (!ArrayBuffer.isView(input) || !(input instanceof Uint8Array)))
      throw new Error("raw frame bytes required");
    const payloadLength = kind === "frame" ? byteLengthOf.call(input) : 0;
    const length = kind === "frame" ? payloadLength + 5 : 0;
    if (
      attemptedActions >= maxActions ||
      (kind === "frame" &&
        (payloadLength > maxFrameBytes ||
          frameReservations >= maxFrames ||
          length > maxOutgoingBytes - outgoingBytes))
    )
      throw new Error("streaming reservation bound exceeded");
    const wire = kind === "frame" ? Buffer.alloc(length) : undefined;
    if (wire) {
      wire.writeUInt32BE(payloadLength, 1);
      Buffer.from(
        new Uint8Array(bufferOf.call(input), byteOffsetOf.call(input), payloadLength),
      ).copy(wire, 5);
    }
    if (secret && wire?.includes(secret)) throw new Error("credential reflection refused");
    const intent = Object.freeze({
      index: attemptedActions++,
      kind,
      ...(wire
        ? {
            frameBase64: wire.toString("base64"),
            frameBytes: wire.length,
            frameSha256: createHash("sha256").update(wire).digest("hex"),
          }
        : {}),
    });
    if (kind === "open") openingReservations++;
    if (kind === "frame") {
      frameReservations++;
      outgoingBytes += length;
    }
    active = true;
    return (async () => {
      try {
        await bounded(`${intent.index}:guard-before`, () =>
          guard(intent, { signal: controller.signal }),
        );
        await bounded(`${intent.index}:intent`, () =>
          persist(Object.freeze({ ...intent, state: "before-send" }), {
            signal: controller.signal,
          }),
        );
        await bounded(`${intent.index}:guard-after`, () =>
          guard(intent, { signal: controller.signal }),
        );
        check();
        const live = liveCheck(intent);
        rejectAsync(`${intent.index}:async-live`, live);
        if (live !== true) {
          stop("revocation");
          check();
        }
        check();
        let result;
        try {
          result = issue(intent, wire ? Buffer.from(wire) : undefined);
        } catch (error) {
          // A native write can throw after some bytes left; nothing proves otherwise.
          issueFailed = true;
          throw error;
        }
        rejectAsync(`${intent.index}:async-issue`, result);
        issuedActions++;
        if (kind === "open") direction = "OPEN";
        if (kind === "half-close") direction = "HALF_CLOSED";
        await bounded(`${intent.index}:issued`, () =>
          persist(Object.freeze({ ...intent, state: "issued" }), { signal: controller.signal }),
        );
        completedActions++;
        if (kind === "client-cancel") stop("client-cancel");
      } catch {
        stop("uncertain");
        throw new Error("streaming admission stopped");
      } finally {
        active = false;
      }
    })();
  }
  async function done() {
    stop("local-close");
    let cutoff;
    const expired = new Promise((resolve) => {
      cutoff = setTimeout(resolve, Math.max(0, deadline - performance.now()));
    });
    try {
      await Promise.race([Promise.allSettled(pending.values()), expired]);
    } finally {
      clearTimeout(cutoff);
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
    unsettledObserved = unsettledObserved || pending.size > 0 || performance.now() >= deadline;
    return {
      deadlineAt: deadline,
      attemptedActions,
      issuedActions,
      completedActions,
      unknownActions: attemptedActions - completedActions,
      openingReservations,
      frameReservations,
      outgoingBytes,
      direction,
      stopOrigin,
      pendingCallbacks: [...pending.keys()],
      terminationRequired:
        unsettledObserved ||
        synchronousContractFailed ||
        issueFailed ||
        containmentFailed ||
        !containmentSettled,
    };
  }
  return {
    open: () => action("open"),
    write: (bytes) => action("frame", bytes),
    halfClose: () => action("half-close"),
    cancel: () => action("client-cancel"),
    stop,
    done,
  };
}
