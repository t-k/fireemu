// Bounded durable inbound candidates only; peer terminal and owned process proofs belong to the collector.
import { createStreamingFrameDecoder, credentialPrefix } from "./streaming-frames.mjs";

export function createStreamingReceiptQueue({
  maxFrameBytes,
  maxTotalBytes,
  maxFrames,
  maxChunks,
  maxHeaderBytes,
  maxHeaderEvents,
  maxHeaderPairs,
  maxEvents,
  wallMs,
  deadlineAt,
  credential,
  persist,
  onFrame,
  stopOwned,
  signal,
}) {
  for (const value of [maxHeaderBytes, maxHeaderEvents, maxHeaderPairs, maxEvents, wallMs])
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new Error("finite positive receipt bounds required");
  if (wallMs > 2147483647) throw new Error("finite timer bound required");
  for (const callback of [persist, onFrame, stopOwned])
    if (typeof callback !== "function") throw new Error("owned receipt callbacks required");
  const startedAt = performance.now(),
    deadline = deadlineAt === undefined ? startedAt + wallMs : deadlineAt;
  if (!Number.isFinite(deadline) || deadline <= startedAt || deadline > startedAt + wallMs)
    throw new Error("live bounded monotonic deadline required");
  const decoder = createStreamingFrameDecoder({
    maxFrameBytes,
    maxTotalBytes,
    maxFrames,
    maxChunks,
    credential,
  });
  const secret = credential === undefined ? undefined : credentialPrefix(credential);
  const controller = new AbortController(),
    pending = new Map();
  let events = 0,
    persistedEvents = 0,
    drainedEvents = 0,
    frameAttempts = 0,
    acknowledgedFrames = 0,
    headerBytes = 0,
    headerEvents = 0,
    reason,
    closed = false,
    chain = Promise.resolve(),
    ownedStarted = false,
    ownedSettled = false,
    ownedFailed = false,
    uncertainSeen = false;
  function track(id, callback) {
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
  function requestOwnedStop() {
    if (ownedStarted) return;
    ownedStarted = true;
    track("owned-stop", () => stopOwned({ signal: controller.signal, reason })).then(
      () => {
        if (performance.now() >= deadline) uncertainSeen = true;
        else ownedSettled = true;
      },
      () => {
        ownedFailed = true;
      },
    );
  }
  function stop(why) {
    reason ??= why;
    controller.abort();
    requestOwnedStop();
  }
  const onAbort = () => stop("abort");
  signal?.addEventListener("abort", onAbort, { once: true });
  if (signal?.aborted) stop("abort");
  const timer = setTimeout(() => stop("deadline"), Math.max(0, deadline - performance.now()));
  timer.unref();
  function checkBudget() {
    if (performance.now() >= deadline) {
      stop("deadline");
      throw new Error("receipt deadline");
    }
  }
  function admit() {
    if (closed || reason) return false;
    if (performance.now() >= deadline) {
      stop("deadline");
      return false;
    }
    if (events >= maxEvents) {
      stop("event-bound");
      return false;
    }
    return true;
  }
  function enqueue(row, candidates = []) {
    row = Object.freeze({ ...row, index: events++ });
    chain = chain.then(async () => {
      try {
        checkBudget();
        try {
          await track(`receipt:${row.index}`, () => persist(row, { signal: controller.signal }));
        } catch {
          stop("persistence");
          return;
        }
        persistedEvents++;
        for (const frame of candidates) {
          if (reason) break;
          checkBudget();
          frameAttempts++;
          try {
            await track(`frame:${frame.index}`, () =>
              onFrame(Object.freeze({ ...frame }), { signal: controller.signal }),
            );
          } catch {
            stop("observer");
            return;
          }
          acknowledgedFrames++;
        }
      } catch {
        stop("deadline");
      } finally {
        drainedEvents++;
      }
    });
  }
  function data(input) {
    if (!admit()) return false;
    let result;
    try {
      result = decoder.push(input);
    } catch {
      stop("invalid-data");
      return false;
    }
    if (result.raw) enqueue({ kind: "data", raw: Object.freeze({ ...result.raw }) }, result.frames);
    if (result.reason) {
      stop(result.reason);
      return false;
    }
    return true;
  }
  function headers(kind, raw, flags = 0) {
    if (!admit()) return false;
    if (
      !["response", "trailers", "additional"].includes(kind) ||
      !Number.isInteger(flags) ||
      flags < 0 ||
      flags > 255 ||
      !Array.isArray(raw) ||
      raw.length % 2
    ) {
      stop("invalid-headers");
      return false;
    }
    if (headerEvents >= maxHeaderEvents) {
      stop("header-event-bound");
      return false;
    }
    if (raw.length > maxHeaderPairs * 2) {
      stop("header-pair-bound");
      return false;
    }
    let size = 0;
    for (const value of raw) {
      if (typeof value !== "string") {
        stop("invalid-headers");
        return false;
      }
      size += Buffer.byteLength(value);
      if (size > maxHeaderBytes - headerBytes) {
        stop("header-bound");
        return false;
      }
      if (secret && Buffer.from(value).includes(secret)) {
        stop("credential-reflection");
        return false;
      }
    }
    if (secret)
      for (let index = 0; index < raw.length; index += 2)
        if (raw[index].endsWith("-bin"))
          for (const part of raw[index + 1].split(","))
            if (Buffer.from(part.trim(), "base64").includes(secret)) {
              stop("credential-reflection");
              return false;
            }
    headerBytes += size;
    headerEvents++;
    enqueue({ kind, flags, rawHeaders: Object.freeze(raw.slice()) });
    return true;
  }
  function lifecycle(kind) {
    if (!admit()) return false;
    if (
      !["end", "close", "error", "goaway", "reset", "abort", "local-cancel", "half-close"].includes(
        kind,
      )
    ) {
      stop("invalid-lifecycle");
      return false;
    }
    enqueue({ kind });
    return true;
  }
  async function boundedWait(work) {
    let cutoff;
    const expired = new Promise((resolve) => {
      cutoff = setTimeout(resolve, Math.max(0, deadline - performance.now()));
    });
    try {
      await Promise.race([work, expired]);
    } finally {
      clearTimeout(cutoff);
    }
  }
  async function done() {
    closed = true;
    const framing = decoder.finish();
    if (framing.reason) stop(framing.reason);
    await boundedWait(chain);
    requestOwnedStop();
    await boundedWait(Promise.allSettled(pending.values()));
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
    uncertainSeen =
      uncertainSeen ||
      pending.size > 0 ||
      drainedEvents !== events ||
      performance.now() >= deadline;
    return {
      deadlineAt: deadline,
      events,
      persistedEvents,
      unknownEvents: events - persistedEvents,
      frameAttempts,
      acknowledgedFrames,
      headerBytes,
      headerEvents,
      framing,
      ...(reason ? { reason } : {}),
      pendingCallbacks: [...pending.keys()],
      terminationRequired: uncertainSeen || ownedFailed || !ownedSettled,
    };
  }
  return { data, headers, lifecycle, done };
}
