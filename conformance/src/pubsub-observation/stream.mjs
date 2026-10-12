import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { PROJECT } from "./plan.mjs";
import { metadataBytes, FRAMING_RESERVE } from "./metadata.mjs";
import { CAPS } from "./plan.mjs";
const Request = protos.google.pubsub.v1.StreamingPullRequest;
const Response = protos.google.pubsub.v1.StreamingPullResponse;

export async function openStream({
  meter,
  client,
  journal,
  credential,
  beforeDispatch = () => {},
  now = Date.now,
  cellId,
  runId,
  opener,
}) {
  meter.start("stream", "streams");
  const token = await credential(false);
  const metadata = new grpc.Metadata();
  metadata.add("authorization", `Bearer ${token}`);
  metadata.add("x-goog-user-project", PROJECT);
  if (metadataBytes(metadata) + FRAMING_RESERVE > CAPS.metadataBytesEachDirection)
    throw new Error("stream outgoing metadata byte cap");
  const intentAt = now(),
    intentClock = meter.clock();
  const initialRemaining = meter.remaining();
  journal.write({
    event: "stream-dispatch",
    cellId,
    requestedWindowMs: 90000,
    requestDeadlineAt: new Date(intentAt + initialRemaining).toISOString(),
    deadlineBasis: "conservative active-cell ceiling before persistence",
  });
  beforeDispatch();
  const windowMs = Math.min(90000, meter.remaining() - 1);
  if (windowMs < 1) throw new Error("stream time exhausted before dispatch");
  const startedAt = now(),
    monotonicStarted = meter.clock();
  const preDispatchMs = monotonicStarted - intentClock;
  const rpc = client.makeBidiStreamRequest(
    "/google.pubsub.v1.Subscriber/StreamingPull",
    (value) => value,
    (value) => value,
    metadata,
    { deadline: new Date(startedAt + windowMs) },
  );
  // This exact observed terminal is a capture witness, not inferred validation success.
  const knownZeroDetails =
    "A service error has occurred. Please retry your request. If the error persists, please report it. [code=e8c0]";
  const exactZeroOpening =
    cellId === "S10" &&
    Object.keys(opener).length === 4 &&
    typeof runId === "string" &&
    /^[0-9a-f]{12}$/.test(runId) &&
    opener.subscription === `projects/${PROJECT}/subscriptions/fe${runId}-s10-sub` &&
    opener.streamAckDeadlineSeconds === 0 &&
    opener.maxOutstandingMessages === "1" &&
    opener.maxOutstandingBytes === "1024";
  let openingWrites = 0,
    zeroPhase = 0,
    initialMetadataSeen = false,
    captureFault = windowMs < 90000;
  const queue = [];
  let waiter,
    cancelled = false,
    cancelReason = null,
    ended = false,
    disposed = false,
    draining = false,
    drainPromise,
    drainTimer,
    finishDrain,
    drainFailure;
  const state = {
    startedAt,
    windowMs,
    terminal: null,
    inboundEnded: false,
    incomplete: windowMs < 90000,
    windowExpired: false,
    received: 0,
    preDispatchMs,
    metadataBytesIn: FRAMING_RESERVE,
  };
  const wake = () => {
    const callback = waiter;
    waiter = null;
    callback?.();
  };
  const elapsed = () => meter.clock() - monotonicStarted;
  const event = (name, value = {}) => {
    if (!disposed)
      journal.write({
        event: name,
        cellId,
        elapsedMs: elapsed(),
        ...value,
        ...(draining && ["stream-status", "stream-error"].includes(name)
          ? { phase: "disposal", cancelReason }
          : {}),
      });
  };
  const cancel = (reason) => {
    if (!cancelled && !state.terminal) {
      cancelled = true;
      cancelReason = reason;
      try {
        event("stream-cancel", { reason });
      } finally {
        rpc.cancel();
      }
    }
    wake();
  };
  const timer = setTimeout(
    () => {
      state.windowExpired = true;
      event("stream-observation-window-end");
      cancel("window-end");
    },
    Math.max(0, windowMs - (meter.clock() - monotonicStarted)),
  );
  rpc.on("data", (raw) => {
    if (cancelled || draining || disposed) return;
    try {
      meter.frame("in", raw.length);
      const body = Response.toObject(Response.decode(raw), {
        longs: String,
        enums: String,
        bytes: String,
        defaults: false,
      });
      journal.frame(Buffer.from(raw), {
        event: "stream-frame",
        cellId,
        direction: "in",
        elapsedMs: elapsed(),
        body,
      });
      state.received++;
      queue.push(body);
      wake();
    } catch {
      state.incomplete = true;
      captureFault = true;
      event("stream-frame-refused", { bytes: raw.length });
      cancel("frame-overflow-or-decode");
    }
  });
  const diagnostic = (details) => {
    if (details === undefined) return {};
    if (
      typeof details !== "string" ||
      metadataBytes(undefined, details) > CAPS.metadataBytesEachDirection - state.metadataBytesIn
    )
      return { details: null };
    return {
      details: details
        .replaceAll(token, "[REDACTED]")
        .replace(/\bBearer\s+\S+/gi, "Bearer [REDACTED]"),
    };
  };
  const acceptMetadata = (value, details) => {
    state.metadataBytesIn += metadataBytes(value, details);
    event("stream-metadata", { metadataBytesIn: state.metadataBytesIn });
    if (state.metadataBytesIn > CAPS.metadataBytesEachDirection) {
      state.incomplete = true;
      captureFault = true;
      cancel("metadata-overflow");
    }
  };
  const lifecycle = (callback) => (value) => {
    if (disposed) return;
    try {
      callback(value);
    } catch (error) {
      captureFault = true;
      state.incomplete = true;
      if (!draining) throw error;
      drainFailure ??= error;
      finishDrain?.();
    }
  };
  rpc.on(
    "metadata",
    lifecycle((value) => {
      if (!disposed) {
        acceptMetadata(value);
        initialMetadataSeen = true;
      }
    }),
  );
  rpc.on(
    "status",
    lifecycle((status) => {
      const details = diagnostic(status.details);
      if (!disposed) acceptMetadata(status.metadata, status.details);
      state.terminal = { code: status.code };
      const localEnd =
        cancelled &&
        ((status.code === 1 && ["window-end", "unacked-owned-delivery"].includes(cancelReason)) ||
          (status.code === 4 && state.windowExpired));
      if ([1, 2, 4, 8, 13, 14, 15].includes(status.code) && !localEnd) {
        state.incomplete = true;
        if (status.code !== 13) captureFault = true;
      }
      zeroPhase =
        zeroPhase === 1 &&
        status.code === 13 &&
        status.details === knownZeroDetails &&
        details.details === knownZeroDetails
          ? 2
          : -1;
      event("stream-status", { ...state.terminal, ...details });
      wake();
      finishDrain?.();
    }),
  );
  rpc.on(
    "error",
    lifecycle((error) => {
      const details = diagnostic(error.details);
      zeroPhase =
        zeroPhase === 0 &&
        initialMetadataSeen &&
        error.code === 13 &&
        error.details === knownZeroDetails &&
        details.details === knownZeroDetails
          ? 1
          : -1;
      if (
        [1, 2, 4, 8, 13, 14, 15].includes(error.code) &&
        !(
          cancelled &&
          ((error.code === 1 && ["window-end", "unacked-owned-delivery"].includes(cancelReason)) ||
            (error.code === 4 && state.windowExpired))
        )
      ) {
        state.incomplete = true;
        if (error.code !== 13) captureFault = true;
      }
      event("stream-error", { code: error.code ?? null, ...details });
      wake();
    }),
  );
  rpc.on(
    "end",
    lifecycle(() => {
      zeroPhase = zeroPhase === 2 ? 3 : -1;
      state.inboundEnded = true;
      event("stream-inbound-end");
      wake();
    }),
  );
  rpc.on(
    "close",
    lifecycle(() => {
      event("stream-close");
      if (!state.inboundEnded) captureFault = true;
      if (!state.terminal && !state.windowExpired) state.incomplete = true;
      wake();
    }),
  );
  const awaitingZeroEnd = () =>
    exactZeroOpening &&
    zeroPhase > 0 &&
    zeroPhase < 3 &&
    !captureFault &&
    !cancelled &&
    !ended &&
    !disposed &&
    !state.windowExpired &&
    openingWrites === 1 &&
    state.received === 0;
  const api = {
    write(body) {
      if (cancelled || draining || ended || disposed || state.terminal)
        throw new Error("closed stream cannot write");
      const raw = Buffer.from(Request.encode(Request.fromObject(body)).finish());
      meter.frame("out", raw.length);
      journal.frame(raw, {
        event: "stream-frame",
        cellId,
        direction: "out",
        elapsedMs: elapsed(),
        body,
      });
      beforeDispatch();
      meter.remaining();
      if (elapsed() >= windowMs) throw new Error("stream observation window exhausted");
      openingWrites++;
      const writable = rpc.write(raw);
      event("stream-local-write", { writable });
    },
    end() {
      if (!ended && !cancelled && !draining && !state.terminal) {
        ended = true;
        event("stream-write-end");
        beforeDispatch();
        meter.remaining();
        if (elapsed() >= windowMs) throw new Error("stream observation window exhausted");
        rpc.end();
      }
    },
    cancel,
    async next(timeoutMs = windowMs) {
      if (queue.length) return queue.shift();
      if (cancelled || (state.terminal && !awaitingZeroEnd()) || state.inboundEnded || disposed)
        return null;
      const nextDeadline = Math.min(meter.clock() + timeoutMs, monotonicStarted + windowMs);
      let timedOut;
      do {
        const delay = Math.min(nextDeadline - meter.clock(), meter.remaining());
        if (delay <= 0) return null;
        let nextTimer;
        try {
          timedOut = await new Promise((resolve) => {
            waiter = () => resolve(false);
            nextTimer = setTimeout(() => resolve(true), delay);
          });
        } finally {
          clearTimeout(nextTimer);
          waiter = null;
        }
      } while (awaitingZeroEnd() && !timedOut);
      return queue.shift() ?? null;
    },
    state: () => ({
      ...structuredClone(state),
      incomplete:
        (exactZeroOpening && (captureFault || cancelled || ended || state.windowExpired)) ||
        (state.incomplete &&
          !(
            exactZeroOpening &&
            zeroPhase === 3 &&
            !captureFault &&
            !cancelled &&
            !ended &&
            !draining &&
            openingWrites === 1 &&
            state.received === 0 &&
            state.inboundEnded &&
            !state.windowExpired &&
            elapsed() < windowMs
          )),
    }),
    disposeWithDiagnostics() {
      if (drainPromise) return drainPromise;
      let resolveDrain, rejectDrain;
      drainPromise = new Promise((resolve, reject) => {
        resolveDrain = resolve;
        rejectDrain = reject;
      });
      (async () => {
        try {
          if (disposed || state.terminal) return;
          draining = true;
          clearTimeout(timer);
          const delay = Math.min(1000, meter.remaining());
          await new Promise((resolve) => {
            finishDrain = resolve;
            drainTimer = setTimeout(resolve, Math.max(0, delay));
            cancel("dispose");
            if (state.terminal) resolve();
          });
          if (drainFailure) throw drainFailure;
        } finally {
          try {
            api.dispose();
          } finally {
            draining = false;
            finishDrain = null;
          }
        }
      })().then(resolveDrain, rejectDrain);
      return drainPromise;
    },
    dispose() {
      if (!disposed) {
        try {
          cancel("dispose");
        } finally {
          clearTimeout(timer);
          clearTimeout(drainTimer);
          disposed = true;
          wake();
          finishDrain?.();
        }
      }
    },
  };
  try {
    api.write(opener);
    event("stream-open-local", {
      serverReadyClaim: false,
      windowMs,
      preDispatchMs,
      requestDeadlineAt: new Date(startedAt + windowMs).toISOString(),
    });
  } catch (error) {
    captureFault = true;
    state.incomplete = true;
    api.dispose();
    throw error;
  }
  return api;
}
