import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";
import { PROJECT } from "./plan.mjs";
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
  opener,
}) {
  meter.start("stream", "streams");
  const token = await credential(false);
  const metadata = new grpc.Metadata();
  metadata.add("authorization", `Bearer ${token}`);
  metadata.add("x-goog-user-project", PROJECT);
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
  const queue = [];
  let waiter,
    cancelled = false,
    cancelReason = null,
    ended = false,
    disposed = false;
  const state = {
    startedAt,
    windowMs,
    terminal: null,
    inboundEnded: false,
    incomplete: windowMs < 90000,
    windowExpired: false,
    received: 0,
    preDispatchMs,
  };
  const wake = () => {
    const callback = waiter;
    waiter = null;
    callback?.();
  };
  const elapsed = () => meter.clock() - monotonicStarted;
  const event = (name, value = {}) => {
    if (!disposed) journal.write({ event: name, cellId, elapsedMs: elapsed(), ...value });
  };
  const cancel = (reason) => {
    if (!cancelled && !state.terminal) {
      cancelled = true;
      cancelReason = reason;
      event("stream-cancel", { reason });
      rpc.cancel();
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
    if (cancelled || disposed) return;
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
      event("stream-frame-refused", { bytes: raw.length });
      cancel("frame-overflow-or-decode");
    }
  });
  rpc.on("status", (status) => {
    state.terminal = { code: status.code };
    const localEnd =
      cancelled &&
      ((status.code === 1 && ["window-end", "unacked-owned-delivery"].includes(cancelReason)) ||
        (status.code === 4 && state.windowExpired));
    if ([1, 2, 4, 13, 14, 15].includes(status.code) && !localEnd) state.incomplete = true;
    event("stream-status", state.terminal);
    wake();
  });
  rpc.on("error", (error) => {
    if (
      [1, 2, 4, 13, 14, 15].includes(error.code) &&
      !(
        cancelled &&
        ((error.code === 1 && ["window-end", "unacked-owned-delivery"].includes(cancelReason)) ||
          (error.code === 4 && state.windowExpired))
      )
    )
      state.incomplete = true;
    event("stream-error", { code: error.code ?? null });
    wake();
  });
  rpc.on("end", () => {
    state.inboundEnded = true;
    event("stream-inbound-end");
    wake();
  });
  rpc.on("close", () => {
    event("stream-close");
    if (!state.terminal && !state.windowExpired) state.incomplete = true;
    wake();
  });
  const api = {
    write(body) {
      if (cancelled || ended || disposed || state.terminal)
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
      const writable = rpc.write(raw);
      event("stream-local-write", { writable });
    },
    end() {
      if (!ended && !cancelled && !state.terminal) {
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
      if (cancelled || state.terminal || state.inboundEnded || disposed) return null;
      const delay = Math.min(timeoutMs, meter.remaining(), Math.max(0, windowMs - elapsed()));
      if (delay <= 0) return null;
      let nextTimer;
      try {
        await new Promise((resolve) => {
          waiter = resolve;
          nextTimer = setTimeout(resolve, delay);
        });
      } finally {
        clearTimeout(nextTimer);
        waiter = null;
      }
      return queue.shift() ?? null;
    },
    state: () => structuredClone(state),
    dispose() {
      if (!disposed) {
        cancel("dispose");
        clearTimeout(timer);
        disposed = true;
        wake();
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
    state.incomplete = true;
    api.dispose();
    throw error;
  }
  return api;
}
