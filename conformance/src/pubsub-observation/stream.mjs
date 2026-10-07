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
  now = Date.now,
  cellId,
  opener,
}) {
  meter.start("stream", "streams");
  const token = await credential(false);
  const windowMs = Math.min(90000, meter.remaining() - 1);
  if (windowMs < 1) throw new Error("stream time exhausted");
  const metadata = new grpc.Metadata();
  metadata.add("authorization", `Bearer ${token}`);
  metadata.add("x-goog-user-project", PROJECT);
  const startedAt = now();
  const monotonicStarted = meter.clock();
  journal.write({
    event: "stream-dispatch",
    cellId,
    windowMs,
    requestedWindowMs: 90000,
    requestDeadlineAt: new Date(startedAt + windowMs).toISOString(),
  });
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
      event("stream-cancel", { reason });
      rpc.cancel();
    }
    wake();
  };
  const timer = setTimeout(() => {
    state.windowExpired = true;
    event("stream-observation-window-end");
    cancel("window-end");
  }, windowMs);
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
    event("stream-status", state.terminal);
    wake();
  });
  rpc.on("error", (error) => {
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
      const writable = rpc.write(raw);
      event("stream-local-write", { writable });
    },
    end() {
      if (!ended && !cancelled && !state.terminal) {
        ended = true;
        event("stream-write-end");
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
    event("stream-open-local", { serverReadyClaim: false });
  } catch (error) {
    state.incomplete = true;
    api.dispose();
    throw error;
  }
  return api;
}
