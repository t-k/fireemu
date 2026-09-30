// Raw grpc-js unary binding. Client construction/credentials are supplied by the admitted caller.
function values(metadata) {
  const first = metadata?.getMap?.() ?? {};
  return Object.fromEntries(
    Object.entries(first).map(([key, value]) => [key, metadata.get?.(key) ?? [value]]),
  );
}
export function createRawGrpcTransport(client, metadataFactory) {
  if (
    typeof client?.makeUnaryRequest !== "function" ||
    typeof client.close !== "function" ||
    typeof metadataFactory !== "function"
  )
    throw new Error("explicit native client and metadata factory required");
  const pending = new Set();
  let closed = false;
  function send({ path, requestBytes, metadata, deadline, signal }) {
    if (closed || signal?.aborted)
      return Promise.reject(new Error("native transport closed or aborted"));
    if (!(deadline instanceof Date) || !Number.isFinite(deadline.getTime()))
      return Promise.reject(new Error("native deadline required"));
    const budget = deadline.getTime() - Date.now();
    if (budget <= 0) return Promise.reject(new Error("native deadline expired before dispatch"));
    const expiresAt = performance.now() + budget;
    return new Promise((resolve, reject) => {
      let call,
        timer,
        finished = false,
        callbackDone = false,
        callbackSucceeded = false,
        callbackCode,
        status,
        bytes;
      const headers = metadataFactory();
      for (const [key, value] of Object.entries(metadata ?? {})) headers.set(key, value);
      const ticket = {
        stop() {
          if (finished) return;
          finish(new Error("native call interrupted"));
          try {
            call?.cancel();
          } catch {}
        },
      };
      function finish(error) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        pending.delete(ticket);
        signal?.removeEventListener("abort", ticket.stop);
        if (error) reject(error);
        else {
          const expired = Date.now() >= deadline.getTime() || performance.now() >= expiresAt;
          resolve({
            ...(bytes !== undefined ? { responseBytes: bytes } : {}),
            status,
            statusOrigin:
              status.code === 0 && callbackSucceeded && !expired
                ? "successful-response"
                : "unverified",
            ...(callbackCode !== undefined ? { callbackCode } : {}),
            ...(expired ? { interruption: "deadline" } : {}),
          });
        }
      }
      function complete() {
        if (callbackDone && status) finish();
      }
      try {
        pending.add(ticket);
        call = client.makeUnaryRequest(
          path,
          (value) => value,
          (value) => Buffer.from(value),
          requestBytes,
          headers,
          { deadline },
          (error, response) => {
            callbackDone = true;
            callbackSucceeded = !error && response !== undefined;
            callbackCode = error?.code;
            bytes = response === undefined ? undefined : Buffer.from(response);
            // Public status merges peer and locally synthesized errors; preserve it without claiming origin.
            if (error && !Number.isInteger(error.code)) {
              ticket.stop();
              return;
            }
            complete();
          },
        );
        call.on("status", (value) => {
          status = { code: value.code, details: value.details, metadata: values(value.metadata) };
          complete();
        });
        signal?.addEventListener("abort", ticket.stop, { once: true });
        if (signal?.aborted) ticket.stop();
        if (!finished) timer = setTimeout(ticket.stop, Math.max(0, expiresAt - performance.now()));
      } catch {
        finish(new Error("native call did not start"));
      }
    });
  }
  function close() {
    if (closed) return;
    closed = true;
    for (const ticket of pending) ticket.stop();
    client.close();
  }
  return { send, close };
}
