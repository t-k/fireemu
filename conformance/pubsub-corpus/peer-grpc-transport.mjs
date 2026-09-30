// Direct peer events from an exclusively owned, admitted Node ClientHttp2Session. No connection is created here.
const allowedMetadata = new Set(["authorization", "x-goog-request-params", "x-goog-user-project"]);
function unaryMessage(data) {
  if (!data.length) return undefined;
  if (data.length < 5 || data[0] !== 0 || data.readUInt32BE(1) !== data.length - 5)
    throw new Error("invalid uncompressed unary frame");
  return data.subarray(5);
}
function terminalStatus(raw) {
  const entries = [];
  for (let i = 0; i < raw.length; i += 2) entries.push([raw[i], raw[i + 1]]);
  const codes = entries.filter(([key]) => key === "grpc-status").map(([, value]) => value);
  if (codes.length !== 1 || !/^(?:[0-9]|1[0-6])$/.test(codes[0])) return undefined;
  const messages = entries.filter(([key]) => key === "grpc-message").map(([, value]) => value);
  if (messages.length > 1) throw new Error("duplicate grpc-message");
  const metadata = {};
  for (const [key, value] of entries) {
    if (key.startsWith(":") || key === "grpc-status" || key === "grpc-message") continue;
    const values = key.endsWith("-bin")
      ? value.split(",").map((part) => {
          const text = part.trim(),
            bytes = Buffer.from(text, "base64");
          if (
            !/^[A-Za-z0-9+/]*={0,2}$/.test(text) ||
            bytes.toString("base64").replace(/=+$/, "") !== text.replace(/=+$/, "")
          )
            throw new Error("invalid binary metadata");
          return bytes;
        })
      : [value];
    (metadata[key] ??= []).push(...values);
  }
  return { code: Number(codes[0]), details: decodeURIComponent(messages[0] ?? ""), metadata };
}
export function createPeerGrpcTransport(
  session,
  { authority, maxResponseBytes, maxHeaderBytes, maxRequestBytes = maxResponseBytes },
) {
  if (
    typeof session?.request !== "function" ||
    typeof session.destroy !== "function" ||
    typeof session.on !== "function"
  )
    throw new Error("owned native HTTP2 session required");
  const endpoint = new URL(authority);
  if (
    endpoint.origin !== authority ||
    (authority !== "https://pubsub.googleapis.com" &&
      !(
        endpoint.protocol === "http:" &&
        ["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname)
      ))
  )
    throw new Error("bare admitted broker authority required");
  for (const bound of [maxResponseBytes, maxHeaderBytes, maxRequestBytes])
    if (!Number.isSafeInteger(bound) || bound <= 0) throw new Error("finite wire bounds required");
  const pending = new Set();
  let closed = false,
    destroyed = false;
  function shutdown(reason) {
    closed = true;
    for (const ticket of pending) ticket.stop(reason);
  }
  const onError = () => shutdown("session-error"),
    onClose = () => shutdown("session-close"),
    onGoaway = () => shutdown("session-goaway");
  session.on("error", onError);
  session.on("close", onClose);
  session.on("goaway", onGoaway);
  function send({ path, requestBytes, metadata, deadline, signal }) {
    if (closed || signal?.aborted)
      return Promise.reject(new Error("peer session closed or aborted"));
    const budget = deadline instanceof Date ? deadline.getTime() - Date.now() : NaN;
    if (!Number.isFinite(budget) || budget <= 0 || budget > 99999999)
      return Promise.reject(new Error("bounded live native deadline required"));
    if (
      !/^\/google\.pubsub\.v1\.(?:Publisher|Subscriber)\/[A-Za-z]+$/.test(path) ||
      !Buffer.isBuffer(requestBytes) ||
      requestBytes.length > maxRequestBytes
    )
      return Promise.reject(new Error("bounded broker unary request required"));
    for (const [key, value] of Object.entries(metadata ?? {}))
      if (!allowedMetadata.has(key) || typeof value !== "string" || /[\r\n]/.test(value))
        return Promise.reject(new Error("protocol overrides and invalid metadata refused"));
    const expiresAt = performance.now() + budget;
    return new Promise((resolve) => {
      let stream,
        timer,
        finished = false,
        size = 0,
        headerSize = 0,
        responseHeaders = [],
        trailerHeaders = [],
        response,
        terminal,
        truncated = false;
      const chunks = [],
        additionalHeaders = [];
      function finish(reason) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        pending.delete(ticket);
        signal?.removeEventListener("abort", onAbort);
        const data = Buffer.concat(chunks, size);
        let status, bytes;
        try {
          status = terminalStatus(terminal ?? []);
          bytes = unaryMessage(data);
        } catch {
          reason ??= "protocol";
        }
        if (!reason) {
          if (Date.now() >= deadline.getTime() || performance.now() >= expiresAt)
            reason = "deadline";
          else if (
            !response ||
            String(response[":status"]) !== "200" ||
            !/^application\/grpc(?:\+proto)?(?:;.*)?$/i.test(response["content-type"] ?? "")
          )
            reason = "protocol";
          else if (!status) reason = "invalid-status";
          else if (status.code === 0 && bytes === undefined) reason = "protocol";
        }
        resolve({
          ...(bytes !== undefined ? { responseBytes: Buffer.from(bytes) } : {}),
          ...(status ? { status } : {}),
          statusOrigin: reason ? "unverified" : "peer-trailers",
          ...(reason ? { reason } : {}),
          wire: {
            headers: responseHeaders,
            trailers: trailerHeaders,
            ...(additionalHeaders.length ? { additionalHeaders } : {}),
            dataBase64: data.toString("base64"),
            ...(truncated ? { truncated: true } : {}),
          },
        });
      }
      const ticket = {
        stop(reason) {
          if (finished) return;
          finish(reason);
          try {
            stream?.close(8);
          } catch {}
        },
      };
      const onAbort = () => ticket.stop("abort");
      function capture(raw) {
        if (
          !Array.isArray(raw) ||
          raw.length % 2 ||
          raw.some((value) => typeof value !== "string")
        ) {
          ticket.stop("invalid-headers");
          return undefined;
        }
        const bytes = raw.reduce((sum, value) => sum + Buffer.byteLength(value), 0);
        if (headerSize + bytes > maxHeaderBytes) {
          truncated = true;
          ticket.stop("header-bound");
          return undefined;
        }
        headerSize += bytes;
        return raw.slice();
      }
      try {
        pending.add(ticket);
        stream = session.request({
          ...metadata,
          ":method": "POST",
          ":scheme": endpoint.protocol.slice(0, -1),
          ":authority": endpoint.host,
          ":path": path,
          "content-type": "application/grpc+proto",
          te: "trailers",
          "grpc-accept-encoding": "identity",
          "grpc-timeout": `${Math.ceil(budget)}m`,
        });
        stream.on("headers", (_headers, _flags, raw) => {
          if (finished) return;
          const captured = capture(raw);
          if (!captured) return;
          additionalHeaders.push(captured);
          ticket.stop("extra-headers");
        });
        stream.on("response", (headers, flags, raw) => {
          if (finished) return;
          const captured = capture(raw);
          if (!captured) return;
          responseHeaders = captured;
          response = { ...headers };
          if (flags & 1) terminal = captured;
        });
        stream.on("trailers", (_headers, _flags, raw) => {
          if (finished) return;
          const captured = capture(raw);
          if (!captured) return;
          trailerHeaders = captured;
          terminal = captured;
        });
        stream.on("data", (chunk) => {
          if (finished) return;
          const bytes = Buffer.from(chunk),
            remaining = maxResponseBytes - size;
          chunks.push(bytes.subarray(0, remaining));
          size += Math.min(bytes.length, remaining);
          if (bytes.length > remaining) {
            truncated = true;
            ticket.stop("response-bound");
          }
        });
        stream.on("end", () => finish());
        stream.on("error", () => ticket.stop("stream-error"));
        stream.on("close", () => finish("stream-close"));
        signal?.addEventListener("abort", onAbort, { once: true });
        if (signal?.aborted) {
          ticket.stop("abort");
          return;
        }
        timer = setTimeout(
          () => ticket.stop("deadline"),
          Math.max(0, expiresAt - performance.now()),
        );
        const frame = Buffer.alloc(5 + requestBytes.length);
        frame.writeUInt32BE(requestBytes.length, 1);
        requestBytes.copy(frame, 5);
        stream.end(frame);
      } catch {
        ticket.stop("stream-error");
      }
    });
  }
  function close() {
    if (destroyed) return;
    destroyed = true;
    shutdown("close");
    session.destroy();
    session.off("close", onClose);
    session.off("goaway", onGoaway);
  }
  return { send, close };
}
