// A native gRPC Listen stream held open across Auth changes (AUTH-FS-CROSS stage 2).
//
// One stream per listener: it adds its targets once, then records every response frame with the
// milliseconds since the stream opened, until it ends with a status, errors, or is closed. The
// recording is what a row compares; nothing here decides whether an event was expected.

const LISTEN = "/google.firestore.v1.Firestore/Listen";

/** The frames a stream may record before it is closed as over its cap. */
export const FRAME_CAP = 500;

/** A Listen `addTarget` of one document, or of one query under `parent`. */
export function listenTarget(targetId, { document, query, parent }) {
  if (document) return { targetId, documents: { documents: [document] } };
  if (query) return { targetId, query: { parent, structuredQuery: query } };
  throw new Error("a listen target names a document or a query");
}

/** What one response frame says, in plain JSON (bytes as base64, enums as names). */
export function describeFrame(frame) {
  const plain = JSON.parse(
    JSON.stringify(frame, (_, value) =>
      value && value.type === "Buffer" && Array.isArray(value.data)
        ? Buffer.from(value.data).toString("base64")
        : value,
    ),
  );
  const kind = Object.keys(plain).find((key) => plain[key] !== null && key !== "responseType");
  return { kind: frame.responseType ?? kind, ...plain };
}

/**
 * Opens a Listen stream on `client` (a grpc.Client) and adds `targets`. `metadata` carries the
 * bearer and routing; `now` is injected for tests. Returns the recorder and a `closed` promise.
 */
export function openListen({
  client,
  protos,
  database,
  targets,
  metadata,
  now = () => Date.now(),
  cap = FRAME_CAP,
}) {
  const opened = now();
  const frames = [];
  let end;
  let resolveClosed;
  const closed = new Promise((resolve) => {
    resolveClosed = resolve;
  });
  const finish = (how) => {
    if (end) return;
    end = { at: now() - opened, ...how };
    resolveClosed(end);
  };
  const stream = client.makeBidiStreamRequest(
    LISTEN,
    (message) => protos.google.firestore.v1.ListenRequest.serialize(message),
    // proto-loader answers a plain object with a `responseType` discriminator.
    (bytes) => protos.google.firestore.v1.ListenResponse.deserialize(bytes),
    metadata,
    {},
  );
  stream.on("data", (frame) => {
    if (frames.length >= cap) {
      finish({ reason: "frame-cap" });
      stream.cancel();
      return;
    }
    frames.push({ at: now() - opened, ...describeFrame(frame) });
  });
  stream.on("error", (error) =>
    finish({ reason: "error", code: error.code, details: String(error.details ?? "") }),
  );
  stream.on("status", (status) => {
    if (status.code)
      finish({ reason: "error", code: status.code, details: String(status.details ?? "") });
    else finish({ reason: "ended", code: 0 });
  });
  stream.on("end", () => finish({ reason: "ended", code: 0 }));
  for (const target of targets) stream.write({ database, addTarget: target });
  return {
    frames,
    closed,
    ended: () => end,
    /** Frames recorded after `mark` (a length of `frames` taken earlier). */
    since: (mark) => frames.slice(mark),
    close() {
      if (end) return closed;
      finish({ reason: "closed-by-harness" });
      stream.cancel();
      return closed;
    },
  };
}
