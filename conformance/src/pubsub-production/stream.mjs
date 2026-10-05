// One native bidirectional RPC per observation. No SDK subscriber, reconnect, lease extension or retry.
import grpcLib from "@grpc/grpc-js";
import { protos as pubsubProtos } from "@google-cloud/pubsub";

export const STREAM_BOUNDS = Object.freeze({
  outboundFrames: 2,
  inboundFrames: 4,
  frameBytes: 16_384,
  timeoutMs: 30_000,
});
const unsure = new Set([
  "UNKNOWN",
  "INTERNAL",
  "UNAVAILABLE",
  "CANCELLED",
  "DEADLINE_EXCEEDED",
  "RESOURCE_EXHAUSTED",
]);
const names = Object.fromEntries(
  Object.entries(grpcLib.status).map(([name, code]) => [code, name]),
);

export function createStreamingPull({
  target,
  secure,
  budget,
  capture,
  getToken = null,
  quotaProject = null,
  grpc = grpcLib,
  protos = pubsubProtos,
  now = Date.now,
}) {
  const Request = protos.google.pubsub.v1.StreamingPullRequest;
  const Response = protos.google.pubsub.v1.StreamingPullResponse;
  const client = new grpc.Client(
    target,
    secure ? grpc.credentials.createSsl() : grpc.credentials.createInsecure(),
    {
      "grpc.max_receive_message_length": STREAM_BOUNDS.frameBytes,
      "grpc.max_send_message_length": STREAM_BOUNDS.frameBytes,
    },
  );
  return {
    close: () => client.close(),
    async stream({ label, frames, afterReceive, timeoutMs = STREAM_BOUNDS.timeoutMs }) {
      if (
        !Array.isArray(frames) ||
        frames.length < 1 ||
        frames.length > STREAM_BOUNDS.outboundFrames ||
        !Number.isSafeInteger(timeoutMs) ||
        timeoutMs < 1 ||
        timeoutMs > STREAM_BOUNDS.timeoutMs
      )
        throw new Error("stream frame/time bound exceeded before dispatch");
      const encoded = frames.map((frame) =>
        Buffer.from(Request.encode(Request.fromObject(frame)).finish()),
      );
      if (encoded.some((bytes) => bytes.length > STREAM_BOUNDS.frameBytes))
        throw new Error("stream encoded-byte bound exceeded before dispatch");
      if (
        afterReceive !== undefined &&
        (frames.length !== 1 ||
          afterReceive.modifyDeadlineSeconds !== -1 ||
          Object.keys(afterReceive).length !== 1)
      )
        throw new Error("stream followup bound exceeded before dispatch");
      budget.consume();
      const metadata = new grpc.Metadata();
      if (getToken !== null) metadata.add("authorization", `Bearer ${await getToken()}`);
      if (quotaProject !== null) metadata.add("x-goog-user-project", quotaProject);
      const started = now();
      let inboundFrames = 0;
      let outboundFrames = 0;
      let followUpSent = false;
      let reason;
      let terminal;
      const result = await new Promise((resolve) => {
        let finished = false;
        const rpc = client.makeBidiStreamRequest(
          "/google.pubsub.v1.Subscriber/StreamingPull",
          (bytes) => bytes,
          (bytes) => bytes,
          metadata,
          { deadline: new Date(now() + timeoutMs) },
        );
        const finish = (status) => {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          const code = names[status.code] ?? "UNKNOWN";
          resolve({
            code,
            message: status.details ?? "",
            unknown: reason !== undefined || unsure.has(code),
            inboundFrames,
            outboundFrames,
            followUpSent,
            ...(reason ? { reason } : {}),
          });
        };
        // The RPC deadline normally emits status. The watchdog also bounds a broken local transport.
        const timer = setTimeout(() => {
          reason ??= "watchdog-deadline";
          rpc.cancel();
          finish({ code: grpc.status.DEADLINE_EXCEEDED, details: "local watchdog expired" });
        }, timeoutMs + 100);
        rpc.on("error", (error) => {
          terminal = { code: error.code ?? grpc.status.UNKNOWN, details: error.details ?? "" };
        });
        rpc.on("status", (status) => {
          terminal = status;
          finish(status);
        });
        rpc.on("close", () => {
          if (!finished)
            finish(
              terminal ?? { code: grpc.status.UNKNOWN, details: "stream closed without status" },
            );
        });
        rpc.on("data", (bytes) => {
          if (finished || reason !== undefined) return;
          if (inboundFrames >= STREAM_BOUNDS.inboundFrames) {
            reason = "inbound-frame-limit";
            rpc.cancel();
            return;
          }
          if (bytes.length > STREAM_BOUNDS.frameBytes) {
            reason = "inbound-byte-limit";
            rpc.cancel();
            return;
          }
          inboundFrames += 1;
          let body;
          try {
            body = Response.toObject(Response.decode(bytes), {
              longs: String,
              enums: String,
              bytes: String,
            });
          } catch {
            capture.frame(
              { ...label, direction: "in", frame: inboundFrames, unreadable: true },
              bytes,
            );
            reason = "unreadable-frame";
            rpc.cancel();
            return;
          }
          capture.frame(
            {
              ...label,
              direction: "in",
              frame: inboundFrames,
              body,
            },
            bytes,
          );
          const ackId = body.receivedMessages?.[0]?.ackId;
          if (
            afterReceive !== undefined &&
            !followUpSent &&
            typeof ackId === "string" &&
            ackId.length > 0
          ) {
            const followup = {
              modifyDeadlineAckIds: [ackId],
              modifyDeadlineSeconds: [afterReceive.modifyDeadlineSeconds],
            };
            const wire = Buffer.from(Request.encode(Request.fromObject(followup)).finish());
            if (wire.length > STREAM_BOUNDS.frameBytes) {
              reason = "followup-byte-limit";
              rpc.cancel();
              return;
            }
            rpc.write(wire);
            outboundFrames += 1;
            followUpSent = true;
            capture.frame(
              {
                ...label,
                direction: "out",
                frame: outboundFrames,
                causedByInboundFrame: inboundFrames,
                body: followup,
              },
              wire,
            );
            rpc.end();
          }
        });
        encoded.forEach((bytes, index) => {
          rpc.write(bytes);
          outboundFrames += 1;
          capture.frame(
            {
              ...label,
              direction: "out",
              frame: outboundFrames,
              body: frames[index],
            },
            bytes,
          );
        });
        if (afterReceive === undefined) rpc.end();
      });
      capture.record({
        ...label,
        transport: "grpc",
        op: "streamingPull",
        request: {
          rpc: "Subscriber/StreamingPull",
          frames,
          ...(afterReceive === undefined ? {} : { afterReceive }),
        },
        response: result,
        ms: now() - started,
        ...(result.unknown ? { unknown: true } : {}),
      });
      return result;
    },
  };
}
