import http from "node:http";
import https from "node:https";
import grpc from "@grpc/grpc-js";
import { protos } from "@google-cloud/pubsub";

export function createTransport({
  getToken,
  clock,
  protocol = "https",
  host = "pubsub.googleapis.com",
  port = 443,
  grpcCall,
}) {
  const net = protocol === "https" ? https : protocol === "http" ? http : null;
  if (!net) throw new Error("unsupported protocol");
  const shared = new net.Agent({ keepAlive: true });
  const dedicated = new Map();
  let client;
  const defaultGrpc = ({ path, deadlineMs }) =>
    new Promise((resolve) => {
      client ??= new grpc.Client("pubsub.googleapis.com:443", grpc.credentials.createSsl(), {
        "grpc.enable_retries": 0,
      });
      const metadata = new grpc.Metadata();
      metadata.add("authorization", `Bearer ${getToken()}`);
      const Type = protos.google.pubsub.v1.GetSubscriptionRequest;
      const payload = Buffer.from(Type.encode(Type.fromObject({ subscription: path })).finish());
      client.makeUnaryRequest(
        "/google.pubsub.v1.Subscriber/GetSubscription",
        (v) => v,
        (v) => v,
        payload,
        metadata,
        { deadline: new Date(Date.now() + deadlineMs) },
        (error) => {
          if (!error) resolve({ code: "OK" });
          else
            resolve({
              code:
                Object.keys(grpc.status).find((k) => grpc.status[k] === error.code) ?? "UNKNOWN",
              message: error.details ?? "",
            });
        },
      );
    });
  const send = async (request, { conn, connPolicy, timeoutMs } = {}) => {
    if (request.grpc) {
      const startedAt = clock.now();
      try {
        const result = await (grpcCall ?? defaultGrpc)({
          path: request.path,
          deadlineMs: timeoutMs,
        });
        const completedAt = clock.now();
        const status = {
          OK: 200,
          NOT_FOUND: 404,
          PERMISSION_DENIED: 403,
          UNAUTHENTICATED: 401,
          ALREADY_EXISTS: 409,
          INVALID_ARGUMENT: 400,
        }[result.code];
        if (!status) return { startedAt, completedAt, failure: `grpc:${result.code}` };
        const bodyText = JSON.stringify(
          status === 200
            ? { name: request.path }
            : { error: { code: status, message: result.message, status: result.code } },
        );
        return { startedAt, headersAt: completedAt, completedAt, status, bodyText };
      } catch {
        return { startedAt, completedAt: clock.now(), failure: "grpc:UNKNOWN" };
      }
    }
    return new Promise((resolve) => {
      let agent = shared;
      if (connPolicy === "dedicated") {
        if (!dedicated.has(conn))
          dedicated.set(conn, new net.Agent({ keepAlive: true, maxSockets: 1 }));
        agent = dedicated.get(conn);
      } else if (connPolicy === "fresh") agent = new net.Agent({ keepAlive: false });
      let req,
        timer,
        finished = false;
      let startedAt;
      const finish = (value) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (connPolicy === "fresh") agent.destroy();
        resolve({ startedAt: startedAt ?? clock.now(), completedAt: clock.now(), ...value });
      };
      try {
        const body = request.body === undefined ? undefined : JSON.stringify(request.body);
        const headers = { Authorization: `Bearer ${getToken()}`, Accept: "application/json" };
        if (body !== undefined) headers["Content-Type"] = "application/json";
        if (connPolicy === "fresh") headers.Connection = "close";
        startedAt = clock.now();
        req = net.request(
          { host, port, method: request.method, path: request.path, agent, headers },
          (res) => {
            const headersAt = clock.now();
            let size = 0;
            const chunks = [];
            res.on("data", (chunk) => {
              size += chunk.length;
              if (size > 1024 * 1024) {
                finish({ failure: "body-too-large" });
                req.destroy();
              } else chunks.push(chunk);
            });
            res.on("end", () =>
              finish({
                headersAt,
                status: res.statusCode,
                bodyText: Buffer.concat(chunks).toString("utf8"),
              }),
            );
            res.on("error", (error) => finish({ failure: error.code ?? "error" }));
            res.on("aborted", () => finish({ failure: "ECONNRESET" }));
          },
        );
        req.on("error", (error) => finish({ failure: error.code ?? "error" }));
        timer = setTimeout(() => {
          finish({ failure: "timeout" });
          req.destroy();
        }, timeoutMs);
        req.end(body);
      } catch (error) {
        finish({ failure: error.code ?? "error" });
        req?.destroy();
      }
    });
  };
  return {
    send,
    close() {
      shared.destroy();
      for (const agent of dedicated.values()) agent.destroy();
      client?.close();
    },
  };
}
