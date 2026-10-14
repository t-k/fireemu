// The native gRPC side of the FS-3 recorder: unary and server-streaming Firestore calls and the
// Listen stream, against production Firestore or a loopback emulator. The session talks to the
// small interface returned here (`call`, `listen`, `close`) so tests can replace it.

import { createRequire } from "node:module";

import { listenTarget, openListen } from "../auth-fs-cross/listen-grpc.mjs";
import { PRODUCTION } from "../fs-rules/harness.mjs";

const require = createRequire(import.meta.url);

export { listenTarget };

/** @param {object} ctx a context from createContext; `timeoutMs` bounds each call */
export function createGrpcAdapter(ctx, { timeoutMs = 60_000 } = {}) {
  const grpc = require("@grpc/grpc-js");
  const { v1 } = require("@google-cloud/firestore");
  const gapic = new v1.FirestoreClient({ projectId: ctx.project });
  const protos = gapic._protos;
  const client =
    ctx.target.kind === "production"
      ? new grpc.Client(
          `${PRODUCTION.grpc.host}:${PRODUCTION.grpc.port}`,
          grpc.credentials.createSsl(),
        )
      : new grpc.Client(
          `${ctx.target.grpcHost}:${ctx.target.grpcPort}`,
          grpc.credentials.createInsecure(),
        );

  function metadataFor({ bearer, resourcePrefix, routing }) {
    const metadata = new grpc.Metadata();
    if (bearer !== undefined) metadata.set("authorization", bearer);
    metadata.set("google-cloud-resource-prefix", resourcePrefix);
    metadata.set("x-goog-request-params", routing);
    return metadata;
  }

  return {
    /** One call as `built` (from buildFirestoreGrpc): `{ code, details, messages }`. */
    call(built, bearer) {
      const requestType = protos.google.firestore.v1[`${built.method}Request`];
      const responseType =
        built.method === "GetDocument" || built.method === "UpdateDocument"
          ? protos.google.firestore.v1.Document
          : protos.google.firestore.v1[`${built.method}Response`];
      const metadata = metadataFor({ bearer, ...built });
      const path = `/google.firestore.v1.Firestore/${built.method}`;
      const options = { deadline: new Date(Date.now() + timeoutMs) };
      return new Promise((resolve) => {
        const messages = [];
        const finish = (error) =>
          resolve({
            code: error ? error.code : 0,
            details: error ? error.details : "",
            messages: JSON.parse(JSON.stringify(messages)),
          });
        const serialize = (message) => requestType.serialize(message);
        const deserialize = (bytes) => responseType.deserialize(bytes);
        if (built.stream) {
          const stream = client.makeServerStreamRequest(
            path,
            serialize,
            deserialize,
            built.request,
            metadata,
            options,
          );
          let failed;
          stream.on("data", (message) => messages.push(message));
          stream.on("error", (error) => {
            failed = error;
          });
          stream.on("status", (status) => finish(failed ?? (status.code ? status : undefined)));
        } else {
          client.makeUnaryRequest(
            path,
            serialize,
            deserialize,
            built.request,
            metadata,
            options,
            (error, message) => {
              if (message) messages.push(message);
              finish(error ?? undefined);
            },
          );
        }
      });
    },
    /** A Listen stream with one query target; the handle of openListen. */
    listen({ database, parent, structuredQuery, bearer }) {
      return openListen({
        client,
        protos,
        database,
        targets: [listenTarget(1, { query: structuredQuery, parent })],
        metadata: metadataFor({
          bearer,
          resourcePrefix: database,
          routing: `database=${encodeURIComponent(database)}`,
        }),
      });
    },
    close: async () => {
      client.close();
      await gapic.close();
    },
  };
}
