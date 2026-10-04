// The gRPC side of the native Listen recorder: one Listen stream per `openStream`, and the unary
// calls the programs need (Commit, BeginTransaction, BatchGetDocuments for the read-back and
// ListDocuments for the cleanup sweep). Production is firestore.googleapis.com with the owner's
// access token and the project as the quota project; local is the fireemu loopback port.

import { createRequire } from "node:module";

import { describeFrame } from "../auth-fs-cross/listen-grpc.mjs";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");
const { v1 } = require("@google-cloud/firestore");

const SERVICE = "/google.firestore.v1.Firestore";
/** The frames a stream may record before it is closed as over its cap. */
export const FRAME_CAP = 500;

export function createNativeClient({ project, target, token, now = () => Date.now() }) {
  const protos = new v1.FirestoreClient({ projectId: project })._protos.google.firestore.v1;
  const database = `projects/${project}/databases/(default)`;
  const grpcClient =
    target.kind === "production"
      ? new grpc.Client("firestore.googleapis.com:443", grpc.credentials.createSsl())
      : new grpc.Client(`${target.host}:${target.port}`, grpc.credentials.createInsecure());
  const metadata = () => {
    const meta = new grpc.Metadata();
    meta.set("authorization", `Bearer ${target.kind === "production" ? token : "owner"}`);
    meta.set("google-cloud-resource-prefix", database);
    meta.set("x-goog-request-params", `database=${encodeURIComponent(database)}`);
    if (target.kind === "production") meta.set("x-goog-user-project", project);
    return meta;
  };
  const unary = (method, request, responseType = `${method}Response`) =>
    new Promise((resolve, reject) => {
      grpcClient.makeUnaryRequest(
        `${SERVICE}/${method}`,
        (message) => protos[`${method}Request`].serialize(message),
        (bytes) => protos[responseType].deserialize(bytes),
        request,
        metadata(),
        { deadline: new Date(Date.now() + 30_000) },
        (error, response) => (error ? reject(error) : resolve(response)),
      );
    });
  const serverStream = (method, request) =>
    new Promise((resolve, reject) => {
      const messages = [];
      const stream = grpcClient.makeServerStreamRequest(
        `${SERVICE}/${method}`,
        (message) => protos[`${method}Request`].serialize(message),
        (bytes) => protos[`${method}Response`].deserialize(bytes),
        request,
        metadata(),
        { deadline: new Date(Date.now() + 30_000) },
      );
      stream.on("data", (message) => messages.push(message));
      stream.on("error", reject);
      stream.on("end", () => resolve(messages));
    });

  return {
    close: () => grpcClient.close(),

    async commit({ writes, transaction }) {
      return unary("Commit", { database, writes, ...(transaction ? { transaction } : {}) });
    },

    async beginTransaction() {
      const response = await unary("BeginTransaction", { database, options: { readWrite: {} } });
      return response.transaction;
    },

    openStream() {
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
      const stream = grpcClient.makeBidiStreamRequest(
        `${SERVICE}/Listen`,
        (message) => protos.ListenRequest.serialize(message),
        (bytes) => protos.ListenResponse.deserialize(bytes),
        metadata(),
        {},
      );
      stream.on("data", (frame) => {
        if (frames.length >= FRAME_CAP) {
          finish({ reason: "frame-cap" });
          stream.cancel();
          return;
        }
        frames.push(describeFrame(frame));
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
      return {
        frames,
        ended: () => end,
        send: (request) => stream.write(request),
        close() {
          if (!end) {
            finish({ reason: "closed-by-harness" });
            stream.cancel();
          }
          return closed;
        },
      };
    },

    async missing(names) {
      const out = [];
      for (let i = 0; i < names.length; i += 100) {
        const chunk = names.slice(i, i + 100);
        const results = await serverStream("BatchGetDocuments", { database, documents: chunk });
        const found = new Set(results.filter((r) => r.found).map((r) => r.found.name));
        for (const name of chunk) out.push({ name, exists: found.has(name) });
      }
      return out;
    },

    async listIds({ parent, collectionId, prefix }) {
      const names = [];
      let pageToken = "";
      do {
        const page = await unary("ListDocuments", {
          parent,
          collectionId,
          pageSize: 300,
          pageToken,
          showMissing: false,
        });
        for (const doc of page.documents ?? [])
          if (doc.name.split("/").at(-1).startsWith(prefix)) names.push(doc.name);
        pageToken = page.nextPageToken ?? "";
      } while (pageToken);
      return names;
    },
  };
}
