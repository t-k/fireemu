// The gRPC side of the native Listen recorder: one Listen stream per `openStream`, and the unary
// calls the programs need (Commit, BeginTransaction, BatchGetDocuments for the read-back and
// ListDocuments for the cleanup sweep). Production is firestore.googleapis.com with the owner's
// access token and the project as the quota project; local is the fireemu loopback port.

import { createRequire } from "node:module";

import { describeFrame } from "../auth-fs-cross/listen-grpc.mjs";
import { listedNames, readBack } from "./native-parse.mjs";

const require = createRequire(import.meta.url);
const grpc = require("@grpc/grpc-js");
const { v1 } = require("@google-cloud/firestore");

const SERVICE = "/google.firestore.v1.Firestore";
/** The frames a stream may record before it is closed as over its cap. */
export const FRAME_CAP = 500;

/** Where a target's Firestore lives: production over TLS, local on a loopback port. */
export function grpcAddress(target) {
  return target.kind === "production"
    ? { address: "firestore.googleapis.com:443", secure: true }
    : { address: `${target.host}:${target.port}`, secure: false };
}

/** The channel credentials of a target: TLS for production, plaintext for a loopback port. */
export function credentialsFor(target) {
  return grpcAddress(target).secure
    ? grpc.credentials.createSsl()
    : grpc.credentials.createInsecure();
}

export function createNativeClient({
  project,
  target,
  token,
  refreshToken,
  now = () => Date.now(),
  grpcClient: injected,
}) {
  let bearer = token;
  // Every RPC sent to the target, counted when it starts (the close rows need the exact number).
  let requests = 0;
  const protos = new v1.FirestoreClient({ projectId: project })._protos.google.firestore.v1;
  const database = `projects/${project}/databases/(default)`;
  const where = grpcAddress(target);
  const grpcClient = injected ?? new grpc.Client(where.address, credentialsFor(target));
  const metadata = () => {
    const meta = new grpc.Metadata();
    meta.set("authorization", `Bearer ${target.kind === "production" ? bearer : "owner"}`);
    meta.set("google-cloud-resource-prefix", database);
    meta.set("x-goog-request-params", `database=${encodeURIComponent(database)}`);
    if (target.kind === "production") meta.set("x-goog-user-project", project);
    return meta;
  };
  const unary = (method, request, responseType = `${method}Response`) =>
    new Promise((resolve, reject) => {
      requests += 1;
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
      requests += 1;
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

    /** How many RPCs this client has sent (unary, server-streaming and Listen streams). */
    requestCount: () => requests,

    /** A new access token for later calls (a recording that waits longer than a token lives). */
    async refresh() {
      if (refreshToken) bearer = await refreshToken();
    },

    async commit({ writes, transaction }) {
      return unary("Commit", { database, writes, ...(transaction ? { transaction } : {}) });
    },

    async beginTransaction() {
      const response = await unary("BeginTransaction", { database, options: { readWrite: {} } });
      return response.transaction;
    },

    openStream() {
      requests += 1;
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
      // grpc-js emits `status` before `end`; an end that no status preceded is not an OK status.
      stream.on("end", () =>
        setImmediate(() => finish({ reason: "ended-without-status", code: null })),
      );
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
        out.push(...readBack(chunk, results));
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
        names.push(...listedNames(page, prefix));
        pageToken = page.nextPageToken ?? "";
      } while (pageToken);
      return names;
    },
  };
}
