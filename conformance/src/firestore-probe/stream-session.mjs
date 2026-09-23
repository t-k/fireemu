import { readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { normalize, normalizeError } from "../normalize.mjs";
import { normalizeRecordedResponse } from "./production-normalization.mjs";

const require = createRequire(import.meta.url);
const { v1 } = require("@google-cloud/firestore");
const grpc = require("@grpc/grpc-js");

const SAVED_ID = "writes/write-stream-transaction";
const TRAILERS_ID = "writes/write-stream-terminal/trailing-metadata";
const HALF_CLOSE_ID = "writes/write-stream-terminal/half-close";
const RESPONSE_HALF_CLOSE_ID = "writes/write-stream-terminal/response-before-half-close";
const UNARY_EXACT_ID = "writes/limits/grpc-unary-request-bytes/10485760";
const UNARY_OVER_ID = "writes/limits/grpc-unary-request-bytes/10485761";
const STREAM_EXACT_ID = "writes/limits/grpc-stream-request-bytes/10485760";
const STREAM_OVER_ID = "writes/limits/grpc-stream-request-bytes/10485761";
const SAVED_SOURCE = "spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json";
const SANDBOX_PROJECT = "fireemu-oracle-sbx";
const UNARY_BYTE_TARGETS = new Set([10_485_760, 10_485_761]);
const STREAM_BYTE_TARGETS = new Set([10_485_760, 10_485_761]);

export async function makeUnaryRequestByWireBytes(targetBytes) {
  if (!UNARY_BYTE_TARGETS.has(targetBytes)) throw new Error("unsupported unary byte target");
  const client = new v1.FirestoreClient({ projectId: SANDBOX_PROJECT });
  try {
    const name = `projects/${SANDBOX_PROJECT}/databases/(default)/documents/byteProbe/x`;
    const serialize = client._protos.google.firestore.v1.GetDocumentRequest.serialize;
    const request = { name, transaction: Buffer.alloc(targetBytes - 76) };
    const wireBytes = serialize(request).length;
    if (wireBytes !== targetBytes) throw new Error("unary request wire size differs");
    return { request, wireBytes };
  } finally {
    await client.close();
  }
}

export async function makeStreamRequestByWireBytes(targetBytes) {
  if (!STREAM_BYTE_TARGETS.has(targetBytes)) throw new Error("unsupported stream byte target");
  const client = new v1.FirestoreClient({ projectId: SANDBOX_PROJECT });
  try {
    const database = `projects/${SANDBOX_PROJECT}/databases/(default)`;
    const serialize = client._protos.google.firestore.v1.WriteRequest.serialize;
    const request = { database, streamToken: Buffer.alloc(targetBytes - 54) };
    const wireBytes = serialize(request).length;
    if (wireBytes !== targetBytes) throw new Error("stream request wire size differs");
    return { request, wireBytes };
  } finally {
    await client.close();
  }
}

/** Keep live gRPC sends limited to the fixed terminal and request-byte actions. */
export function validateStreamRecipes(recipes) {
  if (!Array.isArray(recipes) || recipes.length !== 8) {
    throw new Error("unsupported stream recipe set");
  }
  const byId = new Map(recipes.map((recipe) => [recipe.id, recipe]));
  if (
    byId.size !== 8 ||
    byId.get(SAVED_ID)?.transport !== "saved-reference" ||
    byId.get(SAVED_ID)?.source !== SAVED_SOURCE ||
    byId.get(TRAILERS_ID)?.transport !== "grpc" ||
    byId.get(TRAILERS_ID)?.action !== "invalid-empty-write-after-handshake" ||
    byId.get(TRAILERS_ID)?.maxFrames !== 2 ||
    byId.get(HALF_CLOSE_ID)?.transport !== "grpc" ||
    byId.get(HALF_CLOSE_ID)?.action !== "half-close-after-handshake" ||
    byId.get(HALF_CLOSE_ID)?.maxFrames !== 1 ||
    byId.get(RESPONSE_HALF_CLOSE_ID)?.transport !== "grpc" ||
    byId.get(RESPONSE_HALF_CLOSE_ID)?.action !== "empty-write-response-before-half-close" ||
    byId.get(RESPONSE_HALF_CLOSE_ID)?.maxFrames !== 2 ||
    byId.get(UNARY_EXACT_ID)?.transport !== "grpc" ||
    byId.get(UNARY_EXACT_ID)?.action !== "get-document-transaction-bytes" ||
    byId.get(UNARY_EXACT_ID)?.wireBytes !== 10_485_760 ||
    byId.get(UNARY_EXACT_ID)?.maxFrames !== 1 ||
    byId.get(UNARY_OVER_ID)?.transport !== "grpc" ||
    byId.get(UNARY_OVER_ID)?.action !== "get-document-transaction-bytes" ||
    byId.get(UNARY_OVER_ID)?.wireBytes !== 10_485_761 ||
    byId.get(UNARY_OVER_ID)?.maxFrames !== 1 ||
    byId.get(STREAM_EXACT_ID)?.transport !== "grpc" ||
    byId.get(STREAM_EXACT_ID)?.action !== "write-stream-token-bytes" ||
    byId.get(STREAM_EXACT_ID)?.wireBytes !== 10_485_760 ||
    byId.get(STREAM_EXACT_ID)?.maxFrames !== 1 ||
    byId.get(STREAM_OVER_ID)?.transport !== "grpc" ||
    byId.get(STREAM_OVER_ID)?.action !== "write-stream-token-bytes" ||
    byId.get(STREAM_OVER_ID)?.wireBytes !== 10_485_761 ||
    byId.get(STREAM_OVER_ID)?.maxFrames !== 1
  ) {
    throw new Error("unsupported stream recipe");
  }
  return {
    live: [
      byId.get(TRAILERS_ID),
      byId.get(HALF_CLOSE_ID),
      byId.get(RESPONSE_HALF_CLOSE_ID),
      byId.get(UNARY_EXACT_ID),
      byId.get(UNARY_OVER_ID),
      byId.get(STREAM_EXACT_ID),
      byId.get(STREAM_OVER_ID),
    ],
    saved: byId.get(SAVED_ID),
  };
}

export function shouldHalfCloseAfterResponse(recipe, responseCount) {
  return recipe.id === RESPONSE_HALF_CLOSE_ID ? responseCount === 2 : responseCount === 1;
}

export function responseGatedDeadlineIsIndeterminate(recipe, status, responseCount) {
  return recipe.id === RESPONSE_HALF_CLOSE_ID && status?.code === 4 && responseCount < 2;
}

function opaqueShape(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return value.length > 0 ? "nonempty-bytes" : "empty-bytes";
  }
  if (typeof value === "string") return value.length > 0 ? "nonempty-string" : "empty-string";
  return normalize(value);
}

/** Opaque stream credentials are not comparable or safe to save verbatim. */
export function projectStreamResponse(response) {
  if (!response || typeof response !== "object") throw new Error("invalid stream response");
  const { streamId, streamToken, ...rest } = response;
  return {
    ...(streamId === undefined ? {} : { streamId: opaqueShape(streamId) }),
    ...(streamToken === undefined ? {} : { streamToken: opaqueShape(streamToken) }),
    ...normalize(rest),
  };
}

export function projectStreamStatus(status) {
  const normalized = normalizeError(status);
  const trailers = normalized.trailers?.map((trailer) =>
    trailer.key === "x-debug-tracking-id" && trailer.kind === "ascii"
      ? { ...trailer, value: trailer.value ? "nonempty-volatile-id" : "empty-volatile-id" }
      : trailer,
  );
  return {
    code: status.code,
    details: normalized.details ?? null,
    ...(trailers === undefined ? {} : { trailers }),
  };
}

export function validateStreamTarget({ target, projectId, host, port }) {
  if (projectId !== SANDBOX_PROJECT) throw new Error("stream must address the sandbox project");
  if (target === "production") {
    if (host !== undefined || port !== undefined)
      throw new Error("production stream endpoint is fixed");
    return { host: "firestore.googleapis.com", port: 443, tls: true };
  }
  if (target === "local") {
    if (!new Set(["127.0.0.1", "::1", "localhost"]).has(host)) {
      throw new Error("local stream requires loopback host");
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error("local stream port is invalid");
    }
    return { host, port, tls: false };
  }
  throw new Error("unknown stream target");
}

export function terminalComplete({ status, sawEnd, sawClose, sentFrames, expectedFrames }) {
  return Boolean(status && (sawEnd || sawClose) && sentFrames === expectedFrames);
}

async function runUnaryRequestByteRecipe(recipe, { connection, projectId, token }) {
  const { request, wireBytes } = await makeUnaryRequestByWireBytes(recipe.wireBytes);
  const client = new v1.FirestoreClient({
    servicePath: connection.host,
    port: connection.port,
    projectId,
    sslCreds: connection.tls ? grpc.credentials.createSsl() : grpc.credentials.createInsecure(),
    fallback: false,
  });
  try {
    let result;
    try {
      const [response] = await client.getDocument(request, {
        deadline: new Date(Date.now() + 30_000),
        retry: { retryCodes: [] },
        otherArgs: { headers: { authorization: `Bearer ${token}` } },
      });
      result = {
        sentFrames: 1,
        wireBytes,
        status: { code: 0, details: "", trailers: [] },
        response: normalize(response),
      };
    } catch (error) {
      if (error?.code === 4) throw new Error("indeterminate: unary client deadline");
      const status = projectStreamStatus(error);
      result = { sentFrames: 1, wireBytes, status };
    }
    const recorded = normalizeRecordedResponse(result, {
      project: SANDBOX_PROJECT,
      recordProject: "demo-firestore-probe",
      scope: "error",
    });
    if (
      JSON.stringify(recorded).includes(token) ||
      JSON.stringify(recorded).includes(SANDBOX_PROJECT)
    ) {
      throw new Error("unary recording contains private identity or credential");
    }
    return recorded;
  } finally {
    await client.close();
  }
}

/** Run one fixed, no-document-write terminal probe using the real Firestore gRPC client. */
export async function runStreamRecipe(recipe, { target, projectId, host, port, token }) {
  const connection = validateStreamTarget({ target, projectId, host, port });
  if (typeof token !== "string" || token.length === 0) throw new Error("stream bearer is required");
  if ([UNARY_EXACT_ID, UNARY_OVER_ID].includes(recipe?.id)) {
    return runUnaryRequestByteRecipe(recipe, { connection, projectId, token });
  }
  const requestByteStream = [STREAM_EXACT_ID, STREAM_OVER_ID].includes(recipe?.id);
  if (
    ![TRAILERS_ID, HALF_CLOSE_ID, RESPONSE_HALF_CLOSE_ID].includes(recipe?.id) &&
    !requestByteStream
  )
    throw new Error("unsupported live stream recipe");
  const byteRequest = requestByteStream
    ? await makeStreamRequestByWireBytes(recipe.wireBytes)
    : undefined;
  const client = new v1.FirestoreClient({
    servicePath: connection.host,
    port: connection.port,
    projectId,
    sslCreds: connection.tls ? grpc.credentials.createSsl() : grpc.credentials.createInsecure(),
    fallback: false,
  });
  const call = client.write({
    deadline: new Date(Date.now() + 30_000),
    retry: { retryCodes: [] },
    otherArgs: { headers: { authorization: `Bearer ${token}` } },
  });
  return await new Promise((resolve, reject) => {
    const events = [];
    let status;
    let sentFrames = 0;
    let sawClose = false;
    let sawEnd = false;
    let responseCount = 0;
    let settled = false;
    let grace;
    const timer = setTimeout(
      () =>
        finish(
          new Error(
            `stream terminal timeout after ${events.map((event) => event.type).join(",")}; sent=${sentFrames}`,
          ),
        ),
      31_000,
    );
    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(grace);
      if (error) call.destroy(error);
      client.close();
      if (error) return reject(error);
      if (
        !terminalComplete({
          status,
          sawEnd,
          sawClose,
          sentFrames,
          expectedFrames: recipe.maxFrames,
        })
      ) {
        return reject(new Error("incomplete gRPC terminal observation"));
      }
      if (responseGatedDeadlineIsIndeterminate(recipe, status, responseCount)) {
        return reject(new Error("indeterminate: client deadline before the gated stream response"));
      }
      if (requestByteStream && status.code === 4) {
        return reject(new Error("indeterminate: request-byte stream client deadline"));
      }
      const recorded = normalizeRecordedResponse(
        {
          status,
          sentFrames,
          events,
          ...(byteRequest ? { wireBytes: byteRequest.wireBytes } : {}),
        },
        {
          project: SANDBOX_PROJECT,
          recordProject: "demo-firestore-probe",
          scope: "error",
        },
      );
      if (
        JSON.stringify(recorded).includes(token) ||
        JSON.stringify(recorded).includes(SANDBOX_PROJECT)
      ) {
        return reject(new Error("stream recording contains private identity or credential"));
      }
      return resolve(recorded);
    }
    function maybeFinish() {
      if (
        terminalComplete({
          status,
          sawEnd,
          sawClose,
          sentFrames,
          expectedFrames: recipe.maxFrames,
        }) &&
        !grace
      ) {
        grace = setTimeout(() => finish(), 100);
      }
    }
    try {
      call.on("data", (response) => {
        events.push({ type: "data", value: projectStreamResponse(response) });
        responseCount += 1;
        if (responseCount === 1 && recipe.id !== HALF_CLOSE_ID && !requestByteStream) {
          call.write({ streamToken: response.streamToken, writes: [{}] });
          sentFrames += 1;
        }
        if (shouldHalfCloseAfterResponse(recipe, responseCount)) {
          if (recipe.id === RESPONSE_HALF_CLOSE_ID) {
            events.push({ type: "half-close-after-response", responseCount });
          }
          call.end();
        }
      });
      call.on("status", (value) => {
        status = projectStreamStatus(value);
        events.push({ type: "status", value: status });
        maybeFinish();
      });
      call.on("error", (error) => {
        events.push({ type: "error", value: projectStreamStatus(error) });
      });
      call.on("end", () => {
        sawEnd = true;
        events.push({ type: "end" });
        maybeFinish();
      });
      call.on("close", () => {
        sawClose = true;
        events.push({ type: "close" });
        maybeFinish();
      });
      call.write(byteRequest?.request ?? { database: `projects/${projectId}/databases/(default)` });
      sentFrames += 1;
      if (requestByteStream) call.end();
    } catch (error) {
      finish(error);
    }
  });
}

async function main() {
  const input = process.env.FIRESTORE_STREAM_CORPUS;
  const output = process.env.FIRESTORE_STREAM_OUT;
  const target = process.env.FIRESTORE_STREAM_TARGET;
  const token = process.env.FIRESTORE_STREAM_TOKEN;
  if (!input || !output || !target || !token) throw new Error("stream session inputs are required");
  const corpus = JSON.parse(await readFile(input, "utf8"));
  const { live } = validateStreamRecipes(corpus.streamRecipes);
  const options = {
    target,
    projectId: SANDBOX_PROJECT,
    host: process.env.FIRESTORE_STREAM_HOST,
    port:
      process.env.FIRESTORE_STREAM_PORT === undefined
        ? undefined
        : Number(process.env.FIRESTORE_STREAM_PORT),
    token,
  };
  const results = {};
  for (const recipe of live) results[recipe.id] = await runStreamRecipe(recipe, options);
  await writeFile(output, `${JSON.stringify(results, null, 2)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  await main();
}
