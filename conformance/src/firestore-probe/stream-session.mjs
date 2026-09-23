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
const SAVED_SOURCE = "spec/compatibility/broad-runs/fs-write-txn-dee737c14-production-result.json";
const SANDBOX_PROJECT = "fireemu-oracle-sbx";

/** Keep live gRPC sends limited to the two reviewed terminal actions. */
export function validateStreamRecipes(recipes) {
  if (!Array.isArray(recipes) || recipes.length !== 3) {
    throw new Error("unsupported stream recipe set");
  }
  const byId = new Map(recipes.map((recipe) => [recipe.id, recipe]));
  if (
    byId.size !== 3 ||
    byId.get(SAVED_ID)?.transport !== "saved-reference" ||
    byId.get(SAVED_ID)?.source !== SAVED_SOURCE ||
    byId.get(TRAILERS_ID)?.transport !== "grpc" ||
    byId.get(TRAILERS_ID)?.action !== "invalid-empty-write-after-handshake" ||
    byId.get(TRAILERS_ID)?.maxFrames !== 2 ||
    byId.get(HALF_CLOSE_ID)?.transport !== "grpc" ||
    byId.get(HALF_CLOSE_ID)?.action !== "half-close-after-handshake" ||
    byId.get(HALF_CLOSE_ID)?.maxFrames !== 1
  ) {
    throw new Error("unsupported stream recipe");
  }
  return { live: [byId.get(TRAILERS_ID), byId.get(HALF_CLOSE_ID)], saved: byId.get(SAVED_ID) };
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
  return {
    code: status.code,
    details: normalized.details ?? null,
    ...(normalized.trailers === undefined ? {} : { trailers: normalized.trailers }),
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

/** Run one fixed, no-document-write terminal probe using the real Firestore gRPC client. */
export async function runStreamRecipe(recipe, { target, projectId, host, port, token }) {
  const connection = validateStreamTarget({ target, projectId, host, port });
  if (typeof token !== "string" || token.length === 0) throw new Error("stream bearer is required");
  if (![TRAILERS_ID, HALF_CLOSE_ID].includes(recipe?.id))
    throw new Error("unsupported live stream recipe");
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
    let firstResponse = false;
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
      const recorded = normalizeRecordedResponse(
        { status, sentFrames, events },
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
        if (firstResponse) return;
        firstResponse = true;
        if (recipe.id === TRAILERS_ID) {
          call.write({ streamToken: response.streamToken, writes: [{}] });
          sentFrames += 1;
        }
        call.end();
      });
      call.on("status", (value) => {
        status = projectStreamStatus(value);
        events.push({ type: "status", value: status });
        maybeFinish();
      });
      call.on("error", (error) => {
        events.push({ type: "error", value: normalizeError(error) });
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
      call.write({ database: `projects/${projectId}/databases/(default)` });
      sentFrames += 1;
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
