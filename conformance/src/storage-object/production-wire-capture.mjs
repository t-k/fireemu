import { createHash } from "node:crypto";
import { closeSync, constants, fsyncSync, openSync } from "node:fs";
import { join } from "node:path";
import {
  privateCaptureDirectory,
  writePrivateBytes,
  writePrivateExclusive,
} from "./private-wire-capture.mjs";
import { sanitizeProductionCapture } from "./production-capture-policy.mjs";
import { isProductionSecretRegistry } from "./production-secret-registry.mjs";
import { originalProductionArtifactContext } from "./production-artifact-policy.mjs";
import {
  createProductionWireFileWriter,
  createPrototypeWireFileWriter,
  isProductionWireFileReceipt,
} from "./production-owned-wire-files.mjs";
import {
  productionStandaloneOwnsDirectory,
  productionStandaloneUsesArtifactProfile,
  failStopProductionPrivacy,
  failStopProductionStandalone,
} from "./production-standalone-fail-stop.mjs";
import {
  isProductionCaptureProfile,
  productionCaptureRequestBodyKind,
} from "./production-capture-coverage.mjs";
import {
  HTTP_RESPONSE_READ_UNIT_BYTES,
  MAX_RESPONSE_BODY_BYTES,
  MAX_RESPONSE_WIRE_BYTES,
} from "./wire-limits.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const commitment = (bytes) => ({ byteLength: bytes.length, sha256: sha256(bytes) });
const encode = (value) => Buffer.from(`${JSON.stringify(value)}\n`);
const REASONS = new Set([
  "WIRE_ABORTED",
  "WIRE_ABORTED_BEFORE_DISPATCH",
  "WIRE_PREDISPATCH_REJECTED",
  "WIRE_TRUNCATED",
  "WIRE_REQUEST_SERIALIZATION_DIFFERED",
  "WIRE_TIMEOUT",
  "WIRE_CAPTURE_FAILED",
  "WIRE_RESPONSE_CAP_EXCEEDED",
  "WIRE_TLS_VALIDATION_FAILED",
  "WIRE_CONNECTION_FAILED",
  "WIRE_UNSUPPORTED_ENCODING",
  "WIRE_RESPONSE_BODY_CAP_EXCEEDED",
  "WIRE_RESPONSE_FAILED",
  "WIRE_UNEXPECTED_UPGRADE",
  "WIRE_REQUEST_FAILED",
  "WIRE_REQUEST_CREATION_FAILED",
  "WIRE_REQUEST_CAP_EXHAUSTED",
  "WIRE_RESPONSE_CAP_EXHAUSTED",
  "WIRE_BUDGET_HALTED",
  "WIRE_PREDISPATCH_OR_CAPTURE_FAILED",
  "WIRE_UNSUPPORTED_AUXILIARY_RESPONSE",
]);
const RECEIPT_FIELDS = new Set([
  "complete",
  "reason",
  "status",
  "finishConfirmed",
  "socketReportedWrittenBytes",
  "requestReservedBytes",
  "responseObservedBytes",
  "rawResponseHeaders",
  "responseBodyBase64",
]);

function persistenceCopy(value) {
  const { body, ...copy } = value;
  return { ...copy, bodyBase64: body === null ? null : body.toString("base64") };
}

function compactPersistenceCopy(value) {
  const jsonCommitment = (child) => commitment(Buffer.from(JSON.stringify(child)));
  return {
    originalByteLength: value.originalByteLength,
    originalSha256: value.originalSha256,
    mode: "COMMITMENT_ONLY",
    bodyBase64: null,
    replacedFields: jsonCommitment(value.replacedFields),
    url: jsonCommitment(value.url),
    headers: jsonCommitment(value.headers),
    replacedHeaders: jsonCommitment(value.replacedHeaders),
    observation: value.observation ?? {
      byteLength: value.originalByteLength,
      sha256: value.originalSha256,
    },
    taskSecretStatus: "AVAILABLE",
    representation: "SIZE_BOUND_COMMITMENT",
  };
}

/** The original HTTP plaintext is committed in memory and never passed to a file writer. */
export function createProductionWireAttempt({
  directory,
  sequence,
  request,
  metadata,
  policy = {},
}) {
  let responseFd;
  try {
    const method = request?.method;
    const requestBody = request?.body;
    const requestWireBytes = request?.wire;
    const requestHeaders = request?.headers;
    const url = request?.url;
    const operationId = metadata?.operationId;
    const phase = metadata?.phase;
    if (
      !Number.isSafeInteger(sequence) ||
      sequence < 1 ||
      sequence > 999999 ||
      !["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"].includes(method) ||
      !Buffer.isBuffer(requestBody) ||
      !Buffer.isBuffer(requestWireBytes) ||
      requestWireBytes.length > MAX_RESPONSE_WIRE_BYTES ||
      metadata === null ||
      typeof metadata !== "object" ||
      Array.isArray(metadata) ||
      Object.keys(metadata).some((key) => !["operationId", "phase"].includes(key)) ||
      typeof operationId !== "string" ||
      !operationId ||
      operationId.length > 120 ||
      !["subject", "cleanup"].includes(phase)
    )
      throw new Error("invalid production wire capture");
    const secretRegistry = policy.secretRegistry;
    const captureProfile = policy.captureProfile;
    const privacyBoundary = policy.standaloneBoundary;
    const artifactProfile = policy.artifactProfile;
    const recording = /^r([12])\/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)\/[a-f0-9]{64}$/.exec(
      operationId,
    )?.[1];
    if (privacyBoundary !== undefined || artifactProfile !== undefined) {
      const context = originalProductionArtifactContext(artifactProfile);
      if (
        recording === undefined ||
        context?.secretRegistry !== secretRegistry ||
        !productionStandaloneUsesArtifactProfile(privacyBoundary, artifactProfile) ||
        !productionStandaloneOwnsDirectory(privacyBoundary, directory)
      )
        throw new Error("invalid production wire privacy boundary");
    }
    // Every generated field and the actual serialization suffix are checked together.
    const encoded = (value) => {
      let bytes = encode(value);
      if (secretRegistry !== undefined) {
        let reason = "artifact-uncheckable";
        try {
          if (bytes.length > MAX_RESPONSE_BODY_BYTES) {
            const key = Object.hasOwn(value, "capture") ? "capture" : "response";
            const capture = value[key];
            const state = secretRegistry.snapshot();
            if (
              value.complete === false ||
              state.failed ||
              state.closed ||
              capture?.taskSecretStatus !== "AVAILABLE" ||
              !["RAW_BODY", "CAPABILITY_FIELDS_REPLACED"].includes(capture.mode)
            )
              throw new Error();
            bytes = encode({ ...value, [key]: compactPersistenceCopy(capture) });
          }
          if (bytes.length > MAX_RESPONSE_BODY_BYTES) throw new Error();
          if (secretRegistry.openScan().hasSecretCopy(bytes.toString("utf8"))) {
            reason = "artifact-withheld-privacy";
            throw new Error();
          }
        } catch {
          secretRegistry.close();
          if (privacyBoundary !== undefined)
            failStopProductionPrivacy(privacyBoundary, { recording: Number(recording), reason });
          throw new Error("production wire artifact withheld");
        }
      }
      return bytes;
    };
    if (secretRegistry !== undefined && !isProductionSecretRegistry(secretRegistry))
      throw new Error("invalid task secret registry");
    if (secretRegistry !== undefined && !isProductionCaptureProfile(captureProfile))
      throw new Error("invalid production capture profile");
    const options = {
      ...structuredClone({
        knownSecrets: policy.knownSecrets ?? [],
        approvedBodySha256: policy.approvedBodySha256 ?? [],
        expectedObjectNames: policy.expectedObjectNames ?? [],
        expectedBucket: policy.expectedBucket,
        expectedEmails: policy.expectedEmails ?? [],
      }),
      secretRegistry,
      captureProfile,
    };
    const responseBodyKind = policy.responseBodyKind ?? "json";
    if (!["json", "media"].includes(responseBodyKind))
      throw new Error("invalid production wire capture");
    const ownedWriter =
      privacyBoundary === undefined
        ? secretRegistry === undefined
          ? null
          : createPrototypeWireFileWriter({
              directory,
              registry: secretRegistry,
              operationId,
              sequence,
            })
        : createProductionWireFileWriter({
            directory,
            profile: artifactProfile,
            boundary: privacyBoundary,
            operationId,
            sequence,
          });
    const capturedRequest = sanitizeProductionCapture({
      ...options,
      url,
      direction: "request",
      headers: requestHeaders,
      body: requestBody,
      complete: true,
      status: null,
      bodyKind: secretRegistry
        ? productionCaptureRequestBodyKind(captureProfile)
        : (policy.requestBodyKind ?? "json"),
    });
    const requestWire = commitment(requestWireBytes);
    const parent = privateCaptureDirectory(directory);
    const stem = String(sequence).padStart(6, "0");
    const files =
      ownedWriter?.files ??
      Object.freeze({
        request: join(parent, `${stem}-request.json`),
        intent: join(parent, `${stem}-intent.json`),
        response: join(parent, `${stem}-response.json`),
        result: join(parent, `${stem}-result.json`),
      });
    const persist = (kind, value) => {
      const bytes = encoded(value);
      if (ownedWriter !== null) {
        const receipt = ownedWriter.write(kind, bytes);
        if (!isProductionWireFileReceipt(receipt, ownedWriter, kind))
          failStopProductionStandalone(privacyBoundary, {
            recording: Number(recording),
            operationId,
            reason: "PERSISTENCE_UNCERTAIN",
            providerKind: "runtime",
          });
      } else writePrivateExclusive(files[kind], bytes);
    };
    persist("request", {
      sequence,
      method,
      requestWire,
      capture: persistenceCopy(capturedRequest),
    });
    persist("intent", {
      sequence,
      phase,
      operationId: commitment(Buffer.from(operationId)),
      boundary: "HTTP_PLAINTEXT_COMMITMENT_AND_SANITIZED_BODY",
    });
    if (capturedRequest.taskSecretStatus === "UNAVAILABLE")
      throw new Error("task secret registry unavailable");
    if (ownedWriter === null)
      responseFd = openSync(
        files.response,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
    const wireHash = createHash("sha256");
    let byteLength = 0;
    let readUnits = 0;
    let capExceeded = false;
    let closed = false;
    return Object.freeze({
      files,
      snapshot: () => ({
        requestWireBytes: requestWire.byteLength,
        responseWireBytes: byteLength,
        readUnits,
        capExceeded,
        closed,
      }),
      appendResponse(bytes) {
        if (closed) throw new Error("production wire capture is closed");
        if (capExceeded) throw new Error("production capture wire cap exhausted");
        if (
          !Buffer.isBuffer(bytes) ||
          bytes.length < 1 ||
          bytes.length > HTTP_RESPONSE_READ_UNIT_BYTES
        )
          throw new Error("invalid production wire capture chunk");
        wireHash.update(bytes);
        byteLength += bytes.length;
        readUnits++;
        if (byteLength > MAX_RESPONSE_WIRE_BYTES) {
          capExceeded = true;
          throw new Error("production capture wire cap exhausted");
        }
      },
      finish(receipt) {
        if (closed) throw new Error("production wire capture is closed");
        closed = true;
        try {
          const responseWire = { byteLength, readUnits, sha256: wireHash.digest("hex") };
          if (secretRegistry === undefined) {
            writePrivateBytes(responseFd, encoded({ sequence, responseWire }));
            fsyncSync(responseFd);
          }
          if (
            receipt === null ||
            typeof receipt !== "object" ||
            Object.getPrototypeOf(receipt) !== Object.prototype
          )
            throw new Error("invalid production wire capture receipt record");
          const keys = Reflect.ownKeys(receipt);
          const descriptors = Object.getOwnPropertyDescriptors(receipt);
          if (
            keys.length !== RECEIPT_FIELDS.size ||
            keys.some(
              (key) =>
                !RECEIPT_FIELDS.has(key) ||
                !descriptors[key].enumerable ||
                !Object.hasOwn(descriptors[key], "value"),
            )
          )
            throw new Error("invalid production wire capture receipt property");
          receipt = Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
          const rawHeaders = receipt.rawResponseHeaders;
          if (
            !Array.isArray(rawHeaders) ||
            Object.getPrototypeOf(rawHeaders) !== Array.prototype ||
            rawHeaders.length > 512
          )
            throw new Error("invalid production wire capture header record");
          const headerDescriptors = Object.getOwnPropertyDescriptors(rawHeaders);
          if (Reflect.ownKeys(rawHeaders).length !== rawHeaders.length + 1)
            throw new Error("invalid production wire capture header property");
          receipt.rawResponseHeaders = Array.from({ length: rawHeaders.length }, (_, index) => {
            const descriptor = headerDescriptors[index];
            if (
              !descriptor?.enumerable ||
              !Object.hasOwn(descriptor, "value") ||
              typeof descriptor.value !== "string"
            )
              throw new Error("invalid production wire capture header value");
            return descriptor.value;
          });
          if (
            receipt === null ||
            typeof receipt !== "object" ||
            Array.isArray(receipt) ||
            Object.keys(receipt).some((key) => !RECEIPT_FIELDS.has(key)) ||
            typeof receipt.complete !== "boolean" ||
            typeof receipt.finishConfirmed !== "boolean" ||
            (receipt.status !== null &&
              (!Number.isSafeInteger(receipt.status) ||
                receipt.status < 100 ||
                receipt.status > 599)) ||
            [
              receipt.socketReportedWrittenBytes,
              receipt.requestReservedBytes,
              receipt.responseObservedBytes,
            ].some((value) => !Number.isSafeInteger(value) || value < 0) ||
            receipt.requestReservedBytes !== requestWire.byteLength ||
            receipt.responseObservedBytes !== byteLength ||
            !Array.isArray(receipt.rawResponseHeaders) ||
            receipt.rawResponseHeaders.length % 2 ||
            receipt.rawResponseHeaders.length > 512 ||
            (receipt.responseBodyBase64 !== null &&
              (typeof receipt.responseBodyBase64 !== "string" ||
                receipt.responseBodyBase64.length > Math.ceil(MAX_RESPONSE_BODY_BYTES / 3) * 4))
          )
            throw new Error("invalid production wire capture receipt");
          const body =
            receipt.responseBodyBase64 === null
              ? Buffer.alloc(0)
              : Buffer.from(receipt.responseBodyBase64, "base64");
          if (
            body.length > MAX_RESPONSE_BODY_BYTES ||
            (receipt.responseBodyBase64 !== null &&
              body.toString("base64") !== receipt.responseBodyBase64)
          )
            throw new Error("invalid production wire capture body");
          const headers = [];
          for (let index = 0; index < receipt.rawResponseHeaders.length; index += 2)
            headers.push(receipt.rawResponseHeaders.slice(index, index + 2));
          const complete =
            receipt.complete &&
            !capExceeded &&
            receipt.reason === null &&
            receipt.finishConfirmed &&
            receipt.status !== null &&
            byteLength > 0 &&
            receipt.socketReportedWrittenBytes === requestWire.byteLength;
          const reason = capExceeded
            ? "WIRE_RESPONSE_CAP_EXCEEDED"
            : receipt.reason === null
              ? null
              : REASONS.has(receipt.reason)
                ? receipt.reason
                : "WIRE_RESPONSE_FAILED";
          const response = sanitizeProductionCapture({
            ...options,
            url,
            direction: "response",
            complete,
            headers,
            body,
            bodyKind: responseBodyKind,
            status: receipt.status,
          });
          const taskUnavailable = response.taskSecretStatus === "UNAVAILABLE";
          if (secretRegistry !== undefined) {
            // Response discoveries must precede every generated response commitment.
            if (ownedWriter !== null) persist("response", { sequence, responseWire });
            else {
              writePrivateBytes(responseFd, encoded({ sequence, responseWire }));
              fsyncSync(responseFd);
            }
          }
          persist("result", {
            sequence,
            complete: complete && !taskUnavailable,
            reason: taskUnavailable ? "SECRET_DISCOVERY_UNAVAILABLE" : reason,
            status: receipt.status,
            finishConfirmed: receipt.finishConfirmed,
            socketReportedWrittenBytes: receipt.socketReportedWrittenBytes,
            requestReservedBytes: requestWire.byteLength,
            responseObservedBytes: byteLength,
            responseWire,
            response: persistenceCopy(response),
          });
          if (taskUnavailable) throw new Error("task secret registry unavailable");
        } catch {
          throw new Error("production wire capture receipt failed");
        } finally {
          if (responseFd !== undefined) closeSync(responseFd);
        }
      },
    });
  } catch {
    if (responseFd !== undefined) closeSync(responseFd);
    throw new Error("production wire capture creation failed");
  }
}
