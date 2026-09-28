import { createHash } from "node:crypto";
import { types } from "node:util";

function dataRecord(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error();
  const result = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      (keys && !keys.includes(key)) ||
      !descriptor.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error();
    result[key] = descriptor.value;
  }
  return result;
}

function sessionBoundary(value) {
  const config = dataRecord(value, ["dialect", "bucket", "prefix", "objectName"]);
  if (
    Object.keys(config).length !== 4 ||
    !["firebase", "gcs"].includes(config.dialect) ||
    typeof config.bucket !== "string" ||
    config.bucket.length < 3 ||
    config.bucket.length > 222 ||
    !config.bucket.split(".").every((part) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part)) ||
    typeof config.prefix !== "string" ||
    !/^storage-object\/[a-z0-9]{8,32}\/$/.test(config.prefix) ||
    typeof config.objectName !== "string" ||
    !config.objectName.isWellFormed() ||
    !config.objectName.startsWith(config.prefix) ||
    config.objectName.length === config.prefix.length ||
    Buffer.byteLength(config.objectName) > 1024
  )
    throw new Error();
  return config;
}

function endpoint(config) {
  return config.dialect === "gcs"
    ? {
        origin: "https://storage.googleapis.com",
        path: `/upload/storage/v1/b/${config.bucket}/o`,
        protocol: "uploadType",
      }
    : {
        origin: "https://firebasestorage.googleapis.com",
        path: `/v0/b/${config.bucket}/o`,
        protocol: "upload_protocol",
      };
}

/** Validate an opaque URI in memory. This does not establish actual-response provenance. */
export function validateProductionSessionUri(value, boundary) {
  try {
    const config = sessionBoundary(boundary),
      expected = endpoint(config);
    if (
      typeof value !== "string" ||
      value.length > 8192 ||
      !/^[\x21-\x7e]+$/.test(value) ||
      value.includes("#") ||
      /%(?![a-fA-F0-9]{2})/.test(value)
    )
      throw new Error();
    const url = new URL(value);
    if (
      url.href !== value ||
      url.origin !== expected.origin ||
      url.pathname !== expected.path ||
      url.username ||
      url.password ||
      url.port ||
      url.hash
    )
      throw new Error();
    const keys = [...url.searchParams.keys()];
    if (
      new Set(keys).size !== keys.length ||
      keys.some((key) => ![expected.protocol, "upload_id", "name"].includes(key)) ||
      url.searchParams.get(expected.protocol) !== "resumable" ||
      (url.searchParams.has("name") && url.searchParams.get("name") !== config.objectName)
    )
      throw new Error();
    const uploadId = url.searchParams.get("upload_id");
    if (typeof uploadId !== "string" || !/^[\x21-\x7e]{1,4096}$/.test(uploadId)) throw new Error();
    return Object.freeze({
      url: value,
      uploadId,
      objectName: config.objectName,
      uriSha256: createHash("sha256").update(value).digest("hex"),
    });
  } catch {
    throw new Error("invalid production session URI");
  }
}

function canonicalDecimal(value, positive = false) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,15})$/.test(value)) throw new Error();
  const number = BigInt(value);
  if (positive && number === 0n) throw new Error();
  return number;
}

function continuationMutation(step) {
  const headers = dataRecord(step.headers),
    keys = Object.keys(headers);
  if (Object.values(headers).some((value) => typeof value !== "string" || value.length > 256))
    throw new Error();
  if (step.dialect === "firebase") {
    if (
      step.method !== "POST" ||
      keys.some((key) => !["x-goog-upload-command", "x-goog-upload-offset"].includes(key))
    )
      throw new Error();
    const command = headers["x-goog-upload-command"];
    if (["query", "cancel"].includes(command)) {
      if (keys.length !== 1) throw new Error();
      return command === "cancel";
    }
    if (!["upload", "upload, finalize"].includes(command) || keys.length !== 2) throw new Error();
    canonicalDecimal(headers["x-goog-upload-offset"]);
    return true;
  }
  if (keys.some((key) => !["content-length", "content-range"].includes(key))) throw new Error();
  const length = canonicalDecimal(headers["content-length"]);
  if (step.method === "DELETE") {
    if (keys.length !== 1 || length !== 0n) throw new Error();
    return true;
  }
  if (step.method !== "PUT" || keys.length !== 2) throw new Error();
  const range = headers["content-range"],
    query = /^bytes \*\/([1-9][0-9]{0,15})$/.exec(range);
  if (query) {
    if (length !== 0n) throw new Error();
    return false;
  }
  const upload = /^bytes (0|[1-9][0-9]{0,15})-(0|[1-9][0-9]{0,15})\/([1-9][0-9]{0,15})$/.exec(
    range,
  );
  if (!upload) throw new Error();
  const [, begin, end, total] = upload.map((entry, index) => (index === 0 ? entry : BigInt(entry)));
  if (end < begin || end >= total || length !== end - begin + 1n) throw new Error();
  return true;
}

/** Resolve the declared continuation family; only a wire-owned capability may authorize dispatch. */
export function resolveProductionSessionRoute(value, suppliedBinding) {
  try {
    const binding = dataRecord(suppliedBinding, [
      "dialect",
      "bucket",
      "prefix",
      "objectName",
      "uri",
      "initiateStep",
    ]);
    if (
      Object.keys(binding).length !== 6 ||
      typeof binding.initiateStep !== "string" ||
      !/^[a-z][a-z0-9-]{0,127}$/.test(binding.initiateStep)
    )
      throw new Error();
    const config = sessionBoundary({
      dialect: binding.dialect,
      bucket: binding.bucket,
      prefix: binding.prefix,
      objectName: binding.objectName,
    });
    const captured = validateProductionSessionUri(binding.uri, config),
      expected = endpoint(config),
      step = dataRecord(value);
    const reference = dataRecord(step.sessionUriReference, [
      "kind",
      "initiateStep",
      "expectedOrigin",
      "expectedPath",
      "expectedName",
      "secretHandling",
    ]);
    if (
      Object.keys(reference).length !== 6 ||
      reference.kind !==
        (config.dialect === "gcs" ? "gcs-resumable-location" : "firebase-resumable-url") ||
      reference.initiateStep !== binding.initiateStep ||
      reference.expectedOrigin !== expected.origin ||
      reference.expectedPath !== expected.path ||
      reference.expectedName !== config.objectName ||
      reference.secretHandling !== "private-only" ||
      step.dialect !== config.dialect ||
      step.objectName !== config.objectName ||
      Object.hasOwn(step, "path") ||
      step.credential !== "admin" ||
      Object.hasOwn(step, "credentialRef") ||
      Object.keys(dataRecord(step.query)).length !== 0
    )
      throw new Error();
    return Object.freeze({
      method: step.method,
      url: captured.url,
      objectName: config.objectName,
      mutation: continuationMutation(step),
    });
  } catch {
    throw new Error("invalid production session route");
  }
}
