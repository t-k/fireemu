import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  realpathSync,
  writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { isAbsolute, join } from "node:path";
import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import {
  isProductionArtifactProfile,
  sanitizeProductionArtifact,
} from "./production-artifact-policy.mjs";
import {
  failStopProductionStandalone,
  productionStandaloneOwnsDirectory,
  productionStandaloneUsesArtifactProfile,
} from "./production-standalone-fail-stop.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const writers = new WeakSet();
const receipts = new WeakMap();
// A finite prototype ceiling; the runtime must still prove every actual producer count.
const MAX_ARTIFACT_FILES = 6000 * 16 + 1024;
const MAX_OUTPUT_BYTES = MAX_RESPONSE_BODY_BYTES + 4096 * 160;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
function owned(stat, mode) {
  return (
    (stat.mode & 0o777) === mode &&
    (typeof process.getuid !== "function" || stat.uid === process.getuid())
  );
}
function sameDirectory(stat, expected) {
  return (
    stat.isDirectory() &&
    owned(stat, 0o700) &&
    stat.dev === expected.dev &&
    stat.ino === expected.ino
  );
}
function sameArtifact(stat, expected, byteLength) {
  return (
    stat.isFile() &&
    stat.nlink === 1 &&
    owned(stat, 0o600) &&
    stat.size === byteLength &&
    stat.dev === expected.dev &&
    stat.ino === expected.ino
  );
}
function context(supplied) {
  const value = copyProductionCaptureRecord(supplied, [
    "recording",
    "operationId",
    "kind",
    "value",
  ]);
  if (
    Object.keys(value).length !== 4 ||
    ![1, 2].includes(value.recording) ||
    typeof value.kind !== "string" ||
    typeof value.operationId !== "string" ||
    value.operationId.length > 120 ||
    !new RegExp(`^r${value.recording}/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)/[a-f0-9]{64}$`).test(
      value.operationId,
    )
  )
    throw new Error("invalid production artifact context");
  return value;
}
/** Receipts prove this persistence operation only, never semantic state or terminal cleanup. */
export function isProductionArtifactReceipt(receipt, supplied) {
  try {
    const proof = copyProductionCaptureRecord(supplied, [
      "writer",
      "recording",
      "operationId",
      "kind",
    ]);
    const original = receipts.get(receipt);
    return (
      Object.keys(proof).length === 4 &&
      writers.has(proof.writer) &&
      original?.writer === proof.writer &&
      original.recording === proof.recording &&
      original.operationId === proof.operationId &&
      original.kind === proof.kind
    );
  } catch {
    return false;
  }
}
/** This original synchronous writer owns every path and never receives a raw error object. */
export function createProductionArtifactWriter(supplied) {
  let input, expected;
  try {
    input = copyProductionCaptureRecord(supplied, ["directory", "profile", "boundary"]);
    if (
      Object.keys(input).length !== 3 ||
      !isProductionArtifactProfile(input.profile) ||
      typeof input.directory !== "string" ||
      input.directory.length > 4096 ||
      input.directory.includes("\0") ||
      !isAbsolute(input.directory) ||
      realpathSync(input.directory) !== input.directory ||
      !productionStandaloneOwnsDirectory(input.boundary, input.directory) ||
      !productionStandaloneUsesArtifactProfile(input.boundary, input.profile)
    )
      throw new Error();
    const stat = lstatSync(input.directory);
    if (!stat.isDirectory() || !owned(stat, 0o700)) throw new Error();
    expected = { dev: stat.dev, ino: stat.ino };
  } catch {
    throw new Error("invalid production artifact writer");
  }
  let sequence = 0,
    closed = false;
  const stop = (row) =>
    failStopProductionStandalone(input.boundary, {
      recording: row.recording,
      operationId: row.operationId,
      reason: "PERSISTENCE_UNCERTAIN",
      providerKind: "runtime",
    });
  const writer = Object.freeze({
    write(value) {
      const row = context(value);
      let directoryFd,
        fileFd,
        result,
        durable = false;
      try {
        if (closed || sequence >= MAX_ARTIFACT_FILES) throw new Error();
        const projection = sanitizeProductionArtifact(input.profile, {
          kind: row.kind,
          value: row.value,
        });
        if (projection === null) throw new Error();
        const bytes = Buffer.from(JSON.stringify(projection));
        if (bytes.length > MAX_OUTPUT_BYTES || !sameDirectory(lstatSync(input.directory), expected))
          throw new Error();
        const file = `artifact-${String(++sequence).padStart(6, "0")}-r${row.recording}.json`,
          path = join(input.directory, file);
        directoryFd = openSync(
          input.directory,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        );
        if (!sameDirectory(fstatSync(directoryFd), expected)) throw new Error();
        fileFd = openSync(
          path,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
        const before = fstatSync(fileFd);
        if (!before.isFile() || before.nlink !== 1 || !owned(before, 0o600)) throw new Error();
        let offset = 0;
        while (offset < bytes.length) {
          const count = writeSync(fileFd, bytes, offset, bytes.length - offset);
          if (!Number.isSafeInteger(count) || count <= 0 || count > bytes.length - offset)
            throw new Error();
          offset += count;
        }
        fsyncSync(fileFd);
        const after = fstatSync(fileFd),
          pathStat = lstatSync(path);
        if (
          !sameArtifact(after, before, bytes.length) ||
          !sameArtifact(pathStat, before, bytes.length) ||
          !sameDirectory(lstatSync(input.directory), expected)
        )
          throw new Error();
        fsyncSync(directoryFd);
        if (
          !sameArtifact(fstatSync(fileFd), before, bytes.length) ||
          !sameArtifact(lstatSync(path), before, bytes.length) ||
          !sameDirectory(fstatSync(directoryFd), expected) ||
          !sameDirectory(lstatSync(input.directory), expected)
        )
          throw new Error();
        result = Object.freeze({
          type: "production-artifact-durable",
          recording: row.recording,
          sequence,
          kind: row.kind,
          file,
          sha256: hash(bytes),
          byteLength: bytes.length,
        });
        durable = projection.taskSecretStatus === "AVAILABLE";
      } catch {
        durable = false;
      } finally {
        for (const fd of [fileFd, directoryFd])
          if (fd !== undefined)
            try {
              closeSync(fd);
            } catch {
              durable = false;
            }
      }
      if (!durable) stop(row);
      receipts.set(result, {
        writer,
        recording: row.recording,
        operationId: row.operationId,
        kind: row.kind,
      });
      return result;
    },
    close() {
      closed = true;
    },
  });
  writers.add(writer);
  return writer;
}
