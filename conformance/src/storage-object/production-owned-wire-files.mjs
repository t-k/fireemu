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
import { types } from "node:util";
import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { originalProductionArtifactContext } from "./production-artifact-policy.mjs";
import {
  productionStandaloneOwnsDirectory,
  productionStandaloneUsesArtifactProfile,
  failStopProductionStandalone,
  failStopProductionPrivacy,
} from "./production-standalone-fail-stop.mjs";
import { isProductionSecretRegistry } from "./production-secret-registry.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

import {
  ensureProductionArtifactInventory,
  ensurePrototypeArtifactInventory,
  reserveProductionArtifactFile,
  trackProductionArtifactFile,
} from "./production-artifact-inventory.mjs";

const writers = new WeakSet(),
  receipts = new WeakMap(),
  pendingFiles = new WeakMap();
export function originalProductionWireArtifactPending(writer) {
  return writers.has(writer) ? (pendingFiles.get(writer) ?? null) : null;
}
const kinds = Object.freeze(["request", "intent", "response", "result"]);
// The final scan accepts at most 2 MiB of text; this conservative byte ceiling never exceeds it.
// The operational capture representation still needs its separate producer inventory and boundary proof.
const MAX_CAPTURE_FILE_BYTES = MAX_RESPONSE_BODY_BYTES;
const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteLength",
).get;
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
function sameFile(stat, expected, length) {
  return (
    stat.isFile() &&
    stat.nlink === 1 &&
    owned(stat, 0o600) &&
    stat.size === length &&
    stat.dev === expected.dev &&
    stat.ino === expected.ino
  );
}
function copyBytes(value) {
  if (
    types.isProxy(value) ||
    !Buffer.isBuffer(value) ||
    Object.getPrototypeOf(value) !== Buffer.prototype
  )
    throw new Error();
  const length = byteLength.call(value);
  if (length < 1 || length > MAX_CAPTURE_FILE_BYTES) throw new Error();
  const copy = Buffer.alloc(length);
  Uint8Array.prototype.set.call(copy, value);
  return copy;
}

/** This receipt proves one original persistence operation, never HTTP completion or semantic state. */
export function isProductionWireFileReceipt(receipt, writer, kind) {
  const binding = receipts.get(receipt);
  return writers.has(writer) && binding?.writer === writer && binding.kind === kind;
}

export function originalProductionWireArtifactFile(receipt, writer) {
  const original = receipts.get(receipt);
  return writers.has(writer) && original?.writer === writer ? original.fileBinding : null;
}

/** The owned wire supplies already sanitized serialized records; every actual byte is checked again. */
export function createProductionWireFileWriter(supplied) {
  return createWireFileWriter(supplied, false);
}
/** This legacy prototype cannot authorize production dispatch or a standalone terminal result. */
export function createPrototypeWireFileWriter(supplied) {
  return createWireFileWriter(supplied, true);
}
function createWireFileWriter(supplied, prototype) {
  let input, runtime, expected, recording;
  try {
    input = copyProductionCaptureRecord(supplied, [
      "directory",
      "profile",
      "boundary",
      "operationId",
      "sequence",
      ...(prototype ? ["registry"] : []),
    ]);
    runtime = prototype
      ? { secretRegistry: input.registry }
      : originalProductionArtifactContext(input.profile);
    if (typeof input.operationId !== "string" || input.operationId.length > 120) throw new Error();
    recording = /^r([12])\/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)\/[a-f0-9]{64}$/.exec(
      input.operationId,
    )?.[1];
    if (
      Object.keys(input).length !== (prototype ? 4 : 5) ||
      !runtime ||
      (!prototype && recording === undefined) ||
      (prototype && !isProductionSecretRegistry(input.registry)) ||
      !Number.isSafeInteger(input.sequence) ||
      input.sequence < 1 ||
      input.sequence > (prototype ? 999999 : 6000) ||
      typeof input.directory !== "string" ||
      input.directory.length > 4096 ||
      input.directory.includes("\0") ||
      !isAbsolute(input.directory) ||
      realpathSync(input.directory) !== input.directory ||
      (!prototype &&
        (!productionStandaloneUsesArtifactProfile(input.boundary, input.profile) ||
          !productionStandaloneOwnsDirectory(input.boundary, input.directory)))
    )
      throw new Error();
    runtime.secretRegistry.openScan();
    const stat = lstatSync(input.directory);
    if (!stat.isDirectory() || !owned(stat, 0o700)) throw new Error();
    expected = { dev: stat.dev, ino: stat.ino };
  } catch {
    throw new Error("invalid production wire file writer");
  }
  recording = Number(recording ?? 1);
  const inventory = prototype
    ? ensurePrototypeArtifactInventory({ directory: input.directory, registry: input.registry })
    : ensureProductionArtifactInventory({
        directory: input.directory,
        profile: input.profile,
        boundary: input.boundary,
      });
  const stem = String(input.sequence).padStart(6, "0");
  const files = Object.freeze(
    Object.fromEntries(kinds.map((kind) => [kind, join(input.directory, `${stem}-${kind}.json`)])),
  );
  const written = new Set();
  const stop = () => {
    if (prototype) {
      runtime.secretRegistry.close();
      throw new Error("production wire file persistence failed");
    }
    return failStopProductionStandalone(input.boundary, {
      recording,
      operationId: input.operationId,
      reason: "PERSISTENCE_UNCERTAIN",
      providerKind: "runtime",
    });
  };
  const writer = Object.freeze({
    files,
    write(kind, value) {
      let fileFd,
        directoryFd,
        result,
        fileBinding,
        durable = false;
      try {
        if (!kinds.includes(kind) || written.has(kind)) throw new Error();
        written.add(kind);
        const bytes = copyBytes(value);
        let reason = "artifact-uncheckable";
        try {
          if (runtime.secretRegistry.openScan().hasSecretCopy(bytes.toString("utf8"))) {
            reason = "artifact-withheld-privacy";
            throw new Error();
          }
        } catch {
          if (prototype) {
            runtime.secretRegistry.close();
            throw new Error("production wire artifact withheld");
          }
          failStopProductionPrivacy(input.boundary, { recording, reason });
        }
        if (!sameDirectory(lstatSync(input.directory), expected)) throw new Error();
        pendingFiles.set(
          writer,
          Object.freeze({
            directory: input.directory,
            profile: input.profile,
            boundary: input.boundary,
            registry: runtime.secretRegistry,
            file: `${stem}-${kind}.json`,
            path: files[kind],
            recording,
          }),
        );
        reserveProductionArtifactFile(inventory, writer);
        directoryFd = openSync(
          input.directory,
          constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
        );
        if (!sameDirectory(fstatSync(directoryFd), expected)) throw new Error();
        fileFd = openSync(
          files[kind],
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
        const before = fstatSync(fileFd);
        if (!before.isFile() || before.nlink !== 1 || !owned(before, 0o600)) throw new Error();
        pendingFiles.set(
          writer,
          Object.freeze({ ...pendingFiles.get(writer), dev: before.dev, ino: before.ino }),
        );
        reserveProductionArtifactFile(inventory, writer);
        let offset = 0;
        while (offset < bytes.length) {
          const count = writeSync(fileFd, bytes, offset, bytes.length - offset);
          if (!Number.isSafeInteger(count) || count <= 0 || count > bytes.length - offset)
            throw new Error();
          offset += count;
        }
        fsyncSync(fileFd);
        if (
          !sameFile(fstatSync(fileFd), before, bytes.length) ||
          !sameFile(lstatSync(files[kind]), before, bytes.length) ||
          !sameDirectory(lstatSync(input.directory), expected)
        )
          throw new Error();
        fsyncSync(directoryFd);
        if (
          !sameFile(fstatSync(fileFd), before, bytes.length) ||
          !sameFile(lstatSync(files[kind]), before, bytes.length) ||
          !sameDirectory(fstatSync(directoryFd), expected) ||
          !sameDirectory(lstatSync(input.directory), expected)
        )
          throw new Error();
        result = Object.freeze({
          type: "production-wire-file-durable",
          sequence: input.sequence,
          kind,
          sha256: hash(bytes),
          byteLength: bytes.length,
        });
        fileBinding = Object.freeze({
          directory: input.directory,
          profile: input.profile,
          boundary: input.boundary,
          writerKind: "wire",
          kind,
          registry: runtime.secretRegistry,
          file: `${stem}-${kind}.json`,
          path: files[kind],
          dev: before.dev,
          ino: before.ino,
          recording,
          sha256: result.sha256,
          byteLength: bytes.length,
        });
        durable = true;
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
      if (!durable) stop();
      receipts.set(result, { writer, kind, fileBinding });
      try {
        trackProductionArtifactFile(inventory, writer, result);
        pendingFiles.delete(writer);
      } catch {
        stop();
      }
      return result;
    },
  });
  writers.add(writer);
  return writer;
}
