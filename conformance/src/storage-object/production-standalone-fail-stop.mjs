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
import {
  copyProductionCaptureArray,
  copyProductionCaptureRecord,
} from "./production-capture-input.mjs";

const boundaries = new WeakMap();
const exit = process.exit.bind(process);
const kinds = new Set(["owner", "account", "admission", "secret"]);
const reasons = new Set([
  "PROVIDER_THREW",
  "PROVIDER_RESULT_UNSAFE",
  "STARTED_UNCERTAIN",
  "TERMINAL_UNCERTAIN",
  "PERSISTENCE_UNCERTAIN",
]);

/** Capability identity is checked without reading caller properties. */
export function isProductionStandaloneFailStop(value) {
  return boundaries.has(value);
}

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
function metadata(supplied) {
  const value = copyProductionCaptureRecord(supplied, [
    "recording",
    "operationId",
    "reason",
    "providerKind",
  ]);
  if (
    Object.keys(value).length !== 4 ||
    ![1, 2].includes(value.recording) ||
    typeof value.operationId !== "string" ||
    value.operationId.length > 120 ||
    !new RegExp(`^r${value.recording}/(?:p(?:[1-9]|1[0-9]|2[0-6])|control)/[a-f0-9]{64}$`).test(
      value.operationId,
    ) ||
    !reasons.has(value.reason) ||
    ![...kinds, "runtime"].includes(value.providerKind)
  )
    throw new Error();
  return {
    type: "production-fixed-failure",
    state: "NEEDS_RECOVERY",
    recording: value.recording,
    operationIdSha256: createHash("sha256").update(value.operationId).digest("hex"),
    reason: value.reason,
    providerKind: value.providerKind,
  };
}

/** Only the owned standalone may pass this original capability to a process-ending boundary. */
export function createProductionStandaloneFailStop(supplied) {
  try {
    const { directory } = copyProductionCaptureRecord(supplied, ["directory"]);
    if (
      typeof directory !== "string" ||
      directory.length > 4096 ||
      directory.includes("\0") ||
      !isAbsolute(directory) ||
      realpathSync(directory) !== directory
    )
      throw new Error();
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || !owned(stat, 0o700)) throw new Error();
    const boundary = Object.freeze({});
    boundaries.set(boundary, { directory, dev: stat.dev, ino: stat.ino });
    return boundary;
  } catch {
    throw new Error("invalid production standalone boundary");
  }
}

/** Fixed fields only; neither a provider result nor an error object crosses the persistence boundary. */
export function failStopProductionStandalone(boundary, supplied) {
  const expected = boundaries.get(boundary);
  if (!expected) throw new Error("invalid production standalone boundary");
  let directoryFd, fileFd;
  try {
    const value = metadata(supplied);
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    if (bytes.length > 1024 || !sameDirectory(lstatSync(expected.directory), expected))
      throw new Error();
    directoryFd = openSync(
      expected.directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    if (!sameDirectory(fstatSync(directoryFd), expected)) throw new Error();
    const path = join(expected.directory, `fatal-r${value.recording}.json`);
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
      !after.isFile() ||
      after.nlink !== 1 ||
      !owned(after, 0o600) ||
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== bytes.length ||
      !pathStat.isFile() ||
      pathStat.dev !== after.dev ||
      pathStat.ino !== after.ino ||
      !sameDirectory(lstatSync(expected.directory), expected)
    )
      throw new Error();
    fsyncSync(directoryFd);
  } catch {
    // Uncertain persistence retains the started lease and cannot turn into normal closure.
  } finally {
    for (const fd of [fileFd, directoryFd])
      if (fd !== undefined) {
        try {
          closeSync(fd);
        } catch {
          /* Exit stays silent even if closing a descriptor fails. */
        }
      }
  }
  exit(2);
}

/** The runtime must additionally pin original provider identities and their synchronous source contract. */
export function callProductionStandaloneProvider(supplied) {
  let input, args;
  try {
    input = copyProductionCaptureRecord(supplied, [
      "boundary",
      "kind",
      "provider",
      "args",
      "recording",
      "operationId",
    ]);
    if (
      Object.keys(input).length !== 6 ||
      !boundaries.has(input.boundary) ||
      !kinds.has(input.kind)
    )
      throw new Error();
    metadata({
      recording: input.recording,
      operationId: input.operationId,
      providerKind: input.kind,
      reason: "PROVIDER_RESULT_UNSAFE",
    });
    args = copyProductionCaptureArray(input.args, 2);
    if (
      typeof input.provider !== "function" ||
      types.isProxy(input.provider) ||
      Object.getPrototypeOf(input.provider) !== Function.prototype
    )
      throw new Error();
  } catch {
    throw new Error("invalid production standalone provider");
  }
  const stop = (reason) =>
    failStopProductionStandalone(input.boundary, {
      recording: input.recording,
      operationId: input.operationId,
      providerKind: input.kind,
      reason,
    });
  let result;
  try {
    result = input.provider(...args);
  } catch {
    stop("PROVIDER_THREW");
  }
  const valid =
    input.kind === "admission"
      ? result === true
      : input.kind === "secret"
        ? result === undefined
        : typeof result === "string" &&
          result.length <= 8201 &&
          (input.kind === "owner"
            ? /^Bearer [\x21-\x7e]{1,8192}$/
            : /^Firebase [\x21-\x7e]{1,8192}$/
          ).test(result);
  if (!valid) stop("PROVIDER_RESULT_UNSAFE");
  return result;
}
