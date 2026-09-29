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

import {
  originalProductionArtifactContext,
  productionArtifactFailureCode,
} from "./production-artifact-policy.mjs";

const boundaries = new WeakMap();
const exit = process.exit.bind(process);
const now = Date.now.bind(Date);
const Instant = Date;
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

/** A persistence writer must share the original owned failure directory. */
export function productionStandaloneOwnsDirectory(value, directory) {
  const expected = boundaries.get(value);
  try {
    return (
      typeof directory === "string" &&
      expected?.directory === directory &&
      sameDirectory(lstatSync(directory), expected)
    );
  } catch {
    return false;
  }
}

/** Only a profile-bound capability can audit a task whose secret scan has become unavailable. */
export function productionStandaloneUsesArtifactProfile(value, profile) {
  const expected = boundaries.get(value);
  return expected?.profile === profile && originalProductionArtifactContext(profile) !== null;
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
    const input = copyProductionCaptureRecord(supplied, ["directory", "profile"]);
    const { directory } = input;
    const runtime = Object.hasOwn(input, "profile")
      ? originalProductionArtifactContext(input.profile)
      : null;
    if (Object.hasOwn(input, "profile") && !runtime) throw new Error();
    runtime?.secretRegistry.openScan();
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
    boundaries.set(boundary, {
      directory,
      dev: stat.dev,
      ino: stat.ino,
      profile: input.profile,
      runtime,
    });
    return boundary;
  } catch {
    throw new Error("invalid production standalone boundary");
  }
}

function persistFixedRecord(expected, bytes, file) {
  let directoryFd, fileFd;
  try {
    if (bytes.length > 1024 || !sameDirectory(lstatSync(expected.directory), expected))
      throw new Error();
    directoryFd = openSync(
      expected.directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    if (!sameDirectory(fstatSync(directoryFd), expected)) throw new Error();
    const path = join(expected.directory, file);
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
}

/** Fixed source metadata only; unchecked payload or digest bytes are never persisted. */
export function failStopProductionStandalone(boundary, supplied) {
  const expected = boundaries.get(boundary);
  if (!expected) throw new Error("invalid production standalone boundary");
  try {
    const value = metadata(supplied);
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    let privacyCode = null;
    if (expected.runtime) {
      try {
        if (expected.runtime.secretRegistry.openScan().hasSecretCopy(bytes.toString("utf8")))
          privacyCode = "artifact-withheld-privacy";
      } catch {
        const originalCode = productionArtifactFailureCode(expected.profile);
        privacyCode = ["artifact-withheld-privacy", "artifact-uncheckable"].includes(originalCode)
          ? originalCode
          : "artifact-uncheckable";
      }
    }
    if (privacyCode) {
      // The coordinator explicitly admits these source-only audit fields even when payload scanning is unavailable.
      const audit = {
        reason: privacyCode,
        timestamp: new Instant(now()).toISOString(),
        runId: expected.runtime.runIds[value.recording - 1],
      };
      persistFixedRecord(
        expected,
        Buffer.from(`${JSON.stringify(audit)}\n`),
        `privacy-r${value.recording}.json`,
      );
    } else persistFixedRecord(expected, bytes, `fatal-r${value.recording}.json`);
  } catch {
    // Uncertain persistence retains the started lease and cannot turn into normal closure.
  }
  exit(2);
}

/** Source-only privacy audit: a checked payload or commitment cannot be fabricated after scan failure. */
export function failStopProductionPrivacy(boundary, supplied) {
  const expected = boundaries.get(boundary);
  if (!expected?.runtime) throw new Error("invalid production privacy boundary");
  let input;
  try {
    input = copyProductionCaptureRecord(supplied, ["recording", "reason"]);
    if (
      Object.keys(input).length !== 2 ||
      ![1, 2].includes(input.recording) ||
      ![
        "artifact-withheld-privacy",
        "artifact-uncheckable",
        "artifact-removed-late-secret",
        "artifact-past-scan-uncertain",
        "shared-record-withheld-privacy",
        "shared-record-uncheckable",
      ].includes(input.reason)
    )
      throw new Error();
  } catch {
    throw new Error("invalid production privacy failure");
  }
  expected.runtime.secretRegistry.close();
  try {
    const audit = {
      reason: input.reason,
      timestamp: new Instant(now()).toISOString(),
      runId: expected.runtime.runIds[input.recording - 1],
    };
    persistFixedRecord(
      expected,
      Buffer.from(`${JSON.stringify(audit)}\n`),
      `privacy-r${input.recording}.json`,
    );
  } catch {
    // Persistence uncertainty retains the started lease and exits without exposing payload metadata.
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
