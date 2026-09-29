import { createProductionArtifactWorkAccount } from "./production-artifact-work-profile.mjs";
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { originalProductionArtifactContext } from "./production-artifact-policy.mjs";
import {
  copyProductionSharedInspectionReportBytes,
  originalProductionSharedInspectionContext,
  productionSharedInspectorUsesArtifactContext,
} from "./production-shared-file-inspector.mjs";
import {
  ensureProductionArtifactInventory,
  reserveProductionArtifactFile,
  trackProductionArtifactFile,
  productionSharedArtifactBrokerAllows,
} from "./production-artifact-inventory.mjs";
const writers = new WeakMap(),
  pending = new WeakMap(),
  receipts = new WeakMap();
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const uncertain = () => new Error("production shared report uncertain");
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
function sameFile(stat, before, size) {
  return (
    stat.isFile() &&
    owned(stat, 0o600) &&
    stat.nlink === 1 &&
    stat.dev === before.dev &&
    stat.ino === before.ino &&
    stat.size === size
  );
}
export function createProductionSharedReportWriter(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, [
      "directory",
      "profile",
      "boundary",
      "inspector",
    ]);
    if (
      Object.keys(input).length !== 4 ||
      !productionSharedInspectorUsesArtifactContext(input.inspector, {
        directory: input.directory,
        profile: input.profile,
        boundary: input.boundary,
      })
    )
      throw new Error();
    const runtime = originalProductionArtifactContext(input.profile);
    runtime.secretRegistry.openScan();
    const stat = lstatSync(input.directory);
    if (!sameDirectory(stat, stat)) throw new Error();
    const writer = Object.freeze({});
    const inventory = ensureProductionArtifactInventory({
      directory: input.directory,
      profile: input.profile,
      boundary: input.boundary,
    });
    writers.set(writer, {
      ...input,
      inventory,
      registry: runtime.secretRegistry,
      dev: stat.dev,
      ino: stat.ino,
      records: new Set(),
      account: createProductionArtifactWorkAccount({
        profile: runtime.workProfile ?? null,
        kind: "shared-report",
        ...(runtime.workProfile
          ? {}
          : { prototypeLimit: runtime.secretRegistry.snapshot().limits.maxScanCodeUnits }),
      }),
      failed: false,
      outcome: "NONE",
      permit: null,
      requiresBroker: !!runtime.workProfile,
    });
    return writer;
  } catch {
    throw new Error("invalid production shared report writer");
  }
}
export function originalProductionSharedReportPending(writer) {
  return writers.has(writer) ? (pending.get(writer) ?? null) : null;
}
export function originalProductionSharedReportFile(receipt, writer) {
  const bound = receipts.get(receipt);
  return writers.has(writer) && bound?.writer === writer ? bound.fileBinding : null;
}
export function originalProductionSharedReportWriterContext(writer) {
  const source = writers.get(writer);
  return source
    ? Object.freeze({
        directory: source.directory,
        profile: source.profile,
        boundary: source.boundary,
        registry: source.registry,
        inspector: source.inspector,
        work: source.account.consumed(),
        outcome: source.outcome,
      })
    : null;
}
/** This deferred internal writer never stops before the broker has collected and removed owned matches. */
export function writeProductionSharedPrivacyReport(writer, supplied, permit) {
  const source = writers.get(writer);
  if (
    source &&
    (source.requiresBroker || source.permit !== null) &&
    (source.permit === null ||
      source.permit !== permit ||
      !productionSharedArtifactBrokerAllows(permit, writer, "report"))
  )
    throw uncertain();
  let directoryFd,
    fileFd,
    fileBinding,
    result,
    durable = false;
  try {
    const input = copyProductionCaptureRecord(supplied, ["receipt", "recording", "remainingWork"]);
    const context =
      source && originalProductionSharedInspectionContext(input.receipt, source.inspector);
    if (
      !source ||
      source.failed ||
      Object.keys(input).length !== 3 ||
      ![1, 2].includes(input.recording) ||
      !context ||
      context.profile !== source.profile ||
      context.boundary !== source.boundary ||
      context.directory !== source.directory ||
      context.registry !== source.registry ||
      source.records.has(input.recording) ||
      !Number.isSafeInteger(input.remainingWork) ||
      input.remainingWork < 1 ||
      input.remainingWork > source.account.allowance("shared-report")
    )
      throw new Error();
    const bytes = copyProductionSharedInspectionReportBytes(input.receipt, source.inspector);
    if (
      !bytes ||
      !input.receipt.hasMatches ||
      bytes.length > 32768 ||
      !sameDirectory(lstatSync(source.directory), source)
    )
      throw new Error();
    source.outcome = "UNCERTAIN";
    const scan = source.registry.openScan(input.remainingWork);
    let copy;
    try {
      copy = scan.hasSecretCopy(bytes.toString("utf8"));
    } finally {
      source.account.consume(scan.snapshot().scanCodeUnits);
    }
    if (copy) {
      source.outcome = "WITHHELD_PRIVACY";
      source.failed = true;
      return null;
    }
    source.records.add(input.recording);
    const file = `privacy-shared-r${input.recording}.json`,
      path = join(source.directory, file);
    pending.set(
      writer,
      Object.freeze({
        directory: source.directory,
        profile: source.profile,
        boundary: source.boundary,
        registry: source.registry,
        writerKind: "shared-privacy",
        kind: "shared-privacy-report",
        file,
        path,
        recording: input.recording,
      }),
    );
    reserveProductionArtifactFile(source.inventory, writer);
    directoryFd = openSync(
      source.directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    if (!sameDirectory(fstatSync(directoryFd), source)) throw new Error();
    fileFd = openSync(
      path,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600,
    );
    const before = fstatSync(fileFd);
    if (!before.isFile() || !owned(before, 0o600) || before.nlink !== 1) throw new Error();
    pending.set(
      writer,
      Object.freeze({ ...pending.get(writer), dev: before.dev, ino: before.ino }),
    );
    reserveProductionArtifactFile(source.inventory, writer);
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
      !sameFile(lstatSync(path), before, bytes.length) ||
      !sameDirectory(lstatSync(source.directory), source)
    )
      throw new Error();
    fsyncSync(directoryFd);
    if (
      !sameFile(fstatSync(fileFd), before, bytes.length) ||
      !sameFile(lstatSync(path), before, bytes.length) ||
      !sameDirectory(fstatSync(directoryFd), source) ||
      !sameDirectory(lstatSync(source.directory), source)
    )
      throw new Error();
    result = Object.freeze({
      type: "production-shared-report-durable",
      recording: input.recording,
      file,
    });
    fileBinding = Object.freeze({
      ...pending.get(writer),
      dev: before.dev,
      ino: before.ino,
      byteLength: bytes.length,
      sha256: hash(bytes),
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
  if (!durable) {
    if (source) {
      source.failed = true;
      source.outcome = "UNCERTAIN";
    }
    throw uncertain();
  }
  receipts.set(result, { writer, fileBinding });
  try {
    trackProductionArtifactFile(source.inventory, writer, result);
    pending.delete(writer);
  } catch {
    source.failed = true;
    source.outcome = "UNCERTAIN";
    throw uncertain();
  }
  source.outcome = "COMPLETE";
  return result;
}
export function bindProductionSharedReportWriterBroker(writer, permit) {
  const source = writers.get(writer);
  if (
    !source ||
    source.failed ||
    source.permit !== null ||
    source.records.size !== 0 ||
    source.outcome !== "NONE" ||
    (source.account.consumed() !== 0 && source.account.consumed() !== 0n) ||
    !productionSharedArtifactBrokerAllows(permit, writer, "bind-report")
  )
    throw uncertain();
  source.permit = permit;
}
export function originalProductionSharedReportWriterAllowance(writer) {
  const source = writers.get(writer);
  if (!source || source.failed) throw uncertain();
  return source.account.allowance("shared-report");
}
