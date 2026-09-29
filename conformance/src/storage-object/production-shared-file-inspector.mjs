import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  realpathSync,
} from "node:fs";
import { dirname, isAbsolute } from "node:path";
import {
  copyProductionCaptureArray,
  copyProductionCaptureRecord,
} from "./production-capture-input.mjs";
import { originalProductionArtifactContext } from "./production-artifact-policy.mjs";
import {
  productionStandaloneOwnsDirectory,
  productionStandaloneUsesArtifactProfile,
} from "./production-standalone-fail-stop.mjs";

const inspectors = new WeakMap(),
  receipts = new WeakMap();
const MAX_BYTES = 2097152;
const KINDS = new Set(["owner-ledger", "sandbox-ledger", "project-lock", "legacy-lock"]);
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const uncheckable = () => new Error("production shared files uncheckable");
function owned(stat, mode) {
  return (
    (stat.mode & 0o777n) === mode &&
    (typeof process.getuid !== "function" || stat.uid === BigInt(process.getuid()))
  );
}
function directoryIdentity(stat, expected) {
  return (
    stat.isDirectory() &&
    owned(stat, 0o700n) &&
    stat.dev === expected.dev &&
    stat.ino === expected.ino
  );
}
function fileIdentity(stat, expected) {
  return (
    stat.isFile() &&
    owned(stat, 0o600n) &&
    stat.nlink === 1n &&
    stat.dev === expected.dev &&
    stat.ino === expected.ino
  );
}
function stable(stat, before) {
  return (
    fileIdentity(stat, before) &&
    stat.size === before.size &&
    stat.mtimeNs === before.mtimeNs &&
    stat.ctimeNs === before.ctimeNs
  );
}
function sourceFile(supplied, directory) {
  const row = copyProductionCaptureRecord(supplied, ["kind", "path"]);
  if (
    Object.keys(row).length !== 2 ||
    !KINDS.has(row.kind) ||
    typeof row.path !== "string" ||
    row.path.length > 4096 ||
    !row.path.isWellFormed() ||
    /[\0\r\n]/.test(row.path) ||
    !isAbsolute(row.path) ||
    realpathSync(row.path) !== row.path ||
    dirname(row.path) === directory
  )
    throw new Error();
  const parent = dirname(row.path);
  const parentStat = lstatSync(parent, { bigint: true }),
    fileStat = lstatSync(row.path, { bigint: true });
  if (
    !directoryIdentity(parentStat, parentStat) ||
    !fileIdentity(fileStat, fileStat) ||
    fileStat.size > BigInt(MAX_BYTES)
  )
    throw new Error();
  return Object.freeze({
    ...row,
    parent,
    dev: fileStat.dev,
    ino: fileStat.ino,
    parentDev: parentStat.dev,
    parentIno: parentStat.ino,
  });
}
function readShared(file) {
  let directoryFd,
    fileFd,
    bytes,
    failed = false;
  const parent = { dev: file.parentDev, ino: file.parentIno };
  try {
    if (!directoryIdentity(lstatSync(file.parent, { bigint: true }), parent)) throw new Error();
    const before = lstatSync(file.path, { bigint: true });
    if (!fileIdentity(before, file) || before.size < 0n || before.size > BigInt(MAX_BYTES))
      throw new Error();
    directoryFd = openSync(
      file.parent,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    if (!directoryIdentity(fstatSync(directoryFd, { bigint: true }), parent)) throw new Error();
    fileFd = openSync(file.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!stable(fstatSync(fileFd, { bigint: true }), before)) throw new Error();
    bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fileFd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isSafeInteger(count) || count <= 0 || count > bytes.length - offset)
        throw new Error();
      offset += count;
    }
    if (
      readSync(fileFd, Buffer.alloc(1), 0, 1, bytes.length) !== 0 ||
      !stable(fstatSync(fileFd, { bigint: true }), before) ||
      !stable(lstatSync(file.path, { bigint: true }), before) ||
      !directoryIdentity(fstatSync(directoryFd, { bigint: true }), parent) ||
      !directoryIdentity(lstatSync(file.parent, { bigint: true }), parent)
    )
      throw new Error();
  } catch {
    failed = true;
  } finally {
    for (const descriptor of [fileFd, directoryFd])
      if (descriptor !== undefined)
        try {
          closeSync(descriptor);
        } catch {
          failed = true;
        }
  }
  if (failed) throw uncheckable();
  return bytes;
}

/** The future admission gate must prove these fixed path inputs; this original capability grants no production access. */
export function createProductionSharedFileInspector(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, [
      "directory",
      "profile",
      "boundary",
      "files",
    ]);
    const runtime = originalProductionArtifactContext(input.profile);
    if (
      Object.keys(input).length !== 4 ||
      !runtime ||
      !productionStandaloneOwnsDirectory(input.boundary, input.directory) ||
      !productionStandaloneUsesArtifactProfile(input.boundary, input.profile)
    )
      throw new Error();
    runtime.secretRegistry.openScan();
    const files = copyProductionCaptureArray(input.files, 4).map((row) =>
      sourceFile(row, input.directory),
    );
    if (
      !files.length ||
      new Set(files.map((row) => row.kind)).size !== files.length ||
      new Set(files.map((row) => row.path)).size !== files.length
    )
      throw new Error();
    const inspector = Object.freeze({});
    inspectors.set(inspector, {
      directory: input.directory,
      profile: input.profile,
      boundary: input.boundary,
      registry: runtime.secretRegistry,
      files: Object.freeze(files),
      work: 0,
      epoch: 0,
      latestReceipt: null,
      limit: runtime.secretRegistry.snapshot().limits.maxScanCodeUnits,
      busy: false,
      failed: false,
    });
    return inspector;
  } catch {
    throw new Error("invalid production shared file inspector");
  }
}
/** Inspection is read-only; its controller must synchronously retain the lease and stop on this fixed failure. */
export function inspectProductionSharedFiles(inspector) {
  const source = inspectors.get(inspector);
  if (!source || source.failed || source.busy) {
    if (source) source.failed = true;
    throw uncheckable();
  }
  source.busy = true;
  source.epoch++;
  source.latestReceipt = null;
  const files = [],
    beginning = source.work;
  try {
    source.registry.openScan();
    for (const file of source.files) {
      if (source.failed) throw uncheckable();
      const size = lstatSync(file.path, { bigint: true }).size;
      if (size < 0n || size > BigInt(MAX_BYTES) || size > BigInt(source.limit - source.work))
        throw uncheckable();
      source.work += Number(size);
      const bytes = readShared(file);
      // Charge the actual stable read as well when an append occurred before opening the file.
      if (bytes.length !== Number(size)) throw uncheckable();
      const scan = source.registry.openScan(source.limit - source.work);
      let report;
      try {
        report = scan.findSecretCopyLines(decoder.decode(bytes));
      } finally {
        source.work += scan.snapshot().scanCodeUnits;
      }
      if (report.matchedLineCount) files.push(Object.freeze({ path: file.path, ...report }));
    }
    if (source.failed) throw uncheckable();
    const receipt = Object.freeze({
      type: "production-shared-inspection",
      hasMatches: files.length > 0,
    });
    const report = Object.freeze({
      type: "production-shared-privacy-report",
      files: Object.freeze(files),
    });
    const bytes = Buffer.from(JSON.stringify(report) + "\n");
    if (bytes.length > 32768) throw uncheckable();
    receipts.set(receipt, {
      inspector,
      report,
      bytes,
      work: source.work - beginning,
      epoch: source.epoch,
    });
    source.latestReceipt = receipt;
    return receipt;
  } catch {
    source.failed = true;
    throw uncheckable();
  } finally {
    source.busy = false;
  }
}
/** Only original inspection bytes are copied; no observation value or digest enters this closed report. */
export function copyProductionSharedInspectionReportBytes(receipt, inspector) {
  const binding = receipts.get(receipt);
  const source = inspectors.get(inspector);
  return source &&
    !source.failed &&
    source.latestReceipt === receipt &&
    binding?.inspector === inspector &&
    binding.epoch === source.epoch
    ? Buffer.from(binding.bytes)
    : null;
}
