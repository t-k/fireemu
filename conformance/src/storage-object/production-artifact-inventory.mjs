import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readSync,
  unlinkSync,
} from "node:fs";
import { isAbsolute, join } from "node:path";
import { realpathSync } from "node:fs";
import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { originalProductionArtifactContext } from "./production-artifact-policy.mjs";
import {
  bindProductionSecretArtifactInventory,
  isProductionSecretRegistry,
} from "./production-secret-registry.mjs";
import {
  originalProductionArtifactFile,
  originalProductionArtifactPending,
} from "./production-artifact-writer.mjs";
import {
  originalProductionWireArtifactFile,
  originalProductionWireArtifactPending,
} from "./production-owned-wire-files.mjs";
import {
  failStopProductionPrivacy,
  productionStandaloneOwnsDirectory,
  productionStandaloneUsesArtifactProfile,
} from "./production-standalone-fail-stop.mjs";

import {
  inspectProductionSharedFiles,
  originalProductionSharedInspectionContext,
  originalProductionSharedInspectorWork,
  productionSharedInspectorUsesArtifactContext,
} from "./production-shared-file-inspector.mjs";
import {
  originalProductionSharedReportFile,
  originalProductionSharedReportPending,
  originalProductionSharedReportWriterContext,
  writeProductionSharedPrivacyReport,
} from "./production-shared-report-file.mjs";

const inventories = new WeakMap(),
  tasks = new WeakMap();
// Finite prototype ceilings, derived from the two existing writer ceilings.
// A runtime still needs its separate producer count and work/memory profile.
const MAX_FILES = 6000 * 20 + 1024;
const MAX_BYTES = 2097152 + 4096 * 160;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const decoder = new TextDecoder("utf-8", { fatal: true });
function owned(stat, mode) {
  return (
    (stat.mode & 0o777) === mode &&
    (typeof process.getuid !== "function" || stat.uid === process.getuid())
  );
}
function sameDirectory(stat, state) {
  return (
    stat.isDirectory() && owned(stat, 0o700) && stat.dev === state.dev && stat.ino === state.ino
  );
}
function sameFile(stat, file) {
  return (
    stat.isFile() &&
    owned(stat, 0o600) &&
    stat.nlink === 1 &&
    stat.dev === file.dev &&
    stat.ino === file.ino &&
    stat.size === file.byteLength
  );
}
function readOriginal(state, file) {
  let fd,
    directoryFd,
    bytes,
    failed = false;
  try {
    if (
      !sameDirectory(lstatSync(state.directory), state) ||
      !sameFile(lstatSync(file.path), file) ||
      file.byteLength < 1 ||
      file.byteLength > MAX_BYTES
    )
      throw new Error();
    directoryFd = openSync(
      state.directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    if (!sameDirectory(fstatSync(directoryFd), state)) throw new Error();
    fd = openSync(file.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!sameFile(fstatSync(fd), file)) throw new Error();
    bytes = Buffer.alloc(file.byteLength);
    let offset = 0;
    while (offset < bytes.length) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isSafeInteger(count) || count <= 0 || count > bytes.length - offset)
        throw new Error();
      offset += count;
    }
    if (readSync(fd, Buffer.alloc(1), 0, 1, bytes.length) !== 0) throw new Error();
    if (
      !sameDirectory(fstatSync(directoryFd), state) ||
      !sameFile(fstatSync(fd), file) ||
      !sameFile(lstatSync(file.path), file) ||
      !sameDirectory(lstatSync(state.directory), state) ||
      hash(bytes) !== file.sha256
    )
      throw new Error();
  } catch {
    failed = true;
  } finally {
    for (const descriptor of [fd, directoryFd])
      if (descriptor !== undefined)
        try {
          closeSync(descriptor);
        } catch {
          failed = true;
        }
  }
  if (failed) throw new Error();
  return bytes;
}
function removeOriginal(state, file) {
  let fd,
    directoryFd,
    failed = false;
  try {
    if (!sameDirectory(lstatSync(state.directory), state) || !sameFile(lstatSync(file.path), file))
      throw new Error();
    directoryFd = openSync(
      state.directory,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    fd = openSync(file.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (
      !sameDirectory(fstatSync(directoryFd), state) ||
      !sameFile(fstatSync(fd), file) ||
      !sameFile(lstatSync(file.path), file) ||
      !sameDirectory(lstatSync(state.directory), state)
    )
      throw new Error();
    // No user callback or event-loop yield can run between this path check and removal.
    unlinkSync(file.path);
    fsyncSync(directoryFd);
    let absent = false;
    try {
      lstatSync(file.path);
    } catch (error) {
      absent = error?.code === "ENOENT";
    }
    if (!absent) throw new Error();
    if (
      !sameDirectory(fstatSync(directoryFd), state) ||
      !sameDirectory(lstatSync(state.directory), state)
    )
      throw new Error();
  } catch {
    failed = true;
  } finally {
    for (const fdToClose of [fd, directoryFd])
      if (fdToClose !== undefined)
        try {
          closeSync(fdToClose);
        } catch {
          failed = true;
        }
  }
  if (failed) throw new Error();
}
function rescan(state) {
  if (state.phase !== "OPEN") {
    if (state.prototype) throw new Error("production wire artifact withheld");
    failStopProductionPrivacy(state.boundary, {
      recording: state.recording,
      reason: "artifact-past-scan-uncertain",
    });
  }
  state.phase = "CHECKING";
  const matched = [];
  let uncertain = false,
    sharedFailure = false,
    reportFailure = false,
    reportWithheld = false,
    sharedReceipt = null;
  if (state.shared) {
    const before = originalProductionSharedInspectorWork(state.shared.inspector);
    try {
      sharedReceipt = inspectProductionSharedFiles(
        state.shared.inspector,
        state.workLimit - state.work,
      );
      const context = originalProductionSharedInspectionContext(
        sharedReceipt,
        state.shared.inspector,
      );
      if (
        !context ||
        context.profile !== state.profile ||
        context.boundary !== state.boundary ||
        context.directory !== state.directory ||
        context.registry !== state.registry
      )
        throw new Error();
    } catch {
      sharedFailure = true;
      uncertain = true;
    } finally {
      const after = originalProductionSharedInspectorWork(state.shared.inspector);
      if (!Number.isSafeInteger(before) || !Number.isSafeInteger(after) || after < before) {
        state.work = state.workLimit;
        sharedFailure = true;
        uncertain = true;
      } else state.work += after - before;
    }
  }
  try {
    state.registry.openScan();
  } catch {
    uncertain = true;
  }
  for (const file of state.files.values()) {
    try {
      if (file.pending || file.byteLength > state.workLimit - state.work) throw new Error();
      state.work += file.byteLength;
      const bytes = readOriginal(state, file);
      const scan = state.registry.openScan(state.workLimit - state.work);
      let copy;
      try {
        copy = scan.hasSecretCopy(decoder.decode(bytes));
      } finally {
        state.work += scan.snapshot().scanCodeUnits;
      }
      if (copy) matched.push(file);
    } catch {
      uncertain = true;
    }
  }
  state.phase = "REMOVING";
  for (const file of matched) {
    try {
      removeOriginal(state, file);
      state.files.delete(file.path);
    } catch {
      uncertain = true;
    }
  }
  const sharedMatch = sharedReceipt?.hasMatches === true;
  if (sharedMatch) {
    state.phase = "REPORTING";
    const before = originalProductionSharedReportWriterContext(state.shared.reportWriter).work;
    try {
      const report = writeProductionSharedPrivacyReport(state.shared.reportWriter, {
        receipt: sharedReceipt,
        recording: state.recording,
        remainingWork: state.workLimit - state.work,
      });
      const status = originalProductionSharedReportWriterContext(state.shared.reportWriter).outcome;
      if (report === null && status === "WITHHELD_PRIVACY") reportWithheld = true;
      else if (!report || status !== "COMPLETE") throw new Error();
    } catch {
      reportFailure = true;
      uncertain = true;
    } finally {
      const after = originalProductionSharedReportWriterContext(state.shared.reportWriter).work;
      if (!Number.isSafeInteger(before) || !Number.isSafeInteger(after) || after < before) {
        state.work = state.workLimit;
        reportFailure = true;
        uncertain = true;
      } else state.work += after - before;
    }
  }
  if (uncertain || matched.length || sharedMatch) {
    state.phase = "STOPPED";
    if (state.prototype) {
      state.registry.close();
      throw new Error("production wire artifact withheld");
    }
    failStopProductionPrivacy(state.boundary, {
      recording: state.recording,
      reason: sharedFailure
        ? "shared-file-uncheckable"
        : reportFailure
          ? "shared-report-persistence-uncertain"
          : reportWithheld
            ? "shared-report-withheld-privacy"
            : uncertain
              ? "artifact-past-scan-uncertain"
              : sharedMatch
                ? "shared-file-secret-copy"
                : "artifact-removed-late-secret",
    });
  }
  state.phase = "OPEN";
}
/** Original cumulative work is diagnostic only and grants no runtime admission. */
export function originalProductionArtifactInventoryWork(inventory) {
  return inventories.get(inventory)?.work ?? null;
}

/** Only the original registry may invoke its original task inventory observer. */
export function originalProductionArtifactInventoryObserver(inventory, registry) {
  const state = inventories.get(inventory);
  return state && state.registry === registry ? state.observer : null;
}
/** One registry, profile, capability and directory own one task-wide inventory. */
export function ensureProductionArtifactInventory(supplied) {
  let input, runtime;
  try {
    input = copyProductionCaptureRecord(supplied, ["directory", "profile", "boundary"]);
    runtime = originalProductionArtifactContext(input.profile);
    if (
      Object.keys(input).length !== 3 ||
      !runtime ||
      !productionStandaloneOwnsDirectory(input.boundary, input.directory) ||
      !productionStandaloneUsesArtifactProfile(input.boundary, input.profile)
    )
      throw new Error();
    runtime.secretRegistry.openScan();
    const previous = tasks.get(runtime.secretRegistry);
    if (previous) {
      const state = inventories.get(previous);
      if (
        state.phase !== "OPEN" ||
        state.profile !== input.profile ||
        state.boundary !== input.boundary ||
        state.directory !== input.directory
      )
        throw new Error();
      return previous;
    }
    const stat = lstatSync(input.directory);
    const state = {
      ...input,
      registry: runtime.secretRegistry,
      dev: stat.dev,
      ino: stat.ino,
      phase: "OPEN",
      recording: 1,
      files: new Map(),
      work: 0,
      workLimit: runtime.secretRegistry.snapshot().limits.maxScanCodeUnits,
      observer: null,
    };
    const inventory = Object.freeze({});
    state.observer = () => rescan(state);
    inventories.set(inventory, state);
    bindProductionSecretArtifactInventory(state.registry, inventory);
    tasks.set(state.registry, inventory);
    return inventory;
  } catch {
    throw new Error("invalid production artifact inventory");
  }
}
/** Legacy capture is a prototype: it throws after removal and carries no production authority. */
export function ensurePrototypeArtifactInventory(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, ["directory", "registry"]);
    if (
      Object.keys(input).length !== 2 ||
      !isProductionSecretRegistry(input.registry) ||
      typeof input.directory !== "string" ||
      input.directory.length > 4096 ||
      input.directory.includes("\0") ||
      !isAbsolute(input.directory) ||
      realpathSync(input.directory) !== input.directory
    )
      throw new Error();
    input.registry.openScan();
    const previous = tasks.get(input.registry);
    if (previous) {
      const state = inventories.get(previous);
      if (state.phase !== "OPEN" || !state.prototype || state.directory !== input.directory)
        throw new Error();
      return previous;
    }
    const stat = lstatSync(input.directory);
    if (!stat.isDirectory() || !owned(stat, 0o700)) throw new Error();
    const inventory = Object.freeze({});
    const state = {
      ...input,
      prototype: true,
      dev: stat.dev,
      ino: stat.ino,
      phase: "OPEN",
      recording: 1,
      files: new Map(),
      work: 0,
      workLimit: input.registry.snapshot().limits.maxScanCodeUnits,
      observer: null,
    };
    state.observer = () => rescan(state);
    inventories.set(inventory, state);
    bindProductionSecretArtifactInventory(state.registry, inventory);
    tasks.set(state.registry, inventory);
    return inventory;
  } catch {
    throw new Error("invalid prototype artifact inventory");
  }
}

/** Original writers reserve inventory capacity before opening, then enroll the actual pending inode. */
export function reserveProductionArtifactFile(inventory, writer) {
  const state = inventories.get(inventory);
  const file =
    originalProductionArtifactPending(writer) ??
    originalProductionWireArtifactPending(writer) ??
    originalProductionSharedReportPending(writer);
  if (
    !state ||
    (state.phase !== "OPEN" &&
      !(
        state.phase === "REPORTING" &&
        writer === state.shared?.reportWriter &&
        file?.writerKind === "shared-privacy"
      )) ||
    !file ||
    file.profile !== state.profile ||
    file.boundary !== state.boundary ||
    file.registry !== state.registry ||
    file.directory !== state.directory ||
    file.path !== join(state.directory, file.file) ||
    ![1, 2].includes(file.recording) ||
    !sameDirectory(lstatSync(state.directory), state)
  )
    throw new Error("invalid production artifact reservation");
  const previous = state.files.get(file.path);
  if (previous ? !previous.pending || previous.writer !== writer : state.files.size >= MAX_FILES)
    throw new Error("unavailable production artifact reservation");
  state.files.set(file.path, Object.freeze({ ...file, writer, pending: true }));
  state.recording = file.recording;
}

/** Only original successful writer receipts can enroll an owned inode. */
export function trackProductionArtifactFile(inventory, writer, receipt) {
  const state = inventories.get(inventory);
  if (
    !state ||
    (state.phase !== "OPEN" &&
      !(state.phase === "REPORTING" && writer === state.shared?.reportWriter))
  )
    throw new Error("invalid production artifact inventory");
  const file =
    originalProductionArtifactFile(receipt, writer) ??
    originalProductionWireArtifactFile(receipt, writer) ??
    originalProductionSharedReportFile(receipt, writer);
  if (
    !file ||
    file.profile !== state.profile ||
    file.boundary !== state.boundary ||
    file.registry !== state.registry ||
    file.directory !== state.directory ||
    file.path !== join(state.directory, file.file) ||
    ![1, 2].includes(file.recording) ||
    !sameDirectory(lstatSync(state.directory), state) ||
    !sameFile(lstatSync(file.path), file)
  )
    throw new Error("invalid production artifact receipt");
  const pending = state.files.get(file.path);
  if (!pending?.pending || pending.writer !== writer)
    throw new Error("unreserved production artifact receipt");
  state.files.set(file.path, Object.freeze({ ...file, pending: false }));
  state.recording = file.recording;
}

/** One original shared inspector and internal report writer join the original owned observer before any producer. */
export function attachProductionSharedArtifactInspection(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, ["inventory", "inspector", "reportWriter"]);
    const state = inventories.get(input.inventory),
      writer = originalProductionSharedReportWriterContext(input.reportWriter);
    if (
      Object.keys(input).length !== 3 ||
      !state ||
      state.prototype ||
      state.phase !== "OPEN" ||
      state.shared ||
      state.files.size ||
      !productionSharedInspectorUsesArtifactContext(input.inspector, {
        directory: state.directory,
        profile: state.profile,
        boundary: state.boundary,
      }) ||
      !writer ||
      writer.directory !== state.directory ||
      writer.profile !== state.profile ||
      writer.boundary !== state.boundary ||
      writer.registry !== state.registry ||
      writer.inspector !== input.inspector ||
      writer.outcome !== "NONE"
    )
      throw new Error();
    state.shared = Object.freeze({ inspector: input.inspector, reportWriter: input.reportWriter });
  } catch {
    throw new Error("invalid production shared artifact inspection");
  }
}
