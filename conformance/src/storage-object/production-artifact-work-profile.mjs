import { isDeepStrictEqual } from "node:util";
import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { copyCanonicalProductionStage3Plan } from "./production-context.mjs";

// Structural accounting is not an operational profile or production admission.
export const PRODUCTION_ARTIFACT_WORK_SCOPE = "STRUCTURAL_NOT_ADMISSION";
export const PRODUCTION_SECRET_REGISTRY_CEILINGS = Object.freeze({
  maxValues: 81 + 6000 * 4 * 64,
  maxUtf8Bytes: 268435456,
  maxIndexNodes: 1048576,
});
const profiles = new WeakMap(),
  accounts = new WeakMap();
const kinds = new Set(["inventory", "shared-reader", "shared-report"]);
const prototypeMaximum = 268435456;
const unavailable = () => new Error("PRODUCTION_ARTIFACT_WORK_UNAVAILABLE");
const ownedBound = (length) => 420n * length;
const sharedBound = (length) => {
  let width = 1n,
    levels = 0n;
  while (width < length + 1n) {
    width *= 2n;
    levels++;
  }
  return (831n + 410n * levels) * length + 2n;
};

/** Compile source ceilings with exact integer arithmetic; narrower producers remain a separate obligation. */
export function createProductionArtifactWorkProfile(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, ["plan", "limits"]);
    if (Object.keys(input).length !== 2) throw new Error();
    const plan = copyCanonicalProductionStage3Plan(input.plan),
      limits = copyProductionCaptureRecord(
        input.limits,
        Object.keys(PRODUCTION_SECRET_REGISTRY_CEILINGS),
      );
    if (Object.keys(limits).length !== 3) throw new Error();
    for (const [key, maximum] of Object.entries(PRODUCTION_SECRET_REGISTRY_CEILINGS))
      if (!Number.isSafeInteger(limits[key]) || limits[key] < 1 || limits[key] > maximum)
        throw new Error();
    const length = 2097152n,
      files = 6000n * 20n + 1024n,
      fileBytes = 2097152n + 4096n * 160n,
      events = BigInt(limits.maxValues) + 1n,
      single = sharedBound(length),
      sharedInspection = 4n * (2097152n + single),
      report = ownedBound(32768n),
      maxReportTaskCodeUnits = 2n * report;
    for (const value of [single, sharedInspection, report])
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error();
    const binding = Object.freeze({
      scope: PRODUCTION_ARTIFACT_WORK_SCOPE,
      sendAuthorized: false,
      plan,
      limits: Object.freeze(limits),
      maxSingleScanCodeUnits: Number(single),
      maxSharedInspectionCodeUnits: Number(sharedInspection),
      maxReportScanCodeUnits: Number(report),
      maxTaskScanCodeUnits:
        events * (files * (fileBytes + ownedBound(length)) + sharedInspection) +
        maxReportTaskCodeUnits,
      maxSharedTaskCodeUnits: events * sharedInspection,
      maxReportTaskCodeUnits,
      maxCompileWorkUnits: events * 16n * BigInt(limits.maxIndexNodes),
      retainedIndexTypedBytes: 22 * limits.maxIndexNodes,
      compileScratchTypedBytes: 4 * limits.maxIndexNodes,
      sharedLiveMappedTypedBytes: Number(8n * length + 12n + 32n * 6291456n),
    });
    const profile = Object.freeze({});
    profiles.set(profile, binding);
    return profile;
  } catch {
    throw new Error("invalid production artifact work profile");
  }
}

/** Only the original cap returns structural bounds; snapshots and clones never mint an account. */
export function originalProductionArtifactWorkProfile(profile, supplied) {
  try {
    const binding = profiles.get(profile);
    if (!binding) return null;
    if (supplied !== undefined) {
      const input = copyProductionCaptureRecord(supplied, ["plan"]);
      if (
        Object.keys(input).length !== 1 ||
        !isDeepStrictEqual(binding.plan, copyCanonicalProductionStage3Plan(input.plan))
      )
        return null;
    }
    return binding;
  } catch {
    return null;
  }
}

/** Each private account has one irreversible cumulative balance and bounded local allowances. */
export function createProductionArtifactWorkAccount(supplied) {
  let input, binding, limit;
  try {
    input = copyProductionCaptureRecord(supplied, ["profile", "kind", "prototypeLimit"]);
    if (!kinds.has(input.kind)) throw new Error();
    if (input.profile === null) {
      if (
        Object.keys(input).length !== 3 ||
        !Number.isSafeInteger(input.prototypeLimit) ||
        input.prototypeLimit < 1 ||
        input.prototypeLimit > prototypeMaximum
      )
        throw new Error();
      limit = input.prototypeLimit;
    } else {
      binding = profiles.get(input.profile);
      if (Object.keys(input).length !== 2 || !binding) throw new Error();
      limit = {
        inventory: binding.maxTaskScanCodeUnits,
        "shared-reader": binding.maxSharedTaskCodeUnits,
        "shared-report": binding.maxReportTaskCodeUnits,
      }[input.kind];
    }
  } catch {
    throw new Error("invalid production artifact work account");
  }
  let work = binding ? 0n : 0,
    failed = false;
  const ready = () => {
    if (failed) throw unavailable();
  };
  function invalid() {
    failed = true;
    throw unavailable();
  }
  const account = Object.freeze({
    consume(amount) {
      ready();
      if (
        (typeof amount !== "bigint" && (!Number.isSafeInteger(amount) || amount < 0)) ||
        (typeof amount === "bigint" && amount < 0n)
      )
        return invalid();
      const count = binding ? BigInt(amount) : amount;
      if (!binding && typeof count !== "number") return invalid();
      if (count > limit - work) return invalid();
      work += count;
    },
    consumed: () => work,
    halt: () => {
      failed = true;
    },
    allowance(kind = "owned-scan") {
      ready();
      if (
        !["owned-scan", "shared-reader", "shared-report"].includes(kind) ||
        (input.kind !== "inventory" && kind !== "owned-scan" && kind !== input.kind)
      )
        return invalid();
      if (!binding) return limit - work;
      const maximum = {
          "owned-scan": binding.maxSingleScanCodeUnits,
          "shared-reader": binding.maxSharedInspectionCodeUnits,
          "shared-report": binding.maxReportScanCodeUnits,
        }[kind],
        remaining = limit - work,
        bounded = remaining < BigInt(maximum) ? remaining : BigInt(maximum);
      return Number(bounded);
    },
  });
  accounts.set(account, {
    profile: input.profile,
    kind: input.kind,
    read: () => Object.freeze({ work, limit, failed }),
  });
  return account;
}
export function originalProductionArtifactWorkAccount(account, profile) {
  const binding = accounts.get(account);
  return binding && binding.profile === profile
    ? Object.freeze({ kind: binding.kind, ...binding.read() })
    : null;
}
