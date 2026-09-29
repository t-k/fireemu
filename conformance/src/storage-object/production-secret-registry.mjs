import {
  originalProductionArtifactWorkProfile,
  PRODUCTION_SECRET_REGISTRY_CEILINGS,
} from "./production-artifact-work-profile.mjs";
import { types } from "node:util";
import { captureSecretForms } from "./production-capture-body.mjs";
import { createProductionSecretIndex } from "./production-secret-index.mjs";

import { originalProductionArtifactInventoryObserver } from "./production-artifact-inventory.mjs";

import { copyProductionCaptureArray } from "./production-capture-input.mjs";

const artifactObservers = new WeakMap(),
  batchRegistrations = new WeakMap();
/** Discovery enrolls every value in its bounded original batch before rescanning past artifacts. */
export function registerProductionSecretBatch(registry, values) {
  const register = batchRegistrations.get(registry);
  if (!register) throw new Error("invalid production secret registry");
  return register(values);
}
export function bindProductionSecretArtifactInventory(registry, inventory) {
  const observer = originalProductionArtifactInventoryObserver(inventory, registry);
  if (!registries.has(registry) || !observer || artifactObservers.has(registry))
    throw new Error("invalid production secret artifact inventory");
  artifactObservers.set(registry, observer);
}

const registryWorkProfiles = new WeakMap();
export const originalProductionSecretRegistryWorkProfile = (registry) =>
  registryWorkProfiles.get(registry) ?? null;
const registries = new WeakSet();
const memberships = new WeakMap();
const unavailable = () => new Error("SECRET_REGISTRY_UNAVAILABLE");

/** A production capture must use the original registry, never a copied public method set. */
export const isProductionSecretRegistry = (registry) => registries.has(registry);
export function productionSecretRegistryHasValue(registry, value) {
  if (typeof value !== "string" || !value || value.length > 8192 || !value.isWellFormed())
    return false;
  return memberships.get(registry)?.(value) ?? false;
}

/** Pure prototype: the approved runtime must separately pin its tested count, memory and work profile. */
export function createProductionSecretRegistry(supplied) {
  let limits,
    workProfile = null,
    workBinding = null;
  try {
    if (
      !supplied ||
      types.isProxy(supplied) ||
      Object.getPrototypeOf(supplied) !== Object.prototype
    )
      throw new Error();
    const keys = ["maxValues", "maxUtf8Bytes", "maxIndexNodes", "maxScanCodeUnits"];
    const workDescriptor = Object.getOwnPropertyDescriptor(supplied, "workProfile");
    if (Reflect.ownKeys(supplied).length !== keys.length + (workDescriptor ? 1 : 0))
      throw new Error();
    if (workDescriptor) {
      if (!workDescriptor.enumerable || !Object.hasOwn(workDescriptor, "value")) throw new Error();
      workProfile = workDescriptor.value;
      workBinding = originalProductionArtifactWorkProfile(workProfile);
      if (!workBinding) throw new Error();
    }
    limits = Object.fromEntries(
      keys.map((key) => {
        const d = Object.getOwnPropertyDescriptor(supplied, key);
        if (
          !d?.enumerable ||
          !Object.hasOwn(d, "value") ||
          !Number.isSafeInteger(d.value) ||
          d.value < 1
        )
          throw new Error();
        return [key, d.value];
      }),
    );
    if (
      limits.maxValues > PRODUCTION_SECRET_REGISTRY_CEILINGS.maxValues ||
      limits.maxUtf8Bytes > PRODUCTION_SECRET_REGISTRY_CEILINGS.maxUtf8Bytes ||
      limits.maxIndexNodes > PRODUCTION_SECRET_REGISTRY_CEILINGS.maxIndexNodes ||
      limits.maxScanCodeUnits > (workBinding?.maxSingleScanCodeUnits ?? 268435456)
    )
      throw new Error();
    if (
      workBinding &&
      (limits.maxScanCodeUnits !== workBinding.maxSingleScanCodeUnits ||
        Object.entries(workBinding.limits).some(([key, value]) => limits[key] !== value))
    )
      throw new Error();
  } catch {
    throw new Error("invalid secret registry configuration");
  }
  const values = new Set(),
    index = createProductionSecretIndex(limits.maxIndexNodes, workProfile);
  let utf8Bytes = 0,
    failed = false,
    closed = false,
    retainedCount = 0;
  const ready = () => {
    if (closed || failed || index.snapshot().failed) throw unavailable();
  };
  function enroll(value) {
    ready();
    if (typeof value !== "string" || !value || value.length > 8192 || !value.isWellFormed())
      throw unavailable();
    if (values.has(value)) return false;
    const bytes = Buffer.byteLength(value);
    if (values.size >= limits.maxValues || bytes > limits.maxUtf8Bytes - utf8Bytes)
      throw unavailable();
    const retained = Buffer.from(value, "utf8").toString("utf8");
    index.registerPatterns(captureSecretForms(retained));
    values.add(retained);
    utf8Bytes += bytes;
    retainedCount = values.size;
    return true;
  }
  function failRegistration() {
    failed = true;
    index.halt();
    artifactObservers.get(registry)?.();
    throw unavailable();
  }
  const registry = Object.freeze({
    register(value) {
      try {
        if (enroll(value)) artifactObservers.get(registry)?.();
      } catch {
        failRegistration();
      }
    },
    openScan(maximum = limits.maxScanCodeUnits) {
      ready();
      if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > limits.maxScanCodeUnits)
        throw unavailable();
      return index.openScan(maximum);
    },
    snapshot: () =>
      Object.freeze({
        values: retainedCount,
        utf8Bytes,
        failed: failed || index.snapshot().failed,
        closed,
        index: index.snapshot(),
        limits: Object.freeze({ ...limits }),
      }),
    close() {
      closed = true;
      index.close();
      values.clear();
    },
  });
  batchRegistrations.set(registry, (suppliedValues) => {
    try {
      const batch = copyProductionCaptureArray(suppliedValues, 64);
      let changed = false;
      for (const value of batch) changed = enroll(value) || changed;
      if (changed) artifactObservers.get(registry)?.();
    } catch {
      failRegistration();
    }
  });
  registryWorkProfiles.set(registry, workProfile);
  registries.add(registry);
  memberships.set(registry, (value) => {
    try {
      ready();
      return values.has(value);
    } catch {
      return false;
    }
  });
  return registry;
}
