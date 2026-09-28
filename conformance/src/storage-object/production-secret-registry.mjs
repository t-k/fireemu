import { types } from "node:util";
import { captureSecretForms } from "./production-capture-body.mjs";
import { createProductionSecretIndex } from "./production-secret-index.mjs";

const registries = new WeakSet();
const unavailable = () => new Error("SECRET_REGISTRY_UNAVAILABLE");

/** A production capture must use the original registry, never a copied public method set. */
export const isProductionSecretRegistry = (registry) => registries.has(registry);

/** Pure prototype: the approved runtime must separately pin its tested count, memory and work profile. */
export function createProductionSecretRegistry(supplied) {
  let limits;
  try {
    if (
      !supplied ||
      types.isProxy(supplied) ||
      Object.getPrototypeOf(supplied) !== Object.prototype
    )
      throw new Error();
    const keys = ["maxValues", "maxUtf8Bytes", "maxIndexNodes", "maxScanCodeUnits"];
    if (Reflect.ownKeys(supplied).length !== keys.length) throw new Error();
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
      limits.maxValues > 81 + 6000 * 4 * 64 ||
      limits.maxUtf8Bytes > 268435456 ||
      limits.maxIndexNodes > 1048576 ||
      limits.maxScanCodeUnits > 268435456
    )
      throw new Error();
  } catch {
    throw new Error("invalid secret registry configuration");
  }
  const values = new Set(),
    index = createProductionSecretIndex(limits.maxIndexNodes);
  let utf8Bytes = 0,
    failed = false,
    closed = false,
    retainedCount = 0;
  const ready = () => {
    if (closed || failed || index.snapshot().failed) throw unavailable();
  };
  const registry = Object.freeze({
    register(value) {
      ready();
      try {
        if (typeof value !== "string" || !value || value.length > 8192 || !value.isWellFormed())
          throw unavailable();
        if (values.has(value)) return;
        const bytes = Buffer.byteLength(value);
        if (values.size >= limits.maxValues || bytes > limits.maxUtf8Bytes - utf8Bytes)
          throw unavailable();
        // A caller's short slice can retain an arbitrarily large backing string.
        const retained = Buffer.from(value, "utf8").toString("utf8");
        index.registerPatterns(captureSecretForms(retained));
        values.add(retained);
        utf8Bytes += bytes;
        retainedCount = values.size;
      } catch {
        failed = true;
        index.halt();
        throw unavailable();
      }
    },
    openScan() {
      ready();
      return index.openScan(limits.maxScanCodeUnits);
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
  registries.add(registry);
  return registry;
}
