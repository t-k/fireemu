import { types } from "node:util";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const byteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteLength",
).get;

/** Read original Buffer bytes with intrinsic methods, ignoring caller length and coercion hooks. */
export function copyProductionCaptureBody(value) {
  if (
    types.isProxy(value) ||
    !Buffer.isBuffer(value) ||
    Object.getPrototypeOf(value) !== Buffer.prototype
  )
    throw new Error("invalid capture input");
  const length = byteLength.call(value);
  if (length > MAX_RESPONSE_BODY_BYTES) throw new Error("invalid capture input");
  const copy = Buffer.alloc(length);
  Uint8Array.prototype.set.call(copy, value);
  return copy;
}

/** Only dense original arrays with enumerable data elements cross the persistence boundary. */
export function copyProductionCaptureArray(value, maximum) {
  if (
    !Number.isSafeInteger(maximum) ||
    maximum < 0 ||
    types.isProxy(value) ||
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  )
    throw new Error("invalid capture input");
  return Array.from({ length: value.length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value"))
      throw new Error("invalid capture input");
    return descriptor.value;
  });
}

/** Snapshot closed plain records without getters, proxies, symbols or inherited input fields. */
export function copyProductionCaptureRecord(value, keys) {
  keys = copyProductionCaptureArray(keys, 64);
  if (
    keys.some((key) => typeof key !== "string" || key.length > 128) ||
    new Set(keys).size !== keys.length
  )
    throw new Error("invalid capture input");
  if (
    !value ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    throw new Error("invalid capture input");
  const descriptors = Object.getOwnPropertyDescriptors(value),
    names = Reflect.ownKeys(value);
  if (
    names.some(
      (key) =>
        typeof key !== "string" ||
        !keys.includes(key) ||
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value"),
    )
  )
    throw new Error("invalid capture input");
  return Object.fromEntries(names.map((key) => [key, descriptors[key].value]));
}
