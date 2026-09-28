import { PRODUCTION_WIRE_ORIGINS } from "./production-tls.mjs";
import { serializeBoundedHttpRequest } from "./wire-serialization.mjs";

const HEADER_NAMES = new Set([
  "authorization",
  "x-goog-user-project",
  "accept",
  "content-type",
  "range",
  "x-goog-upload-protocol",
  "x-goog-upload-command",
  "x-goog-upload-header-content-length",
  "x-goog-upload-header-content-type",
  "x-goog-upload-offset",
  "x-upload-content-type",
  "x-upload-content-length",
  "content-length",
  "content-range",
]);
const OPTION_NAMES = new Set([
  "method",
  "headers",
  "body",
  "redirect",
  "signal",
  "operationId",
  "accountingPhase",
  "verifyBeforeDispatch",
]);

function dataRecord(value) {
  if (
    !value ||
    typeof value !== "object" ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
    Object.getOwnPropertySymbols(value).length
  )
    throw new Error();
  const copy = Object.create(null);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error();
    copy[key] = descriptor.value;
  }
  return copy;
}

/** Frame a resolved route in memory. Semantic route, credential and phase admission belong to the factory. */
export function serializeProductionHttpRequest(suppliedRoute, suppliedInit = {}) {
  try {
    const route = dataRecord(suppliedRoute),
      init = dataRecord(suppliedInit);
    if (
      !Object.isFrozen(suppliedRoute) ||
      typeof route.url !== "string" ||
      !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(route.method)
    )
      throw new Error();
    if (
      Object.keys(init).some((key) => !OPTION_NAMES.has(key)) ||
      (init.method !== undefined && init.method !== route.method) ||
      (init.redirect !== undefined && init.redirect !== "manual")
    )
      throw new Error();
    const headers = dataRecord(init.headers ?? {});
    if (Object.keys(headers).some((name) => !HEADER_NAMES.has(name.toLowerCase())))
      throw new Error();
    return serializeBoundedHttpRequest(
      route.url,
      { method: route.method, body: init.body, headers },
      PRODUCTION_WIRE_ORIGINS,
    );
  } catch {
    throw new Error("invalid production wire request");
  }
}
