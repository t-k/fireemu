import { createHash } from "node:crypto";
import { types } from "node:util";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const RESPONSE_KEYS = new Set([
  "sub",
  "azp",
  "aud",
  "scope",
  "expires_in",
  "exp",
  "access_type",
  "email",
  "email_verified",
]);
function dataRecord(value) {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
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
function ascii(value, max = 1024) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    /^[\x21-\x7e]+$/.test(value)
  );
}
function positiveInteger(value) {
  if (typeof value === "string" && /^[1-9][0-9]{0,15}$/.test(value)) value = Number(value);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error();
  return value;
}

/** Compare supplied tokeninfo with an approved prior principal. Times are monotonic; email has no binding. */
export function verifyProductionOwnerTokenInfo(input) {
  try {
    const args = dataRecord(input),
      principal = dataRecord(args.principal),
      data = dataRecord(args.data);
    if (
      Object.keys(args).length !== 4 ||
      Object.keys(args).some(
        (key) => !["data", "principal", "requestStartedAtMs", "receivedAtMs"].includes(key),
      )
    )
      throw new Error();
    if (
      Object.keys(principal).length !== 3 ||
      Object.keys(principal).some(
        (key) => !["subject", "clientId", "requiredScopes"].includes(key),
      ) ||
      !ascii(principal.subject, 512) ||
      !ascii(principal.clientId, 512)
    )
      throw new Error();
    const suppliedScopes = principal.requiredScopes;
    if (
      types.isProxy(suppliedScopes) ||
      !Array.isArray(suppliedScopes) ||
      Object.getPrototypeOf(suppliedScopes) !== Array.prototype
    )
      throw new Error();
    const scopeCount = suppliedScopes.length;
    if (
      scopeCount < 1 ||
      scopeCount > 32 ||
      Reflect.ownKeys(suppliedScopes).length !== scopeCount + 1
    )
      throw new Error();
    const scopes = [];
    for (let index = 0; index < scopeCount; index++) {
      const descriptor = Object.getOwnPropertyDescriptor(suppliedScopes, String(index));
      if (
        !descriptor?.enumerable ||
        !Object.hasOwn(descriptor, "value") ||
        !ascii(descriptor.value)
      )
        throw new Error();
      scopes.push(descriptor.value);
    }
    if (
      new Set(scopes).size !== scopes.length ||
      Object.keys(data).some((key) => !RESPONSE_KEYS.has(key)) ||
      data.sub !== principal.subject ||
      data.azp !== principal.clientId ||
      data.aud !== principal.clientId
    )
      throw new Error();
    if (
      typeof data.scope !== "string" ||
      data.scope.length > 8192 ||
      !/^[\x21-\x7e]+(?: [\x21-\x7e]+)*$/.test(data.scope)
    )
      throw new Error();
    const granted = data.scope.split(" ");
    if (
      new Set(granted).size !== granted.length ||
      scopes.some((scope) => !granted.includes(scope))
    )
      throw new Error();
    for (const key of ["access_type", "email", "email_verified"])
      if (
        Object.hasOwn(data, key) &&
        typeof data[key] !== "string" &&
        !(key === "email_verified" && typeof data[key] === "boolean")
      )
        throw new Error();
    if (Object.hasOwn(data, "exp")) positiveInteger(data.exp);
    const expires = positiveInteger(data.expires_in);
    const { requestStartedAtMs, receivedAtMs } = args;
    if (
      expires > 3600 ||
      !Number.isFinite(requestStartedAtMs) ||
      requestStartedAtMs < 0 ||
      !Number.isFinite(receivedAtMs) ||
      receivedAtMs < requestStartedAtMs ||
      receivedAtMs - requestStartedAtMs > 30000
    )
      throw new Error();
    const deadline = requestStartedAtMs + expires * 1000;
    if (!Number.isFinite(deadline) || deadline - receivedAtMs <= 60000) throw new Error();
    return Object.freeze({
      principalSha256: hash(
        JSON.stringify({
          subject: principal.subject,
          clientId: principal.clientId,
          requiredScopes: scopes,
        }),
      ),
      scopeSha256: hash(data.scope),
      deadlineMonotonicMs: deadline,
    });
  } catch {
    throw new Error("owner tokeninfo proof is invalid");
  }
}
