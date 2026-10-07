// A finite recorder outcome contract; uncertainty is monotonic and transport specific.
const restErrors = new Map([
  [400, new Set(["INVALID_ARGUMENT", "FAILED_PRECONDITION", "OUT_OF_RANGE"])],
  [401, new Set(["UNAUTHENTICATED"])],
  [403, new Set(["PERMISSION_DENIED"])],
  [404, new Set(["NOT_FOUND"])],
  [409, new Set(["ALREADY_EXISTS", "ABORTED"])],
  [412, new Set(["FAILED_PRECONDITION"])],
  [429, new Set(["RESOURCE_EXHAUSTED"])],
]);
const nativeErrors = new Set([
  "INVALID_ARGUMENT",
  "NOT_FOUND",
  "ALREADY_EXISTS",
  "PERMISSION_DENIED",
  "UNAUTHENTICATED",
  "FAILED_PRECONDITION",
  "ABORTED",
  "OUT_OF_RANGE",
  "UNIMPLEMENTED",
]);
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
export function unknownOutcome(reply) {
  if (!object(reply) || reply.unknown === true || !object(reply.body)) return true;
  if (reply.ok === true)
    return (
      reply.code !== "OK" ||
      "error" in reply.body ||
      (reply.status !== undefined &&
        (!Number.isInteger(reply.status) || reply.status < 200 || reply.status >= 300))
    );
  if (reply.ok !== false) return true;
  if (reply.status === undefined)
    return (
      !nativeErrors.has(reply.code) ||
      (reply.body.error !== undefined && reply.body.error.status !== reply.code)
    );
  return (
    !restErrors.get(reply.status)?.has(reply.code) ||
    !object(reply.body.error) ||
    reply.body.error.status !== reply.code ||
    (reply.body.error.code !== undefined && reply.body.error.code !== reply.status)
  );
}
export const normalizeOutcome = (reply) => ({ ...reply, unknown: unknownOutcome(reply) });
