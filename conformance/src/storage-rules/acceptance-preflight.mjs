import { createHash } from "node:crypto";
import { isObject, jsonBody, result, secretResult, unexpected } from "./acceptance-core.mjs";

// Environment probes made before a run. They are read-only checks of identities, projects, keys, permissions, the bucket
// and the database; the controller compares the facts with the approved private inputs. Fields the checks consume are
// validated strictly, extra fields are tolerated, and anything that identifies a person or grants access stays out of
// the facts (email, subject, key string and members are digests, counts or a non-enumerable secret).
const PROJECT_NUMBER = /^[1-9]\d{0,19}$/;
const nonEmpty = (value) => typeof value === "string" && value !== "";
const pathName = (row, prefix) => (typeof row.request.path === "string" && row.request.path.startsWith(prefix) ? row.request.path.slice(prefix.length) : null);
const okBody = (response) => (response.status === 200 ? jsonBody(response) : undefined);
const sha = (value) => createHash("sha256").update(value).digest("hex");

function permissionsResult(kind, row, response, requested) {
  const body = okBody(response);
  if (!isObject(body) || !Array.isArray(requested) || requested.length === 0 || (body.permissions !== undefined && (!Array.isArray(body.permissions) || !body.permissions.every(nonEmpty)))) return unexpected(kind, response);
  const granted = body.permissions ?? [];
  if (granted.some((name) => !requested.includes(name)) || new Set(granted).size !== granted.length) return unexpected(kind, response);
  return result(kind, "accepted", { status: 200, requested: requested.length, granted: granted.length, missing: requested.filter((name) => !granted.includes(name)) });
}

function policyResult(kind, response, expectedKind) {
  const body = okBody(response);
  if (!isObject(body) || (expectedKind !== null && body.kind !== expectedKind) || (body.bindings !== undefined && !Array.isArray(body.bindings)) || (body.version !== undefined && !Number.isSafeInteger(body.version))) return unexpected(kind, response);
  const bindings = body.bindings ?? [];
  if (!bindings.every((entry) => isObject(entry) && nonEmpty(entry.role) && Array.isArray(entry.members) && entry.members.every(nonEmpty))) return unexpected(kind, response);
  const canonical = bindings.map((entry) => ({ role: entry.role, members: [...entry.members].sort() })).sort((a, b) => (a.role < b.role ? -1 : a.role > b.role ? 1 : 0));
  return result(kind, "accepted", { status: 200, bindings: bindings.length, members: bindings.reduce((total, entry) => total + entry.members.length, 0), version: body.version ?? 0, policySha256: sha(JSON.stringify(canonical)) });
}

const canonical = (value) => (Array.isArray(value) ? value.map(canonical) : isObject(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value);
/** The digest of a key's whole restriction object, independent of key order and of the order of its API targets. */
export function restrictionsSha256(restrictions) {
  const shape = canonical(restrictions ?? {});
  if (Array.isArray(shape.apiTargets)) shape.apiTargets = shape.apiTargets.map((target) => JSON.stringify(target)).sort().map((text) => JSON.parse(text));
  return sha(JSON.stringify(shape));
}

export const PREFLIGHT_CLASSIFIERS = {
  "preflight-identity": (row, response) => {
    const body = okBody(response);
    if (isObject(body) && nonEmpty(body.id) && nonEmpty(body.email) && typeof body.verified_email === "boolean") {
      return secretResult("preflight-identity", "accepted", { status: 200, verifiedEmail: body.verified_email }, { email: body.email, subject: body.id });
    }
    return unexpected("preflight-identity", response);
  },
  "preflight-project": (row, response) => {
    const body = okBody(response);
    const number = pathName(row, "/v3/projects/");
    if (isObject(body) && number !== null && PROJECT_NUMBER.test(number) && body.name === `projects/${number}` && nonEmpty(body.projectId) && nonEmpty(body.state)) {
      return result("preflight-project", "accepted", { status: 200, projectId: body.projectId, state: body.state, deleted: body.deleteTime !== undefined });
    }
    return unexpected("preflight-project", response);
  },
  "preflight-key-metadata": (row, response) => {
    const body = okBody(response);
    const name = pathName(row, "/v2/");
    const restrictions = isObject(body) ? body.restrictions : undefined;
    const targets = restrictions?.apiTargets;
    if (isObject(body) && name !== null && body.name === name && nonEmpty(body.uid) && (restrictions === undefined || (isObject(restrictions) && (targets === undefined || (Array.isArray(targets) && targets.every((target) => isObject(target) && nonEmpty(target.service) && (target.methods === undefined || Array.isArray(target.methods)))))))) {
      const list = targets ?? [];
      return result("preflight-key-metadata", "accepted", {
        status: 200, uid: body.uid, deleted: body.deleteTime !== undefined, apiTargets: list.map((target) => target.service).sort(),
        otherRestrictions: Object.keys(restrictions ?? {}).filter((key) => key !== "apiTargets").sort(), methodRestricted: list.some((target) => target.methods !== undefined),
        restrictionsSha256: restrictionsSha256(restrictions),
      });
    }
    return unexpected("preflight-key-metadata", response);
  },
  "preflight-key-string": (row, response) => {
    const body = okBody(response);
    if (isObject(body) && nonEmpty(body.keyString)) return secretResult("preflight-key-string", "accepted", { status: 200, keyStringLength: body.keyString.length }, { keyString: body.keyString });
    return unexpected("preflight-key-string", response);
  },
  "preflight-permissions": (row, response) => permissionsResult("preflight-permissions", row, response, row.request.body?.json?.permissions),
  "preflight-bucket-permissions": (row, response) => {
    const body = okBody(response);
    if (isObject(body) && body.kind !== "storage#testIamPermissionsResponse" && body.kind !== undefined) return unexpected("preflight-bucket-permissions", response);
    if (!isObject(body) || body.kind !== "storage#testIamPermissionsResponse") return unexpected("preflight-bucket-permissions", response);
    return permissionsResult("preflight-bucket-permissions", row, response, row.request.query?.permissions);
  },
  "preflight-bucket-metadata": (row, response) => {
    const body = okBody(response);
    const bucket = /^\/storage\/v1\/b\/([^/]+)$/.exec(row.request.path ?? "")?.[1];
    if (isObject(body) && body.kind === "storage#bucket" && bucket !== undefined && body.name === bucket && typeof body.projectNumber === "string" && PROJECT_NUMBER.test(body.projectNumber) && nonEmpty(body.location)) {
      const config = isObject(body.iamConfiguration) ? body.iamConfiguration : {};
      const uniform = isObject(config.uniformBucketLevelAccess) && typeof config.uniformBucketLevelAccess.enabled === "boolean" ? config.uniformBucketLevelAccess.enabled : null;
      return result("preflight-bucket-metadata", "accepted", { status: 200, projectNumber: body.projectNumber, location: body.location, uniformBucketLevelAccess: uniform, publicAccessPrevention: typeof config.publicAccessPrevention === "string" ? config.publicAccessPrevention : null });
    }
    return unexpected("preflight-bucket-metadata", response);
  },
  "preflight-bucket-iam": (row, response) => policyResult("preflight-bucket-iam", response, "storage#policy"),
  "preflight-project-iam": (row, response) => policyResult("preflight-project-iam", response, null),
  "preflight-database": (row, response) => {
    const body = okBody(response);
    const name = pathName(row, "/v1/");
    if (isObject(body) && name !== null && body.name === name && nonEmpty(body.locationId) && nonEmpty(body.type)) return result("preflight-database", "accepted", { status: 200, locationId: body.locationId, type: body.type });
    return unexpected("preflight-database", response);
  },
};
