import { createHash } from "node:crypto";
import { isDeepStrictEqual, types } from "node:util";
import { copyCanonicalProductionStage3Plan } from "./production-context.mjs";
import {
  copyProductionCaptureRecord,
  copyProductionCaptureBody,
} from "./production-capture-input.mjs";
import {
  createProductionCaptureProfile,
  productionCaptureIsCovered,
} from "./production-capture-coverage.mjs";
import { parseCaptureJsonSpans } from "./production-capture-body.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const baselines = new WeakMap();
const hash = (value) => createHash("sha256").update(value).digest("hex");
const fields = new Map([
  ["project-binding", "project"],
  ["default-bucket", "defaultBucket"],
  ["bucket-config", "bucket"],
  ["auth-config", "auth"],
  ["api-key-metadata", "key"],
]);
const apiServices = ["identitytoolkit.googleapis.com", "securetoken.googleapis.com"];

function snapshot(supplied) {
  let nodes = 0,
    units = 0;
  function copy(value, depth = 0) {
    if (depth > 16 || ++nodes > 4096 || types.isProxy(value)) throw new Error();
    if (typeof value === "string") {
      if (!value.isWellFormed() || value.length > 8192 || (units += value.length) > 65536)
        throw new Error();
      return value;
    }
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) throw new Error();
      return value;
    }
    if (!value || typeof value !== "object") throw new Error();
    const descriptors = Object.getOwnPropertyDescriptors(value),
      names = Reflect.ownKeys(value);
    if (Array.isArray(value)) {
      if (
        Object.getPrototypeOf(value) !== Array.prototype ||
        value.length > 256 ||
        names.length !== value.length + 1
      )
        throw new Error();
      return Object.freeze(
        Array.from({ length: value.length }, (_, i) => {
          const d = descriptors[String(i)];
          if (!d?.enumerable || !Object.hasOwn(d, "value")) throw new Error();
          return copy(d.value, depth + 1);
        }),
      );
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value)) || names.length > 256)
      throw new Error();
    return Object.freeze(
      Object.fromEntries(
        names.map((name) => {
          const d = descriptors[name];
          if (
            typeof name !== "string" ||
            name.length > 128 ||
            !d.enumerable ||
            !Object.hasOwn(d, "value")
          )
            throw new Error();
          return [name, copy(d.value, depth + 1)];
        }),
      ),
    );
  }
  return copy(supplied);
}
function urlFor(kind, plan, resources) {
  switch (kind) {
    case "project-binding":
      return `https://cloudresourcemanager.googleapis.com/v1/projects/${plan.projectId}`;
    case "default-bucket":
      return `https://firebasestorage.googleapis.com/v1alpha/projects/${plan.projectId}/defaultBucket`;
    case "bucket-config":
      return `https://storage.googleapis.com/storage/v1/b/${plan.bucket}`;
    case "auth-config":
      return `https://identitytoolkit.googleapis.com/admin/v2/projects/${plan.projectId}/config`;
    case "api-key-metadata":
      return `https://apikeys.googleapis.com/v2/${resources.apiKeyResource}`;
    case "api-key-value":
      return `https://apikeys.googleapis.com/v2/${resources.apiKeyResource}/keyString`;
    default:
      throw new Error();
  }
}
function covered(binding, kind, body) {
  const url = urlFor(kind, binding.plan, binding.resources);
  const profile = createProductionCaptureProfile({
    kind,
    method: "GET",
    url,
    sessionPhase: null,
    objectName: null,
  });
  return productionCaptureIsCovered(profile, {
    url,
    direction: "response",
    status: 200,
    complete: true,
    headers: [["content-type", "application/json"]],
    body,
    bodyKind: "json",
    expectedObjectNames: [],
    expectedBucket: binding.plan.bucket,
  });
}
function restrictionsAreExact(key) {
  const restrictions = key.restrictions;
  if (
    !restrictions ||
    Reflect.ownKeys(restrictions).length !== 1 ||
    !Array.isArray(restrictions.apiTargets) ||
    restrictions.apiTargets.length !== 2
  )
    return false;
  return (
    restrictions.apiTargets.every(
      (target) => Reflect.ownKeys(target).length === 1 && typeof target.service === "string",
    ) &&
    isDeepStrictEqual(
      restrictions.apiTargets.map((target) => target.service).toSorted(),
      apiServices,
    )
  );
}
function hasTargetIdentity(binding) {
  const { plan, resources, baseline } = binding;
  const aliases = [plan.projectId, resources.projectNumber];
  return (
    baseline.project.projectId === plan.projectId &&
    baseline.project.projectNumber === resources.projectNumber &&
    baseline.project.lifecycleState === "ACTIVE" &&
    aliases.some(
      (project) => baseline.defaultBucket.name === `projects/${project}/defaultBucket`,
    ) &&
    aliases.some(
      (project) =>
        baseline.defaultBucket.bucket.name === `projects/${project}/buckets/${plan.bucket}`,
    ) &&
    typeof baseline.bucket.location === "string" &&
    typeof baseline.defaultBucket.location === "string" &&
    baseline.bucket.location.toLowerCase() === baseline.defaultBucket.location.toLowerCase() &&
    baseline.bucket.name === plan.bucket &&
    baseline.bucket.projectNumber === resources.projectNumber &&
    baseline.auth.name === `projects/${plan.projectId}/config` &&
    baseline.auth.subtype === "FIREBASE_AUTH" &&
    baseline.auth.signIn?.email?.enabled === true &&
    baseline.auth.signIn.email.passwordRequired === true &&
    baseline.key.name === resources.apiKeyResource &&
    !Object.hasOwn(baseline.key, "keyString") &&
    restrictionsAreExact(baseline.key)
  );
}

/** A bounded private baseline is a pure comparison capability, never runtime or request admission. */
export function createProductionResourceBaseline(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, ["plan", "resources", "baseline"]);
    if (Object.keys(input).length !== 3) throw new Error();
    const plan = copyCanonicalProductionStage3Plan(input.plan);
    const resources = snapshot(
      copyProductionCaptureRecord(input.resources, [
        "projectNumber",
        "apiKeyResource",
        "rulesetResource",
      ]),
    );
    if (
      Object.keys(resources).length !== 3 ||
      typeof resources.projectNumber !== "string" ||
      !/^[1-9][0-9]{0,19}$/.test(resources.projectNumber) ||
      typeof resources.apiKeyResource !== "string" ||
      !new RegExp(
        `^projects/${resources.projectNumber}/locations/global/keys/[A-Za-z0-9_-]+$`,
      ).test(resources.apiKeyResource)
    )
      throw new Error();
    const baseline = snapshot(
      copyProductionCaptureRecord(input.baseline, [
        "project",
        "defaultBucket",
        "bucket",
        "auth",
        "key",
        "apiKeySha256",
      ]),
    );
    if (
      Object.keys(baseline).length !== 6 ||
      typeof baseline.apiKeySha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(baseline.apiKeySha256)
    )
      throw new Error();
    const binding = { plan, resources, baseline };
    for (const [kind, field] of fields) {
      if (!covered(binding, kind, Buffer.from(JSON.stringify(baseline[field])))) throw new Error();
    }
    if (!hasTargetIdentity(binding)) throw new Error();
    const capability = Object.freeze({});
    baselines.set(capability, binding);
    return capability;
  } catch {
    throw new Error("invalid production resource baseline");
  }
}
function read(binding, kind, status, suppliedBody) {
  if (status !== 200) throw new Error();
  const body = copyProductionCaptureBody(suppliedBody);
  if (body.length > MAX_RESPONSE_BODY_BYTES || !covered(binding, kind, body)) throw new Error();
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  parseCaptureJsonSpans(text);
  return JSON.parse(text);
}
/** Compare a supplied readback only; its original control response and slot remain separate gates. */
export function verifyProductionResourceBaselineReadback(capability, supplied) {
  try {
    const binding = baselines.get(capability);
    if (!binding) return false;
    const row = copyProductionCaptureRecord(supplied, ["kind", "status", "body"]);
    if (Object.keys(row).length !== 3 || typeof row.kind !== "string" || !fields.has(row.kind))
      return false;
    return isDeepStrictEqual(
      read(binding, row.kind, row.status, row.body),
      binding.baseline[fields.get(row.kind)],
    );
  } catch {
    return false;
  }
}
/** The verified key is returned only to memory; this capability contains no export or writer method. */
export function readVerifiedProductionResourceApiKey(capability, supplied) {
  try {
    const binding = baselines.get(capability);
    if (!binding) return null;
    const row = copyProductionCaptureRecord(supplied, ["status", "body"]);
    if (Object.keys(row).length !== 2) return null;
    const value = read(binding, "api-key-value", row.status, row.body).keyString;
    if (typeof value !== "string" || !value || hash(value) !== binding.baseline.apiKeySha256)
      return null;
    return value;
  } catch {
    return null;
  }
}

/** Original baseline identity and exact data pins do not replace a fresh runtime admission. */
export function productionResourceBaselineUsesContext(capability, supplied) {
  try {
    const binding = baselines.get(capability);
    if (!binding) return false;
    const input = copyProductionCaptureRecord(supplied, ["plan", "resources"]);
    if (Object.keys(input).length !== 2) return false;
    return (
      isDeepStrictEqual(copyCanonicalProductionStage3Plan(input.plan), binding.plan) &&
      isDeepStrictEqual(snapshot(input.resources), binding.resources)
    );
  } catch {
    return false;
  }
}
