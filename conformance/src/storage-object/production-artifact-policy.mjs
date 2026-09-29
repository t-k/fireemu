import { createHash } from "node:crypto";
import { isDeepStrictEqual, types } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";
import { buildCorpus } from "./corpus.mjs";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { resolveProductionControlRoute } from "./production-routes.mjs";
import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import {
  isProductionSecretRegistry,
  productionSecretRegistryHasValue,
} from "./production-secret-registry.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./wire-limits.mjs";

const profiles = new WeakMap();
const kinds = new Set([
  "intent",
  "journal",
  "control-proof",
  "owner-proof",
  "auth-proof",
  "rules-proof",
  "configuration-change",
  "ledger",
  "manifest",
  "export",
  "error",
]);
const fields = new Set(
  `
  type recording phase operationId sequence status recipeId stepId bucket prefix name objectName method
  ownedGeneration ownedMetageneration ownedUid ownedUidSha256 accountRef accountMutation absent slotId placement
  bodyByteLength bodySha256 stage adcSha256 adcType clientId principalSha256 scopeSha256 accessTokenSha256
  accessTokenByteLength exchangeBodySha256 tokeninfoBodySha256 deadlineMonotonicMs uidSha256 tokenSha256 tokenByteLength
  responseBodySha256 checkpoint sourceSha256 releaseBodySha256 rulesetBodySha256 bucketlessBodySha256 bucketlessAbsent
  label pages releaseCount exhausted state releaseName rulesetName releaseAbsent rulesetAbsent namespaceEmpty
  continuationOf ifGenerationMatch credentialProof rulesSourceSha256 loaded localOnly rulesetResource apiKeyResource
  projectId projectNumber runId rows body metadata contentDisposition contentType generation metageneration size
  requestBody requestBodySha256 requestByteLength responseByteLength captureSequence capturePath sha256 byteLength
  packetSha256 sourceCommit runnerSha256 planSha256 corpusSha256 maxRequests reserveUsd mode total subject cleanup
  complete reason needsRecovery timestamp startedAt endedAt runtime nodeVersion argv env files path hash
  recordings estimatedUsd maxUsdReservation taskMaxRequests subjectCapRequests cleanupReserveRequests
  semanticOperationId firstSequence lastSequence requests emailSha256 sessionUriSha256
  requestReservedBytes responseReservedBytes socketReportedWrittenBytes responseObservedBytes readUnits
  attempts largestResponseReadBytes readAfterHaltBytes active halted boundary
  idToken id_token refreshToken refresh_token access_token password rawPassword client_secret clientSecret apiKey keyString
  authorization Authorization error code cause stack message onConfigurationChange
`
    .trim()
    .split(/\s+/),
);
const credentialFields = new Set([
  "idToken",
  "id_token",
  "refreshToken",
  "refresh_token",
  "access_token",
  "password",
  "rawPassword",
  "client_secret",
  "clientSecret",
  "apiKey",
  "keyString",
]);
const fixedValues = [
  ...kinds,
  "subject",
  "cleanup",
  "initial",
  "subject-renewal",
  "cleanup-renewal",
  "authorized_user",
  "production-control",
  "production-owner",
  "production-auth-ownership",
  "production-auth-token-proof",
  "production-auth-account",
  "production-auth-cleanup",
  "production-auth-account-absence",
  "production-rules-checkpoint",
  "production-rules-reference-list",
  "production-rules-config-change",
  "production-rules-cleanup",
  "recipe-terminal",
  "create",
  "receipt",
  "delete",
  "GET",
  "POST",
  "PATCH",
  "DELETE",
  "PUT",
  "HEAD",
  "release-delete-intent",
  "release-absent",
  "ruleset-delete-intent",
  "ruleset-absent",
  "complete",
  "NEEDS_RECOVERY",
  "BLOCKED",
  "COMPLETE",
  "recording-initial",
  "recording-final",
  "recipe",
  "HTTP_PLAINTEXT_DELIVERED_TO_ONREAD",
];
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const commitment = (bytes) =>
  Object.freeze({
    type: "SHA256_OF_ORIGINAL_BYTES",
    sha256: hash(bytes),
    byteLength: bytes.length,
  });

function snapshot(input, classifyFields) {
  let bytes = 0,
    nodes = 0,
    unknown = false;
  function charge(count) {
    bytes += count;
    if (bytes > MAX_RESPONSE_BODY_BYTES) throw new Error();
  }
  function string(value) {
    if (value.length > 8192 || !value.isWellFormed()) throw new Error();
    charge(Buffer.byteLength(JSON.stringify(value)));
    return value;
  }
  function copy(value, depth) {
    if (++nodes > 4096 || depth > 16 || types.isProxy(value)) throw new Error();
    if (typeof value === "string") return string(value);
    if (value === null || typeof value === "boolean") {
      charge(Buffer.byteLength(JSON.stringify(value)));
      return value;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) throw new Error();
      charge(Buffer.byteLength(JSON.stringify(value)));
      return value;
    }
    if (!value || typeof value !== "object") throw new Error();
    if (Array.isArray(value)) {
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      const length = lengthDescriptor?.value;
      if (
        Object.getPrototypeOf(value) !== Array.prototype ||
        !Number.isSafeInteger(length) ||
        length > 256 ||
        Reflect.ownKeys(value).length !== length + 1
      )
        throw new Error();
      charge(2 + Math.max(0, length - 1));
      return Array.from({ length }, (_, index) => {
        const d = Object.getOwnPropertyDescriptor(value, String(index));
        if (!d?.enumerable || !Object.hasOwn(d, "value")) throw new Error();
        return copy(d.value, depth + 1);
      });
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw new Error();
    const names = Reflect.ownKeys(value);
    if (names.length > 64) throw new Error();
    charge(2 + Math.max(0, names.length - 1));
    const result = Object.create(null);
    for (const name of names) {
      if (typeof name !== "string" || name.length > 128) throw new Error();
      const d = Object.getOwnPropertyDescriptor(value, name);
      if (!d?.enumerable || !Object.hasOwn(d, "value")) throw new Error();
      if (classifyFields && !fields.has(name)) unknown = true;
      string(name);
      charge(1);
      Object.defineProperty(result, name, { value: copy(d.value, depth + 1), enumerable: true });
    }
    return result;
  }
  const value = copy(input, 0),
    body = Buffer.from(JSON.stringify(value));
  if (body.length !== bytes || body.length > MAX_RESPONSE_BODY_BYTES) throw new Error();
  return { value, body, unknown };
}

/** Raw literals are compiled from the canonical plan and resource metadata, never a caller whitelist. */
export function createProductionArtifactProfile(supplied) {
  try {
    const input = copyProductionCaptureRecord(supplied, ["plan", "resources", "secretRegistry"]);
    if (Object.keys(input).length !== 3 || !isProductionSecretRegistry(input.secretRegistry))
      throw new Error();
    input.secretRegistry.openScan();
    const plan = JSON.parse(snapshot(input.plan, false).body.toString());
    if (
      !isDeepStrictEqual(
        plan,
        buildProductionStage3DraftPlan({
          projectId: plan.projectId,
          bucket: plan.bucket,
          runIds: plan.recordings.map((row) => row.runId),
        }),
      )
    )
      throw new Error();
    const resources = copyProductionCaptureRecord(input.resources, [
      "projectNumber",
      "apiKeyResource",
      "rulesetResource",
    ]);
    if (Object.keys(resources).length !== 3) throw new Error();
    const literals = new Set([
      ...fixedValues,
      plan.projectId,
      plan.bucket,
      ...Object.values(resources),
    ]);
    for (const recording of plan.recordings) {
      resolveProductionControlRoute("owner-exchange", {
        ...resources,
        projectId: plan.projectId,
        bucket: plan.bucket,
        prefix: recording.prefix,
      });
      literals.add(recording.runId);
      literals.add(recording.prefix);
      for (const recipe of buildCorpus({ bucket: plan.bucket, prefix: recording.prefix }).recipes) {
        literals.add(recipe.id);
        for (const name of recipe.objects) literals.add(name);
      }
      for (const recipe of buildAuthCorpus({
        projectId: plan.projectId,
        bucket: plan.bucket,
        runId: recording.runId,
      }).recipes) {
        literals.add(recipe.id);
        for (const probe of recipe.probes) literals.add(probe.objectName);
        for (const account of Object.values(recipe.accounts)) literals.add(account.ref);
      }
    }
    literals.add(`projects/${plan.projectId}/releases/firebase.storage/${plan.bucket}`);
    literals.add(`projects/${plan.projectId}/releases/firebase.storage`);
    const profile = Object.freeze({});
    profiles.set(profile, {
      registry: input.secretRegistry,
      plan,
      literals,
      failureCode: null,
      runtime: Object.freeze({
        secretRegistry: input.secretRegistry,
        runIds: Object.freeze(plan.recordings.map((row) => row.runId)),
      }),
    });
    return profile;
  } catch {
    throw new Error("invalid production artifact profile");
  }
}

export function isProductionArtifactProfile(value) {
  return profiles.has(value);
}

/** Compare a descriptor-safe plan snapshot with the original private canonical task plan. */
export function productionArtifactProfileUsesPlan(profile, suppliedPlan) {
  const binding = profiles.get(profile);
  if (!binding) return false;
  try {
    const state = binding.registry.snapshot();
    if (state.failed || state.closed) return false;
    const plan = JSON.parse(snapshot(suppliedPlan, false).body.toString());
    return isDeepStrictEqual(plan, binding.plan);
  } catch {
    return false;
  }
}

/** Original task identity supplies only the registry capability and canonical run IDs. */
export function originalProductionArtifactContext(profile) {
  return profiles.get(profile)?.runtime ?? null;
}

function credentialComponents(value) {
  const result = [];
  for (const match of value.matchAll(
    /(?:Bearer|Firebase) ([\x21-\x7e]{1,8192})|(?:GOCSPX-|AMf-|AIza)[A-Za-z0-9_\-+.=/]{1,8192}|[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  ))
    result.push(match[1] ?? match[0]);
  return result;
}

/** A fixed local audit code contains no payload bytes or payload digest. */
export function productionArtifactFailureCode(profile) {
  const binding = profiles.get(profile);
  if (!binding) throw new Error("invalid production artifact profile");
  return binding.failureCode;
}

/** Null withholds persistence; the owned runtime must retain its started lease and audit the fixed failure code. */
export function sanitizeProductionArtifact(profile, supplied) {
  const binding = profiles.get(profile);
  if (!binding) throw new Error("invalid production artifact profile");
  binding.failureCode = null;
  let kind = null,
    captured = null;
  const checked = (value) => {
    try {
      const bytes = JSON.stringify(value);
      if (bytes.length > MAX_RESPONSE_BODY_BYTES + 4096 * 160) throw new Error();
      if (binding.registry.openScan().hasSecretCopy(bytes)) {
        binding.failureCode = "artifact-withheld-privacy";
        binding.registry.close();
        return null;
      }
      return value;
    } catch {
      binding.failureCode = "artifact-uncheckable";
      binding.registry.close();
      return null;
    }
  };
  const unavailable = () => {
    binding.failureCode = "artifact-uncheckable";
    const value = checked(
      Object.freeze({
        artifactKind: kind,
        mode: "COMMITMENT_ONLY",
        taskSecretStatus: "UNAVAILABLE",
        source: captured ? commitment(captured.body) : null,
        data: null,
      }),
    );
    binding.registry.close();
    return value;
  };
  try {
    const input = copyProductionCaptureRecord(supplied, ["kind", "value"]);
    if (Object.keys(input).length !== 2 || !kinds.has(input.kind)) return unavailable();
    kind = input.kind;
    captured = snapshot(input.value, true);
    if (captured.unknown) return unavailable();
    const scan = binding.registry.openScan();
    function project(value, key = null) {
      if (
        credentialFields.has(key) &&
        (typeof value !== "string" || !productionSecretRegistryHasValue(binding.registry, value))
      )
        throw new Error();
      if (Array.isArray(value)) return value.map((row) => project(row, key));
      if (value && typeof value === "object") {
        const result = Object.create(null);
        for (const [name, row] of Object.entries(value)) {
          if (scan.hasSecretCopy(name)) throw new Error();
          result[name] = project(row, name);
        }
        return result;
      }
      if (typeof value === "string") {
        if (!binding.literals.has(value) || ["authorization", "Authorization"].includes(key))
          for (const token of credentialComponents(value))
            if (!productionSecretRegistryHasValue(binding.registry, token)) throw new Error();
        const secretCopy = scan.hasSecretCopy(value);
        return !secretCopy && binding.literals.has(value) ? value : commitment(Buffer.from(value));
      }
      const text = JSON.stringify(value);
      return scan.hasSecretCopy(text) ? commitment(Buffer.from(text)) : value;
    }
    const data = project(captured.value);
    const registryState = binding.registry.snapshot();
    if (registryState.failed || registryState.closed) return unavailable();
    return checked(
      Object.freeze({
        artifactKind: kind,
        mode: "TYPED_REDACTED_ARTIFACT",
        taskSecretStatus: "AVAILABLE",
        source: commitment(captured.body),
        data,
      }),
    );
  } catch {
    return unavailable();
  }
}
