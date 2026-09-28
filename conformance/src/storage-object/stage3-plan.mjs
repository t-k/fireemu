import { createHash } from "node:crypto";
import { FIXED_PRODUCTION_RULES_SHA256, buildSymbolicStorageAuthPlan } from "./auth-plan.mjs";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { buildCorpus } from "./corpus.mjs";

const PER_RECORDING_CAP = 3000;
const PER_RECORDING_CLEANUP_RESERVE = 1000;
const RECOVERY_RESERVE = 600;
const TASK_REQUEST_CAP = 2 * PER_RECORDING_CAP + RECOVERY_RESERVE;
const TASK_USD_RESERVATION = 1;
const EXPECTED_REMAINING = [
  "storage-object/errors/authorization",
  "storage-object/auth/firebase-id-token",
];

const digest = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");

/** A deterministic, non-sending draft for reviewing the two production recordings. */
export function buildStage3DraftPlan({ projectId, bucket, runIds } = {}) {
  if (
    !Array.isArray(runIds) ||
    runIds.length !== 2 ||
    runIds[0] === runIds[1] ||
    runIds.some((runId) => typeof runId !== "string" || !/^[a-z0-9]{8,32}$/.test(runId))
  )
    throw new Error("two distinct bounded run IDs are required");

  const recordings = runIds.map((runId) => {
    const prefix = `storage-object/${runId}/`;
    const corpus = buildCorpus({ bucket, prefix });
    const authPlan = buildSymbolicStorageAuthPlan({ projectId, bucket, runId });
    const authCorpus = buildAuthCorpus({ projectId, bucket, runId });
    if (
      corpus.recipes.length !== 24 ||
      corpus.requestsPerRecording !== 1891 ||
      JSON.stringify(corpus.remainingRecipeIds) !== JSON.stringify(EXPECTED_REMAINING)
    )
      throw new Error("the static corpus changed; review its budget before planning a send");
    const staticRequestEntries = corpus.recipes.reduce(
      (sum, recipe) => sum + recipe.preflight.length + recipe.steps.length + recipe.cleanup.length,
      0,
    );
    const staticCleanupEntries = corpus.recipes.reduce(
      (sum, recipe) => sum + recipe.cleanup.length,
      0,
    );
    const staticSubjectEntries = staticRequestEntries - staticCleanupEntries;
    const invalidNameProof = corpus.recipes.find(
      (recipe) => recipe.id === "storage-object/errors/object-name",
    )?.invalidNameAbsenceProof;
    if (
      invalidNameProof?.dialect !== "gcs" ||
      invalidNameProof.scopePrefix !== prefix ||
      invalidNameProof.delimiter !== null ||
      invalidNameProof.maxPagesPerRefusal !== 32 ||
      invalidNameProof.maxRefusals !== 4 ||
      invalidNameProof.maxRequests !== 128 ||
      invalidNameProof.requiresExactKnownOwnedNames !== true
    )
      throw new Error("invalid-name absence proof budget differs");
    if (staticRequestEntries !== corpus.requestsPerRecording)
      throw new Error("static request accounting is inconsistent");
    if (
      authCorpus.recipeIds.length !== 2 ||
      JSON.stringify(authCorpus.recipeIds) !== JSON.stringify(EXPECTED_REMAINING) ||
      authCorpus.requestsPerRecording !== 212 ||
      authCorpus.subjectEntries !== 156 ||
      authCorpus.cleanupEntries !== 56
    )
      throw new Error("auth corpus changed; review its budget before planning a send");
    const combinedSubjectEntries = staticSubjectEntries + authCorpus.subjectEntries;
    const combinedCleanupEntries = staticCleanupEntries + authCorpus.cleanupEntries;
    const combinedRequestEntries = staticRequestEntries + authCorpus.requestsPerRecording;
    if (
      combinedSubjectEntries + invalidNameProof.maxRequests >
      PER_RECORDING_CAP - PER_RECORDING_CLEANUP_RESERVE
    )
      throw new Error("supplemental invalid-name proof exceeds the subject cap");
    return {
      runId,
      prefix,
      corpusDigest: digest(corpus),
      authPlanDigest: digest(authPlan),
      authCorpusDigest: digest(authCorpus),
      declaredRecipeCount: corpus.recipes.length + authCorpus.recipes.length,
      remainingRecipeIds: [],
      baseStaticEntries: staticRequestEntries,
      authStaticEntries: authCorpus.requestsPerRecording,
      staticRequestEntries: combinedRequestEntries,
      staticCleanupEntries: combinedCleanupEntries,
      staticSubjectEntries: combinedSubjectEntries,
      supplementalSubjectMaxRequests: invalidNameProof.maxRequests,
      maxRequests: PER_RECORDING_CAP,
      cleanupReserveRequests: PER_RECORDING_CLEANUP_RESERVE,
      subjectCapRequests: PER_RECORDING_CAP - PER_RECORDING_CLEANUP_RESERVE,
      subjectAllowance:
        PER_RECORDING_CAP -
        PER_RECORDING_CLEANUP_RESERVE -
        combinedSubjectEntries -
        invalidNameProof.maxRequests,
      cleanupAllowance: PER_RECORDING_CLEANUP_RESERVE - combinedCleanupEntries,
      sendAuthorized: false,
    };
  });

  return {
    status: "LOCAL_DRAFT_NO_SEND",
    projectId,
    bucket,
    rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
    rulesMutationAllowed: false,
    recordings,
    maxRequests: TASK_REQUEST_CAP,
    recoveryReserveRequests: RECOVERY_RESERVE,
    maxUsdReservation: TASK_USD_RESERVATION,
    estimatedUsd: 0.3,
    maxRequestBytes: 32 * 1024 * 1024,
    maxResponseBytes: 256 * 1024 * 1024,
    maxOwnedAuthAccounts: 8,
    budgetStatus: "PROPOSED_NOT_APPROVED",
    sendAuthorized: false,
  };
}
