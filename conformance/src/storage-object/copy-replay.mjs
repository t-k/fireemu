import { createHash } from "node:crypto";
import { assertUnchangedReadbacks } from "./read-state.mjs";
import { resolveDeclaredQuery } from "./reference-resolution.mjs";

const PUBLIC_FAILURE_CODES = new Set([
  "INITIAL_ABSENCE_FAILED",
  "UNDECLARED_OBJECT",
  "SOURCE_SEED_UNPROVED",
  "TRANSFER_SOURCE_UNPROVED",
  "UNRESOLVED_PRIOR_MUTATION",
  "INCOMPLETE_REWRITE",
  "SOURCE_MARKER_NOT_ESTABLISHED",
  "UNRESOLVED_SUBJECT_STATE",
  "REWRITE_REFUSED",
  "INVALID_CLEANUP_DECLARATION",
  "CLEANUP_ABSENCE_FAILED",
  "INVALID_INPUT",
  "INVALID_DECLARATION",
  "INVALID_SEQUENCE",
  "INVALID_QUERY",
  "INVALID_RESPONSE",
  "INVALID_PROGRESS",
  "INVALID_COMPLETION",
  "INVALID_CONTINUATION",
  "INVALID_FIRST_READ_OBSERVATION",
]);
function publicReason(error) {
  for (const value of [error?.code, error?.message])
    if (PUBLIC_FAILURE_CODES.has(value)) return value;
  return "LOCAL_REQUEST_OR_PROOF_FAILED";
}

/** Replay the fixed copy recipe locally, preserving uncertain rewrite responsibility. */
export async function replayLocalCopyRewrite({ sender, recipe, bucket, onCapture } = {}) {
  if (recipe?.id !== "storage-object/gcs/copy-rewrite" || typeof onCapture !== "function")
    throw new Error("the declared copy recipe and private capture are required");
  const responses = new Map(),
    states = new Map(
      recipe.objects.map((name) => [
        name,
        {
          confirmed: true,
          owned: false,
          mutationId: null,
          mutationStatus: null,
          digest: null,
          pendingDigest: null,
          metadataId: null,
          mediaId: null,
        },
      ]),
    );
  const statuses = [],
    cleanupFailures = [],
    firstFirebaseMetadataRead = [];
  let failure = null,
    namespaceReady = false,
    currentId = "initial-state",
    rewriteAttempts = 0,
    rewriteDone = false,
    rewriteRefused = false;
  async function capture(step, response) {
    const record = { status: response.status, bodyBase64: response.raw.toString("base64") };
    responses.set(step.id, record);
    await onCapture({ operationId: step.id, headers: response.headers, ...record });
    return response;
  }
  async function send(step) {
    return capture(step, await sender.sendStep(step));
  }
  function readRecords(label) {
    return ["gcs", "firebase"].flatMap((dialect) =>
      ["metadata", "media"].map((kind) => ({
        dialect,
        kind,
        status: responses.get(`${label}-${dialect}-${kind}`)?.status,
        bodyBase64: responses.get(`${label}-${dialect}-${kind}`)?.bodyBase64,
      })),
    );
  }
  async function observeRead(step, response) {
    const state = states.get(step.objectName);
    if (Object.keys(step.query).length === 0) state.metadataId = step.id;
    else if (Object.keys(step.query).length === 1 && step.query.alt === "media") {
      state.mediaId = step.id;
      if (step.dialect !== "gcs" || state.confirmed || !state.mutationId) return;
      const proof = {
        name: step.objectName,
        mutationOperationId: state.mutationId,
        metadataOperationId: state.metadataId,
        mediaOperationId: state.mediaId,
      };
      if (response.status === 404 && responses.get(state.metadataId)?.status === 404) {
        await sender.confirmAbsent(proof);
        state.owned = false;
        state.digest = null;
      } else if (state.mutationStatus >= 400) {
        sender.confirmRefused(proof);
        state.owned = true;
      } else {
        sender.confirmOwned({
          ...proof,
          uploadOperationId: state.mutationId,
          expectedBytesSha256: state.pendingDigest,
        });
        state.owned = true;
        state.digest = state.pendingDigest;
      }
      state.confirmed = true;
    }
  }
  const ownerReads = (name, label) =>
    [
      { id: `${label}-metadata`, query: {} },
      { id: `${label}-media`, query: { alt: "media" } },
    ].map((row) => ({
      id: row.id,
      query: row.query,
      dialect: "gcs",
      credential: "admin",
      method: "GET",
      objectName: name,
      path: `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`,
      headers: {},
    }));
  try {
    await sender.start();
    await sender.admitNamespace();
    namespaceReady = true;
    for (const name of recipe.objects) sender.admitObject(name);
    for (const step of recipe.preflight) {
      currentId = step.id;
      if ((await send(step)).status !== 404) throw new Error("INITIAL_ABSENCE_FAILED");
    }
    for (const [stepIndex, declared] of recipe.steps.entries()) {
      currentId = declared.id;
      const rewriteSlot = recipe.rewritePagination.stepIds.includes(declared.id);
      if (rewriteSlot && (rewriteDone || rewriteRefused)) continue;
      const state = states.get(declared.objectName);
      if (!state) throw new Error("UNDECLARED_OBJECT");
      if (declared.id === "source-marker") {
        for (const read of ownerReads(declared.objectName, "source-seed-owned"))
          await observeRead(read, await send(read));
        if (!state.confirmed || !state.owned) throw new Error("SOURCE_SEED_UNPROVED");
      }
      if (declared.transfer) {
        const source = states.get(declared.transfer.sourceName);
        if (!source?.confirmed) throw new Error("TRANSFER_SOURCE_UNPROVED");
        if (source.owned)
          sender.assertOwnedReadbacks({
            name: declared.transfer.sourceName,
            metadataOperationId: source.metadataId,
            mediaOperationId: source.mediaId,
          });
      }
      const continuation = rewriteSlot && declared.continuation !== undefined;
      if (declared.method !== "GET") {
        if (!state.confirmed && !continuation) throw new Error("UNRESOLVED_PRIOR_MUTATION");
        state.mutationId = declared.id;
        state.confirmed = false;
        state.pendingDigest = declared.transfer
          ? states.get(declared.transfer.sourceName).digest
          : typeof declared.body?.base64 === "string"
            ? createHash("sha256").update(Buffer.from(declared.body.base64, "base64")).digest("hex")
            : state.digest;
      }
      let response, step;
      if (rewriteSlot) {
        rewriteAttempts++;
        response = await capture(declared, await sender.sendRewriteStep({ recipe, stepIndex }));
        state.mutationStatus = response.status;
        if (response.status >= 400 && response.status <= 599) rewriteRefused = true;
        else {
          const progress = sender.rewriteProgress({ name: declared.objectName });
          rewriteDone = progress.done;
          if (!rewriteDone && rewriteAttempts === recipe.rewritePagination.maxCalls)
            throw new Error("INCOMPLETE_REWRITE");
        }
      } else {
        step = {
          ...declared,
          query: resolveDeclaredQuery({ recipe, stepIndex, responses, bucket }),
        };
        response = await send(step);
        if (declared.method !== "GET") state.mutationStatus = response.status;
        else await observeRead(step, response);
      }
      if (declared.method !== "GET") statuses.push({ id: declared.id, status: response.status });
      if (rewriteRefused && declared.id === "rewrite-gcs-media") throw new Error("REWRITE_REFUSED");
      if (declared.id === recipe.firstFirebaseMetadataRead.stepIds.at(-1)) {
        for (const id of recipe.firstFirebaseMetadataRead.stepIds) {
          const row = responses.get(id),
            declaration = recipe.steps.find((item) => item.id === id);
          const body =
            row?.status === 200 ? JSON.parse(Buffer.from(row.bodyBase64, "base64")) : null;
          if (
            body?.bucket !== bucket ||
            body.name !== declared.objectName ||
            typeof body.metageneration !== "string" ||
            !/^[1-9][0-9]{0,19}$/.test(body.metageneration) ||
            BigInt(body.metageneration) > (1n << 64n) - 1n
          )
            throw new Error("INVALID_FIRST_READ_OBSERVATION");
          const tokens =
            declaration.dialect === "firebase"
              ? body.downloadTokens
              : body.metadata?.firebaseStorageDownloadTokens;
          if (
            tokens !== undefined &&
            typeof tokens !== "string" &&
            (!Array.isArray(tokens) || tokens.some((token) => typeof token !== "string"))
          )
            throw new Error("INVALID_FIRST_READ_OBSERVATION");
          firstFirebaseMetadataRead.push({
            dialect: declaration.dialect,
            metageneration: body.metageneration,
            hasDownloadToken: Array.isArray(tokens)
              ? tokens.some((token) => token.length > 0)
              : Boolean(tokens),
          });
        }
      }
      if (declared.id === "source-before-gcs-media") {
        const marker = JSON.parse(
          Buffer.from(responses.get("source-before-gcs-metadata").bodyBase64, "base64"),
        );
        if (marker.metadata?.marker !== "copy-source")
          throw new Error("SOURCE_MARKER_NOT_ESTABLISHED");
      }
      for (const [before, after] of [
        ["source-before", "source-after"],
        ["copy-refusal-before", "copy-refusal-after"],
        ["rewrite-refusal-before", "rewrite-refusal-after"],
        ["copy-missing-source-before-source", "copy-missing-source-after-source"],
        ["copy-missing-source-before-destination", "copy-missing-source-after-destination"],
        ["rewrite-missing-source-before-source", "rewrite-missing-source-after-source"],
        ["rewrite-missing-source-before-destination", "rewrite-missing-source-after-destination"],
      ])
        if (declared.id === `${after}-gcs-media`)
          assertUnchangedReadbacks({ before: readRecords(before), after: readRecords(after) });
    }
    if (!rewriteDone || [...states.values()].some((state) => !state.confirmed))
      throw new Error("UNRESOLVED_SUBJECT_STATE");
  } catch (error) {
    failure = { id: currentId, reason: publicReason(error) };
  }
  if (namespaceReady && sender.snapshot().mode === "subject") {
    sender.beginCleanup();
    for (const [name, state] of states) {
      if (!state.confirmed) continue;
      const cleanup = recipe.cleanup.filter((step) => step.objectName === name);
      try {
        if (cleanup.length !== 3 || cleanup[0].method !== "DELETE")
          throw new Error("INVALID_CLEANUP_DECLARATION");
        if (state.owned) {
          const reads = ownerReads(name, `${cleanup[0].id}-fresh`);
          for (const step of reads) await send(step);
          const response = await sender.cleanupOwned({
            name,
            metadataOperationId: reads[0].id,
            mediaOperationId: reads[1].id,
            operationId: cleanup[0].id,
          });
          await capture(cleanup[0], response);
        }
        for (const step of cleanup.slice(1))
          if ((await send(step)).status !== 404) throw new Error("CLEANUP_ABSENCE_FAILED");
      } catch (error) {
        cleanupFailures.push({ name, reason: publicReason(error) });
      }
    }
    if (sender.unresolved().length === 0 && cleanupFailures.length === 0) {
      try {
        await sender.verifyRunEmpty();
        sender.close();
      } catch (error) {
        cleanupFailures.push({ reason: publicReason(error) });
      }
    }
  }
  const unresolved = sender.unresolved();
  return {
    recipeId: recipe.id,
    status:
      unresolved.length || cleanupFailures.length
        ? "LOCAL_NEEDS_RECOVERY"
        : failure
          ? "LOCAL_BLOCKED"
          : "LOCAL_COMPLETE",
    requests: sender.snapshot().total,
    rewriteAttempts,
    firstFirebaseMetadataRead,
    statuses,
    failure,
    cleanupFailures,
    unresolved,
  };
}
