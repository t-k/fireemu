import { createHash } from "node:crypto";
import { evaluatePresentRequires } from "./present-requires.mjs";
import { assertUnchangedReadbacks } from "./read-state.mjs";
import { resolveDeclaredQuery } from "./reference-resolution.mjs";
import { evaluateSupplied404Reads } from "./supplied-404.mjs";

/** Replay declared prerequisites with a local sender; this grants no production authority. */
export async function replayLocalPreconditions({ sender, recipe, bucket, onCapture } = {}) {
  if (typeof onCapture !== "function") throw new Error("private response capture is required");
  const responses = new Map();
  const states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        confirmed: true,
        owned: false,
        mutationId: null,
        mutationStatus: null,
        expectedBytesSha256: null,
        pendingBytesSha256: null,
        metadataId: null,
        mediaId: null,
      },
    ]),
  );
  const statuses = [],
    prerequisiteChecks = [],
    cleanupFailures = [];
  let failure = null,
    pendingRead = null,
    namespaceReady = false;
  async function send(step) {
    const response = await sender.sendStep(step);
    const record = { status: response.status, bodyBase64: response.raw.toString("base64") };
    await onCapture({ operationId: step.id, headers: response.headers, ...record });
    responses.set(step.id, record);
    return response;
  }
  const readRecords = (steps) =>
    steps.map((step) => ({
      dialect: step.dialect,
      kind: step.query.alt === "media" ? "media" : "metadata",
      ...responses.get(step.id),
    }));
  let currentId = "initial-state";
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
      const state = states.get(declared.objectName);
      if (!state) throw new Error("UNDECLARED_OBJECT");
      if (declared.requires) {
        if (!state.confirmed || (declared.requires.state === "present") !== state.owned)
          throw new Error("OWNERSHIP_PREREQUISITE_FAILED");
        const evaluate =
          declared.requires.state === "present"
            ? evaluatePresentRequires
            : evaluateSupplied404Reads;
        const result = evaluate({ recipe, stepIndex, responses, bucket });
        if (declared.requires.state === "present") {
          const prior = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)];
          const gcs = (ids) =>
            ids.find((id) => prior.find((row) => row.id === id)?.dialect === "gcs");
          sender.assertOwnedReadbacks({
            name: declared.objectName,
            metadataOperationId: gcs(declared.requires.metadata),
            mediaOperationId: gcs(declared.requires.media),
          });
        }
        prerequisiteChecks.push({ id: declared.id, status: result.status });
        if (declared.method === "GET") {
          const prior = [...recipe.preflight, ...recipe.steps.slice(0, stepIndex)];
          const before = [...declared.requires.metadata, ...declared.requires.media].map((id) =>
            prior.find((row) => row.id === id),
          );
          const after = recipe.steps.slice(stepIndex + 1, stepIndex + 5);
          if (
            after.length !== 4 ||
            after.some(
              (row) =>
                row.objectName !== declared.objectName ||
                row.method !== "GET" ||
                row.credential !== "admin" ||
                Object.keys(row.headers).length ||
                (Object.keys(row.query).length !== 0 &&
                  (Object.keys(row.query).length !== 1 || row.query.alt !== "media")),
            )
          )
            throw new Error("INVALID_POST_READ_DECLARATION");
          pendingRead = { subjectId: declared.id, before: readRecords(before), after };
        }
      }
      if (declared.method !== "GET" && !state.confirmed)
        throw new Error("UNRESOLVED_PRIOR_MUTATION");
      const query = resolveDeclaredQuery({ recipe, stepIndex, responses, bucket });
      if (declared.method !== "GET") {
        state.mutationId = declared.id;
        state.pendingBytesSha256 =
          typeof declared.body?.base64 === "string"
            ? createHash("sha256").update(Buffer.from(declared.body.base64, "base64")).digest("hex")
            : state.expectedBytesSha256;
        state.confirmed = false;
      }
      const response = await send({ ...declared, query });
      if (declared.preconditionCase || declared.method !== "GET")
        statuses.push({ id: declared.id, status: response.status });
      if (declared.method !== "GET") {
        state.mutationStatus = response.status;
      } else if (Object.keys(query).length === 0) {
        state.metadataId = declared.id;
      } else if (Object.keys(query).length === 1 && query.alt === "media") {
        state.mediaId = declared.id;
        if (!state.confirmed && state.mutationId) {
          const proof = {
            name: declared.objectName,
            mutationOperationId: state.mutationId,
            metadataOperationId: state.metadataId,
            mediaOperationId: state.mediaId,
          };
          if (response.status === 404 && responses.get(state.metadataId)?.status === 404) {
            await sender.confirmAbsent(proof);
            state.owned = false;
            state.expectedBytesSha256 = null;
          } else if (state.mutationStatus >= 400) {
            sender.confirmRefused(proof);
            state.owned = true;
          } else {
            sender.confirmOwned({
              ...proof,
              uploadOperationId: state.mutationId,
              expectedBytesSha256: state.pendingBytesSha256,
            });
            state.owned = true;
            state.expectedBytesSha256 = state.pendingBytesSha256;
          }
          state.confirmed = true;
        }
      }
      if (pendingRead?.after.at(-1).id === declared.id) {
        try {
          assertUnchangedReadbacks({
            before: pendingRead.before,
            after: readRecords(pendingRead.after),
          });
        } catch {
          currentId = pendingRead.subjectId;
          throw new Error("READ_STATE_CHANGED");
        }
        pendingRead = null;
      }
    }
    if (pendingRead || [...states.values()].some((state) => !state.confirmed))
      throw new Error("UNRESOLVED_SUBJECT_STATE");
  } catch (error) {
    failure = { id: currentId, reason: error.code ?? error.message };
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
          const path = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
          const metadataOperationId = `${cleanup[0].id}-fresh-metadata`,
            mediaOperationId = `${cleanup[0].id}-fresh-media`;
          for (const [id, query] of [
            [metadataOperationId, {}],
            [mediaOperationId, { alt: "media" }],
          ])
            await send({
              id,
              dialect: "gcs",
              credential: "admin",
              method: "GET",
              objectName: name,
              path,
              query,
              headers: {},
            });
          const response = await sender.cleanupOwned({
            name,
            metadataOperationId,
            mediaOperationId,
            operationId: cleanup[0].id,
          });
          await onCapture({
            operationId: cleanup[0].id,
            status: response.status,
            bodyBase64: response.raw.toString("base64"),
          });
        }
        for (const step of cleanup.slice(1))
          if ((await send(step)).status !== 404) throw new Error("CLEANUP_ABSENCE_FAILED");
      } catch (error) {
        cleanupFailures.push({ name, reason: error.code ?? error.message });
      }
    }
    if (sender.unresolved().length === 0 && cleanupFailures.length === 0) {
      try {
        await sender.verifyRunEmpty();
        sender.close();
      } catch (error) {
        cleanupFailures.push({ reason: error.code ?? error.message });
      }
    }
  }
  const unresolved = sender.unresolved();
  const needsRecovery = unresolved.length > 0 || cleanupFailures.length > 0;
  return {
    recipeId: recipe.id,
    status: needsRecovery ? "LOCAL_NEEDS_RECOVERY" : failure ? "LOCAL_BLOCKED" : "LOCAL_COMPLETE",
    requests: sender.snapshot().total,
    failure,
    prerequisiteChecks,
    statuses,
    cleanupFailures,
    unresolved,
  };
}
