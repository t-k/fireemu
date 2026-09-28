import { createHash } from "node:crypto";
import { resolveDeclaredQuery } from "./reference-resolution.mjs";

/** Replay the existing basic sequence through its supplied counted sender. */
export async function replayLocalBasic({ sender, recipe, bucket } = {}) {
  const recipeId = recipe.id;
  await sender.start();
  await sender.admitNamespace();
  if (recipe.objects.length !== 1) throw new Error("basic local recipe must have one object");
  const name = recipe.objects[0];
  sender.admitObject(name);
  const responses = new Map();
  for (const step of recipe.preflight) {
    const response = await sender.sendStep(step, { operationId: step.id });
    responses.set(step.id, {
      status: response.status,
      bodyBase64: response.raw.toString("base64"),
    });
    if (response.status !== 404)
      throw new Error(`${recipeId}: preflight ${step.id} was not absent`);
  }
  let uploadId = null;
  let expectedBytesSha256 = null;
  let confirmed = false;
  let ownedNow = false;
  let currentMetadataId = null;
  let currentMediaId = null;
  let supplementalReadbacks = 0;
  const mutationStatuses = [];
  for (const [stepIndex, declared] of recipe.steps.entries()) {
    if (declared.method !== "GET" && uploadId && !confirmed) {
      if (responses.get(uploadId)?.status >= 400)
        throw new Error(`${recipeId}: a refused prior write has no declared readbacks`);
      const metadataId = `supplemental-${declared.id}-metadata`;
      const mediaId = `supplemental-${declared.id}-media`;
      const objectPath = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
      const metadata = await sender.sendStep({
        id: metadataId,
        dialect: "gcs",
        method: "GET",
        objectName: name,
        path: objectPath,
        query: {},
      });
      const media = await sender.sendStep({
        id: mediaId,
        dialect: "gcs",
        method: "GET",
        objectName: name,
        path: objectPath,
        query: { alt: "media" },
      });
      if (metadata.status !== 200 || media.status !== 200)
        throw new Error(`${recipeId}: supplemental ownership readback failed`);
      sender.confirmOwned({
        name,
        uploadOperationId: uploadId,
        metadataOperationId: metadataId,
        mediaOperationId: mediaId,
        expectedBytesSha256,
      });
      currentMetadataId = metadataId;
      currentMediaId = mediaId;
      confirmed = true;
      supplementalReadbacks += 2;
    }
    const query = resolveDeclaredQuery({ recipe, stepIndex, responses, bucket });
    const step = { ...declared, query };
    const response = await sender.sendStep(step, { operationId: declared.id });
    responses.set(declared.id, {
      status: response.status,
      bodyBase64: response.raw.toString("base64"),
    });
    if (step.method !== "GET") {
      mutationStatuses.push({ id: declared.id, status: response.status });
      if (uploadId !== null && !confirmed)
        throw new Error(`${recipeId}: unexpected mutation or unresolved prior write`);
      if (typeof step.body?.base64 === "string")
        expectedBytesSha256 = createHash("sha256")
          .update(Buffer.from(step.body.base64, "base64"))
          .digest("hex");
      else if (
        response.status < 400 &&
        !(
          step.method === "DELETE" ||
          (["PATCH", "PUT"].includes(step.method) && step.body?.json && expectedBytesSha256)
        )
      )
        throw new Error(`${recipeId}: unsupported mutation body`);
      uploadId = declared.id;
      confirmed = false;
    } else if (Object.keys(query).length === 0) {
      currentMetadataId = declared.id;
    } else if (
      Object.keys(query).length === 1 &&
      query.alt === "media" &&
      !Object.keys(step.headers ?? {}).some((header) => header.toLowerCase() === "range")
    ) {
      currentMediaId = declared.id;
      if (!confirmed && uploadId && currentMetadataId) {
        try {
          if (response.status === 404 && responses.get(currentMetadataId)?.status === 404) {
            await sender.confirmAbsent({
              name,
              mutationOperationId: uploadId,
              metadataOperationId: currentMetadataId,
              mediaOperationId: currentMediaId,
            });
            ownedNow = false;
          } else if (responses.get(uploadId).status >= 400) {
            sender.confirmRefused({
              name,
              mutationOperationId: uploadId,
              metadataOperationId: currentMetadataId,
              mediaOperationId: currentMediaId,
            });
            ownedNow = true;
          } else {
            sender.confirmOwned({
              name,
              uploadOperationId: uploadId,
              metadataOperationId: currentMetadataId,
              mediaOperationId: currentMediaId,
              expectedBytesSha256,
            });
            ownedNow = true;
          }
        } catch (error) {
          throw new Error(
            `${recipeId}: ${uploadId} status ${responses.get(uploadId)?.status}: ${error.message}`,
            { cause: error },
          );
        }
        confirmed = true;
      }
    }
  }
  if (!confirmed && uploadId && responses.get(currentMetadataId)?.status === 404) {
    const mediaId = `supplemental-${uploadId}-absence-media`;
    const media = await sender.sendStep({
      id: mediaId,
      dialect: "gcs",
      method: "GET",
      objectName: name,
      path: `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`,
      query: { alt: "media" },
    });
    if (media.status !== 404) throw new Error(`${recipeId}: post-mutation media was not absent`);
    await sender.confirmAbsent({
      name,
      mutationOperationId: uploadId,
      metadataOperationId: currentMetadataId,
      mediaOperationId: mediaId,
    });
    currentMediaId = mediaId;
    confirmed = true;
    ownedNow = false;
    supplementalReadbacks += 1;
  }
  if (!confirmed || !currentMetadataId || !currentMediaId)
    throw new Error(`${recipeId}: owned bytes were not confirmed`);
  sender.beginCleanup();
  if (ownedNow) {
    const deleted = await sender.cleanupOwned({
      name,
      metadataOperationId: currentMetadataId,
      mediaOperationId: currentMediaId,
      operationId: recipe.cleanup[0].id,
    });
    if (deleted.status !== 204) throw new Error(`${recipeId}: cleanup delete was not confirmed`);
  }
  for (const step of recipe.cleanup.slice(1)) {
    const response = await sender.sendStep(step, { operationId: step.id });
    if (response.status !== 404) throw new Error(`${recipeId}: cleanup ${step.id} was not absent`);
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length > 0) throw new Error(`${recipeId}: unresolved owned object`);
  return {
    recipeId,
    status: "LOCAL_COMPLETE",
    cleanupFailures: [],
    unresolved: sender.unresolved(),
    requests: sender.snapshot().total,
    supplementalReadbacks,
    cleanupDeleteSkippedAbsent: !ownedNow,
    mutationStatuses,
  };
}
