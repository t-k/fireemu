import { createHash } from "node:crypto";
import {
  assertDeletedTokenDenied,
  assertFirebaseTokenState,
  resolveFirebaseDownloadToken,
} from "./download-token-resolution.mjs";

/** Replay the existing download-token sequence through its supplied counted sender. */
export async function replayLocalDownloadTokens({ sender, recipe, bucket } = {}) {
  const name = recipe.objects[0];
  const byId = new Map(recipe.steps.map((step) => [step.id, step]));
  const evidence = new Map();
  const statuses = [];
  async function send(id, query) {
    const declared = byId.get(id);
    if (!declared) throw new Error(`undeclared token step ${id}`);
    const step = query ? { ...declared, query } : declared;
    const response = await sender.sendStep(step);
    evidence.set(id, { step, response });
    statuses.push({ id, status: response.status });
    return response;
  }
  async function requireSuccess(id, query) {
    const response = await send(id, query);
    if (response.status !== 200) throw new Error(`${id} was ${response.status}`);
    return response;
  }

  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  for (const step of recipe.preflight) {
    const response = await sender.sendStep(step);
    if (response.status !== 404) throw new Error(`${step.id} was not absent`);
  }

  await requireSuccess("upload");
  await requireSuccess("after-upload-gcs-metadata");
  await requireSuccess("after-upload-gcs-media");
  const expectedBytes = Buffer.from(byId.get("upload").body.base64, "base64");
  const expectedBytesSha256 = createHash("sha256").update(expectedBytes).digest("hex");
  sender.confirmOwned({
    name,
    uploadOperationId: "upload",
    metadataOperationId: "after-upload-gcs-metadata",
    mediaOperationId: "after-upload-gcs-media",
    expectedBytesSha256,
  });
  await requireSuccess("after-upload-firebase-metadata");
  await requireSuccess("after-upload-firebase-media");

  await requireSuccess("create-token");
  await requireSuccess("metadata-with-token");
  await requireSuccess("metadata-with-token-again");
  const tokenReference = byId.get("download-with-token").query.token;
  const token = resolveFirebaseDownloadToken({
    reference: tokenReference,
    prior: evidence.get(tokenReference.priorStep),
    created: evidence.get(tokenReference.fromStep),
    bucket,
    name,
  });
  const tokenSha256 = createHash("sha256").update(token).digest("hex");
  for (const id of ["metadata-with-token", "metadata-with-token-again"])
    assertFirebaseTokenState({ evidence: evidence.get(id), bucket, name, token, present: true });
  const objectPath = `/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
  const postCreateMedia = await sender.sendStep({
    id: "supplemental-post-create-media",
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: objectPath,
    query: { alt: "media" },
    credential: "admin",
  });
  if (postCreateMedia.status !== 200) throw new Error("post-create media was not readable");
  sender.confirmOwned({
    name,
    uploadOperationId: "create-token",
    metadataOperationId: "metadata-with-token-again",
    mediaOperationId: "supplemental-post-create-media",
    expectedBytesSha256,
  });

  for (const id of ["download-with-token", "download-with-token-again"]) {
    const step = byId.get(id);
    const response = await send(id, { ...step.query, token });
    if (
      response.status !== 200 ||
      createHash("sha256").update(response.raw).digest("hex") !== expectedBytesSha256
    )
      throw new Error(`${id} did not return the owned bytes`);
  }
  await requireSuccess("delete-token", { delete_token: token });
  const deleted = byId.get("download-with-deleted-token");
  assertDeletedTokenDenied(await send(deleted.id, { ...deleted.query, token }), expectedBytes);
  await requireSuccess("after-delete-gcs-metadata");
  await requireSuccess("after-delete-gcs-media");
  sender.confirmOwned({
    name,
    uploadOperationId: "delete-token",
    metadataOperationId: "after-delete-gcs-metadata",
    mediaOperationId: "after-delete-gcs-media",
    expectedBytesSha256,
  });
  await requireSuccess("after-delete-firebase-metadata");
  await requireSuccess("after-delete-firebase-media");
  assertFirebaseTokenState({
    evidence: evidence.get("after-delete-firebase-metadata"),
    bucket,
    name,
    token,
    present: false,
  });

  sender.beginCleanup();
  const cleanup = await sender.cleanupOwned({
    name,
    metadataOperationId: "after-delete-gcs-metadata",
    mediaOperationId: "after-delete-gcs-media",
    operationId: recipe.cleanup[0].id,
  });
  if (cleanup.status !== 204) throw new Error("token object cleanup failed");
  for (const step of recipe.cleanup.slice(1)) {
    const response = await sender.sendStep(step);
    if (response.status !== 404) throw new Error(`${step.id} was not absent`);
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length !== 0) throw new Error("token object remains unresolved");
  return {
    recipeId: recipe.id,
    status: "LOCAL_COMPLETE",
    cleanupFailures: [],
    unresolved: sender.unresolved(),
    requests: sender.snapshot().total,
    tokenSha256,
    statuses,
  };
}
