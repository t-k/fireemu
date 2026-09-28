import { createHash } from "node:crypto";
import { resolveDeclaredQuery } from "./reference-resolution.mjs";

/** Replay the existing admin sequence through its supplied counted sender. */
export async function replayLocalAdmin({ sender, recipe, bucket } = {}) {
  await sender.start();
  await sender.admitNamespace();
  for (const name of recipe.objects) sender.admitObject(name);
  for (const step of recipe.preflight) {
    const response = await sender.sendStep(step);
    if (response.status !== 404)
      throw new Error(`${recipe.id}: preflight ${step.id} was ${response.status}`);
  }

  const responses = new Map();
  const states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        mutationId: null,
        mutationMethod: null,
        expectedBytesSha256: null,
        metadataId: null,
        mediaId: null,
        owned: false,
        deleted: false,
      },
    ]),
  );
  const mutationStatuses = [];
  for (const [stepIndex, declared] of recipe.steps.entries()) {
    const query = resolveDeclaredQuery({ recipe, stepIndex, responses, bucket });
    const step = { ...declared, query };
    const state = states.get(step.objectName);
    if (!state) throw new Error(`${recipe.id}: undeclared object`);
    const response = await sender.sendStep(step);
    responses.set(step.id, {
      status: response.status,
      bodyBase64: response.raw.toString("base64"),
    });
    if (step.method !== "GET") {
      if (step.method === "POST") {
        if (state.mutationId !== null || response.status !== 200 || !step.body?.base64)
          throw new Error(`${recipe.id}: initial upload failed or repeated`);
        state.expectedBytesSha256 = createHash("sha256")
          .update(Buffer.from(step.body.base64, "base64"))
          .digest("hex");
      } else if (step.method === "DELETE") {
        if (!state.owned || state.deleted || response.status !== 204)
          throw new Error(`${recipe.id}: subject delete was not confirmed`);
      } else {
        throw new Error(`${recipe.id}: unexpected mutation method`);
      }
      state.mutationId = step.id;
      state.mutationMethod = step.method;
      mutationStatuses.push({ id: step.id, status: response.status });
    } else if (step.dialect === "gcs" && Object.keys(query).length === 0) {
      state.metadataId = step.id;
    } else if (step.dialect === "gcs" && query.alt === "media") {
      state.mediaId = step.id;
      if (state.mutationMethod === "POST" && !state.owned) {
        sender.confirmOwned({
          name: step.objectName,
          uploadOperationId: state.mutationId,
          metadataOperationId: state.metadataId,
          mediaOperationId: state.mediaId,
          expectedBytesSha256: state.expectedBytesSha256,
        });
        state.owned = true;
      } else if (state.mutationMethod === "DELETE" && !state.deleted) {
        await sender.confirmAbsent({
          name: step.objectName,
          mutationOperationId: state.mutationId,
          metadataOperationId: state.metadataId,
          mediaOperationId: state.mediaId,
        });
        state.deleted = true;
      }
    }
  }
  if ([...states.values()].some((state) => !state.owned || !state.deleted))
    throw new Error(`${recipe.id}: subject ownership and deletion were not confirmed`);
  sender.beginCleanup();
  for (const name of recipe.objects) {
    const cleanup = recipe.cleanup.filter((step) => step.objectName === name);
    if (cleanup.length !== 3 || cleanup[0].method !== "DELETE")
      throw new Error(`${recipe.id}: invalid cleanup declaration`);
    for (const step of cleanup.slice(1)) {
      const response = await sender.sendStep(step);
      if (response.status !== 404)
        throw new Error(`${recipe.id}: cleanup ${step.id} was not absent`);
    }
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length !== 0) throw new Error(`${recipe.id}: unresolved objects`);
  return {
    recipeId: recipe.id,
    status: "LOCAL_COMPLETE",
    cleanupFailures: [],
    unresolved: sender.unresolved(),
    credentialProof: "LOCAL_STUB_ONLY",
    requests: sender.snapshot().total,
    mutationStatuses,
  };
}
