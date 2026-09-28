import { createHash } from "node:crypto";

const PUBLIC_CODES = new Set([
  "INITIAL_ABSENCE_FAILED",
  "SUBJECT_ABSENCE_FAILED",
  "UNRESOLVED_SESSION",
  "CLEANUP_ABSENCE_FAILED",
  "UNKNOWN_SESSION_BINDING",
]);
const publicReason = (error) =>
  PUBLIC_CODES.has(error?.message) ? error.message : "LOCAL_SESSION_REQUEST_OR_PROOF_FAILED";

/** Execute the fixed resumable recipes only through the local counted sender. */
export async function replayLocalSessions({ sender, recipe, bucket, onCapture } = {}) {
  if (typeof onCapture !== "function") throw new Error("private session capture is required");
  const states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        owned: false,
        metadataId: null,
        mediaId: null,
        finishId: null,
      },
    ]),
  );
  const statuses = [],
    cleanupFailures = [];
  let failure = null,
    currentId = "initial-state",
    namespaceReady = false;
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
  async function capture(step, response) {
    await onCapture({
      operationId: step.id,
      status: response.status,
      headers: response.headers,
      bodyBase64: response.raw.toString("base64"),
    });
    statuses.push({ id: step.id, status: response.status });
    return response;
  }
  const send = async (step) => capture(step, await sender.sendStep(step));
  const sessionSend = async (step, options) =>
    capture(step, await sender.sendSessionStep({ recipe, ...options }));
  async function cancellation(name, cancelId, queryId, ids) {
    await sender.confirmCancelledSession({
      name,
      cancelOperationId: cancelId,
      queryOperationId: queryId,
      readbackOperationIds: ids,
    });
  }
  try {
    await sender.start();
    await sender.admitNamespace();
    namespaceReady = true;
    for (const name of recipe.objects) sender.admitObject(name);
    for (const step of recipe.preflight) {
      currentId = step.id;
      if ((await send(step)).status !== 404) throw new Error("INITIAL_ABSENCE_FAILED");
    }
    for (const [stepIndex, step] of recipe.steps.entries()) {
      currentId = step.id;
      const state = states.get(step.objectName);
      const response = step.sessionUriReference
        ? await sessionSend(step, { stepIndex })
        : await send(step);
      if (step.method === "POST" && !step.sessionUriReference) {
        sender.bindSession({ recipe, initiateOperationId: step.id });
      }
      if (step.id === "finish" && response.status === 200) state.finishId = step.id;
      if (step.method === "GET" && step.dialect === "gcs") {
        if (Object.keys(step.query).length === 0) state.metadataId = step.id;
        else if (step.query.alt === "media") {
          state.mediaId = step.id;
          if (state.finishId && !state.owned) {
            const expected = Buffer.concat(
              recipe.steps
                .filter(
                  (row) =>
                    row.objectName === step.objectName && ["chunk-0", "finish"].includes(row.id),
                )
                .map((row) => Buffer.from(row.body.base64, "base64")),
            );
            sender.confirmOwned({
              name: step.objectName,
              uploadOperationId: state.finishId,
              metadataOperationId: state.metadataId,
              mediaOperationId: state.mediaId,
              expectedBytesSha256: createHash("sha256").update(expected).digest("hex"),
            });
            state.owned = true;
          }
        }
      }
      if (step.responseExpectation?.status === 404 && response.status !== 404)
        throw new Error("SUBJECT_ABSENCE_FAILED");
      for (const [label, cancelId, queryId] of [
        ["after-cancel-wrong", "cancel-wrong-active", "query-after-cancel-wrong"],
        ["after-cancel", "cancel-session", "query-cancelled-session"],
      ])
        if (step.id === `${label}-firebase-media`) {
          const ids = ["gcs", "firebase"].flatMap((dialect) =>
            ["metadata", "media"].map((kind) => `${label}-${dialect}-${kind}`),
          );
          await cancellation(step.objectName, cancelId, queryId, ids);
        }
    }
    if (
      recipe.objects.some((name) => {
        const session = sender.sessionSnapshot({ name });
        return !session || (!session.completed && !session.cancelled);
      })
    )
      throw new Error("UNRESOLVED_SESSION");
  } catch (error) {
    failure = { id: currentId, reason: publicReason(error) };
  }
  if (namespaceReady && sender.snapshot().mode === "subject") {
    sender.beginCleanup();
    for (const [objectIndex, name] of recipe.objects.entries()) {
      let session = sender.sessionSnapshot({ name });
      if (session && !session.completed && !session.cancelled) {
        let lastError = null;
        const entries = recipe.cleanup
          .map((step, cleanupIndex) => ({ step, cleanupIndex }))
          .filter(({ step }) => step.objectName === name && step.sessionUriReference);
        for (const { step, cleanupIndex } of entries) {
          try {
            await sessionSend(step, { cleanupIndex });
          } catch (error) {
            lastError = error;
          }
        }
        try {
          const ids = [];
          for (const dialect of ["gcs", "firebase"])
            for (const kind of ["metadata", "media"]) {
              const id = `session-cleanup-${objectIndex}-${dialect}-${kind}`;
              ids.push(id);
              await send({
                id,
                dialect,
                credential: "admin",
                method: "GET",
                objectName: name,
                path: `/${dialect === "gcs" ? "storage/v1" : "v0"}/b/${bucket}/o/${encodeURIComponent(name)}`,
                query: kind === "metadata" ? {} : { alt: "media" },
                headers: {},
              });
            }
          if (entries.length !== 2) throw new Error("UNRESOLVED_SESSION");
          await cancellation(name, entries[0].step.id, entries[1].step.id, ids);
          session = sender.sessionSnapshot({ name });
        } catch (error) {
          lastError = error;
        }
        if (!session.completed && !session.cancelled) {
          cleanupFailures.push({ name, reason: publicReason(lastError) });
          continue;
        }
      }
      if (!session && sender.unresolved().includes(name)) {
        cleanupFailures.push({ name, reason: "UNKNOWN_SESSION_BINDING" });
        continue;
      }
      const cleanup = recipe.cleanup.filter(
        (step) => step.objectName === name && !step.sessionUriReference,
      );
      try {
        if (states.get(name).owned) {
          const fresh = ownerReads(name, `cleanup-session-object-${objectIndex}`);
          for (const step of fresh) await send(step);
          await capture(
            cleanup[0],
            await sender.cleanupOwned({
              name,
              metadataOperationId: fresh[0].id,
              mediaOperationId: fresh[1].id,
              operationId: cleanup[0].id,
            }),
          );
        }
        for (const step of cleanup.filter((row) => row.method === "GET"))
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
    failure,
    statuses,
    cleanupFailures,
    unresolved,
  };
}
