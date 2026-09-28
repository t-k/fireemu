import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { evaluateListPages } from "./list-pages.mjs";

function listBody(response) {
  if (response.status !== 200) throw new Error("list response was not 200");
  let parsed;
  try {
    parsed = JSON.parse(response.raw.toString("utf8"));
  } catch {
    throw new Error("list response was not JSON");
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    (parsed.items !== undefined && !Array.isArray(parsed.items)) ||
    (parsed.prefixes !== undefined && !Array.isArray(parsed.prefixes))
  )
    throw new Error("list response has invalid collection data");
  return parsed;
}

function nextToken(body, cap) {
  const token = body.nextPageToken;
  if (token === undefined) return null;
  if (
    typeof token !== "string" ||
    !token ||
    Buffer.byteLength(token) > cap ||
    [...token].some((character) => {
      const code = character.codePointAt(0);
      return code < 32 || code === 127;
    })
  )
    throw new Error("list nextPageToken is invalid or exceeds the declared bound");
  return token;
}

function knownLocalGap(recipe, step, response, bucket) {
  const scope = step.scopePrefix;
  const parameter = { "offset-filter": "startOffset", "glob-filter": "matchGlob" }[step.id];
  if (
    recipe.id !== "storage-object/gcs/list" ||
    !parameter ||
    response.status !== 400 ||
    step.dialect !== "gcs" ||
    step.collection !== true ||
    step.method !== "GET" ||
    step.credential !== "admin" ||
    step.path !== `/storage/v1/b/${bucket}/o` ||
    typeof scope !== "string" ||
    !scope.endsWith("/list/gcs/") ||
    !isDeepStrictEqual(
      recipe.objects,
      ["a.txt", "b.txt", "dir/c.txt", "dir/d.txt", "dir2/e.txt", "zz.txt"].map(
        (suffix) => `${scope}${suffix}`,
      ),
    ) ||
    !isDeepStrictEqual(
      step.query,
      parameter === "startOffset"
        ? { prefix: scope, startOffset: `${scope}b.txt`, endOffset: `${scope}zz.txt` }
        : { prefix: scope, matchGlob: `${scope}dir/*` },
    )
  )
    return null;
  let body;
  try {
    body = JSON.parse(response.raw.toString("utf8"));
  } catch {
    return null;
  }
  const message = `unsupported JSON API list parameter: ${parameter}`;
  if (
    !isDeepStrictEqual(body, {
      error: { code: 400, message, errors: [{ domain: "global", message, reason: "invalid" }] },
    })
  )
    return null;
  return {
    stepId: step.id,
    status: 400,
    parameter,
    compatibility: "UNOBSERVED_PRODUCTION",
    reason: "FIREEMU_STRICT_UNSUPPORTED_LIST_PARAMETER",
  };
}

/** Replay the existing list sequence through its supplied counted sender. */
export async function replayLocalList({
  sender,
  recipe,
  bucket,
  allowKnownLocalListGaps = false,
  onCapture,
} = {}) {
  if (
    typeof allowKnownLocalListGaps !== "boolean" ||
    (onCapture !== undefined && typeof onCapture !== "function")
  )
    throw new Error("invalid local list observation options");
  if (allowKnownLocalListGaps && typeof onCapture !== "function")
    throw new Error("private response capture writer is required for local list gaps");
  const recipeId = recipe.id;
  const localDifferenceCandidates = [];
  async function send(step) {
    const response = await sender.sendStep(step);
    if (onCapture)
      await onCapture({
        stepId: step.id,
        dialect: step.dialect,
        status: response.status,
        bodyBase64: response.raw.toString("base64"),
      });
    return response;
  }
  await sender.start();
  await sender.admitNamespace();
  for (const name of recipe.objects) sender.admitObject(name);
  for (const step of recipe.preflight) {
    const response = await send(step);
    if (step.collection) {
      const body = listBody(response);
      if (
        body.nextPageToken ||
        (body.items?.length ?? 0) !== 0 ||
        (body.prefixes?.length ?? 0) !== 0
      )
        throw new Error(`${recipeId}: baseline list was not empty`);
    } else if (response.status !== 404) {
      throw new Error(`${recipeId}: preflight ${step.id} was not absent`);
    }
  }

  const states = new Map(
    recipe.objects.map((name) => [
      name,
      {
        uploadId: null,
        expectedBytesSha256: null,
        metadataId: null,
        mediaId: null,
        confirmed: false,
      },
    ]),
  );
  const pageRecords = [];
  const pageSummaries = [];
  let pageToken = null;
  let pageFinished = false;
  for (const step of recipe.steps) {
    if (step.collection) {
      if (step.continuation && pageFinished) continue;
      if (step.continuation && pageToken === null)
        throw new Error(`${recipeId}: page continuation has no token`);
      const query = step.continuation
        ? { ...step.query, [step.continuation.targetQuery]: pageToken }
        : step.query;
      const response = await send({ ...step, query });
      const candidate = allowKnownLocalListGaps
        ? knownLocalGap(recipe, step, response, bucket)
        : null;
      if (candidate) {
        localDifferenceCandidates.push(candidate);
        continue;
      }
      const body = listBody(response);
      if (step.id.startsWith("page-")) {
        pageRecords.push({
          stepId: step.id,
          query,
          status: response.status,
          bodyBase64: response.raw.toString("base64"),
        });
        pageToken = nextToken(body, step.continuation?.maxTokenBytes ?? 4096);
        pageSummaries.push({
          stepId: step.id,
          items: body.items?.length ?? 0,
          prefixes: body.prefixes?.length ?? 0,
          hasNextPageToken: pageToken !== null,
        });
        pageFinished = pageToken === null;
      }
      continue;
    }
    const state = states.get(step.objectName);
    if (!state) throw new Error(`${recipeId}: undeclared seed object`);
    const response = await send(step);
    if (step.method === "POST") {
      if (response.status !== 200 || state.uploadId !== null || !step.body?.base64)
        throw new Error(`${recipeId}: seed upload failed or repeated`);
      state.uploadId = step.id;
      state.expectedBytesSha256 = createHash("sha256")
        .update(Buffer.from(step.body.base64, "base64"))
        .digest("hex");
    } else if (Object.keys(step.query).length === 0) {
      state.metadataId = step.id;
    } else if (step.query.alt === "media") {
      state.mediaId = step.id;
      sender.confirmOwned({
        name: step.objectName,
        uploadOperationId: state.uploadId,
        metadataOperationId: state.metadataId,
        mediaOperationId: state.mediaId,
        expectedBytesSha256: state.expectedBytesSha256,
      });
      state.confirmed = true;
    }
  }
  if ([...states.values()].some((state) => !state.confirmed) || !pageFinished)
    throw new Error(`${recipeId}: seed or list traversal is incomplete`);
  let pageEvaluation;
  try {
    pageEvaluation = evaluateListPages({ recipe, pages: pageRecords, bucket });
  } catch (error) {
    if (!error.message.startsWith("list pages:")) throw error;
    pageEvaluation = { status: "LOCAL_MISMATCH", reason: error.message };
  }
  sender.beginCleanup();
  for (const [name, state] of states) {
    const cleanup = recipe.cleanup.filter((step) => step.objectName === name);
    if (cleanup.length !== 3 || cleanup[0].method !== "DELETE")
      throw new Error(`${recipeId}: invalid seed cleanup declaration`);
    const deletion = await sender.cleanupOwned({
      name,
      metadataOperationId: state.metadataId,
      mediaOperationId: state.mediaId,
      operationId: cleanup[0].id,
    });
    if (deletion.status !== 204) throw new Error(`${recipeId}: seed cleanup failed`);
    for (const step of cleanup.slice(1)) {
      const response = await send(step);
      if (response.status !== 404)
        throw new Error(`${recipeId}: cleanup ${step.id} was not absent`);
    }
  }
  await sender.verifyRunEmpty();
  sender.close();
  if (sender.unresolved().length !== 0) throw new Error(`${recipeId}: unresolved seed objects`);
  return {
    recipeId,
    status: "LOCAL_COMPLETE",
    cleanupFailures: [],
    unresolved: sender.unresolved(),
    requests: sender.snapshot().total,
    pageEvaluation,
    pageSummaries,
    localDifferenceCandidates,
  };
}
