// The STORAGE-OBJECT probe-v3: records how production answers the routes whose judges cannot be
// made local to one recipe, because what a recipe must clean up depends on the answer: the GCS
// multipart and resumable uploads, the Firebase resumable upload in chunks, copyTo and rewriteTo,
// create_token and delete_token, and GCS lists that hold objects, with paging. It creates seven
// small objects under one fresh prefix, records every answer without judging any, and removes the
// objects again.
//
// Nothing that is cleaned up depends on an answer of this probe. The seven names are fixed by the
// plan, so cleanup finds each object with a GCS metadata read (a shape production has already
// answered), deletes it (conditionally on the generation that read gave, or, when it gave none,
// by name, which only this run can have created), and reads it absent. A final list of the prefix
// decides the closing row, and lists what is left so that it can be removed by name.
//
// Every request goes through the lean wire and has the shape the recorder's own corpus declares for
// it (the steps are the corpus's, built for this probe's prefix). Every GCS create carries
// `ifGenerationMatch=0`; the Firebase v0 creates have no such precondition.

import { buildCorpus } from "./corpus.mjs";
import {
  cleanUpAndList,
  createExchange,
  finalListRow,
  firstLine,
  GENERATION,
  OWNER,
  parse,
  requestOf,
} from "./probe-common.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

export const PROBE3_MAX_REQUESTS = 60;
export const PROBE3_RESERVE_USD = 0.05;
export const PROBE3_ESTIMATE_USD = 0.02;

const REWRITE_CALLS = 3;
const LIST_PAGES = 4;

/**
 * The plan of one probe-v3 run: the corpus steps for this probe's prefix, and the seven object
 * names, which are the same whatever any answer says.
 */
export function buildProbe3Plan({ projectId, bucket, runId, otherRunId }) {
  const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, otherRunId] });
  const prefix = plan.recordings[0].prefix;
  const scope = `${prefix}probe3/`;
  const corpus = buildCorpus({ bucket, prefix: scope });
  const recipe = (id) => {
    const found = corpus.recipes.find((row) => row.id === id);
    if (!found) throw new Error(`the corpus has no recipe ${id}`);
    return found;
  };
  const step = (recipeId, stepId) => {
    const found = recipe(recipeId).steps.find((row) => row.id === stepId);
    if (!found) throw new Error(`the corpus has no step ${stepId} in ${recipeId}`);
    return found;
  };
  const multipart = step("storage-object/gcs/simple-multipart-upload", "valid");
  const gcs = recipe("storage-object/gcs/resumable-upload");
  const firebase = recipe("storage-object/firebase/resumable-upload");
  const copy = recipe("storage-object/gcs/copy-rewrite");
  const tokens = recipe("storage-object/firebase/download-tokens");
  const steps = {
    multipart,
    gcsResumable: Object.fromEntries(
      ["initiate", "chunk-0", "query-progress", "finish"].map((id) => [id, step(gcs.id, id)]),
    ),
    firebaseResumable: Object.fromEntries(
      ["initiate", "query-initial", "chunk-0", "query-progress", "finish"].map((id) => [
        id,
        step(firebase.id, id),
      ]),
    ),
    copy: Object.fromEntries(
      ["source-upload", "source-before-gcs-metadata", "copy", "rewrite-0", "rewrite-1"].map(
        (id) => [id, step(copy.id, id)],
      ),
    ),
    tokens: Object.fromEntries(
      ["upload", "create-token", "delete-token"].map((id) => [id, step(tokens.id, id)]),
    ),
  };
  const objects = [
    multipart.objectName,
    gcs.objects[0],
    firebase.objects[0],
    copy.objects[0],
    copy.objects[1],
    copy.objects[2],
    tokens.objects[0],
  ];
  return Object.freeze({ prefix, scope, bucket, steps, objects: Object.freeze(objects) });
}

const tokensOf = (body) =>
  typeof body?.downloadTokens === "string" ? body.downloadTokens.split(",") : [];

/**
 * Send the probe: record every step, then clean up. A step that cannot be completed (a failed
 * transport, a timeout, a capture failure) ends the recording, and cleanup still runs; a step the
 * wire's route table refuses before sending is recorded as skipped. A step that needs an earlier
 * answer that is not there is skipped with the reason. Cleanup does not read any answer of the
 * recording. Resolves with `{ answers, interrupted }`, and throws (with `probeStep` and `answered`)
 * only when cleanup itself cannot be completed.
 */
export async function sendProbe3({ wire, plan, origins }) {
  const { answers, exchange, skip, sessionUrl } = createExchange({ wire, origins });
  const gcsCreate = (step) => ({ ...step.query, ifGenerationMatch: "0" });
  const { steps } = plan;

  let interrupted = null;
  try {
    // GCS multipart upload.
    await exchange(
      "multipart-create",
      requestOf(steps.multipart, origins, { query: gcsCreate(steps.multipart) }),
    );

    // GCS resumable upload in two chunks: the start, the first chunk, a status probe, the last chunk.
    const gcs = steps.gcsResumable;
    const gcsStart = await exchange("gcs-resumable-start", requestOf(gcs.initiate, origins));
    const gcsUrl = sessionUrl(gcsStart, "location");
    for (const [id, key] of [
      ["gcs-resumable-chunk", "chunk-0"],
      ["gcs-resumable-status", "query-progress"],
      ["gcs-resumable-finish", "finish"],
    ]) {
      if (gcsUrl === null) skip(id, "no session URL");
      else await exchange(id, requestOf(gcs[key], origins, { href: gcsUrl }));
    }

    // Firebase resumable upload in two chunks.
    const firebase = steps.firebaseResumable;
    const firebaseStart = await exchange(
      "firebase-resumable-start",
      requestOf(firebase.initiate, origins),
    );
    const firebaseUrl = sessionUrl(firebaseStart, "x-goog-upload-url");
    for (const [id, key] of [
      ["firebase-resumable-query", "query-initial"],
      ["firebase-resumable-chunk", "chunk-0"],
      ["firebase-resumable-query-after-chunk", "query-progress"],
      ["firebase-resumable-finish", "finish"],
    ]) {
      if (firebaseUrl === null) skip(id, "no session URL");
      else await exchange(id, requestOf(firebase[key], origins, { href: firebaseUrl }));
    }

    // copyTo and rewriteTo of one source. The source preconditions are the generation and
    // metageneration its metadata read gave, when it gave them.
    const copy = steps.copy;
    await exchange(
      "copy-source-create",
      requestOf(copy["source-upload"], origins, { query: gcsCreate(copy["source-upload"]) }),
    );
    const sourceMetadata = await exchange(
      "copy-source-metadata",
      requestOf(copy["source-before-gcs-metadata"], origins),
    );
    const source = parse(sourceMetadata?.text);
    const sourceQuery = {
      ifGenerationMatch: "0",
      ...(GENERATION.test(source?.generation ?? "")
        ? { ifSourceGenerationMatch: source.generation }
        : {}),
      ...(GENERATION.test(source?.metageneration ?? "")
        ? { ifSourceMetagenerationMatch: source.metageneration }
        : {}),
    };
    await exchange("copy-to", requestOf(copy.copy, origins, { query: sourceQuery }));
    let rewrite = await exchange(
      "rewrite-0",
      requestOf(copy["rewrite-0"], origins, { query: sourceQuery }),
    );
    for (let call = 1; call < REWRITE_CALLS; call++) {
      const progress = parse(rewrite?.text);
      if (progress?.done !== false) break;
      if (typeof progress.rewriteToken !== "string" || progress.rewriteToken === "") {
        skip(`rewrite-${call}`, "no rewrite token");
        break;
      }
      rewrite = await exchange(
        `rewrite-${call}`,
        requestOf(copy["rewrite-1"], origins, { query: { rewriteToken: progress.rewriteToken } }),
      );
    }

    // create_token and delete_token of one Firebase upload: the token to delete is the one the
    // create added.
    const token = steps.tokens;
    const upload = await exchange("token-upload", requestOf(token.upload, origins));
    const before = tokensOf(parse(upload?.text));
    const created = await exchange(
      "token-create",
      requestOf(token["create-token"], origins, {
        query: token["create-token"].query,
      }),
    );
    const added = tokensOf(parse(created?.text)).filter((value) => !before.includes(value));
    if (added.length === 1)
      await exchange(
        "token-delete",
        requestOf(token["delete-token"], origins, { query: { delete_token: added[0] } }),
      );
    else skip("token-delete", "no single new token");

    // GCS lists of the prefix while it holds objects: pages of two, then one with a delimiter.
    const listUrl = (query) => {
      const url = new URL(`/storage/v1/b/${plan.bucket}/o`, origins.storage);
      for (const [key, value] of Object.entries({ prefix: plan.scope, ...query }))
        url.searchParams.set(key, value);
      return url.href;
    };
    const listRequest = (query) => ({
      href: listUrl(query),
      init: { method: "GET", headers: { authorization: OWNER } },
    });
    let pageToken;
    for (let page = 1; page <= LIST_PAGES; page++) {
      const result = await exchange(
        `list-page-${page}`,
        listRequest({ maxResults: "2", ...(pageToken ? { pageToken } : {}) }),
      );
      pageToken = parse(result?.text)?.nextPageToken;
      if (typeof pageToken !== "string" || pageToken === "") break;
    }
    await exchange("list-delimiter", listRequest({ delimiter: "/" }));
  } catch (error) {
    // The recording ends here; the objects are still removed.
    interrupted = { step: error.probeStep ?? null, reason: firstLine(error) };
  }

  // Cleanup: every fixed name, found by a metadata read and removed, whatever the recording said.
  await cleanUpAndList({ exchange, answers, plan, origins });
  return { answers, interrupted };
}

/** The list row the closing row is decided on: the last one of the run. */
export const probe3ClosingRow = finalListRow;
