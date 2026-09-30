// The STORAGE-OBJECT probe-v4: records how production answers the requests a recipe expects to be
// refused, whose answers were never recorded. If production accepted one of them (an object would
// change) the recipe could not prove what it owns and recording 1 would end in needs-recovery, so
// their answers are recorded first: mismatched generation and metageneration preconditions on
// upload, PATCH, PUT and DELETE (GCS, and on the Firebase v0 routes), malformed preconditions,
// copyTo and rewriteTo of a missing source and onto a live destination under
// `ifGenerationMatch=0`, a chunk at a wrong offset and a request to an invalid session (GCS and
// Firebase), the GCS list filters `startOffset` and `matchGlob`, and Firebase list paging.
//
// Three small objects are created under one fresh prefix, every GCS create carrying
// `ifGenerationMatch=0`, and removed again. Nothing that is cleaned up depends on an answer of the
// recording: the names are fixed by the plan (see probe-common.mjs), so a refused write that was in
// fact accepted still leaves objects that cleanup finds and removes. Nothing is judged; only the
// last list of the prefix decides the closing row.
//
// Not recorded, because it does not fit the request budget: a rewrite in several calls. It needs a
// source of at least a few MiB (`maxBytesRewrittenPerCall` is at least 1 MiB), two more objects and
// about a dozen more requests.

import { buildCorpus } from "./corpus.mjs";
import {
  cleanUpAndList,
  createExchange,
  finalListRow,
  firstLine,
  GENERATION,
  gcsObjectRequest,
  OWNER,
  parse,
  requestOf,
} from "./probe-common.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";

export const PROBE4_MAX_REQUESTS = 60;
export const PROBE4_RESERVE_USD = 0.05;
export const PROBE4_ESTIMATE_USD = 0.02;

/**
 * The plan of one probe-v4 run: the corpus steps for this probe's prefix, and the three object
 * names, which are the same whatever any answer says.
 */
export function buildProbe4Plan({ projectId, bucket, runId, otherRunId }) {
  const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, otherRunId] });
  const prefix = plan.recordings[0].prefix;
  const scope = `${prefix}probe4/`;
  const corpus = buildCorpus({ bucket, prefix: scope });
  const step = (recipeId, stepId) => {
    const recipe = corpus.recipes.find((row) => row.id === recipeId);
    const found = recipe?.steps.find((row) => row.id === stepId);
    if (!found) throw new Error(`the corpus has no step ${stepId} in ${recipeId}`);
    return found;
  };
  const generation = "storage-object/gcs/generation-preconditions";
  const metageneration = "storage-object/gcs/metageneration-preconditions";
  const copy = corpus.recipes.find((row) => row.id === "storage-object/gcs/copy-rewrite");
  const gcsSession = corpus.recipes.find((row) => row.id === "storage-object/gcs/resumable-upload");
  const firebaseSession = corpus.recipes.find(
    (row) => row.id === "storage-object/firebase/resumable-upload",
  );
  const names = {
    target: `${scope}pre/target.bin`,
    source: copy.objects[0],
    live: `${scope}copy/refused-copy.bin`,
    missingSource: `${scope}copy/missing-source.bin`,
    missingDestination: `${scope}copy/missing-destination.bin`,
    rewriteMissingSource: `${scope}copy/rewrite-missing-source.bin`,
    rewriteMissingDestination: `${scope}copy/rewrite-missing-destination.bin`,
    gcsSession: gcsSession.objects[0],
    firebaseSession: firebaseSession.objects[0],
  };
  const steps = {
    create: step(generation, "upload-ifGenerationMatch-zero-present"),
    patch: step(metageneration, "patch-ifMetagenerationMatch-stale"),
    put: step(metageneration, "put-ifMetagenerationMatch-stale"),
    remove: step(generation, "delete-ifGenerationMatch-stale"),
    copyMissing: step("storage-object/gcs/copy-rewrite", "copy-missing-source"),
    rewriteMissing: step("storage-object/gcs/copy-rewrite", "rewrite-missing-source"),
    gcsInitiate: step(gcsSession.id, "initiate"),
    firebaseInitiate: step(firebaseSession.id, "initiate"),
    firebaseWrongOffset: step(firebaseSession.id, "wrong-offset"),
  };
  const objects = [names.target, names.source, names.live];
  return Object.freeze({
    prefix,
    scope,
    bucket,
    names: Object.freeze(names),
    steps,
    objects: Object.freeze(objects),
  });
}

/**
 * Send the probe: record every step, then clean up. Failure handling is that of probe-v3: a step
 * that cannot be completed ends the recording and cleanup still runs; a step the route table
 * refuses before sending, or that needs an earlier answer that is not there, is recorded as
 * skipped. Resolves with `{ answers, interrupted }`, and throws only when cleanup cannot finish.
 */
export async function sendProbe4({ wire, plan, origins }) {
  const { answers, exchange, skip, sessionUrl } = createExchange({ wire, origins });
  const { names, steps, bucket, scope } = plan;
  const gcs = (method, name, query) => gcsObjectRequest({ bucket, origins }, method, name, query);
  const withInit = (request, step) => ({
    href: request.href,
    init: {
      ...request.init,
      headers: { ...step.headers, authorization: OWNER },
      ...(step.body === undefined ? {} : { body: bodyOf(step.body) }),
    },
  });
  const bodyOf = (body) =>
    body.base64 !== undefined ? Buffer.from(body.base64, "base64") : JSON.stringify(body.json);
  const upload = (step, name, query) => {
    const url = new URL(`/upload/storage/v1/b/${bucket}/o`, origins.storage);
    for (const [key, value] of Object.entries({ uploadType: "media", name, ...query }))
      url.searchParams.set(key, value);
    return withInit({ href: url.href, init: { method: "POST" } }, step);
  };
  const transfer = (verb, from, to, query) => {
    const url = new URL(
      `/storage/v1/b/${bucket}/o/${encodeURIComponent(from)}/${verb}/b/${bucket}/o/${encodeURIComponent(to)}`,
      origins.storage,
    );
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    return url.href;
  };
  const listUrl = (path, query) => {
    const url = new URL(path, origins.storage);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    return { href: url.href, init: { method: "GET", headers: { authorization: OWNER } } };
  };

  let interrupted = null;
  try {
    // The target of the precondition refusals, and the generation and metageneration it has.
    await exchange("target-create", upload(steps.create, names.target, { ifGenerationMatch: "0" }));
    const metadata = await exchange("target-metadata", gcs("GET", names.target));
    const found = parse(metadata?.text);
    const known =
      GENERATION.test(found?.generation ?? "") && GENERATION.test(found?.metageneration ?? "");
    const refusals = [
      "upload-zero-present",
      "upload-generation-stale",
      "patch-generation-stale",
      "patch-metageneration-stale",
      "patch-metageneration-empty",
      "patch-metageneration-text",
      "put-metageneration-stale",
      "firebase-patch-generation-stale",
      "firebase-upload-zero-present",
      "delete-generation-stale",
      "delete-generation-not-match-current",
    ];
    if (!known) for (const id of refusals) skip(id, "no target metadata");
    else {
      const current = found.generation;
      const later = (value) => (BigInt(value) + 1n).toString();
      const staleGeneration = later(current);
      const staleMetageneration = later(found.metageneration);
      const patch = (query) => withInit(gcs("PATCH", names.target, query), steps.patch);
      const put = (query) => withInit(gcs("PUT", names.target, query), steps.put);
      const v0Path = (query) => {
        const url = new URL(
          `/v0/b/${bucket}/o/${encodeURIComponent(names.target)}`,
          origins.storage,
        );
        for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
        return url.href;
      };
      // Writes that must be refused, on the target; the deletes come last.
      await exchange(
        "upload-zero-present",
        upload(steps.create, names.target, { ifGenerationMatch: "0" }),
      );
      await exchange(
        "upload-generation-stale",
        upload(steps.create, names.target, { ifGenerationMatch: staleGeneration }),
      );
      await exchange("patch-generation-stale", patch({ ifGenerationMatch: staleGeneration }));
      await exchange(
        "patch-metageneration-stale",
        patch({ ifGenerationMatch: current, ifMetagenerationMatch: staleMetageneration }),
      );
      await exchange(
        "patch-metageneration-empty",
        patch({ ifGenerationMatch: current, ifMetagenerationMatch: "" }),
      );
      await exchange(
        "patch-metageneration-text",
        patch({ ifGenerationMatch: current, ifMetagenerationMatch: "abc" }),
      );
      await exchange(
        "put-metageneration-stale",
        put({ ifGenerationMatch: current, ifMetagenerationMatch: staleMetageneration }),
      );
      // The Firebase v0 routes, with the same preconditions (whether v0 takes them is the question).
      await exchange("firebase-patch-generation-stale", {
        href: v0Path({ ifGenerationMatch: staleGeneration }),
        init: {
          method: "PATCH",
          headers: { ...steps.patch.headers, authorization: OWNER },
          body: bodyOf(steps.patch.body),
        },
      });
      await exchange(
        "delete-generation-stale",
        gcs("DELETE", names.target, { ifGenerationMatch: staleGeneration }),
      );
      await exchange(
        "delete-generation-not-match-current",
        gcs("DELETE", names.target, { ifGenerationNotMatch: current }),
      );
      // Last, because an accepted upload replaces the target and would make the generations above stale.
      const v0Upload = new URL(`/v0/b/${bucket}/o`, origins.storage);
      v0Upload.searchParams.set("name", names.target);
      v0Upload.searchParams.set("ifGenerationMatch", "0");
      await exchange("firebase-upload-zero-present", {
        href: v0Upload.href,
        init: {
          method: "POST",
          headers: { "content-type": "application/octet-stream", authorization: OWNER },
          body: bodyOf(steps.create.body),
        },
      });
    }

    // copyTo and rewriteTo: a source that is not there, and a destination that is.
    await exchange(
      "copy-source-create",
      upload(steps.create, names.source, { ifGenerationMatch: "0" }),
    );
    await exchange(
      "copy-live-create",
      upload(steps.create, names.live, { ifGenerationMatch: "0" }),
    );
    const copyRequest = (step, from, to, verb, query) => ({
      href: transfer(verb, from, to, query),
      init: {
        method: "POST",
        headers: { ...step.headers, authorization: OWNER },
        body: bodyOf(step.body),
      },
    });
    await exchange(
      "copy-missing-source",
      copyRequest(steps.copyMissing, names.missingSource, names.missingDestination, "copyTo", {
        ifGenerationMatch: "0",
      }),
    );
    await exchange(
      "rewrite-missing-source",
      copyRequest(
        steps.rewriteMissing,
        names.rewriteMissingSource,
        names.rewriteMissingDestination,
        "rewriteTo",
        { ifGenerationMatch: "0" },
      ),
    );
    await exchange(
      "copy-live-destination",
      copyRequest(steps.copyMissing, names.source, names.live, "copyTo", {
        ifGenerationMatch: "0",
      }),
    );
    await exchange(
      "rewrite-live-destination",
      copyRequest(steps.rewriteMissing, names.source, names.live, "rewriteTo", {
        ifGenerationMatch: "0",
      }),
    );

    // A GCS resumable session: a chunk at the wrong offset, a cancel, and an invalid session.
    const gcsStart = await exchange(
      "gcs-session-start",
      requestOf(steps.gcsInitiate, origins, {
        query: { ...steps.gcsInitiate.query, name: names.gcsSession },
      }),
    );
    const gcsUrl = sessionUrl(gcsStart, "location");
    if (gcsUrl === null) {
      for (const id of ["gcs-session-wrong-offset", "gcs-session-cancel", "gcs-session-invalid"])
        skip(id, "no session URL");
    } else {
      const wrong = Buffer.alloc(262044, 0x5a);
      await exchange("gcs-session-wrong-offset", {
        href: gcsUrl,
        init: {
          method: "PUT",
          headers: {
            "content-length": String(wrong.length),
            "content-range": "bytes 100-262143/262147",
            authorization: OWNER,
          },
          body: wrong,
        },
      });
      await exchange("gcs-session-cancel", {
        href: gcsUrl,
        init: { method: "DELETE", headers: { authorization: OWNER } },
      });
      const invalid = new URL(gcsUrl);
      invalid.searchParams.set("upload_id", "invalid-session-id");
      await exchange("gcs-session-invalid", {
        href: invalid.href,
        init: {
          method: "PUT",
          headers: {
            "content-length": "0",
            "content-range": "bytes */262147",
            authorization: OWNER,
          },
        },
      });
    }

    // A Firebase resumable session: a chunk at the wrong offset, and a cancel.
    const firebaseStart = await exchange(
      "firebase-session-start",
      requestOf(steps.firebaseInitiate, origins, {
        query: { name: names.firebaseSession },
      }),
    );
    const firebaseUrl = sessionUrl(firebaseStart, "x-goog-upload-url");
    if (firebaseUrl === null) {
      for (const id of ["firebase-session-wrong-offset", "firebase-session-cancel"])
        skip(id, "no session URL");
    } else {
      await exchange(
        "firebase-session-wrong-offset",
        requestOf(steps.firebaseWrongOffset, origins, { href: firebaseUrl }),
      );
      await exchange("firebase-session-cancel", {
        href: firebaseUrl,
        init: {
          method: "POST",
          headers: { "x-goog-upload-command": "cancel", authorization: OWNER },
        },
      });
    }

    // Lists of the prefix while it holds objects: the GCS filters, and Firebase paging.
    const gcsList = `/storage/v1/b/${bucket}/o`;
    await exchange(
      "list-start-offset",
      listUrl(gcsList, {
        prefix: scope,
        startOffset: `${scope}copy/`,
        endOffset: `${scope}pre/`,
      }),
    );
    await exchange(
      "list-match-glob",
      listUrl(gcsList, { prefix: scope, matchGlob: `${scope}copy/*` }),
    );
    const firebaseList = `/v0/b/${bucket}/o`;
    const page = await exchange(
      "firebase-list-page-1",
      listUrl(firebaseList, { prefix: scope, maxResults: "1" }),
    );
    const token = parse(page?.text)?.nextPageToken;
    if (typeof token === "string" && token !== "")
      await exchange(
        "firebase-list-page-2",
        listUrl(firebaseList, { prefix: scope, maxResults: "1", pageToken: token }),
      );
    else skip("firebase-list-page-2", "no next page token");
  } catch (error) {
    // The recording ends here; the objects are still removed.
    interrupted = { step: error.probeStep ?? null, reason: firstLine(error) };
  }

  await cleanUpAndList({ exchange, answers, plan, origins });
  return { answers, interrupted };
}

/** The list row the closing row is decided on: the last one of the run. */
export const probe4ClosingRow = finalListRow;
