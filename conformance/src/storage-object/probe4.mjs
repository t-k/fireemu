// The STORAGE-OBJECT probe-v4: records how production answers the writes that recording 1 sends and
// expects to be refused or to behave in one particular way, where a different answer would leave an
// object the recipe cannot prove it owns (and so end recording 1 in needs-recovery). Three shapes:
//
// (a) the "not match" preconditions: `ifGenerationNotMatch` and `ifMetagenerationNotMatch`, set to the
//     object's current generation or metageneration, on a create (POST), PATCH, PUT and DELETE.
//     Production may answer 412, 304 or something else, or accept the write;
// (b) an accepted GCS object PUT (update): the answer to a PUT whose preconditions hold, and to one
//     whose "not match" guard holds because the value is stale;
// (c) a Firebase resumable chunk at a wrong offset: whether the session ends, and what a later cancel
//     answers (the recipe's own sequence: start, query, wrong-offset chunk, query, cancel, query).
//
// Two small objects are named by the plan under one fresh prefix: the target of (a) and (b), and the
// object of the Firebase session. Every GCS create carries `ifGenerationMatch=0` except the refusal
// tests of (a), which are sent to the target on purpose. Nothing that is cleaned up depends on an
// answer of the recording: the names are fixed by the plan (see probe-common.mjs), so a refused write
// that was in fact accepted still leaves an object that cleanup finds and removes. Nothing is judged;
// only the last list of the prefix decides the closing row.

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
 * The plan of one probe-v4 run: the corpus steps for this probe's prefix, and the two object names,
 * which are the same whatever any answer says.
 */
export function buildProbe4Plan({ projectId, bucket, runId, otherRunId }) {
  const plan = buildStage3DraftPlan({ projectId, bucket, runIds: [runId, otherRunId] });
  const prefix = plan.recordings[0].prefix;
  const scope = `${prefix}probe4/`;
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
  const generation = "storage-object/gcs/generation-preconditions";
  const metageneration = "storage-object/gcs/metageneration-preconditions";
  const firebase = "storage-object/firebase/resumable-upload";
  const names = {
    target: `${scope}pre/target.bin`,
    firebaseSession: recipe(firebase).objects[1],
  };
  const steps = {
    create: step(generation, "upload-ifGenerationMatch-zero-present"),
    patch: step(metageneration, "patch-ifMetagenerationMatch-stale"),
    put: step(metageneration, "put-ifMetagenerationMatch-stale"),
    initiate: step(firebase, "initiate-wrong"),
    query: step(firebase, "query-wrong-initial"),
    wrongOffset: step(firebase, "wrong-offset"),
    queryAfter: step(firebase, "query-wrong-after"),
    cancel: step(firebase, "cancel-wrong-active"),
    queryAfterCancel: step(firebase, "query-after-cancel-wrong"),
  };
  const objects = [names.target, names.firebaseSession];
  return Object.freeze({
    prefix,
    scope,
    bucket,
    names: Object.freeze(names),
    steps,
    objects: Object.freeze(objects),
  });
}

/** The requests that need the target's generation and metageneration, in two groups. */
const GUARDED_STEPS = [
  "patch-generation-not-match",
  "patch-metageneration-not-match",
  "put-generation-not-match",
  "put-metageneration-not-match",
  "upload-generation-not-match",
  "upload-metageneration-not-match",
  "put-metageneration-match",
  "put-metageneration-not-match-stale",
];
const DELETE_STEPS = ["delete-generation-not-match", "delete-metageneration-not-match"];

/**
 * Send the probe: record every step, then clean up. A step that cannot be completed (a failed
 * transport, a timeout) ends the recording, and cleanup still runs; a step the wire's route table
 * refuses before sending, or that needs an earlier answer that is not there, is recorded as skipped.
 * A capture failure, an oversize response or a secret in a non-text body halts the wire, and cleanup
 * cannot send either: the run then throws. Resolves with `{ answers, interrupted }`, and throws
 * (with `probeStep` and `answered`) only when cleanup itself cannot be completed.
 */
export async function sendProbe4({ wire, plan, origins }) {
  const { answers, exchange, skip, sessionUrl } = createExchange({ wire, origins });
  const { names, steps, bucket } = plan;
  const gcs = (method, name, query) => gcsObjectRequest({ bucket, origins }, method, name, query);
  const bodyOf = (body) =>
    body.base64 !== undefined ? Buffer.from(body.base64, "base64") : JSON.stringify(body.json);
  const withInit = (request, step) => ({
    href: request.href,
    init: {
      ...request.init,
      headers: { ...step.headers, authorization: OWNER },
      ...(step.body === undefined ? {} : { body: bodyOf(step.body) }),
    },
  });
  const upload = (step, name, query) => {
    const url = new URL(`/upload/storage/v1/b/${bucket}/o`, origins.storage);
    for (const [key, value] of Object.entries({ uploadType: "media", name, ...query }))
      url.searchParams.set(key, value);
    return withInit({ href: url.href, init: { method: "POST" } }, step);
  };
  const patch = (query) => withInit(gcs("PATCH", names.target, query), steps.patch);
  const put = (query) => withInit(gcs("PUT", names.target, query), steps.put);
  const target = (step, query) => upload(step, names.target, query);

  let interrupted = null;
  try {
    // The target, and the generation and metageneration it has.
    await exchange("target-create", target(steps.create, { ifGenerationMatch: "0" }));
    const known = async (id) => {
      const metadata = await exchange(id, gcs("GET", names.target));
      const found = parse(metadata?.text);
      return GENERATION.test(found?.generation ?? "") &&
        GENERATION.test(found?.metageneration ?? "")
        ? { generation: found.generation, metageneration: found.metageneration }
        : null;
    };
    const first = await known("target-metadata");

    // (a) "not match" guards set to the current value, on the writes that could change the target;
    // (b) two PUTs that the guards accept. The deletes come last, on a fresh read.
    if (first === null) for (const id of GUARDED_STEPS) skip(id, "no target metadata");
    else {
      const { generation, metageneration } = first;
      await exchange("patch-generation-not-match", patch({ ifGenerationNotMatch: generation }));
      await exchange(
        "patch-metageneration-not-match",
        patch({ ifGenerationMatch: generation, ifMetagenerationNotMatch: metageneration }),
      );
      await exchange("put-generation-not-match", put({ ifGenerationNotMatch: generation }));
      await exchange(
        "put-metageneration-not-match",
        put({ ifGenerationMatch: generation, ifMetagenerationNotMatch: metageneration }),
      );
      await exchange(
        "upload-generation-not-match",
        target(steps.create, { ifGenerationNotMatch: generation }),
      );
      await exchange(
        "upload-metageneration-not-match",
        target(steps.create, { ifMetagenerationNotMatch: metageneration }),
      );
      // Accepted updates: the preconditions hold; then the metageneration the guard names is stale.
      await exchange(
        "put-metageneration-match",
        put({ ifGenerationMatch: generation, ifMetagenerationMatch: metageneration }),
      );
      await exchange(
        "put-metageneration-not-match-stale",
        put({ ifGenerationMatch: generation, ifMetagenerationNotMatch: metageneration }),
      );
    }
    const second = await known("target-metadata-again");
    if (second === null) for (const id of DELETE_STEPS) skip(id, "no target metadata");
    else {
      await exchange(
        "delete-generation-not-match",
        gcs("DELETE", names.target, { ifGenerationNotMatch: second.generation }),
      );
      await exchange(
        "delete-metageneration-not-match",
        gcs("DELETE", names.target, { ifMetagenerationNotMatch: second.metageneration }),
      );
    }

    // (c) A Firebase resumable session, the recipe's own sequence: start, query, a chunk at the wrong
    // offset, query, cancel, query.
    const start = await exchange("firebase-session-start", requestOf(steps.initiate, origins));
    const url = sessionUrl(start, "x-goog-upload-url");
    for (const [id, key] of [
      ["firebase-session-query", "query"],
      ["firebase-session-wrong-offset", "wrongOffset"],
      ["firebase-session-query-after", "queryAfter"],
      ["firebase-session-cancel", "cancel"],
      ["firebase-session-query-after-cancel", "queryAfterCancel"],
    ]) {
      if (url === null) skip(id, "no session URL");
      else await exchange(id, requestOf(steps[key], origins, { href: url }));
    }
  } catch (error) {
    // The recording ends here; the objects are still removed.
    interrupted = { step: error.probeStep ?? null, reason: firstLine(error) };
  }

  await cleanUpAndList({ exchange, answers, plan, origins });
  return { answers, interrupted };
}

/** The list row the closing row is decided on: the last one of the run. */
export const probe4ClosingRow = finalListRow;
