import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { buildCorpus } from "./corpus.mjs";
import { buildAuthCorpus } from "./auth-corpus.mjs";
import { buildStage3DraftPlan } from "./stage3-plan.mjs";
import { FIXED_PRODUCTION_RULES_SHA256 } from "./auth-plan.mjs";
import { createStage3RequestCounter } from "./request-counter.mjs";
import { createLocalStorageSender, verifyLocalRecipeTerminal } from "./sender.mjs";
import { createLocalWireTransport } from "./local-wire-transport.mjs";
import { loopbackHttpOrigin } from "./wire-serialization.mjs";
import { replayLocalBasic } from "./basic-replay.mjs";
import { replayLocalIndependent } from "./independent-replay.mjs";
import { replayLocalList } from "./list-replay.mjs";
import { replayLocalAdmin } from "./admin-replay.mjs";
import { replayLocalObjectNames } from "./object-name-replay.mjs";
import { replayLocalDownloadTokens } from "./download-token-replay.mjs";
import { replayLocalPreconditions } from "./precondition-replay.mjs";
import { replayLocalCopyRewrite } from "./copy-replay.mjs";
import { replayLocalSessions } from "./session-replay.mjs";
import { replayLocalAuth } from "./auth-replay.mjs";

const groups = [
  [
    replayLocalBasic,
    [
      "firebase/simple-upload",
      "firebase/download",
      "gcs/download",
      "errors/range",
      "firebase/metadata",
      "gcs/metadata",
      "firebase/overwrite",
      "firebase/delete",
      "gcs/delete",
      "cross-dialect/state",
      "errors/missing",
    ],
  ],
  [
    replayLocalIndependent,
    ["firebase/multipart-upload", "gcs/simple-multipart-upload", "gcs/checksums"],
  ],
  [replayLocalList, ["firebase/list", "gcs/list"]],
  [replayLocalAdmin, ["auth/admin"]],
  [replayLocalObjectNames, ["errors/object-name"]],
  [replayLocalDownloadTokens, ["firebase/download-tokens"]],
  [replayLocalPreconditions, ["gcs/generation-preconditions", "gcs/metageneration-preconditions"]],
  [replayLocalCopyRewrite, ["gcs/copy-rewrite"]],
  [replayLocalSessions, ["firebase/resumable-upload", "gcs/resumable-upload"]],
  [replayLocalAuth, ["errors/authorization", "auth/firebase-id-token"]],
];
const adapters = new Map(
  groups.flatMap(([replay, ids]) => ids.map((id) => [`storage-object/${id}`, replay])),
);

function freeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function fixedPlan(input) {
  const plan = structuredClone(input);
  const expected = buildStage3DraftPlan({
    projectId: plan?.projectId,
    bucket: plan?.bucket,
    runIds: plan?.recordings?.map((row) => row.runId),
  });
  if (!isDeepStrictEqual(plan, expected))
    throw new Error("local aggregate plan differs from its canonical pins");
  return freeze(plan);
}

function registry(plan, recording) {
  if (!Number.isInteger(recording) || recording < 0 || recording > 1)
    throw new Error("invalid aggregate recording");
  const { prefix, runId } = plan.recordings[recording];
  const recipes = [
    ...buildCorpus({ bucket: plan.bucket, prefix }).recipes,
    ...buildAuthCorpus({ projectId: plan.projectId, bucket: plan.bucket, runId }).recipes,
  ];
  if (
    adapters.size !== 26 ||
    recipes.length !== 26 ||
    new Set(recipes.map((row) => row.id)).size !== 26 ||
    recipes.some((row) => !adapters.has(row.id))
  )
    throw new Error("canonical aggregate recipe registry differs");
  return recipes.map((recipe) =>
    Object.freeze({ recipe: freeze(recipe), replay: adapters.get(recipe.id) }),
  );
}

/** Enumerate the fixed local registry without sending or acquiring credentials. */
export function localAggregateRecipeIds(plan, recording) {
  return Object.freeze(registry(fixedPlan(plan), recording).map((row) => row.recipe.id));
}

/** Require successful execution and complete cleanup before checking private terminal evidence. */
export function isLocalAggregateResultComplete(result, recipeId, sequence) {
  return Boolean(
    result &&
    result.status === "LOCAL_COMPLETE" &&
    result.recipeId === recipeId &&
    Array.isArray(result.cleanupFailures) &&
    result.cleanupFailures.length === 0 &&
    Array.isArray(result.unresolved) &&
    result.unresolved.length === 0 &&
    Number.isSafeInteger(sequence) &&
    sequence >= 0 &&
    result.requests === sequence,
  );
}

/** Execute the trusted local registry through one counter and one shared wire provider. */
export async function replayLocalAggregate(options) {
  const keys = new Set([
    "plan",
    "storageOrigin",
    "authOrigin",
    "localAuth",
    "localControl",
    "credentials",
    "captureDirectory",
    "onStart",
    "onReserve",
    "onJournal",
    "onRecipeBegin",
    "onRecipeFinish",
    "onCapture",
    "onByteReserve",
    "wireFactory",
    "recordings",
  ]);
  if (
    !options ||
    Object.getPrototypeOf(options) !== Object.prototype ||
    Reflect.ownKeys(options).some(
      (key) =>
        !keys.has(key) || !Object.hasOwn(Object.getOwnPropertyDescriptor(options, key), "value"),
    )
  )
    throw new Error("invalid local aggregate options");
  const {
    localAuth,
    localControl,
    credentials,
    captureDirectory,
    onStart,
    onReserve,
    onJournal,
    onRecipeBegin,
    onRecipeFinish,
    onCapture,
    onByteReserve,
    wireFactory = createLocalWireTransport,
    recordings: recordingCount = 2,
  } = options;
  // One recording per run is how a production run is split: each run is admitted on its own.
  if (recordingCount !== 1 && recordingCount !== 2) throw new Error("invalid aggregate recordings");
  if (
    [
      onStart,
      onReserve,
      onJournal,
      onRecipeBegin,
      onRecipeFinish,
      onCapture,
      onByteReserve,
      wireFactory,
    ].some((callback) => typeof callback !== "function")
  )
    throw new Error("all durable aggregate writers are required");
  const plan = fixedPlan(options.plan),
    registries = [registry(plan, 0), registry(plan, 1)];
  const origins = [options.storageOrigin, options.authOrigin, localControl?.origin].map((value) => {
    const origin = loopbackHttpOrigin(value);
    if (!origin.startsWith("http:"))
      throw new Error("local aggregate requires loopback HTTP origins");
    return origin;
  });
  if (
    typeof localControl?.token !== "string" ||
    !/^[^\s]+$/.test(localControl.token) ||
    localAuth?.apiKey !== "storage-object-local-key" ||
    typeof localAuth.password !== "string" ||
    localAuth.password.length < 16 ||
    typeof credentials?.admin !== "string" ||
    !/^Bearer [^\s]+$/.test(credentials.admin)
  )
    throw new Error("explicit synthetic local credentials are required");
  const wire = wireFactory({ origins, limits: plan, captureDirectory, onByteReserve });
  if (
    !wire ||
    [wire.fetch, wire.snapshot, wire.close].some((method) => typeof method !== "function")
  )
    throw new Error("invalid local aggregate wire provider");
  let current = null,
    status = "LOCAL_BLOCKED",
    unresolved = [],
    cleanupFailures = [];
  const results = [];
  const wireReady = () => {
    const state = wire.snapshot();
    return (
      state.active === false &&
      state.busy === false &&
      state.halted === false &&
      state.closed === false &&
      state.readAfterHaltBytes === 0
    );
  };
  const guardedFetch = (href, init) => {
    if (!wireReady()) throw new Error("LOCAL_AGGREGATE_WIRE_UNAVAILABLE");
    return wire.fetch(href, init);
  };
  const counter = createStage3RequestCounter(plan, {
    onStart,
    onReserve,
    recipeLifecycle: {
      recipeIds: registries[0].map((row) => row.recipe.id),
      onBegin: onRecipeBegin,
      onFinish: (row) => onRecipeFinish(Object.freeze({ ...row, result: current.result })),
      verifyTerminal: (proof) =>
        Boolean(
          current &&
          current.token === proof.recipeToken &&
          isLocalAggregateResultComplete(
            current.result,
            proof.recipeId,
            counter.snapshot().total,
          ) &&
          wireReady() &&
          wire.snapshot().attempts === counter.snapshot().total &&
          verifyLocalRecipeTerminal(current.sender, proof),
        ),
    },
  });
  async function fixedRules(recording, phase) {
    const operationId = `${phase}-fixed-rules-r${recording + 1}`;
    const response = await counter.send(operationId, () =>
      guardedFetch(new URL("/v1/storage/rules", origins[2]).href, {
        method: "GET",
        headers: { authorization: `Bearer ${localControl.token}` },
        operationId,
        accountingPhase: counter.snapshot().mode,
        redirect: "manual",
        signal: AbortSignal.timeout(30_000),
      }),
    );
    const body = JSON.parse(Buffer.from(await response.arrayBuffer()).toString("utf8"));
    if (
      response.status !== 200 ||
      body?.loaded !== true ||
      body.targeted !== false ||
      typeof body.source !== "string" ||
      createHash("sha256").update(body.source).digest("hex") !== FIXED_PRODUCTION_RULES_SHA256
    )
      throw new Error("LOCAL_FIXED_RULES_DIFFERED");
    await onJournal(
      Object.freeze({
        type: "aggregate-fixed-rules",
        recording: recording + 1,
        phase,
        sequence: counter.snapshot().total,
        rulesSourceSha256: FIXED_PRODUCTION_RULES_SHA256,
      }),
    );
  }
  try {
    await counter.start();
    for (let recording = 0; recording < recordingCount; recording++) {
      current = null;
      await fixedRules(recording, "initial");
      for (const { recipe, replay } of registries[recording]) {
        if (!wireReady()) throw new Error("LOCAL_AGGREGATE_WIRE_UNAVAILABLE");
        const firstSequence = counter.snapshot().total + 1;
        const token = await counter.beginRecipe(recipe.id);
        current = { token, recipeId: recipe.id, sender: null, result: null };
        current.sender = createLocalStorageSender({
          plan,
          recipeToken: token,
          origin: origins[0],
          authOrigin: origins[1],
          localAuth,
          localControl: { ...localControl, origin: origins[2] },
          credentials,
          fetchImpl: guardedFetch,
          onJournal,
        });
        current.result = freeze(
          await replay({
            sender: current.sender,
            recipe,
            bucket: plan.bucket,
            prefix: plan.recordings[recording].prefix,
            onCapture,
            allowKnownLocalListGaps: true,
          }),
        );
        await onJournal(
          Object.freeze({
            type: "aggregate-recipe-result",
            recording: recording + 1,
            recipeId: recipe.id,
            result: current.result,
          }),
        );
        await counter.finishRecipe(token);
        results.push(
          Object.freeze({
            ...current.result,
            recording: recording + 1,
            prefix: plan.recordings[recording].prefix,
            firstSequence,
            lastSequence: counter.snapshot().total,
            cumulativeRequests: current.result.requests,
            requests: counter.snapshot().total - firstSequence + 1,
          }),
        );
      }
      current = null;
      await fixedRules(recording, "final");
      if (recording === 0 && recordingCount === 2) counter.nextRecording();
    }
    if (!wireReady() || wire.snapshot().attempts !== counter.snapshot().total)
      throw new Error("LOCAL_AGGREGATE_WIRE_EVIDENCE_INCOMPLETE");
    if (recordingCount === 2) counter.close();
    else if (counter.snapshot().completedRecipes[0] !== registries[0].length)
      throw new Error("LOCAL_AGGREGATE_RECORDING_INCOMPLETE");
    status = "LOCAL_COMPLETE";
  } catch {
    cleanupFailures = [...(current?.result?.cleanupFailures ?? [])];
    const sender = current?.sender;
    if (sender) {
      try {
        if (sender.snapshot().mode === "subject") sender.beginCleanup();
        if (sender.snapshot().mode === "cleanup" && wireReady()) {
          const cleanup = await sender.cleanupConfirmedOwned({ canSend: wireReady });
          cleanupFailures.push(...cleanup.cleanupFailures);
          if (cleanup.unresolved.length === 0 && cleanupFailures.length === 0) {
            await sender.verifyRunEmpty();
            sender.close();
          }
        }
      } catch {
        cleanupFailures.push({ reason: "LOCAL_AGGREGATE_EXCEPTION_CLEANUP_FAILED" });
      }
      unresolved = sender.unresolved();
    }
    status =
      unresolved.length > 0 || cleanupFailures.length > 0 || wire.snapshot().halted
        ? "LOCAL_NEEDS_RECOVERY"
        : "LOCAL_BLOCKED";
    await onJournal(
      Object.freeze({
        type: "aggregate-stop",
        status,
        failedRecipeId: current?.recipeId ?? null,
        completedRecipes: counter.snapshot().completedRecipes,
        unresolved,
        cleanupFailures,
      }),
    );
  } finally {
    await wire.close();
  }
  return {
    status,
    productionParityProved: false,
    responseCompatibilityProved: false,
    failedRecipeId: status === "LOCAL_COMPLETE" ? null : (current?.recipeId ?? null),
    results,
    unresolved,
    cleanupFailures,
    counter: counter.snapshot(),
    wire: wire.snapshot(),
  };
}
