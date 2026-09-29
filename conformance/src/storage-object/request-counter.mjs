import { copyProductionCaptureRecord } from "./production-capture-input.mjs";
import { copyCanonicalProductionStage3Plan } from "./production-context.mjs";
import { estimateStage3Budget } from "./budget-model.mjs";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { buildProductionStage3DraftPlan } from "./stage3-plan.mjs";

import { productionArtifactProfileUsesPlan } from "./production-artifact-policy.mjs";

const taskCounterBindings = new WeakMap();
/** Private counts remain available for fixed failure diagnostics after registry failure; this grants no admission authority. */
export function originalProductionStage3CounterSnapshot(counter, profile) {
  const binding = taskCounterBindings.get(counter);
  if (
    !binding?.production ||
    binding.artifactProfile === undefined ||
    binding.artifactProfile !== profile
  )
    return null;
  return binding.read();
}
/** Static original task identity is not terminal, source trust or admission authority. */
export function productionStage3CounterUsesArtifactContext(counter, supplied) {
  try {
    const binding = taskCounterBindings.get(counter);
    const input = copyProductionCaptureRecord(supplied, ["profile", "plan"]);
    if (
      Object.keys(input).length !== 2 ||
      !binding?.production ||
      binding.artifactProfile === undefined ||
      binding.artifactProfile !== input.profile ||
      !productionArtifactProfileUsesPlan(
        input.profile,
        copyCanonicalProductionStage3Plan(input.plan),
      ) ||
      Object.getPrototypeOf(counter) !== Object.prototype
    )
      return false;
    const names = Reflect.ownKeys(counter);
    return (
      names.length === Object.keys(binding.methods).length &&
      Object.entries(binding.methods).every(([name, method]) => {
        const d = Object.getOwnPropertyDescriptor(counter, name);
        return d?.enumerable && Object.hasOwn(d, "value") && d.value === method;
      })
    );
  } catch {
    return false;
  }
}

const recipeContextClaims = new WeakMap();

/** Claim one sender context from an actual active recipe capability. */
export function claimStage3RecipeContext(token, plan) {
  const claim = recipeContextClaims.get(token);
  if (!claim) throw new Error("invalid recipe capability");
  return claim(plan);
}

/** Count every outbound attempt before dispatch, with protected cleanup and recovery capacity. */
export function createStage3RequestCounter(
  plan,
  { onStart, onReserve, recipeLifecycle, artifactProfile } = {},
) {
  if (typeof onStart !== "function" || typeof onReserve !== "function")
    throw new Error("durable started and request-reservation writers are required");
  plan = structuredClone(plan);
  const production = plan?.status === "PRODUCTION_DRAFT_NO_SEND";
  if (
    artifactProfile !== undefined &&
    (!production || !productionArtifactProfileUsesPlan(artifactProfile, plan))
  )
    throw new Error("invalid production counter artifact profile");
  const productionStartsAttempted = new Set();
  let productionAdmissionFailed = false;
  let lifecycle = null;
  if (recipeLifecycle !== undefined) {
    const keys = ["recipeIds", "onBegin", "onFinish", "verifyTerminal"];
    if (
      !recipeLifecycle ||
      Object.getPrototypeOf(recipeLifecycle) !== Object.prototype ||
      Reflect.ownKeys(recipeLifecycle).length !== keys.length ||
      keys.some((key) => {
        const descriptor = Object.getOwnPropertyDescriptor(recipeLifecycle, key);
        return !descriptor?.enumerable || !Object.hasOwn(descriptor, "value");
      })
    )
      throw new Error("invalid recipe lifecycle");
    const { recipeIds, onBegin, onFinish, verifyTerminal } = recipeLifecycle;
    if (
      !Array.isArray(recipeIds) ||
      Object.getPrototypeOf(recipeIds) !== Array.prototype ||
      recipeIds.length < 1 ||
      recipeIds.length > 64 ||
      Reflect.ownKeys(recipeIds).length !== recipeIds.length + 1 ||
      Array.from({ length: recipeIds.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(recipeIds, String(index));
        return (
          !descriptor?.enumerable ||
          !Object.hasOwn(descriptor, "value") ||
          typeof descriptor.value !== "string" ||
          !/^storage-object\/[a-z0-9-]+(?:\/[a-z0-9-]+)*$/.test(descriptor.value)
        );
      }).some(Boolean) ||
      new Set(recipeIds).size !== recipeIds.length ||
      plan.recordings?.some((item) => item.declaredRecipeCount !== recipeIds.length) ||
      [onBegin, onFinish, verifyTerminal].some((callback) => typeof callback !== "function")
    )
      throw new Error("invalid recipe lifecycle");
    lifecycle = { recipeIds: [...recipeIds], onBegin, onFinish, verifyTerminal };
  }
  let mode = "not-started";
  let recording = 0;
  let busy = false;
  let total = 0;
  let recovery = 0;
  let activeRecipe = null;
  const completedRecipes = [0, 0];
  const recordings = [
    { subject: 0, cleanup: 0 },
    { subject: 0, cleanup: 0 },
  ];

  function checkEnvelope() {
    if ((!production && plan?.status !== "LOCAL_DRAFT_NO_SEND") || plan.recordings?.length !== 2)
      throw new Error("invalid two-recording plan");
    if (
      production &&
      !isDeepStrictEqual(
        plan,
        buildProductionStage3DraftPlan({
          projectId: plan.projectId,
          bucket: plan.bucket,
          runIds: plan.recordings.map((row) => row.runId),
        }),
      )
    )
      throw new Error("production plan differs from its canonical pins");
    estimateStage3Budget(plan);
    const reserved =
      plan.recordings.reduce((sum, item) => sum + item.maxRequests, 0) +
      plan.recoveryReserveRequests;
    if (plan.maxRequests !== reserved)
      throw new Error("total cap cannot carry two recordings and recovery reserve");
    for (const item of plan.recordings) {
      if (
        item.subjectCapRequests !== item.maxRequests - item.cleanupReserveRequests ||
        item.staticSubjectEntries > item.subjectCapRequests ||
        item.staticCleanupEntries > item.cleanupReserveRequests
      )
        throw new Error("one recording cannot carry its subjects and cleanup reserve");
    }
  }

  function currentLimit() {
    if (mode === "recovery") return plan.recoveryReserveRequests;
    const item = plan.recordings[recording];
    return mode === "subject" ? item.subjectCapRequests : item.cleanupReserveRequests;
  }

  function startedEvent(index) {
    return {
      maxRequests: production ? plan.recordings[index].maxRequests : plan.maxRequests,
      recordings: production ? 1 : 2,
      estimatedUsd: plan.estimatedUsd,
      maxUsdReservation: plan.maxUsdReservation,
      ...(production
        ? {
            recording: index + 1,
            runId: plan.recordings[index].runId,
            prefix: plan.recordings[index].prefix,
            taskMaxRequests: plan.maxRequests,
            subjectCapRequests: plan.recordings[index].subjectCapRequests,
            cleanupReserveRequests: plan.recordings[index].cleanupReserveRequests,
          }
        : {}),
    };
  }

  function currentCount() {
    if (mode === "recovery") return recovery;
    return recordings[recording][mode];
  }

  function requireRecipeCapability(token) {
    if (!lifecycle) {
      if (token !== undefined) throw new Error("invalid recipe capability");
    } else if (activeRecipe ? activeRecipe.token !== token : token !== undefined) {
      throw new Error("invalid recipe capability");
    }
  }

  function bindRecipeContext(token, index) {
    const boundRecording = recording;
    const recipeId = activeRecipe.recipeId;
    const prefix = plan.recordings[boundRecording].prefix;
    let claimed = false;
    const isActive = () => activeRecipe?.token === token && recording === boundRecording;
    function assertActive() {
      if (!isActive()) throw new Error("invalid or expired recipe capability");
      if (busy) throw new Error("concurrent recipe dispatch is forbidden");
    }
    recipeContextClaims.set(token, (suppliedPlan) => {
      if (!isDeepStrictEqual(plan, suppliedPlan)) throw new Error("recipe context plan differs");
      assertActive();
      if (claimed) throw new Error("recipe capability was already claimed");
      claimed = true;
      let scopedMode = "not-started";
      function dispatchOperationId(operationId) {
        assertActive();
        if (scopedMode === "closed") throw new Error("recipe sender is closed");
        if (scopedMode === "not-started") throw new Error("recipe sender is not started");
        if (mode !== scopedMode) throw new Error("recipe phase differs from the controller");
        if (
          typeof operationId !== "string" ||
          !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(operationId)
        )
          throw new Error("invalid recipe operation dispatch");
        const dispatchId = `r${boundRecording + 1}/p${index + 1}/${createHash("sha256").update(operationId).digest("hex")}`;
        const prior = activeRecipe.operationIds.get(dispatchId);
        if (prior !== undefined && prior !== operationId)
          throw new Error("recipe operation digest collision");
        activeRecipe.operationIds.set(dispatchId, operationId);
        return dispatchId;
      }
      const scopedCounter = Object.freeze({
        async start() {
          assertActive();
          if (scopedMode !== "not-started" || mode !== "subject")
            throw new Error("recipe sender already started or has no durable begin");
          scopedMode = "subject";
        },
        async send(operationId, transport) {
          return counter.send(dispatchOperationId(operationId), transport, token);
        },
        beginCleanup() {
          assertActive();
          if (scopedMode !== "subject") throw new Error("recipe cleanup cannot start now");
          counter.beginCleanup(token);
          scopedMode = "cleanup";
        },
        close() {
          assertActive();
          if (scopedMode !== "cleanup" || mode !== "cleanup")
            throw new Error("recipe sender cannot close now");
          scopedMode = "closed";
        },
        nextRecording() {
          throw new Error("recording transitions belong to the controller");
        },
        enterRecovery() {
          throw new Error("recovery transitions belong to the controller");
        },
        snapshot() {
          const snapshot = counter.snapshot();
          return {
            ...snapshot,
            mode: scopedMode,
            globalMode: snapshot.mode,
            recording: boundRecording + 1,
            recipeId,
          };
        },
      });
      return Object.freeze({
        bucket: plan.bucket,
        prefix,
        recording: boundRecording + 1,
        recipeId,
        counter: scopedCounter,
        dispatchOperationId,
        isActive,
      });
    });
  }

  const taskSnapshot = () => {
    return {
      total,
      recordings: recordings.map((item) => ({ subject: item.subject, cleanup: item.cleanup })),
      recovery,
      mode,
      ...(production ? { recording: recording + 1 } : {}),
      ...(lifecycle
        ? {
            completedRecipes: [...completedRecipes],
            activeRecipeId: activeRecipe?.recipeId ?? null,
          }
        : {}),
    };
  };
  const counter = {
    async start() {
      if (mode !== "not-started" || busy) throw new Error("counter already started");
      checkEnvelope();
      if (production && productionStartsAttempted.has(0))
        throw new Error("production start was already attempted");
      busy = true;
      if (production) productionStartsAttempted.add(0);
      try {
        await onStart(startedEvent(0));
        mode = "subject";
      } catch (error) {
        if (production) productionAdmissionFailed = true;
        throw error;
      } finally {
        busy = false;
      }
    },
    async send(operationId, transport, recipeToken) {
      if (mode === "not-started") throw new Error("no durable started row");
      if (mode === "closed") throw new Error("counter is closed");
      if (productionAdmissionFailed) throw new Error("production recording admission failed");
      requireRecipeCapability(recipeToken);
      if (busy) throw new Error("concurrent request dispatch is forbidden");
      if (
        typeof operationId !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,119}$/.test(operationId) ||
        typeof transport !== "function"
      )
        throw new Error("invalid operation dispatch");
      if (currentCount() >= currentLimit()) throw new Error(`${mode} cap exhausted`);
      if (total >= plan.maxRequests) throw new Error("total cap exhausted");
      busy = true;
      try {
        await onReserve({
          sequence: total + 1,
          operationId,
          phase: mode,
          recording: mode === "recovery" ? null : recording + 1,
          ...(lifecycle ? { recipeId: activeRecipe?.recipeId ?? null } : {}),
          ...(activeRecipe?.operationIds.has(operationId)
            ? { semanticOperationId: activeRecipe.operationIds.get(operationId) }
            : {}),
        });
        total++;
        if (mode === "recovery") recovery++;
        else recordings[recording][mode]++;
        return await transport();
      } finally {
        busy = false;
      }
    },
    async beginRecipe(recipeId) {
      if (!lifecycle || !["subject", "cleanup"].includes(mode))
        throw new Error("recipe cannot start now");
      if (activeRecipe) throw new Error("active recipe must finish first");
      if (busy) throw new Error("concurrent recipe transition is forbidden");
      const index = completedRecipes[recording];
      if (
        typeof recipeId !== "string" ||
        index >= lifecycle.recipeIds.length ||
        recipeId !== lifecycle.recipeIds[index]
      )
        throw new Error("invalid recipe order");
      busy = true;
      try {
        await lifecycle.onBegin({
          recording: recording + 1,
          recipeId,
          prefix: plan.recordings[recording].prefix,
          sequence: total,
        });
        const token = Object.freeze({});
        activeRecipe = {
          token,
          recipeId,
          startTotal: total,
          startCounts: { ...recordings[recording] },
          operationIds: new Map(),
        };
        mode = "subject";
        bindRecipeContext(token, index);
        return token;
      } finally {
        busy = false;
      }
    },
    async finishRecipe(recipeToken) {
      requireRecipeCapability(recipeToken);
      if (!lifecycle || !activeRecipe || mode !== "cleanup")
        throw new Error("recipe cleanup must finish first");
      if (busy) throw new Error("concurrent recipe transition is forbidden");
      busy = true;
      try {
        const proof = Object.freeze({
          recipeToken,
          recording: recording + 1,
          recipeId: activeRecipe.recipeId,
          prefix: plan.recordings[recording].prefix,
          sequence: total,
        });
        if ((await lifecycle.verifyTerminal(proof)) !== true)
          throw new Error("verified recipe terminal proof required");
        await lifecycle.onFinish({
          recording: proof.recording,
          recipeId: proof.recipeId,
          prefix: proof.prefix,
          firstSequence: activeRecipe.startTotal + 1,
          lastSequence: total,
          requests: total - activeRecipe.startTotal,
          subject: recordings[recording].subject - activeRecipe.startCounts.subject,
          cleanup: recordings[recording].cleanup - activeRecipe.startCounts.cleanup,
        });
        completedRecipes[recording]++;
        activeRecipe = null;
      } finally {
        busy = false;
      }
    },
    beginCleanup(recipeToken) {
      requireRecipeCapability(recipeToken);
      if (busy || mode !== "subject") throw new Error("cleanup cannot start now");
      mode = "cleanup";
    },
    nextRecording() {
      if (production) throw new Error("fresh production recording admission is required");
      if (lifecycle && (activeRecipe || completedRecipes[0] !== lifecycle.recipeIds.length))
        throw new Error("incomplete recording cannot advance");
      if (busy || mode !== "cleanup" || recording !== 0)
        throw new Error("second recording cannot start now");
      recording = 1;
      mode = "subject";
    },
    async startNextProductionRecording() {
      if (
        !production ||
        busy ||
        mode !== "cleanup" ||
        recording !== 0 ||
        productionStartsAttempted.has(1) ||
        (lifecycle && (activeRecipe || completedRecipes[0] !== lifecycle.recipeIds.length))
      )
        throw new Error("second recording cannot start now");
      busy = true;
      productionStartsAttempted.add(1);
      try {
        await onStart(startedEvent(1));
        recording = 1;
        mode = "subject";
      } catch (error) {
        productionAdmissionFailed = true;
        throw error;
      } finally {
        busy = false;
      }
    },
    enterRecovery() {
      if (production) throw new Error("recovery requires a separate reviewed packet");
      if (busy || mode === "not-started" || mode === "closed")
        throw new Error("recovery cannot start now");
      mode = "recovery";
    },
    close() {
      if (production && recording !== 1)
        throw new Error("both production recordings must finish before closing");
      if (
        lifecycle &&
        (activeRecipe || completedRecipes.some((count) => count !== lifecycle.recipeIds.length))
      )
        throw new Error("incomplete recording cannot close");
      if (busy || (mode !== "cleanup" && mode !== "recovery"))
        throw new Error("counter cannot close now");
      mode = "closed";
    },
    snapshot() {
      return taskSnapshot();
    },
  };
  taskCounterBindings.set(counter, {
    methods: Object.freeze(Object.fromEntries(Object.entries(counter))),
    artifactProfile,
    plan,
    production,
    read: () => {
      const value = taskSnapshot();
      // The second admission callback runs before the public counter advances; diagnostics already belong to its target.
      const targetRecording = productionStartsAttempted.has(1) ? 1 : recording;
      return Object.freeze({
        ...value,
        recording: targetRecording + 1,
        recordings: Object.freeze(value.recordings.map((row) => Object.freeze(row))),
        busy,
        startAttempted: productionStartsAttempted.has(targetRecording),
        admissionFailed: productionAdmissionFailed,
      });
    },
  });
  return counter;
}
