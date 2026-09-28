import { estimateStage3Budget } from "./budget-model.mjs";

/** Count every outbound attempt before dispatch, with protected cleanup and recovery capacity. */
export function createStage3RequestCounter(plan, { onStart, onReserve, recipeLifecycle } = {}) {
  if (typeof onStart !== "function" || typeof onReserve !== "function")
    throw new Error("durable started and request-reservation writers are required");
  plan = structuredClone(plan);
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
    if (plan?.status !== "LOCAL_DRAFT_NO_SEND" || plan.recordings?.length !== 2)
      throw new Error("invalid two-recording plan");
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

  return {
    async start() {
      if (mode !== "not-started" || busy) throw new Error("counter already started");
      checkEnvelope();
      busy = true;
      try {
        await onStart({
          maxRequests: plan.maxRequests,
          recordings: 2,
          estimatedUsd: plan.estimatedUsd,
          maxUsdReservation: plan.maxUsdReservation,
        });
        mode = "subject";
      } finally {
        busy = false;
      }
    },
    async send(operationId, transport, recipeToken) {
      if (mode === "not-started") throw new Error("no durable started row");
      if (mode === "closed") throw new Error("counter is closed");
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
        };
        mode = "subject";
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
      if (lifecycle && (activeRecipe || completedRecipes[0] !== lifecycle.recipeIds.length))
        throw new Error("incomplete recording cannot advance");
      if (busy || mode !== "cleanup" || recording !== 0)
        throw new Error("second recording cannot start now");
      recording = 1;
      mode = "subject";
    },
    enterRecovery() {
      if (busy || mode === "not-started" || mode === "closed")
        throw new Error("recovery cannot start now");
      mode = "recovery";
    },
    close() {
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
      return {
        total,
        recordings: recordings.map((item) => ({ subject: item.subject, cleanup: item.cleanup })),
        recovery,
        mode,
        ...(lifecycle
          ? {
              completedRecipes: [...completedRecipes],
              activeRecipeId: activeRecipe?.recipeId ?? null,
            }
          : {}),
      };
    },
  };
}
