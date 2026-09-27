// Draft stage 3 envelope per recording. This module performs no HTTP or journal I/O.
export const DRAFT_REQUEST_LIMITS = Object.freeze({ maxRequests: 6805, recoveryReserve: 2000 });

/** Reserve each outbound attempt durably before dispatch, including read-only preflight. */
export function createStage3RequestCounter(options = {}) {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.keys(options).some((key) => !["preflightIds", "onStarted", "onReserve", "onTerminal"].includes(key))
  ) {
    throw new Error("invalid draft request envelope");
  }
  const { preflightIds, onStarted, onReserve, onTerminal } = options;
  if (
    !Array.isArray(preflightIds) ||
    preflightIds.length === 0 ||
    new Set(preflightIds).size !== preflightIds.length ||
    preflightIds.some((id) => typeof id !== "string" || !/^preflight\/[A-Za-z0-9._/-]{1,150}$/.test(id))
  ) {
    throw new Error("invalid declared preflight IDs");
  }
  const declaredPreflightIds = [...preflightIds];
  if ([onStarted, onReserve, onTerminal].some((callback) => typeof callback !== "function")) {
    throw new Error("durable started, reservation and terminal writers are required");
  }
  const { maxRequests, recoveryReserve } = DRAFT_REQUEST_LIMITS;
  const normalCap = maxRequests - recoveryReserve;
  const usedIds = new Set();
  let mode = "not-started";
  let busy = false;
  let checkingPreflight = false;
  let requests = 0;
  let normal = 0;
  let recovery = 0;
  const passedPreflightIds = new Set();

  async function writeTerminal(outcome) {
    if (busy) throw new Error("counter cannot close during dispatch");
    busy = true;
    try {
      await onTerminal({ outcome, requests, normal, recovery, maxRequests });
      mode = "closed";
    } catch (error) {
      mode = "journal-uncertain";
      throw error;
    } finally {
      busy = false;
    }
  }

  async function dispatch(operationId, transport, requiredMode) {
    if (busy) throw new Error("concurrent request dispatch is forbidden");
    if (mode === "not-started") throw new Error("no durable started row");
    if (mode === "closed") throw new Error("counter is closed");
    if (mode === "journal-uncertain") throw new Error("journal state is uncertain");
    if (requiredMode === "preflight" ? mode !== "preflight" : mode === "preflight") {
      throw new Error("preflight admission has not completed or is already closed");
    }
    if (
      typeof operationId !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/.test(operationId) ||
      typeof transport !== "function"
    ) {
      throw new Error("invalid request dispatch");
    }
    if (usedIds.has(operationId)) throw new Error(`duplicate request ID: ${operationId}`);
    if (mode !== "recovery" && normal >= normalCap) throw new Error("normal cap exhausted");
    if (mode === "recovery" && recovery >= recoveryReserve) throw new Error("recovery cap exhausted");
    if (requests >= maxRequests) throw new Error("total cap exhausted");
    busy = true;
    usedIds.add(operationId);
    const phase = mode;
    try {
      try {
        await onReserve({ attempt: requests + 1, operationId, phase });
      } catch (error) {
        mode = "journal-uncertain";
        throw error;
      }
      requests++;
      if (phase === "recovery") recovery++;
      else normal++;
      try {
        return await transport();
      } catch (error) {
        if (phase !== "preflight") mode = "recovery";
        throw error;
      }
    } finally {
      busy = false;
    }
  }

  return {
    async start({ runId } = {}) {
      if (busy || mode !== "not-started") throw new Error("counter already started or journal uncertain");
      if (typeof runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(runId)) {
        throw new Error("invalid run ID");
      }
      busy = true;
      try {
        await onStarted({ runId, maxRequests, recoveryReserve, preflightIds: [...declaredPreflightIds] });
        mode = "preflight";
      } catch (error) {
        mode = "journal-uncertain";
        throw error;
      } finally {
        busy = false;
      }
    },
    async sendPreflight(operationId, transport, accept) {
      if (checkingPreflight) throw new Error("concurrent preflight dispatch is forbidden");
      checkingPreflight = true;
      let result;
      try {
        if (typeof accept !== "function") throw new Error("preflight acceptance check is required");
        if (!declaredPreflightIds.includes(operationId)) throw new Error("undeclared preflight request");
        result = await dispatch(operationId, transport, "preflight");
        if (await accept(result) !== true) throw new Error(`preflight failed: ${operationId}`);
      } catch (error) {
        if (mode === "preflight" && !busy) await writeTerminal("preflight-failed");
        throw error;
      } finally {
        checkingPreflight = false;
      }
      passedPreflightIds.add(operationId);
      return result;
    },
    admit() {
      if (busy || checkingPreflight || mode !== "preflight" || passedPreflightIds.size !== declaredPreflightIds.length) {
        throw new Error("preflight admission is incomplete");
      }
      mode = "normal";
    },
    async send(operationId, transport) {
      try {
        return await dispatch(operationId, transport, "normal");
      } catch (error) {
        if (mode === "preflight" && !busy && !checkingPreflight) await writeTerminal("preflight-failed");
        throw error;
      }
    },
    enterRecovery() {
      if (busy || mode !== "normal") throw new Error("recovery cannot start now");
      mode = "recovery";
    },
    async finish(outcome) {
      if (busy || !["normal", "recovery"].includes(mode)) {
        throw new Error("counter cannot close now");
      }
      if (!["finished", "needs-recovery"].includes(outcome)) {
        throw new Error("invalid terminal outcome");
      }
      await writeTerminal(outcome);
    },
    snapshot() {
      return { mode, requests, normal, recovery, normalCap, recoveryReserve, maxRequests };
    },
  };
}
