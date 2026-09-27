// Draft stage 3 envelope per recording. This module performs no HTTP or journal I/O.
export const DRAFT_REQUEST_LIMITS = Object.freeze({ maxRequests: 6805, recoveryReserve: 2000 });

/** Reserve each outbound attempt durably before dispatch, including read-only preflight. */
export function createStage3RequestCounter({
  maxRequests,
  recoveryReserve,
  onStarted,
  onReserve,
  onTerminal,
} = {}) {
  if (
    !Number.isSafeInteger(maxRequests) ||
    !Number.isSafeInteger(recoveryReserve) ||
    maxRequests < 2 ||
    maxRequests > DRAFT_REQUEST_LIMITS.maxRequests ||
    recoveryReserve < 1 ||
    recoveryReserve > DRAFT_REQUEST_LIMITS.recoveryReserve ||
    recoveryReserve >= maxRequests
  ) {
    throw new Error("invalid draft request envelope");
  }
  if ([onStarted, onReserve, onTerminal].some((callback) => typeof callback !== "function")) {
    throw new Error("durable started, reservation and terminal writers are required");
  }
  const normalCap = maxRequests - recoveryReserve;
  const usedIds = new Set();
  let mode = "not-started";
  let busy = false;
  let requests = 0;
  let normal = 0;
  let recovery = 0;

  return {
    async start({ runId } = {}) {
      if (busy || mode !== "not-started") throw new Error("counter already started or journal uncertain");
      if (typeof runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(runId)) {
        throw new Error("invalid run ID");
      }
      busy = true;
      try {
        await onStarted({ runId, maxRequests, recoveryReserve });
        mode = "normal";
      } catch (error) {
        mode = "journal-uncertain";
        throw error;
      } finally {
        busy = false;
      }
    },
    async send(operationId, transport) {
      if (busy) throw new Error("concurrent request dispatch is forbidden");
      if (mode === "not-started") throw new Error("no durable started row");
      if (mode === "closed") throw new Error("counter is closed");
      if (mode === "journal-uncertain") throw new Error("journal state is uncertain");
      if (
        typeof operationId !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$/.test(operationId) ||
        typeof transport !== "function"
      ) {
        throw new Error("invalid request dispatch");
      }
      if (usedIds.has(operationId)) throw new Error(`duplicate request ID: ${operationId}`);
      if (mode === "normal" && normal >= normalCap) throw new Error("normal cap exhausted");
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
        if (phase === "normal") normal++;
        else recovery++;
        try {
          return await transport();
        } catch (error) {
          mode = "recovery";
          throw error;
        }
      } finally {
        busy = false;
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
      if (!["finished", "preflight-failed", "needs-recovery"].includes(outcome)) {
        throw new Error("invalid terminal outcome");
      }
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
    },
    snapshot() {
      return { mode, requests, normal, recovery, normalCap, recoveryReserve, maxRequests };
    },
  };
}
