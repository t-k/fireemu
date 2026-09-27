/** Count every outbound attempt before dispatch, with protected cleanup and recovery capacity. */
export function createStage3RequestCounter(plan, { onStart, onReserve } = {}) {
  if (typeof onStart !== "function" || typeof onReserve !== "function")
    throw new Error("durable started and request-reservation writers are required");
  let mode = "not-started";
  let recording = 0;
  let busy = false;
  let total = 0;
  let recovery = 0;
  const recordings = [
    { subject: 0, cleanup: 0 },
    { subject: 0, cleanup: 0 },
  ];

  function checkEnvelope() {
    if (plan?.status !== "LOCAL_DRAFT_NO_SEND" || plan.recordings?.length !== 2)
      throw new Error("invalid two-recording plan");
    const reserved = plan.recordings.reduce((sum, item) => sum + item.maxRequests, 0) +
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

  return {
    async start() {
      if (mode !== "not-started" || busy) throw new Error("counter already started");
      checkEnvelope();
      busy = true;
      try {
        await onStart({ maxRequests: plan.maxRequests, recordings: 2 });
        mode = "subject";
      } finally {
        busy = false;
      }
    },
    async send(operationId, transport) {
      if (mode === "not-started") throw new Error("no durable started row");
      if (mode === "closed") throw new Error("counter is closed");
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
        });
        total++;
        if (mode === "recovery") recovery++;
        else recordings[recording][mode]++;
        return await transport();
      } finally {
        busy = false;
      }
    },
    beginCleanup() {
      if (busy || mode !== "subject") throw new Error("cleanup cannot start now");
      mode = "cleanup";
    },
    nextRecording() {
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
      if (busy || (mode !== "cleanup" && mode !== "recovery"))
        throw new Error("counter cannot close now");
      mode = "closed";
    },
    snapshot() {
      return {
        total,
        recordings: recordings.map((item) => ({ ...item })),
        recovery,
        mode,
      };
    },
  };
}
