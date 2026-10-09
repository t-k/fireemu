// Fixed per-set reservations. Unused categories and fresh cells cannot be reassigned.
export const SUITE = "pubsub-observation-d-v1";
export const TASK = "PUBSUB-OBSERVATION-D";
export const PROJECT = "fireemu-oracle-idp";
export const minimumCallMs = (method) =>
  method === "CreateTopic"
    ? 43000
    : method === "CreateSubscription"
      ? 19000
      : method.startsWith("Delete")
        ? 13000
        : method === "Publish"
          ? 6000
          : method === "Pull"
            ? 25000
            : 10000;
export const CAPS = Object.freeze({
  G5: { requests: 2894, rest: 1501, grpc: 1393, streams: 0 },
  G7: { requests: 14, rest: 14, grpc: 0, streams: 0 },
  sourceRequests: 2894,
  totalRequests: 2908,
  framesOut: 0,
  framesIn: 0,
  frameBytes: 65536,
  metadataBytesEachDirection: 65536,
  largePublishes: 0,
  largeEncodedPayloadBytes: 0,
  smallPublishes: 14,
  smallEncodedPayloadBytes: 1024,
  sourceWallMs: 21120000,
});
export const iamCategory = (name) =>
  name.includes("Iam") || name.startsWith("iam") || name.startsWith("cleanupIam");
export const categoryCaps = (cell) =>
  cell.group === "G7"
    ? { resourceRead: 6, unknownDeleteRead: 6, iamRead: 2 }
    : {
        create: 4,
        resourceGet: 4,
        baselineIamGet: 2,
        publish: 1,
        sourcePull: 60,
        sinkPull: 60,
        nack: 60,
        ownAck: 2,
        cleanupDelete: 4,
        cleanupGet: 4,
        iamSetupWrite: cell.arm === "managed-grant-readback-wait" ? 2 : 0,
        iamSetupReadback: cell.arm === "managed-grant-readback-wait" ? 2 : 0,
        cleanupIamConflictGet: cell.arm === "managed-grant-readback-wait" ? 2 : 0,
        cleanupIamRestoreWrite: cell.arm === "managed-grant-readback-wait" ? 2 : 0,
        cleanupIamRestoreReadback: cell.arm === "managed-grant-readback-wait" ? 2 : 0,
      };
export function makePlan() {
  const cells = [];
  for (const transport of ["rest", "grpc"]) {
    let index = 0;
    for (const mode of ["active-nack", "passive-deadline", "720-second-source-inactivity"])
      for (const arm of ["no-new-grant", "managed-grant-readback-wait"])
        cells.push({
          id: `${transport === "rest" ? "R" : "N"}${++index}`,
          group: "G5",
          transport,
          mode,
          arm,
          reserve: false,
          cellMs:
            mode === "720-second-source-inactivity"
              ? arm === "no-new-grant"
                ? 1200000
                : 2160000
              : arm === "no-new-grant"
                ? 900000
                : 1800000,
          cleanupReserveMs: arm === "no-new-grant" ? 60000 : 120000,
        });
  }
  for (const transport of ["rest", "grpc"]) {
    const original = cells.find(
      (c) => c.transport === transport && c.arm === "managed-grant-readback-wait",
    );
    cells.push({
      ...original,
      id: `${original.id}F`,
      reserve: true,
      predecessor: original.id,
      activation: "New reviewed source/scope only; never automatic",
    });
  }
  return {
    schema: 1,
    suite: SUITE,
    project: PROJECT,
    groups: ["G5", "G7"],
    recordings: 2,
    caps: structuredClone(CAPS),
    cells,
    ackSelector: "NOT_COMPARABLE-until-observed",
    a2: { minAgeMs: 600000, resourceReads: 6, unknownDeleteReads: 6, iamReads: 2, readOnly: true },
    spendStopUsd: 2,
    campaignLimitUsd: 10,
    iam: {
      waitAfterLastGrantMs: 900000,
      convergenceClaim: false,
      assessment: "needs-review for every IAM row",
      baselinePermission: "UNAUDITED; no-new-grant does not establish absent effective permission",
      principalSource: "Future authentic source-bound APPROVE scope; never argv",
    },
    observationWindowMs: 900000,
    inactivityObservationWindowMs: 1020000,
    timeoutPolicy: {
      createMs: 80000,
      otherMs: 30000,
      minimumCreateTopicMs: 43000,
      minimumCreateSubscriptionMs: 19000,
      minimumDeleteMs: 13000,
      minimumPublishMs: 6000,
      minimumPullMs: 25000,
      minimumOtherMs: 10000,
    },
  };
}
export function validatePlan(value) {
  if (JSON.stringify(value) !== JSON.stringify(makePlan()))
    throw new Error("fixed observation plan mismatch");
  return value;
}
