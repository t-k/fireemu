// Ceilings are per recording set; unused reservations cannot be reassigned.
export const SUITE = "pubsub-observation-b-v1";
export const TASK = "PUBSUB-OBSERVATION-B";
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
          : 10000;
export const CAPS = Object.freeze({
  G3: { requests: 680, rest: 340, grpc: 340, streams: 0, cellMs: 120000 },
  G7: { requests: 14, rest: 14, grpc: 0, streams: 0 },
  sourceRequests: 680,
  totalRequests: 694,
  framesOut: 0,
  framesIn: 0,
  frameBytes: 65536,
  metadataBytesEachDirection: 65536,
  largePublishes: 0,
  largeEncodedPayloadBytes: 0,
  smallPublishes: 20,
  smallEncodedPayloadBytes: 1024,
  sourceWallMs: 2400000,
  cleanupReserveMs: 40000,
});
export const categoryCaps = (group) =>
  group === "G3"
    ? {
        create: 6,
        get: 6,
        publish: 1,
        list: 7,
        cursorDelete: 1,
        cursorGet: 1,
        cleanupDelete: 6,
        cleanupGet: 6,
      }
    : { resourceRead: 6, unknownDeleteRead: 6 };
export function makePlan() {
  const cells = [];
  for (const transport of ["rest", "grpc"])
    for (const kind of ["topics", "subscriptions", "snapshots"])
      for (const permutation of ["lexical", "reverse", "rotated"])
        cells.push({
          id: `${transport === "rest" ? "R" : "N"}${(cells.length % 9) + 1}`,
          group: "G3",
          transport,
          kind,
          permutation,
          reserve: false,
          coordinates: ["/conditions/2/cases/0", "/conditions/2/cases/1", "/conditions/2/cases/2"],
        });
  for (const original of ["R1", "N1"])
    cells.push({
      ...cells.find((c) => c.id === original),
      id: `${original}F`,
      reserve: true,
      predecessor: original,
      activation: "explicit reason and settled predecessor only",
    });
  return {
    schema: 1,
    suite: SUITE,
    project: PROJECT,
    groups: ["G3", "G7"],
    recordings: 2,
    caps: structuredClone(CAPS),
    cells,
    ackSelector: "NOT_COMPARABLE-until-observed",
    a2: { minAgeMs: 600000, resourceReads: 6, unknownDeleteReads: 6, iamReadsUnused: 2 },
    spendStopUsd: 2,
    campaignLimitUsd: 10,
    iam: false,
    timeoutPolicy: {
      createMs: 80000,
      otherMs: 30000,
      minimumCreateTopicMs: 43000,
      minimumCreateSubscriptionMs: 19000,
      minimumDeleteMs: 13000,
      minimumPublishMs: 6000,
      minimumOtherMs: 10000,
    },
  };
}
export function validatePlan(value) {
  if (JSON.stringify(value) !== JSON.stringify(makePlan()))
    throw new Error("fixed observation plan mismatch");
  return value;
}
