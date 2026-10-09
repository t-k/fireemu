// Ceilings are per recording set; unused reservations cannot be reassigned.
export const SUITE = "pubsub-observation-c-v1";
export const TASK = "PUBSUB-OBSERVATION-C";
export const PROJECT = "fireemu-oracle-idp";
export const minimumCallMs = (method) =>
  method === "CreateTopic"
    ? 43000
    : method === "CreateSubscription"
      ? 19000
      : method === "CreateSnapshot"
        ? 16000
        : method.startsWith("Delete")
          ? 13000
          : method === "Publish"
            ? 6000
            : method === "Pull"
              ? 25000
              : 10000;
export const CAPS = Object.freeze({
  G2: { requests: 1036, rest: 518, grpc: 518, streams: 0, cellMs: 180000 },
  G7: { requests: 14, rest: 14, grpc: 0, streams: 0 },
  sourceRequests: 1036,
  totalRequests: 1050,
  framesOut: 0,
  framesIn: 0,
  frameBytes: 65536,
  metadataBytesEachDirection: 65536,
  largePublishes: 0,
  largeEncodedPayloadBytes: 0,
  smallPublishes: 84,
  smallEncodedPayloadBytes: 1024,
  sourceWallMs: 5040000,
  cleanupReserveMs: 40000,
});
export const categoryCaps = (group) =>
  group === "G2"
    ? {
        create: 5,
        get: 5,
        publish: 3,
        pull: 8,
        ackControl: 4,
        other: 2,
        cleanupDelete: 5,
        cleanupGet: 5,
      }
    : { resourceRead: 6, unknownDeleteRead: 6 };
export function makePlan({ selection = "full" } = {}) {
  if (!["full", "remaining-gap"].includes(selection))
    throw new Error("fixed observation selection mismatch");
  const cells = [];
  const coordinates = {
    "multiple-subscriptions": ["/conditions/8/cases/3", "/conditions/8/cases/4"],
    "stale-ack": ["/conditions/8/cases/7"],
    "cancel-followup": ["/conditions/9/cases/5"],
    "filter-inequality": ["/conditions/10/cases/4"],
    "filter-conjunction": ["/conditions/10/cases/5"],
    "filter-disjunction": ["/conditions/10/cases/6"],
    "attribute-exists": ["/conditions/10/cases/3"],
    "nack-blocked-key": ["/conditions/11/cases/3", "/conditions/11/cases/4"],
    "ordered-first-cross-key": ["/conditions/11/cases/0", "/conditions/11/cases/1"],
    "retain-false-seek": ["/conditions/14/cases/6", "/conditions/14/cases/5"],
    "wrong-topic-snapshot": ["/conditions/14/cases/7"],
    "unacked-backlog-seek": ["/conditions/14/cases/3", "/conditions/14/cases/4"],
    "reverse-seek-members": ["/conditions/14/cases/5"],
  };
  const variants = [
    "multiple-subscriptions",
    "stale-ack",
    "cancel-followup",
    "filter-inequality",
    "filter-conjunction",
    "filter-disjunction",
    "attribute-exists",
    "nack-blocked-key",
    "ordered-first-cross-key",
    "retain-false-seek",
    "wrong-topic-snapshot",
    "unacked-backlog-seek",
    "reverse-seek-members",
  ];
  for (const transport of ["rest", "grpc"])
    for (const [index, variant] of variants.entries())
      cells.push({
        id: `${transport === "rest" ? "R" : "N"}${index + 1}`,
        group: "G2",
        transport,
        variant,
        reserve: false,
        coordinates: coordinates[variant],
      });
  for (const original of ["R1", "N1"])
    cells.push({
      ...cells.find((c) => c.id === original),
      id: `${original}F`,
      reserve: true,
      predecessor: original,
      activation: "explicit reason and settled predecessor only",
    });
  const gap = selection === "remaining-gap";
  const selected = gap
    ? cells.filter(
        (cell) => !cell.reserve && [1, 2, 3, 4, 5, 6, 8, 10, 11].includes(Number(cell.id.slice(1))),
      )
    : cells;
  return {
    schema: 1,
    ...(gap ? { selection } : {}),
    suite: SUITE,
    project: PROJECT,
    groups: ["G2", "G7"],
    recordings: 2,
    caps: gap
      ? {
          ...structuredClone(CAPS),
          G2: { ...CAPS.G2, requests: 666, rest: 333, grpc: 333 },
          sourceRequests: 666,
          totalRequests: 680,
          smallPublishes: 54,
          sourceWallMs: 3240000,
        }
      : structuredClone(CAPS),
    cells: selected,
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
      minimumCreateSnapshotMs: 16000,
      minimumDeleteMs: 13000,
      minimumPublishMs: 6000,
      minimumPullMs: 25000,
      minimumOtherMs: 10000,
    },
  };
}
export function validatePlan(value) {
  if (JSON.stringify(value) !== JSON.stringify(makePlan({ selection: value?.selection ?? "full" })))
    throw new Error("fixed observation plan mismatch");
  return value;
}
