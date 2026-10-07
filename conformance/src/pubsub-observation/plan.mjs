// Every ceiling is per recording set; unused reservations are never reassigned.
export const SUITE = "pubsub-observation-a-v1";
export const TASK = "PUBSUB-OBSERVATION-A";
export const PROJECT = "fireemu-oracle-idp";
export const CAPS = Object.freeze({
  G1: { requests: 240, rest: 120, grpc: 120, streams: 0, cellMs: 120000 },
  G4: { requests: 306, rest: 289, grpc: 0, streams: 17, cellMs: 180000 },
  G7: { requests: 14, rest: 14, grpc: 0, streams: 0 },
  sourceRequests: 546,
  totalRequests: 560,
  framesOut: 102,
  framesIn: 102,
  frameBytes: 65536,
  metadataBytesEachDirection: 65536,
  largePublishes: 40,
  largeEncodedPayloadBytes: 16777216,
  smallPublishes: 51,
  smallEncodedPayloadBytes: 1024,
  sourceWallMs: 5460000,
  cleanupReserveMs: 40000,
});
const streamCases = [
  "opening-frame",
  "future-publications",
  "in-stream-ack",
  "in-stream-nack",
  "in-stream-deadline-update",
  "flow-control",
  "client-cancel",
  "half-close",
  "missing-subscription",
  "invalid-opening-frame",
  "invalid-update-frame",
];
const supplements = [
  "missing-opening-subscription",
  "opening-deadline-601",
  "update-array-length",
  "update-deadline-601",
  "invalid-ack-silence",
];
const variants = [
  "topic-path-body",
  "subscription-path-body",
  "unicode-layout",
  "atomic-mask",
  "delete-recreate",
  "request-10000000",
  "request-10485760",
  "message-10000000",
];
const nativeVariants = ["label-key-63-64", "label-value-63-64", ...variants.slice(2)];
const g1Case = (variant) =>
  variant.includes("path-body")
    ? [1, 4]
    : variant === "delete-recreate"
      ? [0, 5]
      : variant === "atomic-mask"
        ? [4, 7]
        : variant.startsWith("request-")
          ? [7, 0]
          : variant.startsWith("message-")
            ? [7, 2]
            : [4, 6];
export function makePlan() {
  const cells = [...streamCases, ...supplements].map((variant, index) => ({
    id: `S${String(index + 1).padStart(2, "0")}`,
    group: "G4",
    transport: "rest",
    variant,
    canonicalCase: streamCases[index] ?? null,
    coordinate: index < 11 ? `/conditions/13/cases/${index}` : null,
    supplement: index >= 11,
    reserve: false,
    ...(variant === "invalid-ack-silence"
      ? { invalidAck: "invalid-ack-for-stream-observation" }
      : {}),
  }));
  for (const [prefix, transport, names] of [
    ["R", "rest", variants],
    ["N", "grpc", nativeVariants],
  ])
    for (const [index, variant] of names.entries()) {
      const [condition, caseIndex] = g1Case(variant);
      cells.push({
        id: `${prefix}${index + 1}`,
        group: "G1",
        transport,
        variant,
        coordinate: `/conditions/${condition}/cases/${caseIndex}`,
        reserve: false,
      });
    }
  for (const original of ["R5", "R6", "N5", "N6", "S05"])
    cells.push({
      ...cells.find((cell) => cell.id === original),
      id: `${original}F`,
      reserve: true,
      predecessor: original,
      activation: "explicit reason and settled predecessor only",
    });
  return {
    schema: 1,
    suite: SUITE,
    project: PROJECT,
    groups: ["G4", "G1", "G7"],
    recordings: 2,
    caps: structuredClone(CAPS),
    cells,
    ackSelector: "NOT_COMPARABLE-until-observed",
    streamWindowMs: 90000,
    a2: { minAgeMs: 600000, resourceReads: 6, unknownDeleteReads: 6, iamReadsUnused: 2 },
    spendStopUsd: 2,
    campaignLimitUsd: 10,
    iam: false,
  };
}
export function validatePlan(value) {
  if (JSON.stringify(value) !== JSON.stringify(makePlan()))
    throw new Error("fixed observation plan mismatch");
  return value;
}
export const categoryCaps = (group) =>
  group === "G1"
    ? { create: 2, get: 2, target: 4, cleanupDelete: 2, cleanupGet: 2 }
    : group === "G4"
      ? { create: 2, get: 2, publish: 3, target: 6, cleanupDelete: 2, cleanupGet: 2, stream: 1 }
      : { resourceRead: 6, unknownDeleteRead: 6 };
