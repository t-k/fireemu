// Every ceiling is per recording set; unused reservations are never reassigned.
export const SUITE = "pubsub-observation-a-v1";
export const TASK = "PUBSUB-OBSERVATION-A";
export const PROJECT = "fireemu-oracle-idp";
// Five seconds above observed successful same-route maxima, rounded up.
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
export function makePlan(selection = "full") {
  if (
    ![
      "full",
      "s10-diagnostic",
      "residual",
      "valid-stream-gap",
      "invalid-path-gap",
      "s03-terminal-pair",
      "closure-mandatory-gap",
    ].includes(selection)
  )
    throw new Error("fixed observation selection required");
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
  const plan = {
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
  if (selection === "closure-mandatory-gap") {
    const extra = [
      ["R9", "rest", "topic-labels-empty", 0, 1],
      ["N9", "grpc", "topic-labels-empty", 0, 1],
      ["R10", "rest", "retention-ordering", 4, 5],
      ["N10", "grpc", "retention-ordering", 4, 5],
      ["R11", "rest", "publish-wire-eight", 6, 0],
      ["N13", "grpc", "publish-wire-eight", 6, 0],
      ["N11", "grpc", "topic-path-body", 1, 4],
      ["N12", "grpc", "subscription-path-body", 1, 4],
      ["R12", "rest", "filter-negation", 10, 7],
      ["N14", "grpc", "filter-negation", 10, 7],
      ["R13", "rest", "positive-deadline-extension", 9, 1],
      ["N15", "grpc", "positive-deadline-extension", 9, 1],
    ].map(([id, transport, variant, condition, index]) => ({
      id,
      group: "G1",
      transport,
      variant,
      coordinate: `/conditions/${condition}/cases/${index}`,
      reserve: false,
      ...(variant === "publish-wire-eight" || variant === "filter-negation"
        ? { cellMs: 240000 }
        : variant === "positive-deadline-extension"
          ? { cellMs: 360000 }
          : {}),
    }));
    plan.selection = selection;
    plan.cells = [
      ...cells.filter((c) =>
        [
          "S10",
          "S11",
          "S12",
          "S13",
          "S14",
          "S15",
          "S16",
          "R1",
          "R2",
          "R3",
          "R4",
          "R5",
          "N1",
          "N2",
          "N3",
          "N4",
          "N5",
        ].includes(c.id),
      ),
      ...extra,
    ];
    plan.caps.G1 = { ...plan.caps.G1, requests: 272, rest: 124, grpc: 148 };
    plan.caps.G4 = { ...plan.caps.G4, requests: 126, rest: 119, streams: 7 };
    Object.assign(plan.caps, {
      sourceRequests: 398,
      totalRequests: 412,
      framesOut: 42,
      framesIn: 42,
      largePublishes: 6,
      largeEncodedPayloadBytes: 1024,
      smallPublishes: 21,
      sourceWallMs: 4860000,
    });
    return plan;
  }
  if (selection === "full") return plan;
  if (["valid-stream-gap", "invalid-path-gap", "s03-terminal-pair"].includes(selection)) {
    const valid = selection === "valid-stream-gap",
      pair = selection === "s03-terminal-pair",
      streams = pair ? 1 : valid ? 9 : 4,
      restCells = valid || pair ? 0 : 2;
    plan.recordings = valid ? 1 : 2;
    plan.caps.G4 = {
      ...plan.caps.G4,
      requests: streams * 18,
      rest: streams * 17,
      grpc: 0,
      streams,
    };
    plan.caps.G1 = {
      ...plan.caps.G1,
      requests: restCells * 12,
      rest: restCells * 12,
      grpc: 0,
      streams: 0,
    };
    plan.caps.sourceRequests = streams * 18 + restCells * 12;
    plan.caps.totalRequests = plan.caps.sourceRequests + plan.caps.G7.requests;
    plan.caps.framesOut = plan.caps.framesIn = streams * 6;
    plan.caps.smallPublishes = streams * 3;
    plan.caps.largePublishes = 0;
    plan.caps.sourceWallMs = streams * plan.caps.G4.cellMs + restCells * plan.caps.G1.cellMs;
  }
  return {
    ...plan,
    selection,
    cells: cells.filter(
      (cell) =>
        !cell.reserve &&
        (selection === "s10-diagnostic"
          ? cell.id === "S10"
          : selection === "s03-terminal-pair"
            ? cell.id === "S03"
            : selection === "valid-stream-gap"
              ? /^S0[1-9]$/.test(cell.id)
              : selection === "invalid-path-gap"
                ? ["S12", "S13", "S14", "S15", "R1", "R2"].includes(cell.id)
                : !/^S0[1-9]$/.test(cell.id) && cell.id !== "S10"),
    ),
  };
}
export function validatePlan(value) {
  if (JSON.stringify(value) !== JSON.stringify(makePlan(value?.selection ?? "full")))
    throw new Error("fixed observation plan mismatch");
  return value;
}
export const categoryCaps = (group, variant) =>
  group === "G1" && variant === "positive-deadline-extension"
    ? { create: 2, get: 2, publish: 1, target: 5, cleanupDelete: 2, cleanupGet: 2 }
    : group === "G1" && ["publish-wire-eight", "filter-negation"].includes(variant)
      ? { create: 2, get: 2, publish: 1, target: 4, cleanupDelete: 2, cleanupGet: 2 }
      : group === "G1"
        ? { create: 2, get: 2, target: 4, cleanupDelete: 2, cleanupGet: 2 }
        : group === "G4"
          ? { create: 2, get: 2, publish: 3, target: 6, cleanupDelete: 2, cleanupGet: 2, stream: 1 }
          : { resourceRead: 6, unknownDeleteRead: 6 };
