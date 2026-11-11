// The cells of the PUBSUB-NEGCACHE observation: which requests are sent to which names, and when.
//
// Scheduling of a step (one request in flight at a time):
//   at: ms         start at cell start + ms
//   since: [i, ms] start at the START of step i + ms (ages measured from an arming request)
//   after: ms      start at the COMPLETION of the previous step + ms
// A step never starts before the previous one completed + MIN_GAP_MS. Judges use the MEASURED
// start-to-start ages, never the planned ones: a create can take 5-9 s and a delete about 3 s.
//
// Roles name resources: X and W are subscriptions, Y a snapshot, T the run's topic, S the run's
// source subscription for snapshots. M (a topic), M2 (a subscription) and Z (a snapshot) are never
// created. `arm` is the index of the request whose start anchors the ages a judge reads.

export const MIN_GAP_MS = 50;

const S = (op, args = {}, when = {}) => ({ op, ...args, ...when });
const GRID_A = [3000, 6000, 8000, 9000, 9300, 9600, 9900, 10200];
const GRID_B = [3000, 6000, 8400, 9100, 9400, 9700, 10000, 10500];
const X = { target: "X" };
const T = { target: "X", topic: "T" };
const gets = (idx, grid, op = "getSub", args = X) =>
  grid.map((ms) => S(op, args, { since: [idx, ms] }));

const cells = [];
const cell = (id, question, conn, arm, steps) => cells.push({ id, question, conn, arm, steps });

cell("N2a", "base effect, grid A, dedicated connection", "dedicated", 0, [
  S("getSub", X, { at: 0 }),
  S("putSub", T, { after: 50 }),
  ...gets(0, GRID_A),
]);
cell("N2b", "base effect, grid A, fresh connection per request", "fresh", 0, [
  S("getSub", X, { at: 0 }),
  S("putSub", T, { after: 50 }),
  ...gets(0, GRID_A),
]);
const existingFirst = (id, conn, grid) =>
  cell(id, `existing subscription armed by a failed create, ${conn}`, conn, 1, [
    S("putSub", T, { at: 0 }),
    S("putSub", { target: "X", topic: "M" }, { after: 500 }),
    ...gets(1, grid),
  ]);
existingFirst("E1", "dedicated", GRID_A);
existingFirst("E2", "fresh", GRID_A);
existingFirst("E3", "dedicated", GRID_B);
existingFirst("E4", "fresh", GRID_B);

cell(
  "N1",
  "still-absent name served fast?",
  "dedicated",
  0,
  [0, 3000, 6000, 9000, 12000].map((ms) => S("getSub", X, { at: ms })),
);

cell("N4", "create whose body name equals the URL name", "dedicated", 0, [
  S("getSub", X, { at: 0 }),
  S("putSub", { ...T, bodyName: "X" }, { after: 50 }),
  ...[3000, 6000, 10500].map((ms) => S("getSub", X, { since: [0, ms] })),
]);
// X exists and is armed by a failed create; W is created with a body name that names X (the create
// takes about 5 s, so the read of X after it still falls inside the window).
cell("N5", "create of another name whose body names the armed resource", "dedicated", 1, [
  S("putSub", T, { at: 0 }),
  S("putSub", { target: "X", topic: "M" }, { after: 500 }),
  S("putSub", { target: "W", topic: "T", bodyName: "X" }, { after: 50 }),
  S("getSub", X, { after: 100 }),
  S("getSub", X, { since: [1, 10500] }),
]);

const arm = (id, question, event, existing = false) =>
  cell(
    id,
    question,
    "dedicated",
    existing ? 1 : 0,
    existing
      ? [
          S("putSub", T, { at: 0 }),
          S(...event, { after: 500 }),
          S("getSub", X, { since: [1, 3000] }),
          S("getSub", X, { since: [1, 10800] }),
        ]
      : [
          S(...event, { at: 0 }),
          S("putSub", T, { after: 50 }),
          S("getSub", X, { since: [0, 3000] }),
          S("getSub", X, { since: [0, 10500] }),
        ],
  );
arm("A1", "failed create (missing topic) on an absent name arms", [
  "putSub",
  { target: "X", topic: "M" },
]);
arm("A2", "DELETE 404 arms", ["deleteSub", X]);
arm("A3", "PATCH 404 arms", ["patchSub", { target: "X", labels: { k: "v" } }]);
arm("A4", "pull 404 arms", ["pullSub", X]);
arm("A5", "getIamPolicy 404 arms", ["getIamSub", X]);
for (const n of [1, 2, 3])
  arm(
    `A6.${n}`,
    `seek 404 on an existing subscription arms (repeat ${n} of 3)`,
    ["seekSub", { target: "X", snapshot: "Z" }],
    true,
  );
const snapArm = (id, question, event) =>
  cell(id, question, "dedicated", 0, [
    S(...event, { at: 0 }),
    S("putSnap", { target: "Y", from: "S" }, { after: 50 }),
    S("getSnap", { target: "Y" }, { since: [0, 3000] }),
    S("getSnap", { target: "Y" }, { since: [0, 10500] }),
  ]);
snapArm("A7", "snapshot GET 404 arms", ["getSnap", { target: "Y" }]);
snapArm("A8", "snapshot DELETE 404 arms", ["deleteSnap", { target: "Y" }]);
snapArm("A9", "snapshot failed create (missing subscription) arms", [
  "putSnap",
  { target: "Y", from: "M2" },
]);

const serve = (id, question, probe, tail) =>
  cell(id, question, "dedicated", 0, [
    S("getSub", X, { at: 0 }),
    S("putSub", T, { after: 50 }),
    S(...probe, { since: [0, 3000] }),
    ...tail,
  ]);
serve(
  "V1",
  "getIamPolicy while armed",
  ["getIamSub", X],
  [S("getSub", X, { since: [0, 4500] }), S("getSub", X, { since: [0, 10800] })],
);
serve(
  "V2",
  "pull while armed",
  ["pullSub", X],
  [S("getSub", X, { since: [0, 4500] }), S("getSub", X, { since: [0, 10800] })],
);
serve(
  "V3",
  "PATCH while armed (did it apply?)",
  ["patchSub", { target: "X", labels: { k: "v" } }],
  [S("getSub", X, { since: [0, 10800] })],
);
serve(
  "V4",
  "DELETE while armed; does a DELETE hit re-arm?",
  ["deleteSub", X],
  [
    S("listSub", {}, { after: 500 }),
    S("getSub", X, { since: [2, 8500] }),
    S("getSub", X, { since: [2, 21000] }),
  ],
);

const Y = { target: "Y" };
const exempt = (id, question, age) =>
  cell(id, question, "dedicated", 3, [
    S("putSnap", { target: "Y", from: "S" }, { at: 0 }),
    S("getSnap", Y, { after: 300 }),
    S("deleteSnap", Y, { since: [1, 500] }),
    S("getSnap", Y, { since: [1, age] }),
    S("putSnap", { target: "Y", from: "S" }, { after: 50 }),
    S("getSnap", Y, { after: 100 }),
    S("getSnap", Y, { after: 2500 }),
  ]);
exempt("P1", "GET 200 4 s before the negative", 4000);
exempt("P3", "GET 200 7 s before the negative", 7000);
exempt("P2", "GET 200 13 s before the negative", 13000);

// The snapshot named X is created first (a snapshot takes up to 9 s), so every read of the cell falls
// inside the window of the arming GET of subscription X.
cell("K1", "query string, cross-kind, gRPC, topic", "dedicated", 1, [
  S("putSnap", { target: "X", from: "S" }, { at: 0 }),
  S("getSub", X, { after: 100 }),
  S("putSub", T, { after: 50 }),
  S("getSub", { target: "X", query: "?alt=json" }, { after: 100 }),
  S("getSub", { target: "X", query: "?fields=name" }, { after: 100 }),
  S("getSnap", { target: "X" }, { after: 100 }),
  S("grpcGetSub", X, { after: 100 }),
  S("getTopic", { target: "T" }, { after: 100 }),
  S("getSub", X, { since: [1, 10800] }),
]);

for (const n of [1, 2])
  cell(`D${n}`, `poll after a seek 404 (repeat ${n} of 2)`, "dedicated", 1, [
    S("putSub", T, { at: 0 }),
    S("seekSub", { target: "X", snapshot: "Z" }, { after: 500 }),
    ...gets(1, [3000, 6000, 9000, 12000, 15000, 20000, 30000, 45000]),
  ]);

export const CELLS = Object.freeze(cells.map((c) => Object.freeze(c)));

/** Planned start of every step of a cell, assuming every request completes instantly. */
export function planned(cell) {
  const starts = [];
  cell.steps.forEach((step, i) => {
    let t = i === 0 ? 0 : starts[i - 1] + MIN_GAP_MS;
    if (step.at !== undefined) t = Math.max(t, step.at);
    if (step.after !== undefined) t = Math.max(t, starts[i - 1] + step.after);
    if (step.since !== undefined) t = Math.max(t, starts[step.since[0]] + step.since[1]);
    starts.push(t);
  });
  return starts;
}

export const requestCount = () => CELLS.reduce((sum, c) => sum + c.steps.length, 0);
