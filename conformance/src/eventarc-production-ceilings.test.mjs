// The ceiling of every case is a maximum for the recorder's own bounds, not for a service that happens to
// answer fast (presend review M1): operations are read up to OPERATION_READS_MAX times and a channel's
// state up to READY_READS times. Each case runs through the real runner, against the model of the service
// in its slowest healthy modes, with the ceilings lifted; the most requests it sent must fit its ceiling.

import assert from "node:assert/strict";
import test from "node:test";
import { createCapture } from "./pubsub-production/capture.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { CASES } from "./eventarc-production/cases/index.mjs";
import { OPERATION_READS_MAX, READY_READS } from "./eventarc-production/cases/support.mjs";
import { CLEANUP_BUDGET, DEFAULT_MAX_REQUESTS } from "./eventarc-production/record.mjs";
import { createClient } from "./eventarc-production/client.mjs";
import { createOwnership } from "./eventarc-production/names.mjs";
import { plannedRequests, runCases } from "./eventarc-production/runner.mjs";
import { createWorld } from "./eventarc-production/testing/world.mjs";

const RUN = "0123456789ab";
const PROJECT = "demo-project";

/** The slow healthy modes: the last read of every operation and of the state is the one that succeeds. */
const MODES = {
  "slow operations and a channel that stays PENDING to its last read": {
    doneAfter: OPERATION_READS_MAX,
    withState: true,
    pendingReads: READY_READS - 1,
  },
  "the same, with every ID probe accepted, and many channels to page through": {
    doneAfter: OPERATION_READS_MAX,
    withState: true,
    pendingReads: READY_READS - 1,
    acceptAnyId: true,
    existing: Array.from(
      { length: 8 },
      (_, i) => `projects/${PROJECT}/locations/us-central1/channels/other-${i}`,
    ),
  },
  "fast operations, every ID probe accepted": { acceptAnyId: true },
  "the limits at the recorded brackets, so that every search runs to its end": {
    doneAfter: OPERATION_READS_MAX,
    withState: true,
    pendingReads: READY_READS - 1,
    textLimit: 524_500,
    attributeLimit: 100,
    keyLimit: 256,
    eventLimit: 100,
  },
  "every deliberate variant of a creation accepted, with slow operations": {
    doneAfter: OPERATION_READS_MAX,
    acceptAnyId: true,
    acceptVariants: true,
    existing: Array.from(
      { length: 250 },
      (_, i) => `projects/${PROJECT}/locations/us-central1/channels/other-${i}`,
    ),
  },
  "a location with 250 other channels (three pages of 100), slow operations, every ID probe accepted":
    {
      doneAfter: OPERATION_READS_MAX,
      acceptAnyId: true,
      existing: Array.from(
        { length: 250 },
        (_, i) => `projects/${PROJECT}/locations/us-central1/channels/other-${i}`,
      ),
    },
  "operations still running when the next request is sent, a second deletion refused": {
    doneAfter: OPERATION_READS_MAX,
    busy: "reject",
    duplicate: "409",
    acceptAnyId: true,
  },
  "operations still running, a second deletion started, and many channels to page through": {
    doneAfter: OPERATION_READS_MAX,
    busy: "accept",
    duplicate: "409",
    acceptAnyId: true,
    existing: Array.from(
      { length: 12 },
      (_, i) => `projects/${PROJECT}/locations/us-central1/channels/other-${i}`,
    ),
  },
  "duplicate creates answered 409, limits in the middle of the ladders": {
    duplicate: "409",
    eventLimit: 100,
    textLimit: 400_000,
    doneAfter: 3,
  },
};

/**
 * The Admin SDK, as an upper bound: every `publish()` the case makes sends one request, although the real
 * SDK refuses some of them client-side without sending anything.
 */
const sdkUpperBound = async ({ transport }) => ({
  publish: async (spec) => {
    const channel = spec.channel?.startsWith("projects/")
      ? spec.channel
      : `projects/${PROJECT}/locations/us-central1/channels/${spec.channel?.replace(/^locations\/[^/]+\/channels\//, "") ?? "firebase"}`;
    await transport.request({
      label: { case: "admin-sdk-publish", step: "s" },
      op: "sdk.publishEvents",
      method: "POST",
      path: `/v1/${channel}:publishEvents`,
      body: { events: [{ id: "x" }] },
    });
    return { threw: false, requests: 1, suppressed: 0 };
  },
  close: async () => {},
});

/** One case through the real runner with its ceiling lifted: the requests it sent, and the cleanup's. */
async function measure(item, worldOptions) {
  const world = createWorld({ project: PROJECT, ...worldOptions });
  const ownership = createOwnership({ project: PROJECT, runId: RUN });
  const ledger = createLedger();
  const capture = createCapture({ journal: { write() {} } });
  const transport = {
    name: "rest",
    request: (call) => (
      capture.record({ case: call.label?.case, op: call.op }),
      world.request(call)
    ),
  };
  const cleanupClient = createClient({
    transports: { eventarc: transport },
    ownership,
    caseId: "cleanup",
    usageProject: PROJECT,
    ledger,
  });
  const summary = await runCases({
    cases: [{ ...item, requests: Infinity }],
    transports: { eventarc: transport, publishing: transport, usage: transport },
    cleanupClient,
    ownership,
    capture,
    options: {
      production: false,
      location: "us-central1",
      usageProject: PROJECT,
      publishPrefix: "/v1",
    },
    sleep: async () => {},
    makeSdk: sdkUpperBound,
    ledger,
  });
  return {
    requests: summary.cases.reduce((sum, entry) => sum + entry.requests, 0),
    cleanup: capture.count() - summary.cases.reduce((sum, entry) => sum + entry.requests, 0),
  };
}

test("every case's ceiling covers its worst case under the recorder's own poll bounds", async () => {
  const worst = Object.fromEntries(CASES.map((item) => [item.id, { requests: 0, mode: null }]));
  for (const [mode, options] of Object.entries(MODES))
    for (const item of CASES) {
      const { requests } = await measure(item, options);
      if (requests > worst[item.id].requests) worst[item.id] = { requests, mode };
    }
  const over = CASES.filter((item) => worst[item.id].requests > item.requests).map(
    (item) =>
      `${item.id}: worst ${worst[item.id].requests} (${worst[item.id].mode}) > ceiling ${item.requests}`,
  );
  assert.deepEqual(
    over,
    [],
    JSON.stringify(Object.fromEntries(Object.entries(worst).map(([id, w]) => [id, w.requests]))),
  );
  // A ceiling is not slack for its own sake: at most a tenth and three requests above the measured worst.
  const loose = CASES.filter(
    (item) => item.requests > Math.ceil(worst[item.id].requests * 1.1) + 3,
  ).map((item) => `${item.id}: ceiling ${item.requests} for a worst of ${worst[item.id].requests}`);
  assert.deepEqual(loose, []);
});

test("the ceilings fit the run's budget, and the cleanup's budget covers every name a run can ledger in the slow modes", async () => {
  assert.ok(
    plannedRequests(CASES) <= DEFAULT_MAX_REQUESTS,
    `${plannedRequests(CASES)} > ${DEFAULT_MAX_REQUESTS}`,
  );
  // A whole recording, every case in order, in each mode: the cleanup that follows must fit its budget.
  for (const [mode, options] of Object.entries(MODES)) {
    const world = createWorld({ project: PROJECT, ...options });
    const ownership = createOwnership({ project: PROJECT, runId: RUN });
    const ledger = createLedger();
    const capture = createCapture({ journal: { write() {} } });
    const transport = {
      name: "rest",
      request: (call) => (
        capture.record({ case: call.label?.case, op: call.op }),
        world.request(call)
      ),
    };
    const cleanupClient = createClient({
      transports: { eventarc: transport },
      ownership,
      caseId: "cleanup",
      usageProject: PROJECT,
      ledger,
    });
    const summary = await runCases({
      cases: CASES,
      transports: { eventarc: transport, publishing: transport, usage: transport },
      cleanupClient,
      ownership,
      capture,
      options: {
        production: false,
        location: "us-central1",
        usageProject: PROJECT,
        publishPrefix: "/v1",
      },
      sleep: async () => {},
      makeSdk: sdkUpperBound,
      ledger,
    });
    const inCases = summary.cases.reduce((sum, entry) => sum + entry.requests, 0);
    const cleanupRequests = capture.count() - inCases;
    assert.deepEqual(summary.limited, [], mode);
    assert.equal(summary.cleanup.budgetSpent, false, mode);
    assert.ok(inCases <= DEFAULT_MAX_REQUESTS, `${mode}: ${inCases}`);
    assert.ok(
      cleanupRequests <= CLEANUP_BUDGET,
      `${mode}: cleanup ${cleanupRequests} > ${CLEANUP_BUDGET}`,
    );
  }
});

test("the cleanup budget is derived from the bounds: every name a run can ledger, at the cleanup's own worst per name", () => {
  // The names a run can ledger: the run's channels (stage B: p1, c1, c2, d1, d2, env, content, limits, sdk,
  // auth; stage C: six of channel-order, two of channel-busy, five of channel-ids (a final hyphen, 63
  // characters, the two of the mismatch, the one of the creation without a channelId) and one of
  // publish-boundaries) and the ID probes (six; the one-character one and the leading-hyphen one; and the
  // location that cannot exist).
  const names = 10 + 6 + 2 + 5 + 1 + (6 + 2 + 1);
  // Per name, at most: 4 reads of a pending creation's operation, 1 read by name, 1 deletion, 15 polls of
  // its operation and 3 read-backs; and two lists of a location.
  const perName = 4 + 1 + 1 + 15 + 3;
  assert.ok(
    CLEANUP_BUDGET >= names * perName + 2 * 20,
    `${CLEANUP_BUDGET} < ${names * perName + 40}`,
  );
});
