// The glue between the CV14 flow and the reviewed parts it runs on: a fetch that adds the token, the log
// reader, the collector of the debug-line forms, the target operations bound to one run, the preflight,
// and the request ceilings. Each piece is checked on its own; the integration test runs them together.

import assert from "node:assert/strict";
import { test } from "node:test";

import { PROJECT } from "../../functions-http/harness.mjs";
import { FRAME_MARKER } from "./frames.mjs";
import { origin } from "./logs.mjs";
import { FIXTURE_HANDLERS } from "./frames.mjs";
import { TARGETS } from "./targets.mjs";
import {
  STAGE2_HOSTS,
  STAGE2_KINDS,
  STAGE2_LIMITS,
  STAGE2_WORST,
  bearerFetch,
  bindOps,
  createFormsCollector,
  createLogReader,
  createStage2Budget,
  preflightStage2,
} from "./wiring.mjs";

test("a fetch that adds the bearer token and the quota project to every request, a fresh token each time", async () => {
  const seen = [];
  let n = 0;
  const base = async (url, init) => {
    seen.push([url, init]);
    return { ok: true };
  };
  const fetchWith = bearerFetch(async () => `tok-${++n}`, PROJECT, base);
  const init = { method: "PUT", headers: { "content-type": "application/json" }, body: "{}" };
  await fetchWith("https://x.test/a", init);
  await fetchWith("https://x.test/b", init);
  assert.equal(seen[0][1].headers.authorization, "Bearer tok-1");
  assert.equal(seen[1][1].headers.authorization, "Bearer tok-2");
  assert.equal(seen[0][1].headers["x-goog-user-project"], PROJECT);
  assert.equal(seen[0][1].headers["content-type"], "application/json");
  assert.deepEqual(
    init.headers,
    { "content-type": "application/json" },
    "the caller's init is not changed",
  );
  assert.equal(seen[0][1].method, "PUT");
});

const entry = (name, n) => {
  const handler = FIXTURE_HANDLERS.find((h) => h.name === name);
  const o = origin(handler);
  return {
    logName: o.logName,
    resource: { type: o.resourceType, labels: o.labels },
    insertId: `i-${name}-${n}`,
    timestamp: "2026-10-27T01:00:00Z",
    textPayload: `${FRAME_MARKER}${JSON.stringify({ handler: name, generation: handler.generation, seq: n, event: {} })}`,
  };
};

test("the log reader asks for the window, reads each frame once across reads, and stops at three pages", async () => {
  const requests = [];
  const pages = [
    { entries: [entry("rtdbCreatedV1", 1)], nextPageToken: "p2" },
    { entries: [entry("rtdbCreatedV2", 1)] },
  ];
  let call = 0;
  const control = async (method, url, body, kind) => {
    requests.push({ method, url, body, kind });
    return { status: 200, value: pages[call++ % 2] };
  };
  const reader = createLogReader({ control, now: () => "2026-10-27T01:00:05Z" });
  const first = await reader.read({ start: "2026-10-27T00:00:00Z", end: "2026-10-27T02:00:00Z" });
  assert.equal(first.complete, true);
  assert.equal(first.frames.length, 2);
  assert.equal(first.entries, 2);
  assert.equal(requests.length, 2);
  assert.ok(requests.every((r) => r.method === "POST" && r.kind === "logs"));
  assert.equal(requests[1].body.pageToken, "p2");
  assert.ok(requests[0].body.filter.includes('timestamp>="2026-10-27T00:00:00Z"'));
  const second = await reader.read({ start: "a", end: "b" });
  assert.equal(second.frames.length, 0, "the same insert ids are not returned twice");

  let endlessCalls = 0;
  const endless = createLogReader({
    control: async () => {
      endlessCalls += 1;
      return { status: 200, value: { entries: [], nextPageToken: "more" } };
    },
    now: () => "t",
  });
  const bounded = await endless.read({ start: "a", end: "b" });
  assert.equal(bounded.complete, false);
  assert.equal(endlessCalls, 3, "three pages and no more");
});

test("a log read that fails is an incomplete read, not an exception", async () => {
  const reader = createLogReader({
    control: async () => {
      throw new Error("bounded logs REST POST returned 503");
    },
    now: () => "t",
  });
  const reply = await reader.read({ start: "a", end: "b" });
  assert.deepEqual(reply, { frames: [], entries: 0, ignored: {}, complete: false });
});

const PN = "424242424242";

test("the forms collector keeps the kind, the status and a masked line, never a project number or a signature", () => {
  const forms = createFormsCollector(PN);
  const v1Line = `[t] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v1/projects/p/locations/us-central1/functions:generateUploadUrl {"uploadUrl":"https://storage.googleapis.com/uploads-100000000001.us-central1.cloudfunctions.appspot.com/o.zip?GoogleAccessId=sa%40x&Signature=SECRETSIG"}`;
  forms.observe(
    {
      type: "external-upload",
      bucket: "uploads-100000000001.us-central1.cloudfunctions.appspot.com",
      object: "o.zip",
    },
    v1Line,
    "rtdbCreatedV1",
  );
  forms.observe(
    {
      type: "put-status",
      bucket: "uploads-100000000001.us-central1.cloudfunctions.appspot.com",
      object: "o.zip",
      status: 200,
    },
    `[t] <<< [apiv2][status] PUT https://storage.googleapis.com/uploads-100000000001.us-central1.cloudfunctions.appspot.com/o.zip 200`,
    "rtdbCreatedV1",
  );
  forms.observe(
    {
      type: "receipt",
      bucket: `gcf-v2-uploads-${PN}.us-central1.cloudfunctions.appspot.com`,
      object: "r.zip",
    },
    `[t] <<< [apiv2][body] POST https://cloudfunctions.googleapis.com/v2/projects/p/locations/us-central1/functions:generateUploadUrl {"uploadUrl":"https://storage.googleapis.com/b/r.zip?Signature=SECRETSIG","storageSource":{"bucket":"gcf-v2-uploads-${PN}.us-central1.cloudfunctions.appspot.com","object":"r.zip"}}`,
    "rtdbCreatedV2",
  );
  forms.observe({ type: "other" }, "x", "rtdbCreatedV2");
  const summary = forms.summary();
  assert.deepEqual(summary.rtdbCreatedV1, {
    receipt: false,
    externalUpload: true,
    putStatusCodes: [200],
  });
  assert.deepEqual(summary.rtdbCreatedV2, {
    receipt: true,
    externalUpload: false,
    putStatusCodes: [],
  });
  const text = forms.maskedLines().join("\n");
  assert.ok(!text.includes(PN) && !text.includes("SECRETSIG") && !text.includes("100000000001"));
  assert.ok(text.includes("123456789012"));
  assert.equal(forms.maskedLines().length, 3);
});

test("the target operations are the 1st gen or 2nd gen ones, bound to this run's control, budget and directory", async () => {
  const calls = [];
  const spy =
    (name) =>
    async (...args) => {
      calls.push([name, args]);
    };
  const impl = {
    assertTargetAbsent: spy("assertTargetAbsent"),
    deployTarget: spy("deployTarget"),
    readDeployedTarget: spy("readDeployedTarget"),
    cleanupTarget: spy("cleanupTarget"),
    assertGen1Absent: spy("assertGen1Absent"),
    assertNoNameCollisions: spy("assertNoNameCollisions"),
    deployGen1: spy("deployGen1"),
    readDeployedGen1: spy("readDeployedGen1"),
    cleanupGen1: spy("cleanupGen1"),
  };
  const getControl = [];
  const control = async (method, url) => {
    getControl.push([method, url]);
    return { status: 200, value: { name: "rec" } };
  };
  const forms = createFormsCollector(PN);
  const ops = bindOps({
    control,
    adcPath: "/adc",
    budget: { b: 1 },
    runDir: "/run",
    uploads: { u: 1 },
    runCli: "cli",
    programId: "cv14-x",
    log: "log",
    sleep: "sleep",
    forms,
    impl,
  });
  const [g1, g1b, , , g2] = TARGETS;
  await ops.gcfv1.assertAbsent(g1);
  assert.deepEqual(
    calls.map(([n]) => n),
    ["assertGen1Absent", "assertNoNameCollisions"],
  );
  assert.equal(
    calls[1][1][1].generation,
    "gcfv2",
    "the collision check reads the name, region and codebase of the twin",
  );
  assert.equal(calls[1][1][1].functionName, g1.functionName);
  calls.length = 0;
  const state = {};
  await ops.gcfv1.deploy(g1, state);
  assert.equal(calls[0][0], "deployGen1");
  assert.deepEqual(calls[0][1].slice(0, 2), [g1, "cv14-x"]);
  await ops.gcfv1.read(g1b, state);
  await ops.gcfv1.cleanup(g1b, state);
  await ops.gcfv2.assertAbsent(g2);
  await ops.gcfv2.deploy(g2, state);
  await ops.gcfv2.read(g2, state);
  await ops.gcfv2.cleanup(g2, state);
  assert.deepEqual(
    calls.map(([n]) => n),
    [
      "deployGen1",
      "readDeployedGen1",
      "cleanupGen1",
      "assertTargetAbsent",
      "deployTarget",
      "readDeployedTarget",
      "cleanupTarget",
    ],
  );
  // a 2nd gen read keeps the function record, which names the Eventarc trigger and topic
  assert.deepEqual(state.record, { name: "rec" });
  assert.ok(getControl.at(-1)[1].includes(`/functions/${g2.functionName}`));
});

test("the preflight needs Cloud Logging enabled, runs the CLI side-effect check and returns the project grants", async () => {
  const order = [];
  const impl = {
    loggingApiState: async () => (order.push("logging"), "ENABLED"),
    preflightCliSideEffects: async () => order.push("cli"),
    readServiceAgentGrants: async (_c, n) => (order.push(`grants ${n}`), { eventarc: ["roles/x"] }),
  };
  const grants = await preflightStage2({ control: () => {}, projectNumber: PN, impl });
  assert.deepEqual(order, ["logging", "cli", `grants ${PN}`]);
  assert.deepEqual(grants, { eventarc: ["roles/x"] });
  for (const state of ["DISABLED", "UNKNOWN", undefined]) {
    order.length = 0;
    await assert.rejects(
      () =>
        preflightStage2({
          control: () => {},
          projectNumber: PN,
          impl: { ...impl, loggingApiState: async () => state },
        }),
      /Cloud Logging is not enabled/,
    );
    assert.deepEqual(order, [], "nothing else is read");
  }
});

test("the ceilings are fixed numbers, the Gen2 and cleanup ones below the global bounds, and the budget has the new kinds", () => {
  assert.deepEqual(STAGE2_LIMITS, {
    invocation: 0,
    auth: 0,
    cliDelete: 0,
    cliDeploy: 8,
    upload: 120,
    token: 12,
    control: 120,
    cleanup: 260,
  });
  assert.deepEqual(STAGE2_KINDS, { logs: 320, inventory: 100 });
  const budget = createStage2Budget();
  const snapshot = budget.snapshot();
  assert.deepEqual(
    Object.keys(snapshot).toSorted(),
    [...Object.keys(STAGE2_LIMITS), ...Object.keys(STAGE2_KINDS)].toSorted(),
  );
  assert.throws(() => budget.take("cliDelete"), /ceiling 0 reached/);
  assert.throws(() => budget.take("invocation"), /ceiling 0 reached/);
  for (let n = 0; n < 8; n += 1) budget.take("cliDeploy");
  assert.throws(() => budget.take("cliDeploy"), /ceiling 8 reached/);
  assert.deepEqual(STAGE2_HOSTS, [
    "https://logging.googleapis.com",
    "https://eventarc.googleapis.com",
    "https://pubsub.googleapis.com",
  ]);
});

test("every ceiling is the worst case counted from the code plus at least a fifth, except the upload one, which is exact", () => {
  const ceilings = { ...STAGE2_LIMITS, ...STAGE2_KINDS };
  for (const [kind, worst] of Object.entries(STAGE2_WORST)) {
    if (kind === "upload") assert.equal(ceilings.upload, worst);
    else assert.ok(ceilings[kind] >= worst * 1.2, `${kind}: ${ceilings[kind]} for ${worst}`);
  }
  // the arithmetic of the comment in wiring.mjs
  assert.equal(88, 6 + 4 * 6 + 4 * 8 + 4 * 6 + 2);
  assert.equal(212, 4 * 36 + 4 * 17);
  assert.equal(243, (7 * 9 + 2 * 3 + 12) * 3);
});
