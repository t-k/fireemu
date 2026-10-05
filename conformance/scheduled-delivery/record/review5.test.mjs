// The first delivery recording (run e0ec2f41, 2026-10-05) stopped because a Gen1 function's Cloud Build build failed
// with "Build error details not available" and the packet had no way to read why. r5 reads, for a function that
// did not become active, its build (one GET) and the build's log lines (one Cloud Logging read), and the fixture's
// retry count is one Cloud Scheduler accepts (it refused 6: "invalid retry count. The retry_count must be a positive
// integer less than 5").
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createGuard } from "./guard.mjs";
import {
  DECLARED,
  EXTRA_JOBS,
  FUNCTIONS,
  PROJECT,
  REGION,
  functionName,
  scheduleId,
} from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const SHORT = { passes: 1, naturalWindowMs: 60_000 };
const BUILD = "2e6013b5-c892-477d-b683-2e716972055b";
const BUILD2 = "9f3b2c1d-0a4e-4b6f-8c7d-1e2f3a4b5c6d";
const here = dirname(fileURLToPath(import.meta.url));

async function go(worldSetup = () => {}, options = {}) {
  const world = createWorld();
  worldSetup(world);
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token",
    save: async (row) => journal.push(row),
    send: world.send,
    runCli: async (o) => {
      const done = await world.runCli(o);
      if (o.action === "deploy") world.afterDeploy?.(world);
      return done;
    },
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
    ...SHORT,
    ...options,
  });
  return { world, journal, result };
}
const buildUrl = (id) =>
  `cloudbuild.googleapis.com/v1/projects/${NUMBER}/locations/${REGION}/builds/${id}`;
const sent = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

/** schedOkV1 ends OFFLINE with a failed build, as in the recorded run. */
const failedGen1 = (w) => {
  w.afterDeploy = () => {
    const name = functionName("schedOkV1");
    w.functionsV1.set(name, {
      name,
      status: "OFFLINE",
      buildId: BUILD,
      buildName: `projects/${NUMBER}/locations/${REGION}/builds/${BUILD}`,
    });
  };
  w.builds.set(BUILD, {
    id: BUILD,
    status: "FAILURE",
    statusDetail: "Build failed: Build error details not available.",
    failureInfo: { type: "USER_BUILD_STEP", detail: "step 3 failed" },
    steps: [
      { name: "ubuntu", status: "SUCCESS" },
      { name: "gcr.io/k8s-skaffold/pack", status: "FAILURE" },
    ],
  });
  w.buildLogs.set(BUILD, [{ insertId: "l1" }, { insertId: "l2" }, { insertId: "l3" }]);
};

test("a function that did not become active has its build and the build's log lines read, once each", async () => {
  const { result, journal } = await go(failedGen1);
  assert.deepEqual(result.buildDiagnostics, [
    {
      function: "schedOkV1",
      buildId: BUILD,
      buildStatus: 200,
      status: "FAILURE",
      statusDetail: "Build failed: Build error details not available.",
      failureInfo: { type: "USER_BUILD_STEP", detail: "step 3 failed" },
      steps: [
        { name: "ubuntu", status: "SUCCESS" },
        { name: "gcr.io/k8s-skaffold/pack", status: "FAILURE" },
      ],
      logsStatus: 200,
      logEntries: 3,
    },
  ]);
  assert.equal(sent(journal).filter((id) => id.startsWith("diagnose-")).length, 2);
  assert.deepEqual(
    sent(journal).filter((id) => id.startsWith("diagnose-")),
    ["diagnose-build-schedOkV1", "diagnose-build-logs-schedOkV1"],
  );
  const logs = journal.find(
    (r) => r.id === "diagnose-build-logs-schedOkV1" && r.state === "before-send",
  );
  assert.deepEqual(logs.json.resourceNames, ["projects/" + PROJECT]);
  assert.equal(logs.json.filter, `resource.type="build" AND resource.labels.build_id="${BUILD}"`);
  const get = journal.find((r) => r.id === "diagnose-build-schedOkV1" && r.state === "before-send");
  assert.equal(get.method, "GET");
  assert.equal(get.url, "https://" + buildUrl(BUILD));
  // the reads judge nothing: the run is as it would be without them (the deploy was incomplete, nothing is left)
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.unknownMutations, 0);
  assert.deepEqual(result.incompleteReads, []);
});

test("a Gen2 function that did not become active is diagnosed through its buildConfig.build", async () => {
  const { result } = await go((w) => {
    w.afterDeploy = () => {
      const name = functionName("schedSlowV2");
      w.functionsV2.set(name, {
        name,
        state: "FAILED",
        buildConfig: { build: `projects/${NUMBER}/locations/${REGION}/builds/${BUILD2}` },
      });
    };
    w.builds.set(BUILD2, { id: BUILD2, status: "TIMEOUT" });
  });
  assert.equal(result.buildDiagnostics.length, 1);
  assert.equal(result.buildDiagnostics[0].function, "schedSlowV2");
  assert.equal(result.buildDiagnostics[0].buildId, BUILD2);
  assert.equal(result.buildDiagnostics[0].status, "TIMEOUT");
  assert.equal(result.buildDiagnostics[0].steps, null);
  assert.equal(result.buildDiagnostics[0].logEntries, 0, "an empty log answer has no entries");
});

test("near misses: active functions, foreign functions, entries with no build, and a build that cannot be read", async () => {
  const clean = await go();
  assert.equal(clean.result.buildDiagnostics, undefined);
  assert.equal(
    sent(clean.journal).some((id) => id.startsWith("diagnose-")),
    false,
  );
  const foreign = await go((w) => {
    w.afterDeploy = () => {
      w.functionsV1.set("projects/fireemu-oracle-sbx/locations/us-central1/functions/other", {
        name: "projects/fireemu-oracle-sbx/locations/us-central1/functions/other",
        status: "OFFLINE",
        buildName: `projects/${NUMBER}/locations/${REGION}/builds/${BUILD}`,
      });
    };
  });
  assert.deepEqual(foreign.result.buildDiagnostics ?? [], []);
  const nobuild = await go((w) => {
    w.afterDeploy = () => {
      const name = functionName("schedOkV1");
      w.functionsV1.set(name, { name, status: "OFFLINE" });
    };
  });
  assert.deepEqual(nobuild.result.buildDiagnostics, [{ function: "schedOkV1", buildId: null }]);
  assert.equal(
    sent(nobuild.journal).some((id) => id.startsWith("diagnose-")),
    false,
  );
  const odd = await go((w) => {
    w.afterDeploy = () => {
      const name = functionName("schedOkV1");
      w.functionsV1.set(name, {
        name,
        status: "OFFLINE",
        buildName: "projects/1/builds/not-an-id",
      });
    };
  });
  assert.deepEqual(odd.result.buildDiagnostics, [{ function: "schedOkV1", buildId: null }]);
});

test("a build that answers 404 or 403 is data, not a stop", async () => {
  const missing = await go((w) => {
    failedGen1(w);
    w.builds.clear();
  });
  assert.equal(missing.result.buildDiagnostics[0].buildStatus, 404);
  assert.equal(missing.result.buildDiagnostics[0].status, null);
  assert.equal(missing.result.cleanup.verified, true);
  const denied = await go((w) => {
    failedGen1(w);
    w.send0 = w.send;
    const original = w.send;
    w.send = async (request) =>
      request.url.includes("cloudbuild.googleapis.com")
        ? reply(403, { error: { code: 403, message: "x", status: "PERMISSION_DENIED" } })
        : original(request);
  });
  assert.equal(denied.result.buildDiagnostics[0].buildStatus, 403);
  assert.equal(denied.result.authStop, undefined);
  assert.equal(denied.result.cleanup.verified, true);
});

// ---- the allowlist -----------------------------------------------------------------------------------------------

test("the Cloud Build rule allows one GET of a build id in this project and region, and nothing near it", () => {
  const guard = createGuard(RUN, NUMBER);
  const url = (rest) => `https://cloudbuild.googleapis.com/v1/projects/${rest}`;
  const ok = { method: "GET", url: url(`${NUMBER}/locations/${REGION}/builds/${BUILD}`) };
  assert.equal(guard.allow(ok), true);
  assert.equal(guard.isMutation(ok), false);
  for (const bad of [
    { ...ok, method: "POST" },
    { ...ok, method: "DELETE" },
    { ...ok, method: "PATCH" },
    { ...ok, url: url(`999999999999/locations/${REGION}/builds/${BUILD}`) },
    { ...ok, url: url(`${NUMBER}/locations/europe-west1/builds/${BUILD}`) },
    { ...ok, url: url(`${NUMBER}/locations/${REGION}/builds/${BUILD.toUpperCase()}`) },
    { ...ok, url: url(`${NUMBER}/locations/${REGION}/builds/${BUILD}0`) },
    { ...ok, url: url(`${NUMBER}/locations/${REGION}/builds/not-a-uuid`) },
    { ...ok, url: url(`${NUMBER}/locations/${REGION}/builds`) },
    { ...ok, url: url(`${NUMBER}/locations/${REGION}/builds/${BUILD}:cancel`) },
    { ...ok, url: url(`${NUMBER}/locations/${REGION}/builds/${BUILD}?alt=media`) },
    { ...ok, url: url(`${NUMBER}/builds/${BUILD}`) },
    { ...ok, url: ok.url.replace("cloudbuild", "cloudbuild2") },
    { ...ok, json: {} },
  ])
    assert.equal(guard.allow(bad), false, JSON.stringify(bad));
});

// ---- the fixture's retry count -----------------------------------------------------------------------------------

test("every retry count the packet declares is one Cloud Scheduler accepts (it refused 6 in run e0ec2f41)", () => {
  const counts = [
    DECLARED.schedRetryV2.retryConfig.retryCount,
    ...EXTRA_JOBS.map((job) => job.retryConfig.retryCount),
  ].filter((n) => n !== undefined);
  assert.ok(counts.length >= 3);
  for (const count of counts) assert.ok(count < 5, String(count));
  assert.equal(
    DECLARED.schedRetryV2.retryConfig.retryCount,
    4,
    "the largest value production's text allows",
  );
  const source = readFileSync(join(here, "../fixture/index.js"), "utf8");
  assert.match(
    source,
    /schedule: "every 5 minutes",\s+timeZone: "Asia\/Tokyo",\s+region: REGION,\s+retryCount: 4,/,
  );
  assert.equal(/retryCount: [5-9]|retryCount: \d\d/.test(source), false);
  assert.ok(FUNCTIONS.v2.includes("schedRetryV2"));
  assert.equal(scheduleId("schedRetryV2"), "firebase-schedule-schedRetryV2-us-central1");
});
