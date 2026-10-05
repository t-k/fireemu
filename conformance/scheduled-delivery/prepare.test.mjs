// Judges replayed on real recorded bodies, the allowlist, and the class rules of the capture.
import assert from "node:assert/strict";
import test from "node:test";
import { answerClass, isUnknownClass, readable } from "./capture.mjs";
import {
  PROJECT,
  TARGET_SERVICES,
  adminSdkConfigSummary,
  allowedRequest,
  appEngineSummary,
  enabledServices,
  expectedPrincipal,
  iamDiff,
  loggingSummary,
  operationDone,
  operationFailed,
  operationPending,
} from "./prepare.mjs";
import { NUMBER, pretty, recorded } from "./prepare-fake.mjs";

// An answer as the capture builds it, from a recorded body (the recorded layout is pretty JSON).
const answer = (r) => ({
  status: r.status,
  json: r.body,
  rawBytes: Buffer.from(pretty(r.body)),
  bodyBytes: Buffer.byteLength(pretty(r.body)),
});

test("the recorded bodies are the real ones: sizes and shapes the fixture states", () => {
  assert.equal(recorded.servicesEnabledList.recordedBytes, 191873);
  assert.equal(recorded.batchEnableAccepted.recordedBytes, 355);
  assert.equal(recorded.appEngineAbsent.recordedBytes, 391);
  assert.equal(recorded.emptyList.recordedBytes, 3);
  assert.deepEqual(recorded.emptyList.body, {});
  assert.ok(
    !/\b\d{12,13}\b/.test(JSON.stringify(recorded).replaceAll(NUMBER, "")),
    "no project number",
  );
});

test("enabledServices reads the recorded enabled-services list", () => {
  const set = enabledServices(answer(recorded.servicesEnabledList));
  assert.equal(set.size, 58);
  assert.ok(set.has("analyticshub.googleapis.com"));
  assert.equal(enabledServices({ status: 200, json: { services: "x" } }), null);
  assert.equal(enabledServices({ status: 500, json: { services: [] } }), null);
  assert.equal(enabledServices(null), null);
  assert.equal(enabledServices({ status: 200, bodyUnknown: true, json: null }), null);
  assert.deepEqual(
    [...enabledServices({ status: 200, json: {} })],
    [],
    "an empty answer is an empty set",
  );
  // Only ENABLED entries with a config name count.
  const mixed = {
    status: 200,
    json: {
      services: [
        { state: "DISABLED", config: { name: "a.googleapis.com" } },
        { state: "ENABLED", config: { name: "b.googleapis.com" } },
        { state: "ENABLED" },
      ],
    },
  };
  assert.deepEqual([...enabledServices(mixed)], ["b.googleapis.com"]);
});

test("the recorded batchEnable answer is a pending operation and its result is a done one", () => {
  const accepted = answer(recorded.batchEnableAccepted);
  const done = answer(recorded.batchEnableDone);
  assert.equal(operationPending(accepted), true);
  assert.equal(operationDone(accepted), false);
  assert.equal(operationDone(done), true);
  assert.equal(operationPending(done), false);
  assert.equal(operationFailed(done), false);
  assert.equal(operationFailed({ ...done, json: { ...done.json, error: { code: 13 } } }), true);
  assert.equal(
    operationPending({ status: 200, json: { name: "x" } }),
    false,
    "a name must be an operation",
  );
  assert.equal(operationPending({ status: 500, json: accepted.json }), false);
});

test("the recorded App Engine absence is a 404, and logging and the admin SDK config summarize", () => {
  assert.deepEqual(appEngineSummary(answer(recorded.appEngineAbsent)), {
    status: 404,
    exists: false,
  });
  assert.deepEqual(appEngineSummary({ status: 200, json: {} }), { status: 200, exists: true });
  assert.deepEqual(appEngineSummary(null), { status: null });
  assert.deepEqual(loggingSummary({ status: 403, json: {} }), { status: 403, canRead: false });
  assert.deepEqual(loggingSummary({ status: 200, json: { entries: [{}] } }), {
    status: 200,
    canRead: true,
    entries: 1,
  });
  assert.deepEqual(loggingSummary({ status: 200, json: {} }), {
    status: 200,
    canRead: true,
    entries: 0,
  });
  assert.deepEqual(loggingSummary(null), { status: null });
  assert.deepEqual(adminSdkConfigSummary(null), { status: null });
  assert.deepEqual(adminSdkConfigSummary({ status: 403, json: {} }), { status: 403 });
  assert.deepEqual(
    adminSdkConfigSummary({ status: 200, json: { projectId: PROJECT, locationId: "us-central" } }),
    {
      status: 200,
      locationIdPresent: true,
      locationId: "us-central",
      projectIdMatches: true,
    },
  );
  assert.deepEqual(adminSdkConfigSummary({ status: 200, json: { projectId: "other" } }), {
    status: 200,
    locationIdPresent: false,
    projectIdMatches: false,
  });
  assert.equal(
    adminSdkConfigSummary({ status: 200, json: { projectId: PROJECT, locationId: "" } })
      .locationIdPresent,
    false,
  );
});

test("the recorded IAM policy against itself differs by nothing, and added principals are classified", () => {
  const policy = answer(recorded.iamPolicy);
  assert.deepEqual(iamDiff(policy, policy, NUMBER), { added: [], removed: [], unexpected: [] });
  const added = {
    ...policy,
    json: {
      ...policy.json,
      bindings: [
        ...policy.json.bindings,
        {
          role: "roles/x",
          members: ["serviceAccount:service-" + NUMBER + "@gcp-sa-run.iam.gserviceaccount.com"],
        },
        { role: "roles/y", members: ["user:someone@example.com"] },
      ],
    },
  };
  const diff = iamDiff(policy, added, NUMBER);
  assert.equal(diff.added.length, 2);
  assert.deepEqual(diff.unexpected, ["roles/y|user:someone@example.com"]);
  const removed = iamDiff(added, policy, NUMBER);
  assert.equal(removed.removed.length, 2);
  assert.equal(iamDiff(policy, null, NUMBER), null);
  assert.equal(iamDiff({ status: 500, json: {} }, policy, NUMBER), null);
});

test("an expected principal is a Google service account that names this project number", () => {
  const ok = [
    "serviceAccount:" + NUMBER + "-compute@developer.gserviceaccount.com",
    "serviceAccount:service-" + NUMBER + "@gcp-sa-run.iam.gserviceaccount.com",
    "serviceAccount:" + NUMBER + "@cloudservices.gserviceaccount.com",
  ];
  for (const member of ok) assert.equal(expectedPrincipal(member, NUMBER), true, member);
  const refused = [
    "user:a@example.com",
    "group:g@example.com",
    "serviceAccount:" + NUMBER + "-compute@developer.gserviceaccount.com.evil.example",
    "serviceAccount:999999999999-compute@developer.gserviceaccount.com",
    "serviceAccount:" + PROJECT + "@appspot.gserviceaccount.com",
    "serviceAccount:x@" + PROJECT + ".iam.gserviceaccount.com",
    "allUsers",
  ];
  for (const member of refused) assert.equal(expectedPrincipal(member, NUMBER), false, member);
});

// ---- the allowlist ----------------------------------------------------------------------------

const S = "https://serviceusage.googleapis.com/v1/projects/" + NUMBER + "/services";
const spec = (method, url, json) => ({ id: "t", method, url, ...(json ? { json } : {}) });

test("the allowlist admits exactly the reads and the one mutation of the packet", () => {
  const yes = [
    spec(
      "GET",
      "https://firebaserules.googleapis.com/v1/projects/" + PROJECT + "/releases/cloud.firestore",
    ),
    spec("GET", S + "?filter=state:ENABLED&pageSize=200"),
    spec("GET", S + "?filter=state:ENABLED&pageSize=200&pageToken=abc"),
    spec(
      "POST",
      "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":getIamPolicy",
      {},
    ),
    spec("GET", "https://firebase.googleapis.com/v1beta1/projects/" + PROJECT + "/adminSdkConfig"),
    spec("GET", "https://appengine.googleapis.com/v1/apps/" + PROJECT),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      resourceNames: ["projects/" + PROJECT],
      orderBy: "timestamp desc",
      pageSize: 1,
    }),
    spec("POST", S + ":batchEnable", {
      serviceIds: ["run.googleapis.com", "compute.googleapis.com"],
    }),
    spec(
      "GET",
      "https://serviceusage.googleapis.com/v1/operations/acf.p2-" +
        NUMBER +
        "-e627f9a7-0f50-48e6-856c-93ad311e8f0e",
    ),
    spec(
      "GET",
      "https://cloudfunctions.googleapis.com/v1/projects/" +
        PROJECT +
        "/locations/us-central1/functions",
    ),
    spec(
      "GET",
      "https://cloudfunctions.googleapis.com/v2/projects/" +
        PROJECT +
        "/locations/us-central1/functions",
    ),
    spec(
      "GET",
      "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/us-central1/services",
    ),
    spec(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        PROJECT +
        "/locations/us-central1/repositories",
    ),
  ];
  for (const r of yes) assert.equal(allowedRequest(r, NUMBER), true, r.method + " " + r.url);
  const no = [
    spec("POST", S + ":batchEnable", { serviceIds: ["pubsub.googleapis.com"] }),
    spec("POST", S + ":batchEnable", { serviceIds: [] }),
    spec("POST", S + ":batchEnable", {
      serviceIds: ["run.googleapis.com", "bigquery.googleapis.com"],
    }),
    spec("POST", S + ":batchEnable", {}),
    spec("POST", S + ":batchDisable", { serviceIds: ["run.googleapis.com"] }),
    spec("POST", S + "/run.googleapis.com:disable", {}),
    spec("DELETE", S + "?filter=state:ENABLED&pageSize=200"),
    spec("GET", S + "?filter=state:DISABLED&pageSize=200"),
    spec("GET", S + "?filter=state:ENABLED&pageSize=100"),
    spec("GET", S + "?filter=state:ENABLED&pageSize=200&other=1"),
    spec(
      "GET",
      "https://serviceusage.googleapis.com/v1/projects/999999999999/services?filter=state:ENABLED&pageSize=200",
    ),
    spec("GET", "https://serviceusage.googleapis.com/v1/operations/../services"),
    spec(
      "POST",
      "https://cloudresourcemanager.googleapis.com/v1/projects/" + PROJECT + ":setIamPolicy",
      {},
    ),
    spec("POST", "https://cloudresourcemanager.googleapis.com/v1/projects/other:getIamPolicy", {}),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      resourceNames: ["projects/other"],
      orderBy: "timestamp desc",
      pageSize: 1,
    }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      resourceNames: ["projects/" + PROJECT],
      orderBy: "timestamp desc",
      pageSize: 1000,
    }),
    spec("PUT", "https://appengine.googleapis.com/v1/apps/" + PROJECT),
    spec("POST", "https://appengine.googleapis.com/v1/apps", { id: PROJECT }),
    spec(
      "GET",
      "https://cloudfunctions.googleapis.com/v1/projects/" +
        PROJECT +
        "/locations/us-east1/functions",
    ),
    spec(
      "DELETE",
      "https://run.googleapis.com/v2/projects/" + PROJECT + "/locations/us-central1/services",
    ),
    spec("GET", "https://example.com/"),
  ];
  for (const r of no) assert.equal(allowedRequest(r, NUMBER), false, r.method + " " + r.url);
});

test("the target services are the eight the deploy needs and none the sandbox already has", () => {
  assert.equal(TARGET_SERVICES.length, 8);
  assert.equal(new Set(TARGET_SERVICES).size, 8);
  for (const id of [
    "cloudscheduler.googleapis.com",
    "pubsub.googleapis.com",
    "appengine.googleapis.com",
  ])
    assert.ok(!TARGET_SERVICES.includes(id), id);
  assert.ok(Object.isFrozen(TARGET_SERVICES));
});

// ---- the classes ------------------------------------------------------------------------------

test("the classes of an answer", () => {
  for (const [a, name, unknown] of [
    [null, "transport", true],
    [{ status: 200, bodyUnknown: true }, "unreadable", true],
    [{ status: 199 }, "unknown-status", true],
    [{ status: 200 }, "2xx", false],
    [{ status: 299 }, "2xx", false],
    [{ status: 300 }, "unknown-status", true],
    [{ status: 399 }, "unknown-status", true],
    [{ status: 400 }, "4xx", false],
    [{ status: 499 }, "4xx", false],
    [{ status: 500 }, "unknown-status", true],
  ]) {
    assert.equal(answerClass(a), name, JSON.stringify(a));
    assert.equal(isUnknownClass(a), unknown, JSON.stringify(a));
  }
  assert.equal(readable({ status: 200, json: {} }), true);
  assert.equal(readable({ status: 200, json: null }), false);
  assert.equal(readable({ status: 200, json: "x" }), false);
  assert.equal(readable({ status: 200, bodyUnknown: true, json: {} }), false);
});
