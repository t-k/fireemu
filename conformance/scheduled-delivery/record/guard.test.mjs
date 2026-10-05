// The delivery recorder's allowlist: every request class it may send, and the near misses it refuses.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, jobIds, matchRule, pullIds, rules, v1TopicIds } from "./guard.mjs";
import { EXTRA_JOBS, extraJobId, pullSubscriptionId, scheduleId } from "./plan.mjs";

const RUN = "0123456789abcdef";
const NUMBER = "123456789012";
const P = "fireemu-oracle-sbx";
const guard = createGuard(RUN, NUMBER);
const spec = (method, url, json) => ({
  id: "t",
  method,
  url,
  ...(json === undefined ? {} : { json }),
});
const SCHED =
  "https://cloudscheduler.googleapis.com/v1/projects/" + P + "/locations/us-central1/jobs";
const PUBSUB = "https://pubsub.googleapis.com/v1/projects/" + P;
const GCF = "https://cloudfunctions.googleapis.com";
const FN = "/projects/" + P + "/locations/us-central1/functions";

const yes = (r) => assert.equal(guard.allow(r), true, r.method + " " + r.url);
const no = (r) => assert.equal(guard.allow(r), false, r.method + " " + r.url);

test("the ids the recorder may touch: five deployed jobs, three extra jobs, two pull subscriptions", () => {
  assert.equal(jobIds(RUN).length, 8);
  assert.deepEqual(
    jobIds(RUN)
      .slice(0, 5)
      .map((id) => id.replace(/-us-central1$/, "")),
    [
      "firebase-schedule-schedOkV2",
      "firebase-schedule-schedRetryV2",
      "firebase-schedule-schedSlowV2",
      "firebase-schedule-schedOkV1",
      "firebase-schedule-schedFailV1",
    ],
  );
  assert.deepEqual(pullIds(RUN), [
    "fe-sd-" + RUN + "-pull-schedokv1",
    "fe-sd-" + RUN + "-pull-schedfailv1",
  ]);
  assert.deepEqual(v1TopicIds(), [
    "firebase-schedule-schedOkV1-us-central1",
    "firebase-schedule-schedFailV1-us-central1",
  ]);
  assert.throws(() => jobIds("nope"), /invalid run ID/);
});

test("the reads of the project's own state are allowed", () => {
  yes(
    spec(
      "GET",
      "https://firebaserules.googleapis.com/v1/projects/" + P + "/releases/cloud.firestore",
    ),
  );
  yes(
    spec(
      "GET",
      "https://serviceusage.googleapis.com/v1/projects/" +
        NUMBER +
        "/services?filter=state:ENABLED&pageSize=200",
    ),
  );
  yes(
    spec(
      "GET",
      "https://serviceusage.googleapis.com/v1/projects/" +
        NUMBER +
        "/services?filter=state:ENABLED&pageSize=200&pageToken=abc",
    ),
  );
  yes(
    spec(
      "POST",
      "https://cloudresourcemanager.googleapis.com/v1/projects/" + P + ":getIamPolicy",
      {},
    ),
  );
  yes(spec("GET", "https://firebase.googleapis.com/v1beta1/projects/" + P + "/adminSdkConfig"));
  yes(spec("GET", "https://appengine.googleapis.com/v1/apps/" + P));
});

test("the function reads and the exact-case deletes are allowed, and nothing else about functions", () => {
  yes(spec("GET", GCF + "/v1" + FN));
  yes(spec("GET", GCF + "/v2" + FN + "?pageToken=abc"));
  yes(spec("GET", GCF + "/v2" + FN + "/schedOkV2"));
  yes(spec("GET", GCF + "/v1" + FN + "/schedFailV1"));
  yes(spec("DELETE", GCF + "/v2" + FN + "/schedRetryV2"));
  yes(spec("DELETE", GCF + "/v1" + FN + "/schedOkV1"));
  yes(spec("GET", GCF + "/v2/projects/" + P + "/locations/us-central1/operations/operation-1-abc"));
  yes(spec("GET", GCF + "/v1/operations/operation-1-abc"));
  for (const r of [
    spec("DELETE", GCF + "/v2" + FN + "/schedokv2"), // lower case
    spec("DELETE", GCF + "/v2" + FN + "/schedOkV1"), // a v1 name on the v2 API
    spec("DELETE", GCF + "/v1" + FN + "/schedOkV2"), // a v2 name on the v1 API
    spec("DELETE", GCF + "/v2" + FN + "/schedOkV2x"),
    spec("DELETE", GCF + "/v2" + FN + "/schedOkV2/"),
    spec("DELETE", GCF + "/v2" + FN + "/schedOkV2?force=true"),
    spec("DELETE", GCF + "/v2/projects/" + P + "/locations/us-east1/functions/schedOkV2"),
    spec("DELETE", GCF + "/v2" + FN),
    spec("POST", GCF + "/v2" + FN, {}),
    spec("PATCH", GCF + "/v2" + FN + "/schedOkV2", {}),
    spec("GET", GCF + "/v2/projects/other/locations/us-central1/functions"),
    spec("GET", GCF + "/v2/projects/" + P + "/locations/us-east1/functions"),
    spec("GET", GCF + "/v2" + FN + "?other=1"),
  ])
    no(r);
});

test("Cloud Run and Artifact Registry are read only", () => {
  yes(
    spec("GET", "https://run.googleapis.com/v2/projects/" + P + "/locations/us-central1/services"),
  );
  yes(
    spec(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        P +
        "/locations/us-central1/repositories",
    ),
  );
  yes(
    spec(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        P +
        "/locations/us-central1/repositories/gcf-artifacts",
    ),
  );
  yes(
    spec(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        P +
        "/locations/us-central1/repositories/gcf-artifacts/packages?pageSize=100",
    ),
  );
  for (const r of [
    spec(
      "DELETE",
      "https://run.googleapis.com/v2/projects/" + P + "/locations/us-central1/services/schedokv2",
    ),
    spec(
      "DELETE",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        P +
        "/locations/us-central1/repositories/gcf-artifacts",
    ),
    spec(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        P +
        "/locations/us-east1/repositories",
    ),
    spec(
      "GET",
      "https://artifactregistry.googleapis.com/v1/projects/" +
        P +
        "/locations/us-central1/repositories/other",
    ),
  ])
    no(r);
});

test("Cloud Scheduler: the eight jobs, the run, the pause, the delete and the create of the extra jobs", () => {
  const deployed = scheduleId("schedRetryV2");
  const extra = extraJobId(RUN, "zero");
  yes(spec("GET", SCHED + "?pageSize=500"));
  for (const id of [deployed, extra]) {
    yes(spec("GET", SCHED + "/" + id));
    yes(spec("POST", SCHED + "/" + id + ":run", {}));
    yes(spec("POST", SCHED + "/" + id + ":pause", {}));
    yes(spec("DELETE", SCHED + "/" + id));
  }
  yes(spec("POST", SCHED, { name: "projects/" + P + "/locations/us-central1/jobs/" + extra }));
  for (const r of [
    spec("POST", SCHED, { name: "projects/" + P + "/locations/us-central1/jobs/" + deployed }), // a deployed job is not created
    spec("POST", SCHED, { name: "projects/" + P + "/locations/us-central1/jobs/other" }),
    spec("POST", SCHED, { name: "projects/other/locations/us-central1/jobs/" + extra }),
    spec("POST", SCHED, {}),
    spec("POST", SCHED),
    spec("GET", SCHED + "/other"),
    spec("DELETE", SCHED + "/other"),
    spec("POST", SCHED + "/other:run", {}),
    spec("POST", SCHED + "/" + deployed + ":resume", {}),
    spec("PATCH", SCHED + "/" + deployed, {}),
    spec("DELETE", SCHED + "/" + deployed + "x"),
    spec("DELETE", SCHED + "/" + extraJobId("fedcba9876543210", "zero")),
    spec("POST", SCHED + "/" + deployed + ":run", { force: true }),
    spec("GET", SCHED + "?pageSize=100"),
    spec(
      "GET",
      "https://cloudscheduler.googleapis.com/v1/projects/" +
        P +
        "/locations/us-east1/jobs?pageSize=500",
    ),
  ])
    no(r);
});

test("Pub/Sub: the two v1 topics, the two pull subscriptions, pull and acknowledge", () => {
  const topic = v1TopicIds()[0];
  const sub = pullSubscriptionId(RUN, "schedOkV1");
  yes(spec("GET", PUBSUB + "/topics?pageSize=1000"));
  yes(spec("GET", PUBSUB + "/subscriptions?pageSize=1000"));
  yes(spec("GET", PUBSUB + "/topics/" + topic));
  yes(spec("DELETE", PUBSUB + "/topics/" + topic));
  yes(
    spec("PUT", PUBSUB + "/subscriptions/" + sub, {
      topic: "projects/" + P + "/topics/" + topic,
      ackDeadlineSeconds: 10,
    }),
  );
  yes(spec("GET", PUBSUB + "/subscriptions/" + sub));
  yes(spec("DELETE", PUBSUB + "/subscriptions/" + sub));
  yes(spec("POST", PUBSUB + "/subscriptions/" + sub + ":pull", { maxMessages: 10 }));
  yes(
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":pull", {
      maxMessages: 1,
      returnImmediately: true,
    }),
  );
  yes(spec("POST", PUBSUB + "/subscriptions/" + sub + ":acknowledge", { ackIds: ["a", "b"] }));
  for (const r of [
    spec("DELETE", PUBSUB + "/topics/other"),
    spec("PUT", PUBSUB + "/topics/" + topic, {}),
    spec("PUT", PUBSUB + "/subscriptions/other", {
      topic: "projects/" + P + "/topics/" + topic,
      ackDeadlineSeconds: 10,
    }),
    spec("PUT", PUBSUB + "/subscriptions/" + sub, {
      topic: "projects/" + P + "/topics/other",
      ackDeadlineSeconds: 10,
    }),
    spec("PUT", PUBSUB + "/subscriptions/" + sub, {
      topic: "projects/" + P + "/topics/" + topic,
      ackDeadlineSeconds: 600,
    }),
    spec("PUT", PUBSUB + "/subscriptions/" + sub, {
      topic: "projects/" + P + "/topics/" + topic,
      ackDeadlineSeconds: 10,
      pushConfig: { pushEndpoint: "https://evil.example" },
    }),
    spec("PUT", PUBSUB + "/subscriptions/" + sub),
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":pull", { maxMessages: 11 }),
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":pull", { maxMessages: 0 }),
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":pull", {}),
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":acknowledge", { ackIds: [] }),
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":acknowledge", { ackIds: [1] }),
    spec("POST", PUBSUB + "/subscriptions/" + sub + ":modifyAckDeadline", {
      ackIds: ["a"],
      ackDeadlineSeconds: 0,
    }),
    spec("POST", PUBSUB + "/topics/" + topic + ":publish", { messages: [{ data: "eA==" }] }),
    spec("GET", PUBSUB + "/topics?pageSize=100"),
  ])
    no(r);
});

test("Cloud Logging reads: only the recorder's own project, ascending, at most 200 per page", () => {
  const body = {
    resourceNames: ["projects/" + P],
    filter: 'resource.type="cloud_run_revision"',
    orderBy: "timestamp asc",
    pageSize: 200,
  };
  yes(spec("POST", "https://logging.googleapis.com/v2/entries:list", body));
  yes(spec("POST", "https://logging.googleapis.com/v2/entries:list", { ...body, pageToken: "t" }));
  for (const r of [
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      ...body,
      resourceNames: ["projects/other"],
    }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      ...body,
      resourceNames: ["projects/" + P, "projects/other"],
    }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", { ...body, pageSize: 1000 }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      ...body,
      orderBy: "timestamp desc",
    }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      ...body,
      filter: "x".repeat(4000),
    }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", { ...body, extra: 1 }),
    spec("POST", "https://logging.googleapis.com/v2/entries:list", {
      resourceNames: body.resourceNames,
    }),
    spec("POST", "https://logging.googleapis.com/v2/entries:write", body),
    spec("DELETE", "https://logging.googleapis.com/v2/logs/x"),
  ])
    no(r);
});

test("a request that is not plain https to a named host and exact path is refused", () => {
  const ok =
    "https://cloudscheduler.googleapis.com/v1/projects/" +
    P +
    "/locations/us-central1/jobs?pageSize=500";
  yes(spec("GET", ok));
  for (const url of [
    ok.replace("https:", "http:"),
    ok.replace("googleapis.com", "googleapis.com:8443"),
    ok.replace("https://", "https://user:pw@"),
    ok + "#frag",
    ok.replace("pageSize=500", "pageSize=500&pageSize=500"),
    ok + "&pageToken=" + "x".repeat(2049),
    ok + "&pageToken=a b",
    "not a url",
    "https://example.com/v1/projects/" + P + "/locations/us-central1/jobs?pageSize=500",
  ])
    no(spec("GET", url));
  assert.equal(matchRule(spec("GET", "nope"), rules(RUN, NUMBER)), null);
});

test("mutations are the writes and the pull; reads are not", () => {
  const sub = pullSubscriptionId(RUN, "schedOkV1");
  const m = (r) => guard.isMutation(r);
  assert.equal(m(spec("POST", SCHED + "/" + scheduleId("schedOkV2") + ":run", {})), true);
  assert.equal(m(spec("DELETE", SCHED + "/" + scheduleId("schedOkV2"))), true);
  assert.equal(m(spec("DELETE", GCF + "/v2" + FN + "/schedOkV2")), true);
  assert.equal(
    m(
      spec("PUT", PUBSUB + "/subscriptions/" + sub, {
        topic: "projects/" + P + "/topics/" + v1TopicIds()[0],
        ackDeadlineSeconds: 10,
      }),
    ),
    true,
  );
  assert.equal(
    m(spec("POST", PUBSUB + "/subscriptions/" + sub + ":pull", { maxMessages: 10 })),
    true,
  );
  assert.equal(m(spec("GET", SCHED + "?pageSize=500")), false);
  assert.equal(
    m(
      spec(
        "POST",
        "https://cloudresourcemanager.googleapis.com/v1/projects/" + P + ":getIamPolicy",
        {},
      ),
    ),
    false,
  );
  assert.equal(
    m(
      spec("POST", "https://logging.googleapis.com/v2/entries:list", {
        resourceNames: ["projects/" + P],
        filter: "x",
        orderBy: "timestamp asc",
        pageSize: 1,
      }),
    ),
    false,
  );
  assert.equal(m(spec("GET", "https://example.com/")), false);
  assert.equal(EXTRA_JOBS.length, 3);
});
