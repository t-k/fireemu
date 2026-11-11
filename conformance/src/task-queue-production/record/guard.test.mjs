// The allowlist: every request of the program passes, and nothing else does (another run's names, another host, a body that
// is not a step of the program, a mutation of anything the run did not create).
import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { PROGRAM, materialize } from "../corpus.mjs";
import {
  PROJECT,
  REGION,
  ROLE_IDS,
  functionName,
  functionOfRole,
  functionsOf,
  packageIds,
  sourceBuckets,
} from "../plan.mjs";
import { createGuard, matchRule, ownPackages, queueIdsOf, rules } from "./guard.mjs";

const RUN = "0123456789abcdef";
const OTHER = "fedcba9876543210";
const NUMBER = "123456789012";
const targets = Object.fromEntries(
  ROLE_IDS.map((role) => [
    role,
    {
      uri: "https://" + role + "-abc-uc.a.run.app",
      serviceAccountEmail: "x@y.gserviceaccount.com",
    },
  ]),
);
const armed = (runId = RUN) => {
  const guard = createGuard(runId, NUMBER);
  guard.setTargets(targets);
  return guard;
};
const fn = (role) => functionOfRole(RUN, role);
const TASKS = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}`;

test("every step of the program is allowed, and the creates and deletes are mutations", () => {
  const guard = armed();
  for (const spec of PROGRAM) {
    const request = materialize(spec, { runId: RUN, now: 1_800_000_000_000, targets });
    assert.equal(guard.allow(request), true, spec.key);
    assert.equal(
      guard.isMutation(request),
      spec.kind === "create" || spec.kind === "delete",
      spec.key,
    );
  }
});

test("before the readbacks no createTask is allowed, and a program of another run is not allowed", () => {
  const request = (runId) => {
    const spec = PROGRAM.find((s) => s.key === "env-default");
    return materialize(spec, { runId, now: 0, targets });
  };
  assert.equal(createGuard(RUN, NUMBER).allow(request(RUN)), false);
  assert.equal(armed().allow(request(RUN)), true);
  assert.equal(armed().allow(request(OTHER)), false);
});

test("a createTask is refused when its body is not a step of the program", () => {
  const guard = armed();
  const spec = PROGRAM.find((s) => s.key === "env-named");
  const good = materialize(spec, { runId: RUN, now: 0, targets });
  const with_ = (change) => {
    const copy = structuredClone(good);
    change(copy.json);
    return copy;
  };
  assert.equal(guard.allow(good), true);
  for (const change of [
    (j) => (j.task.httpRequest.url = "https://example.com/"),
    (j) => (j.task.httpRequest.url = "http://169.254.169.254/"),
    (j) => (j.task.httpRequest.oidcToken.audience = "https://example.com/"),
    (j) => (j.task.httpRequest.headers.Extra = "1"),
    (j) => (j.task.name = j.task.name.replace(RUN, OTHER)),
    (j) => (j.task.name = "projects/other/locations/us-central1/queues/q/tasks/a"),
    (j) => (j.other = 1),
  ])
    assert.equal(guard.allow(with_(change)), false, change.toString());
  assert.equal(guard.allow({ ...good, method: "PUT" }), false);
  assert.equal(guard.allow({ ...good, url: good.url + "?x=1" }), false);
  assert.equal(guard.allow({ ...good, url: good.url.replace("/v2/", "/v1/") }), false);
  assert.equal(
    guard.allow({ ...good, url: good.url.replace("cloudtasks.googleapis.com", "evil.example") }),
    false,
  );
  assert.equal(
    guard.allow({
      ...good,
      url: good.url.replace(fn("tqdef"), "tqdef" + OTHER.slice(0, 6)),
    }),
    false,
  );
});

test("a task is read and deleted only by a name of the program, and a queue only by deleting the run's own", () => {
  const guard = armed();
  const q = (role) => `${TASKS}/queues/${fn(role)}`;
  const name = (role, id) => `${q(role)}/tasks/tqrun-${RUN}-${id}`;
  assert.equal(guard.allow({ method: "DELETE", url: name("tqdef", "dup-sched") }), true);
  assert.equal(guard.allow({ method: "GET", url: name("tqdef", "dup-first") }), true);
  assert.equal(guard.allow({ method: "DELETE", url: name("tqdef", "env-default") }), false);
  assert.equal(guard.allow({ method: "DELETE", url: name("tqretry", "dup-sched") }), false);
  assert.equal(
    guard.allow({ method: "DELETE", url: `${q("tqdef")}/tasks/tqrun-${OTHER}-dup-sched` }),
    false,
  );
  assert.equal(guard.allow({ method: "DELETE", url: `${TASKS}/queues/other/tasks/x` }), false);
  // A queue: read (including the one that is never deployed) and delete the run's functions' only.
  assert.equal(guard.allow({ method: "GET", url: q("tqdef") }), true);
  assert.equal(
    guard.allow({ method: "GET", url: `${TASKS}/queues/tqnone${RUN.slice(0, 6)}` }),
    true,
  );
  assert.equal(guard.allow({ method: "DELETE", url: q("tqrate") }), true);
  assert.equal(
    guard.allow({ method: "DELETE", url: `${TASKS}/queues/tqnone${RUN.slice(0, 6)}` }),
    false,
  );
  assert.equal(
    guard.allow({ method: "DELETE", url: `${TASKS}/queues/tqdef${OTHER.slice(0, 6)}` }),
    false,
  );
  assert.equal(guard.allow({ method: "DELETE", url: `${TASKS}/queues/default` }), false);
  assert.equal(guard.allow({ method: "POST", url: `${q("tqdef")}:purge`, json: {} }), false);
  assert.equal(guard.allow({ method: "POST", url: `${q("tqdef")}:pause`, json: {} }), false);
  assert.equal(guard.allow({ method: "PATCH", url: q("tqdef"), json: {} }), false);
  assert.equal(guard.allow({ method: "POST", url: `${TASKS}/queues`, json: {} }), false);
});

test("functions, packages and the upload object are deleted only by the run's own names", () => {
  const guard = armed();
  const gcf = "https://cloudfunctions.googleapis.com/v2/";
  for (const f of functionsOf(RUN)) {
    assert.equal(guard.allow({ method: "DELETE", url: gcf + functionName(f) }), true);
    assert.equal(guard.allow({ method: "GET", url: gcf + functionName(f) }), true);
  }
  assert.equal(
    guard.allow({ method: "DELETE", url: gcf + functionName("tqdef" + OTHER.slice(0, 6)) }),
    false,
  );
  assert.equal(guard.allow({ method: "DELETE", url: gcf + functionName("other") }), false);
  const registry = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts/packages/`;
  for (const id of ownPackages(RUN)) {
    assert.equal(guard.allow({ method: "DELETE", url: registry + id }), true);
  }
  assert.equal(
    guard.allow({ method: "DELETE", url: registry + packageIds("tqdef" + OTHER.slice(0, 6))[0] }),
    false,
  );
  // The upload bucket object: adoption by name first, then metadata read and a delete by generation.
  const uploads = sourceBuckets(NUMBER)[0];
  const object = "514cacbe-3258-46fd-9a02-54b7485b0001.zip";
  const url = `https://storage.googleapis.com/storage/v1/b/${uploads}/o/${object}`;
  assert.equal(guard.allow({ method: "DELETE", url: url + "?ifGenerationMatch=17" }), false);
  assert.equal(guard.adoptObject(uploads, "../x"), false);
  assert.equal(guard.adoptObject(sourceBuckets(NUMBER)[1], object), false);
  assert.equal(guard.adoptObject(uploads, object), true);
  assert.equal(guard.allow({ method: "DELETE", url: url + "?ifGenerationMatch=17" }), true);
  assert.equal(guard.allow({ method: "DELETE", url }), false, "a delete without a generation");
  assert.equal(guard.allow({ method: "GET", url: url + "?fields=bucket,name,generation" }), true);
  assert.equal(guard.allow({ method: "GET", url: url + "?alt=media" }), false);
  assert.deepEqual(guard.adoptedObjects(), [uploads + "/" + object]);
});

test("nothing outside the recording's services is allowed, and a log read must be the recorder's own", () => {
  const guard = armed();
  for (const request of [
    {
      method: "POST",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/t:publish`,
      json: {},
    },
    {
      method: "PUT",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/t`,
      json: {},
    },
    {
      method: "POST",
      url: `https://cloudscheduler.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/jobs/j:run`,
      json: {},
    },
    {
      method: "POST",
      url: `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services:batchEnable`,
      json: { serviceIds: ["cloudtasks.googleapis.com"] },
    },
    {
      method: "POST",
      url: `https://run.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/services/${fn("tqdef")}:setIamPolicy`,
      json: { policy: {} },
    },
    {
      method: "DELETE",
      url: `https://eventarc.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/channels/firebase`,
    },
    {
      method: "POST",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/x`,
      json: { fields: {} },
    },
  ])
    assert.equal(guard.allow(request), false, request.url);
  const log = (json) => ({
    method: "POST",
    url: "https://logging.googleapis.com/v2/entries:list",
    json,
  });
  const good = {
    resourceNames: ["projects/" + PROJECT],
    filter: 'resource.type="cloud_run_revision"',
    orderBy: "timestamp asc",
    pageSize: 200,
  };
  assert.equal(guard.allow(log(good)), true);
  assert.equal(guard.isMutation(log(good)), false);
  assert.equal(guard.allow(log({ ...good, resourceNames: ["projects/other"] })), false);
  assert.equal(guard.allow(log({ ...good, pageSize: 1000 })), false);
  assert.equal(guard.allow(log({ ...good, extra: 1 })), false);
  assert.equal(guard.allow(log({ ...good, filter: "x".repeat(6000) })), false);
});

test("a rule needs https, no port, no credentials in the URL and no repeated query key", () => {
  const list = rules(RUN, NUMBER);
  const url = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`;
  assert.ok(matchRule({ method: "GET", url }, list));
  assert.equal(matchRule({ method: "GET", url: url.replace("https", "http") }, list), null);
  assert.equal(matchRule({ method: "GET", url: url.replace(".com", ".com:8443") }, list), null);
  assert.equal(
    matchRule({ method: "GET", url: url.replace("https://", "https://u:p@") }, list),
    null,
  );
  assert.equal(matchRule({ method: "GET", url: url + "#x" }, list), null);
  assert.equal(matchRule({ method: "GET", url: url + "?pageSize=500&pageSize=500" }, list), null);
  assert.ok(matchRule({ method: "GET", url: url + "?pageSize=500" }, list));
  assert.equal(matchRule({ method: "GET", url: url + "?pageSize=5" }, list), null);
  assert.equal(matchRule({ method: "GET", url: "not a url" }, list), null);
  assert.equal(queueIdsOf(RUN).length, ROLE_IDS.length + 1);
  assert.ok(queueIdsOf(RUN).includes("tqnone" + RUN.slice(0, 6)));
});

test("the shapes follow the targets: a new set of targets is a new set of planned bodies", () => {
  const guard = armed();
  const spec = PROGRAM.find((s) => s.key === "env-default");
  const mine = materialize(spec, { runId: RUN, now: 0, targets });
  assert.equal(guard.allow(mine), true);
  const other = Object.fromEntries(
    ROLE_IDS.map((role) => [
      role,
      {
        uri: "https://" + role + "-zzz-uc.a.run.app",
        serviceAccountEmail: "x@y.gserviceaccount.com",
      },
    ]),
  );
  guard.setTargets(other);
  assert.equal(guard.allow(mine), false, "the old function URL is no longer planned");
  assert.equal(guard.allow(materialize(spec, { runId: RUN, now: 0, targets: other })), true);
});

test("a task is read only by a planned name, and a log read must be ordered oldest first", () => {
  const guard = armed();
  const q = (role) => `${TASKS}/queues/${fn(role)}`;
  assert.equal(
    guard.allow({ method: "GET", url: `${q("tqdef")}/tasks/tqrun-${RUN}-env-default` }),
    false,
  );
  assert.equal(
    guard.allow({ method: "GET", url: `${q("tqdef")}/tasks/tqrun-${RUN}-dup-sched` }),
    true,
  );
  const log = (json) => ({
    method: "POST",
    url: "https://logging.googleapis.com/v2/entries:list",
    json,
  });
  const base = { resourceNames: ["projects/" + PROJECT], filter: "f", pageSize: 200 };
  assert.equal(guard.allow(log({ ...base, orderBy: "timestamp asc" })), true);
  assert.equal(guard.allow(log(base)), false, "no order");
  assert.equal(guard.allow(log({ ...base, orderBy: "timestamp desc" })), false);
});

test("a createTask body is allowed only on the queue of its own step", () => {
  const guard = armed();
  const spec = PROGRAM.find((s) => s.key === "env-named");
  const mine = materialize(spec, { runId: RUN, now: 0, targets });
  assert.equal(guard.allow(mine), true);
  const elsewhere = { ...mine, url: mine.url.replace(fn("tqdef"), fn("tqretry")) };
  assert.equal(guard.allow(elsewhere), false, "the same body to another queue");
  const absent = { ...mine, url: mine.url.replace(fn("tqdef"), "tqnone" + RUN.slice(0, 6)) };
  assert.equal(guard.allow(absent), false, "the same body to the queue that is never deployed");
  const probe = PROGRAM.find((s) => s.key === "err-queue-missing");
  const onAbsent = materialize(probe, { runId: RUN, now: 0, targets });
  assert.equal(guard.allow(onAbsent), true);
  assert.equal(guard.allow({ ...onAbsent, url: onAbsent.url.replace("tqnone", "tqdef") }), false);
});

test("a query key that is a property of every object is refused, not thrown at", () => {
  const list = rules(RUN, NUMBER);
  const url = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`;
  for (const key of ["__proto__", "constructor", "toString", "hasOwnProperty"])
    assert.equal(matchRule({ method: "GET", url: url + "?" + key + "=1" }, list), null, key);
});

test("the shared image repository is read and never written", () => {
  const guard = armed();
  const url = `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/repositories/gcf-artifacts`;
  assert.equal(guard.allow({ method: "GET", url }), true);
  for (const method of ["PATCH", "DELETE", "POST", "PUT"])
    assert.equal(guard.allow({ method, url, json: { cleanupPolicies: {} } }), false, method);
  assert.equal(guard.allow({ method: "GET", url: url.replace("gcf-artifacts", "other") }), false);
});
