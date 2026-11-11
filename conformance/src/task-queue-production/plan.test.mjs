// The names and pins of the recording: the forms the guard, the cleanup and the read-back rely on.
import "./record/isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import {
  PROJECT,
  REGION,
  REQUIRED_SERVICES,
  ROLES,
  ROLE_IDS,
  functionName,
  fixtureIdIn,
  functionOfRole,
  functionsOf,
  isOwnUploadObject,
  packageId,
  packageIds,
  queueName,
  roleOf,
  runMarker,
  sourceBuckets,
  suffixOf,
  taskName,
  uploadBucket,
} from "./plan.mjs";

const RUN = "0123456789abcdef";
const NUMBER = "123456789012";

test("a run id is sixteen lower-case hexadecimal digits, and its marker and suffix follow it", () => {
  assert.equal(runMarker(RUN), "tqrun-0123456789abcdef");
  assert.equal(suffixOf(RUN), "012345");
  for (const bad of [
    "",
    "0123456789abcde",
    "0123456789abcdeff",
    "0123456789ABCDEF",
    "0123456789abcdeg",
    undefined,
    null,
  ])
    for (const f of [runMarker, suffixOf]) assert.throws(() => f(bad), /invalid run ID/);
});

test("the eight roles make eight function ids, each a role and the suffix, and a role is read back from its id", () => {
  assert.deepEqual(ROLE_IDS, [
    "tqdef",
    "tqretry",
    "tqlimit",
    "tqwindow",
    "tqconc1",
    "tqconc2",
    "tqrate",
    "tqdead",
  ]);
  assert.deepEqual(
    functionsOf(RUN),
    ROLE_IDS.map((r) => r + "012345"),
  );
  for (const role of ROLE_IDS) {
    assert.equal(functionOfRole(RUN, role), role + "012345");
    assert.equal(roleOf(role + "012345"), role);
    assert.equal(roleOf(role + "01234"), null);
    assert.equal(roleOf(role + "0123456"), null);
  }
  assert.equal(roleOf("other012345"), null);
  assert.throws(() => functionOfRole(RUN, "tqnone"), /unknown role/);
  for (const fn of functionsOf(RUN))
    assert.match(fn, /^[a-z][a-z0-9]{10,}$/, "lower case, no hyphen");
});

test("resource names are the project's, in the region", () => {
  const fn = "tqdef012345";
  assert.equal(functionName(fn), `projects/${PROJECT}/locations/${REGION}/functions/${fn}`);
  assert.equal(queueName(fn), `projects/${PROJECT}/locations/${REGION}/queues/${fn}`);
  assert.equal(taskName(fn, "t1"), `projects/${PROJECT}/locations/${REGION}/queues/${fn}/tasks/t1`);
});

test("the image of a function is two packages with the doubled hyphens the repository uses", () => {
  assert.equal(packageId("tqdef012345"), "fireemu--oracle--events__us--central1__tqdef012345");
  assert.deepEqual(packageIds("tqdef012345"), [
    "fireemu--oracle--events__us--central1__tqdef012345",
    "fireemu--oracle--events__us--central1__tqdef012345%2Fcache",
  ]);
});

test("the two Gen2 buckets are named by the project number, and only the upload bucket's <uuid>.zip is an own upload object", () => {
  const [uploads, sources] = sourceBuckets(NUMBER);
  assert.equal(uploads, `gcf-v2-uploads-${NUMBER}.${REGION}.cloudfunctions.appspot.com`);
  assert.equal(sources, `gcf-v2-sources-${NUMBER}-${REGION}`);
  assert.equal(uploadBucket(NUMBER), uploads);
  const object = "514cacbe-3258-46fd-9a02-54b7485b0001.zip";
  assert.equal(isOwnUploadObject(NUMBER, uploads, object), true);
  assert.equal(isOwnUploadObject(NUMBER, sources, object), false);
  assert.equal(isOwnUploadObject(NUMBER, "other-bucket", object), false);
  for (const name of [
    "a.zip",
    "../" + object,
    object + "x",
    object.toUpperCase(),
    "",
    null,
    undefined,
    3,
  ])
    assert.equal(isOwnUploadObject(NUMBER, uploads, name), false, String(name));
});

test("the queue settings of the roles are the ones the fixture and the CLI mapping are checked against", () => {
  assert.deepEqual(ROLES.tqdef, {});
  assert.deepEqual(ROLES.tqretry.retryConfig, {
    maxAttempts: 6,
    minBackoffSeconds: 1,
    maxBackoffSeconds: 6,
    maxDoublings: 2,
  });
  assert.equal(ROLES.tqwindow.retryConfig.maxRetrySeconds, 6);
  assert.deepEqual(ROLES.tqconc1.rateLimits, {
    maxConcurrentDispatches: 1,
    maxDispatchesPerSecond: 500,
  });
  assert.deepEqual(ROLES.tqconc2.rateLimits, {
    maxConcurrentDispatches: 2,
    maxDispatchesPerSecond: 500,
  });
  assert.deepEqual(ROLES.tqrate.rateLimits, {
    maxConcurrentDispatches: 100,
    maxDispatchesPerSecond: 1,
  });
  assert.throws(() => {
    "use strict";
    ROLES.tqretry.retryConfig.maxAttempts = 1;
  }, TypeError);
});

test("the recording enables no service: every one it needs is required, including Cloud Tasks", () => {
  assert.ok(REQUIRED_SERVICES.includes("cloudtasks.googleapis.com"));
  assert.ok(REQUIRED_SERVICES.includes("cloudfunctions.googleapis.com"));
  assert.ok(!REQUIRED_SERVICES.includes("cloudscheduler.googleapis.com"));
});

test("a fixture id is found in a resource name, an image package id or a bare id, for any run", () => {
  assert.equal(fixtureIdIn("tqdef012345"), "tqdef012345");
  assert.equal(
    fixtureIdIn(`projects/${PROJECT}/locations/${REGION}/functions/tqretryffffff`),
    "tqretryffffff",
  );
  assert.equal(
    fixtureIdIn(`projects/${PROJECT}/locations/${REGION}/queues/tqrate0a0b0c`),
    "tqrate0a0b0c",
  );
  assert.equal(
    fixtureIdIn("fireemu--oracle--events__us--central1__tqconc1abcdef"),
    "tqconc1abcdef",
  );
  assert.equal(
    fixtureIdIn("fireemu--oracle--events__us--central1__tqconc1abcdef%2Fcache"),
    "tqconc1abcdef",
  );
  assert.equal(fixtureIdIn(`projects/p/locations/l/queues/tqdef012345/`), "tqdef012345");
  for (const other of [
    "tqdef01234",
    "tqdef0123456",
    "tqdef01234g",
    "tqnone012345",
    "tqdef012345x",
    "xtqdef012345",
    "default",
    "",
    null,
    undefined,
    "projects/p/locations/l/queues/",
  ])
    assert.equal(fixtureIdIn(other), null, String(other));
});
