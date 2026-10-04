import assert from "node:assert/strict";
import test from "node:test";

import { RECOVERY_RULES, RULES, destination } from "./functions-events/record/guard.mjs";

const P = "fireemu-oracle-events";
const fn = (region, id) =>
  `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/${region}/functions/${id}`;
const allowed = (request) => destination(request, RECOVERY_RULES).rule;
const refusal = (request) => destination(request, RECOVERY_RULES).problem;
const get = (url) => ({ method: "GET", url, mutation: false });
const del = (url) => ({ method: "DELETE", url, mutation: true });

test("the recovery rules allow each named delete and read, and the operation and list reads of both regions", () => {
  assert.equal(allowed(del(fn("us-central1", "storageArchivedV2"))), "recovery-function-delete");
  assert.equal(allowed(del(fn("us-east1", "pubsubPublishedV2"))), "recovery-function-delete");
  assert.equal(allowed(get(fn("us-central1", "storageArchivedV2"))), "recovery-function-get");
  for (const region of ["us-central1", "us-east1"]) {
    assert.equal(
      allowed(
        get(
          `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/${region}/operations/operation-1791131667207-65d0656c5167c-7952d5be-c715c3b6`,
        ),
      ),
      "recovery-operation-get",
    );
    for (const [host, path, name] of [
      ["cloudfunctions.googleapis.com", "v1", "functions"],
      ["cloudfunctions.googleapis.com", "v2", "functions"],
      ["run.googleapis.com", "v2", "services"],
      ["eventarc.googleapis.com", "v1", "triggers"],
    ])
      assert.ok(
        allowed(get(`https://${host}/${path}/projects/${P}/locations/${region}/${name}`)),
        `${host} ${region}`,
      );
    assert.equal(
      allowed(
        get(
          `https://artifactregistry.googleapis.com/v1/projects/${P}/locations/${region}/repositories/gcf-artifacts`,
        ),
      ),
      "recovery-artifact-registry-read",
    );
  }
  for (const id of [
    "eventarc-us-east1-pubsubpublishedv2-974238-sub-583",
    "eventarc-us-central1-storagearchivedv2-494903-sub-488",
  ]) {
    assert.equal(
      allowed(del(`https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/${id}`)),
      "recovery-subscription-delete",
    );
    assert.equal(
      allowed(get(`https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/${id}`)),
      "recovery-subscription-get",
    );
  }
  const topic = "eventarc-us-central1-storagearchivedv2-494903-679";
  assert.equal(
    allowed(del(`https://pubsub.googleapis.com/v1/projects/${P}/topics/${topic}`)),
    "recovery-topic-delete",
  );
  assert.equal(
    allowed(get(`https://pubsub.googleapis.com/v1/projects/${P}/topics?pageSize=100`)),
    "pubsub-topic-list",
  );
  assert.equal(
    allowed(get(`https://pubsub.googleapis.com/v1/projects/${P}/subscriptions?pageSize=100`)),
    "pubsub-subscription-list",
  );
  assert.ok(
    allowed(
      get("https://storage.googleapis.com/storage/v1/b/fireemu-oracle-events.firebasestorage.app"),
    ),
  );
});

test("the recovery rules refuse a name that is not written out: another function, region, prefix, suffix or project", () => {
  const refused = [
    del(fn("us-east1", "storageArchivedV2")),
    del(fn("us-central1", "pubsubPublishedV2")),
    del(fn("us-central1", "storageArchivedV1")),
    del(fn("us-central1", "storageArchivedV2x")),
    del(fn("us-central1", "storageArchivedV")),
    del(fn("us-west1", "storageArchivedV2")),
    del(fn("us-central1", "fsCreatedV2")),
    del(
      `https://cloudfunctions.googleapis.com/v2/projects/other-project/locations/us-central1/functions/storageArchivedV2`,
    ),
    del(`${fn("us-central1", "storageArchivedV2")}/`),
    del(`${fn("us-central1", "storageArchivedV2")}?force=true`),
    del(
      `https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/eventarc-us-east1-pubsubpublishedv2-974238-sub-5830`,
    ),
    del(
      `https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/eventarc-us-east1-pubsubpublishedv2-974238-sub-58`,
    ),
    del(
      `https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/x-eventarc-us-east1-pubsubpublishedv2-974238-sub-583`,
    ),
    del(
      `https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/eventarc-us-central1-fscreatedv2-676495-673`,
    ),
    del(`https://pubsub.googleapis.com/v1/projects/${P}/topics/fe-events-primary`),
    del(
      `https://pubsub.googleapis.com/v1/projects/${P}/topics/eventarc-us-central1-storagearchivedv2-494903-6790`,
    ),
    del(
      `https://pubsub.googleapis.com/v1/projects/${P}/topics/eventarc-us-central1-fscreatedv2-676495-673`,
    ),
    del(
      `https://pubsub.googleapis.com/v1/projects/other-project/topics/eventarc-us-central1-storagearchivedv2-494903-679`,
    ),
    del(
      `https://run.googleapis.com/v2/projects/${P}/locations/us-central1/services/storagearchivedv2`,
    ),
    del(
      `https://eventarc.googleapis.com/v1/projects/${P}/locations/us-central1/triggers/storagearchivedv2-494903`,
    ),
    del("https://storage.googleapis.com/storage/v1/b/fireemu-oracle-events.firebasestorage.app"),
    get(`https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/us-west1/functions`),
    get(`https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/-/functions`),
    get(
      `https://cloudfunctions.googleapis.com/v2/projects/${P}/locations/us-east1/operations/..%2Ffunctions`,
    ),
    get(
      `https://artifactregistry.googleapis.com/v1/projects/${P}/locations/us-west1/repositories/gcf-artifacts`,
    ),
    get(
      `https://artifactregistry.googleapis.com/v1/projects/${P}/locations/us-east1/repositories/gcf-artifacts/packages`,
    ),
    {
      method: "POST",
      url: `${fn("us-central1", "storageArchivedV2")}:generateDownloadUrl`,
      mutation: true,
      body: {},
    },
    { method: "PATCH", url: fn("us-central1", "storageArchivedV2"), mutation: true, body: {} },
    {
      method: "POST",
      url: `https://pubsub.googleapis.com/v1/projects/${P}/topics/eventarc-us-central1-storagearchivedv2-494903-679:publish`,
      mutation: true,
      body: {},
    },
    get("http://cloudfunctions.googleapis.com/v2/projects/x"),
  ];
  for (const request of refused) assert.ok(refusal(request), `${request.method} ${request.url}`);
});

test("a delete must say it changes something, and a read must say it does not", () => {
  assert.match(
    refusal({ method: "DELETE", url: fn("us-central1", "storageArchivedV2"), mutation: false }),
    /mutation=false/,
  );
  assert.match(
    refusal({ method: "GET", url: fn("us-central1", "storageArchivedV2"), mutation: true }),
    /mutation=true/,
  );
});

test("the recorder's own rules refuse every recovery delete, and the recovery rules refuse the recorder's writes", () => {
  for (const url of [
    fn("us-central1", "storageArchivedV2"),
    fn("us-east1", "pubsubPublishedV2"),
    `https://pubsub.googleapis.com/v1/projects/${P}/subscriptions/eventarc-us-east1-pubsubpublishedv2-974238-sub-583`,
    `https://pubsub.googleapis.com/v1/projects/${P}/topics/eventarc-us-central1-storagearchivedv2-494903-679`,
  ])
    assert.ok(destination(del(url)).problem, url);
  assert.ok(
    destination(get(fn("us-east1", "pubsubPublishedV2"))).problem,
    "the recorder reads no single function",
  );
  for (const request of [
    {
      method: "POST",
      url: `https://firestore.googleapis.com/v1/projects/${P}/databases/(default)/documents/fe_events_primary?documentId=x`,
      mutation: true,
      body: { fields: {} },
    },
    {
      method: "PUT",
      url: `https://pubsub.googleapis.com/v1/projects/${P}/topics/fe-events-primary`,
      mutation: true,
      body: {},
    },
    {
      method: "DELETE",
      url: `https://pubsub.googleapis.com/v1/projects/${P}/topics/fe-events-primary`,
      mutation: true,
    },
  ])
    assert.ok(refusal(request), `${request.method} ${request.url}`);
});

test("every recovery rule is named recovery-* or is one of the three recorder read rules it borrows", () => {
  const borrowed = new Set(["pubsub-topic-list", "pubsub-subscription-list", "storage-bucket-get"]);
  for (const entry of RECOVERY_RULES)
    assert.ok(entry.name.startsWith("recovery-") || borrowed.has(entry.name), entry.name);
  for (const name of borrowed)
    assert.ok(RULES.some((entry) => entry.name === name && !entry.mutation));
  assert.ok(
    RECOVERY_RULES.filter((entry) => entry.mutation).every(
      (entry) => entry.method === "DELETE" && entry.name.endsWith("-delete"),
    ),
  );
  assert.equal(RECOVERY_RULES.filter((entry) => entry.mutation).length, 3);
});
