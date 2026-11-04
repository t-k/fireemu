// The allowlist: every request the check sends is allowed and classified, an account can be read or deleted only after this
// run's own sign-up returned it, and anything outside the run's own names, shapes and project is refused.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, matchRule, ownPackages, rules } from "./guard.mjs";
import { CONFIG_URL, PROJECT, SIGN_UP_URL, packageIds, sourceBuckets } from "./plan.mjs";
import { frameFilter, listRequest } from "./logs.mjs";
import { deleteAccount, countAccounts, lookupAccount, signUp, signUpBody } from "./script.mjs";

const RUN = "0123456789abcdef";
const NUMBER = "123456789012";
const ID = "Wd3kJ9xQ2mP7sT4vB8nL5cZ6yH1a";
const guard = () => {
  const g = createGuard(RUN, NUMBER);
  g.adopt(ID);
  return g;
};
const R = `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1`;
const get = (url) => ({ method: "GET", url });

test("the sign-up is allowed with exactly its body, and it is a mutation", () => {
  const g = createGuard(RUN, NUMBER);
  assert.equal(g.allow(signUp(RUN)), true);
  assert.equal(g.isMutation(signUp(RUN)), true);
  for (const bad of [
    { ...signUpBody(RUN), extra: 1 },
    { ...signUpBody(RUN), returnSecureToken: false },
    { ...signUpBody(RUN), email: "someone@example.com" },
    { ...signUpBody(RUN), password: "x" },
    { returnSecureToken: true },
    {},
    undefined,
  ])
    assert.equal(
      g.allow({ method: "POST", url: SIGN_UP_URL, json: bad }),
      false,
      JSON.stringify(bad),
    );
  assert.equal(
    createGuard("ffffffffffffffff", NUMBER).allow(signUp(RUN)),
    false,
    "another run's sign-up",
  );
  assert.equal(
    g.allow({ method: "POST", url: SIGN_UP_URL + "?key=abc", json: signUpBody(RUN) }),
    false,
    "the key is never in the URL",
  );
});

test("an account can be looked up or deleted only after this run's sign-up returned it", () => {
  const g = createGuard(RUN, NUMBER);
  assert.equal(g.allow(lookupAccount(ID)), false);
  assert.equal(g.allow(deleteAccount(ID)), false);
  g.adopt(ID);
  assert.deepEqual(g.adopted(), [ID]);
  assert.equal(g.allow(lookupAccount(ID)), true);
  assert.equal(g.isMutation(lookupAccount(ID)), false);
  assert.equal(g.allow(deleteAccount(ID)), true);
  assert.equal(g.isMutation(deleteAccount(ID)), true);
  assert.equal(g.allow(deleteAccount("Other3kJ9xQ2mP7sT4vB8nL5cZ6y")), false);
  assert.equal(
    g.allow({ method: "POST", url: deleteAccount(ID).url, json: { localId: ID, extra: 1 } }),
    false,
  );
  assert.equal(
    g.allow({ method: "POST", url: deleteAccount(ID).url, json: { localId: [ID] } }),
    false,
  );
  assert.equal(
    g.allow({ method: "POST", url: lookupAccount(ID).url, json: { localId: [ID, ID] } }),
    false,
  );
  assert.equal(
    g.allow({ method: "POST", url: lookupAccount(ID).url, json: { localId: ID } }),
    false,
  );
  assert.equal(
    g.allow({ method: "POST", url: lookupAccount(ID).url, json: { email: ["a@b.c"] } }),
    false,
  );
});

test("only a plausible account id is adopted", () => {
  const g = createGuard(RUN, NUMBER);
  for (const bad of [
    null,
    undefined,
    5,
    "",
    "short",
    "has space in it 123456789012",
    "x".repeat(41),
    "../../etc/passwd-aaaaaaaaaa",
  ])
    g.adopt(bad);
  assert.deepEqual(g.adopted(), []);
  g.adopt("a".repeat(20));
  g.adopt("b".repeat(40));
  assert.deepEqual(g.adopted(), ["a".repeat(20), "b".repeat(40)]);
});

test("the account count read takes exactly its body", () => {
  const g = createGuard(RUN, NUMBER);
  assert.equal(g.allow(countAccounts()), true);
  assert.equal(g.isMutation(countAccounts()), false);
  for (const bad of [
    { returnUserInfo: true },
    { returnUserInfo: false, limit: "10" },
    {},
    undefined,
  ])
    assert.equal(
      g.allow({ method: "POST", url: countAccounts().url, json: bad }),
      false,
      JSON.stringify(bad),
    );
});

test("the setup, readbacks, lists and cleanup requests are allowed, and only the deletes are mutations", () => {
  const g = guard();
  const mutating = [
    { method: "DELETE", url: `${R}/functions/pcblock` },
    ...ownPackages().map((id) => ({
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/${id}`,
    })),
  ];
  for (const spec of mutating) {
    assert.equal(g.allow(spec), true, spec.url);
    assert.equal(g.isMutation(spec), true, spec.url);
  }
  const reads = [
    `https://firebase.googleapis.com/v1beta1/projects/${PROJECT}`,
    `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services?filter=state:ENABLED&pageSize=200`,
    CONFIG_URL,
    `${R}/functions`,
    `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/-/functions?pageToken=abc`,
    `${R}/functions/pcblock`,
    `${R}/operations/operation-1234-abcd`,
    `https://cloudbuild.googleapis.com/v1/projects/${NUMBER}/locations/us-central1/builds/01234567-89ab-cdef-0123-456789abcdef`,
    `https://run.googleapis.com/v2/projects/${PROJECT}/locations/-/services`,
    `https://run.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/services/pcblock`,
    `https://run.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/services/pcblock:getIamPolicy`,
    `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts`,
    `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages?pageSize=100`,
    ...packageIds().map(
      (id) =>
        `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/${id}`,
    ),
    `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/operations/op-1`,
    ...sourceBuckets(NUMBER).map(
      (b) => `https://storage.googleapis.com/storage/v1/b/${b}/o?maxResults=1000`,
    ),
  ];
  for (const url of reads) {
    assert.equal(g.allow(get(url)), true, url);
    assert.equal(g.isMutation(get(url)), false, url);
  }
  const iam = {
    method: "POST",
    url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
    json: {},
  };
  assert.equal(g.allow(iam), true);
  assert.equal(g.isMutation(iam), false);
  const logs = listRequest({
    id: "x",
    filter: frameFilter({ start: "2026-11-05T00:00:00Z", end: "2026-11-05T00:01:00Z" }),
  });
  assert.equal(g.allow(logs), true);
  assert.equal(g.isMutation(logs), false);
});

const REFUSED = [
  [
    "another project",
    get(
      `https://cloudfunctions.googleapis.com/v2/projects/other/locations/us-central1/functions/pcblock`,
    ),
  ],
  ["another function name", get(`${R}/functions/somethingelse`)],
  [
    "another region",
    get(
      `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/europe-west1/functions/pcblock`,
    ),
  ],
  ["deleting another function", { method: "DELETE", url: `${R}/functions/somethingelse` }],
  ["creating a function", { method: "POST", url: `${R}/functions?functionId=pcblock`, json: {} }],
  ["a function delete with a body", { method: "DELETE", url: `${R}/functions/pcblock`, json: {} }],
  [
    "deleting another image",
    {
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/someone-else`,
    },
  ],
  [
    "deleting the repository",
    {
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts`,
    },
  ],
  [
    "writing the configuration",
    {
      method: "PATCH",
      url: `${CONFIG_URL}?updateMask=blockingFunctions`,
      json: { blockingFunctions: {} },
    },
  ],
  ["writing the configuration with PUT", { method: "PUT", url: CONFIG_URL, json: {} }],
  [
    "a configuration read of another project",
    get("https://identitytoolkit.googleapis.com/admin/v2/projects/other/config"),
  ],
  ["a configuration read with a query", get(CONFIG_URL + "?updateMask=x")],
  [
    "setting the service's policy",
    {
      method: "POST",
      url: `https://run.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/services/pcblock:setIamPolicy`,
      json: {},
    },
  ],
  [
    "another service's policy",
    get(
      `https://run.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/services/other:getIamPolicy`,
    ),
  ],
  [
    "setting an IAM policy",
    {
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:setIamPolicy`,
      json: { policy: {} },
    },
  ],
  [
    "enabling a service",
    {
      method: "POST",
      url: `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services/pubsub.googleapis.com:enable`,
      json: {},
    },
  ],
  [
    "a service list of another project number",
    get(
      `https://serviceusage.googleapis.com/v1/projects/999999999999/services?filter=state:ENABLED&pageSize=200`,
    ),
  ],
  [
    "deleting an object of a source bucket",
    {
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${sourceBuckets(NUMBER)[0]}/o/some.zip`,
    },
  ],
  [
    "another bucket's list",
    get(`https://storage.googleapis.com/storage/v1/b/someone-elses-bucket/o?maxResults=1000`),
  ],
  [
    "a source bucket list of another project number",
    get(
      `https://storage.googleapis.com/storage/v1/b/${sourceBuckets("999999999999")[0]}/o?maxResults=1000`,
    ),
  ],
  [
    "a log read of another project",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      json: {
        resourceNames: ["projects/other"],
        filter: "x",
        orderBy: "timestamp asc",
        pageSize: 10,
      },
    },
  ],
  [
    "a log read with extra fields",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      json: {
        resourceNames: ["projects/" + PROJECT],
        filter: "x",
        orderBy: "timestamp asc",
        pageSize: 10,
        extra: 1,
      },
    },
  ],
  [
    "http",
    get(
      `http://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  [
    "a port",
    get(
      `https://cloudfunctions.googleapis.com:8443/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  [
    "user info",
    get(
      `https://user:pw@cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  ["a fragment", get(`${R}/functions#x`)],
  ["a repeated query key", get(`${R}/functions?pageToken=a&pageToken=b`)],
  ["an unknown query key", get(`${R}/functions?filter=x`)],
  ["a body on a read", { method: "GET", url: `${R}/functions`, json: {} }],
  [
    "a host that merely contains an allowed one",
    get(
      `https://cloudfunctions.googleapis.com.evil.example/v2/projects/${PROJECT}/locations/us-central1/functions`,
    ),
  ],
  ["a malformed URL", get("not a url")],
  ["an unknown method", { method: "PATCH", url: `${R}/functions/pcblock`, json: {} }],
  [
    "another Identity Toolkit route",
    {
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:batchDelete`,
      json: {},
    },
  ],
  [
    "a sign-in",
    {
      method: "POST",
      url: "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
      json: signUpBody(RUN),
    },
  ],
];
for (const [name, spec] of REFUSED)
  test(`refused: ${name}`, () => assert.equal(guard().allow(spec), false));

test("a Cloud Build read needs a UUID build id, exactly", () => {
  const build = (id) =>
    get(
      `https://cloudbuild.googleapis.com/v1/projects/${NUMBER}/locations/us-central1/builds/${id}`,
    );
  const g = guard();
  assert.equal(g.allow(build("00000000-0000-0000-0000-000000000000")), true);
  assert.equal(g.allow(build("ffffffff-ffff-ffff-ffff-ffffffffffff")), true);
  for (const bad of [
    "0123456-89ab-cdef-0123-456789abcdef",
    "012345678-89ab-cdef-0123-456789abcdef",
    "01234567-89a-cdef-0123-456789abcdef",
    "01234567-89abc-cdef-0123-456789abcdef",
    "01234567-89ab-cde-0123-456789abcdef",
    "01234567-89ab-cdef0-0123-456789abcdef",
    "01234567-89ab-cdef-012-456789abcdef",
    "01234567-89ab-cdef-01234-456789abcdef",
    "01234567-89ab-cdef-0123-456789abcde",
    "01234567-89ab-cdef-0123-456789abcdef0",
    "01234567-89ab-cdeg-0123-456789abcdef",
  ])
    assert.equal(g.allow(build(bad)), false, bad);
});

test("limits: page tokens, page sizes and the log read", () => {
  const g = guard();
  const list = (token) =>
    get(
      `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/-/functions?pageToken=${token}`,
    );
  assert.equal(g.allow(list("a".repeat(2048))), true);
  assert.equal(g.allow(list("a".repeat(2049))), false);
  assert.equal(g.allow(list("a b")), false);
  const pkgs = (size) =>
    get(
      `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages?pageSize=${size}`,
    );
  assert.equal(g.allow(pkgs(100)), true);
  assert.equal(g.allow(pkgs(101)), false);
  const bucket = (size) =>
    get(
      `https://storage.googleapis.com/storage/v1/b/${sourceBuckets(NUMBER)[1]}/o?maxResults=${size}`,
    );
  assert.equal(g.allow(bucket(1000)), true);
  assert.equal(g.allow(bucket(1001)), false);
  const services = (extra) =>
    get(
      `https://serviceusage.googleapis.com/v1/projects/${NUMBER}/services?filter=state:ENABLED&pageSize=${extra}`,
    );
  assert.equal(g.allow(services(200)), true);
  assert.equal(g.allow(services(201)), false);
  const read = (over) => ({
    method: "POST",
    url: "https://logging.googleapis.com/v2/entries:list",
    json: {
      resourceNames: ["projects/" + PROJECT],
      filter: "x",
      orderBy: "timestamp asc",
      pageSize: 200,
      ...over,
    },
  });
  assert.equal(g.allow(read({})), true);
  assert.equal(g.allow(read({ filter: "x".repeat(5999) })), true);
  assert.equal(g.allow(read({ filter: "x".repeat(6000) })), false);
  assert.equal(g.allow(read({ pageSize: 201 })), false);
  assert.equal(g.allow(read({ orderBy: "timestamp desc" })), false);
});

test("an IAM policy read takes no body or an empty one, and a body must be a plain object", () => {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`;
  const g = guard();
  assert.equal(g.allow({ method: "POST", url }), true);
  assert.equal(g.allow({ method: "POST", url, json: {} }), true);
  for (const bad of [{ a: 1 }, [], null, "x"])
    assert.equal(g.allow({ method: "POST", url, json: bad }), false);
});

test("the own images are exactly the function's two ids, and matchRule finds nothing for a stranger", () => {
  assert.deepEqual(ownPackages(), [
    "fireemu--oracle--idp__us--central1__pcblock",
    "fireemu--oracle--idp__us--central1__pcblock%2Fcache",
  ]);
  assert.equal(matchRule(get("https://example.com/"), rules(RUN, NUMBER)), null);
});
