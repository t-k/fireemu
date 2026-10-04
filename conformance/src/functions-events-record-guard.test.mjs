import assert from "node:assert/strict";
import test from "node:test";

import { RULES, destination, quotaProjectFor } from "./functions-events/record/guard.mjs";
import {
  CONTROL_BUCKET,
  PRIMARY_BUCKET,
  PROJECT,
  buildPass,
  runCleanupRequests,
  runSetupRequests,
} from "./functions-events/record/script.mjs";

const SAMPLE = {
  markerName: `projects/${PROJECT}/databases/(default)/documents/fe_events_retry_markers/abc123`,
  firstGeneration: "1700000000000001",
  secondGeneration: "1700000000000002",
  uid: "u1",
  idToken: "token",
  messageId: "m1",
};
const resolve = (text) =>
  text.replace(/\$\{(\w+)\}/g, (_, name) => SAMPLE[name] ?? assert.fail(`unbound ${name}`));
const sequence = () => {
  let n = 0;
  return (role) => `e${String(++n).padStart(4, "0")}${role}`;
};
const asked = (request) => ({
  method: request.method,
  url: resolve(request.url),
  mutation: request.mutation,
  body:
    request.body === undefined
      ? undefined
      : JSON.parse(
          resolve(
            typeof request.body === "string"
              ? JSON.stringify(request.body)
              : JSON.stringify(request.body),
          ),
        ),
  headers: request.headers,
});

test("every request of the script, the setup and the cleanup matches exactly one rule", () => {
  const requests = [
    ...buildPass({ pass: 1, newId: sequence() }).steps.flatMap((step) => step.requests),
    ...runSetupRequests(),
    ...runCleanupRequests(),
  ];
  const used = new Set();
  for (const request of requests) {
    const answer = destination(asked(request));
    assert.equal(answer.problem, undefined, `${request.id}: ${answer.problem}`);
    used.add(answer.rule);
  }
  assert.ok(used.size >= 20, `only ${used.size} rules were exercised`);
});

test("rule names are unique and a rule says whether it changes anything", () => {
  assert.equal(new Set(RULES.map(({ name }) => name)).size, RULES.length);
  for (const { method, mutation, name } of RULES) {
    if (method === "GET") assert.equal(mutation, false, name);
    if (["PUT", "PATCH", "DELETE"].includes(method)) assert.equal(mutation, true, name);
  }
});

const project = (path) =>
  `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents${path}`;
const refused = [
  [
    "another project",
    {
      method: "GET",
      url: "https://firestore.googleapis.com/v1/projects/other-project/databases/(default)/documents/fe_events_primary/e1",
      mutation: false,
    },
  ],
  ["another collection", { method: "GET", url: project("/users/e1"), mutation: false }],
  [
    "another bucket",
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/other-bucket/o/fe-events%2Fe1.txt`,
      mutation: false,
    },
  ],
  [
    "an object outside the owned prefixes",
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}/o/secrets%2Fe1.txt`,
      mutation: false,
    },
  ],
  [
    "another topic",
    {
      method: "DELETE",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/other`,
      mutation: true,
    },
  ],
  [
    "an IAM write",
    {
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:setIamPolicy`,
      mutation: true,
    },
  ],
  [
    "an API enablement",
    {
      method: "POST",
      url: `https://serviceusage.googleapis.com/v1/projects/${PROJECT}/services:batchEnable`,
      mutation: true,
    },
  ],
  [
    "an Artifact Registry delete",
    {
      method: "DELETE",
      url: `https://artifactregistry.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/repositories/gcf-artifacts/packages/x`,
      mutation: true,
    },
  ],
  [
    "a Rules write",
    {
      method: "POST",
      url: `https://firebaserules.googleapis.com/v1/projects/${PROJECT}/releases`,
      mutation: true,
    },
  ],
  [
    "a Functions delete over REST",
    {
      method: "DELETE",
      url: `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/us-central1/functions/x`,
      mutation: true,
    },
  ],
  [
    "a bucket delete of the primary bucket",
    {
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}`,
      mutation: true,
    },
  ],
  [
    "a plain http URL",
    {
      method: "GET",
      url: `http://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)`,
      mutation: false,
    },
  ],
  [
    "credentials in the URL",
    {
      method: "GET",
      url: `https://user:pass@firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)`,
      mutation: false,
    },
  ],
  [
    "a port",
    {
      method: "GET",
      url: `https://firestore.googleapis.com:8443/v1/projects/${PROJECT}/databases/(default)`,
      mutation: false,
    },
  ],
  [
    "an undeclared query parameter",
    {
      method: "GET",
      url: `${project(`/fe_events_primary/e1`)}?mask.fieldPaths=x`,
      mutation: false,
    },
  ],
  [
    "an API key on a call that is not a client sign-in",
    { method: "GET", url: `${project(`/fe_events_primary/e1`)}?key=abc`, mutation: false },
  ],
  [
    "a read declared as a write",
    { method: "GET", url: project("/fe_events_primary/e1"), mutation: true },
  ],
  [
    "a write declared as a read",
    { method: "DELETE", url: project("/fe_events_primary/e1"), mutation: false },
  ],
  [
    "the control bucket's objects outside the owned names",
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${CONTROL_BUCKET}/o/x.txt`,
      mutation: false,
    },
  ],
  ["a URL that does not parse", { method: "GET", url: "not a url", mutation: false }],
];
for (const [label, request] of refused) {
  test(`the guard refuses ${label}`, () => {
    assert.ok(destination(request).problem, label);
  });
}

test("the API key goes only to the two client sign-in calls and the key's project read", () => {
  const body = { email: "e1@example.test", password: "p", returnSecureToken: true };
  for (const tail of ["signUp", "signInWithPassword"]) {
    const answer = destination({
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/accounts:${tail}?key=abc`,
      mutation: true,
      body,
    });
    assert.ok(answer.rule, tail);
  }
  assert.equal(
    destination({
      method: "GET",
      url: "https://identitytoolkit.googleapis.com/v1/projects?key=abc",
      mutation: false,
    }).rule,
    "auth-key-project",
  );
  assert.ok(
    destination({
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup?key=abc`,
      mutation: false,
      body: { localId: ["u"] },
    }).problem,
  );
});

const BUCKET = `https://storage.googleapis.com/storage/v1/b`;
const refusedByValue = [
  [
    "a bucket created in another project",
    {
      method: "POST",
      url: `${BUCKET}?project=other-project`,
      mutation: true,
      body: { name: CONTROL_BUCKET, location: "US-CENTRAL1" },
    },
  ],
  [
    "a bucket created under another name",
    {
      method: "POST",
      url: `${BUCKET}?project=${PROJECT}`,
      mutation: true,
      body: { name: "elsewhere", location: "US-CENTRAL1" },
    },
  ],
  [
    "a bucket created with extra settings",
    {
      method: "POST",
      url: `${BUCKET}?project=${PROJECT}`,
      mutation: true,
      body: {
        name: CONTROL_BUCKET,
        location: "US-CENTRAL1",
        iamConfiguration: { uniformBucketLevelAccess: { enabled: false } },
      },
    },
  ],
  [
    "a bucket patch that is not the versioning field",
    {
      method: "PATCH",
      url: `${BUCKET}/${PRIMARY_BUCKET}?fields=versioning`,
      mutation: true,
      body: { acl: [], versioning: { enabled: true } },
    },
  ],
  [
    "a bucket patch without the fields parameter",
    {
      method: "PATCH",
      url: `${BUCKET}/${PRIMARY_BUCKET}`,
      mutation: true,
      body: { versioning: { enabled: true } },
    },
  ],
  [
    "a bucket patch that sets retention",
    {
      method: "PATCH",
      url: `${BUCKET}/${PRIMARY_BUCKET}?fields=versioning`,
      mutation: true,
      body: { retentionPolicy: { retentionPeriod: "1" } },
    },
  ],
  [
    "an upload outside the owned prefixes",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=media&name=secrets%2Fx.txt`,
      mutation: true,
      body: "t",
    },
  ],
  [
    "an upload with another precondition",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=media&name=fe-events%2Fx.txt&ifGenerationMatch=5`,
      mutation: true,
      body: "t",
    },
  ],
  [
    "an upload that is not media",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=resumable&name=fe-events%2Fx.txt`,
      mutation: true,
      body: "t",
    },
  ],
  [
    "an object patch of another member",
    {
      method: "PATCH",
      url: `${BUCKET}/${PRIMARY_BUCKET}/o/fe-events%2Fx.txt`,
      mutation: true,
      body: { acl: [] },
    },
  ],
  [
    "an object list without an owned prefix",
    { method: "GET", url: `${BUCKET}/${PRIMARY_BUCKET}/o?versions=true&prefix=`, mutation: false },
  ],
  [
    "a bucket list of another prefix",
    { method: "GET", url: `${BUCKET}?project=${PROJECT}&prefix=fireemu`, mutation: false },
  ],
  [
    "a log read of another project",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      mutation: false,
      body: { resourceNames: ["projects/other"], filter: "x", pageSize: 100 },
    },
  ],
  [
    "a log page over 200",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      mutation: false,
      body: { resourceNames: [`projects/${PROJECT}`], filter: "x", pageSize: 1000 },
    },
  ],
  [
    "a log read with a member outside the declared ones",
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      mutation: false,
      body: { resourceNames: [`projects/${PROJECT}`], projectIds: ["x"] },
    },
  ],
  [
    "an account with a real-looking email",
    {
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts`,
      mutation: true,
      body: { localId: "u", email: "someone@gmail.com", password: "p" },
    },
  ],
  [
    "an account with an admin claim",
    {
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts`,
      mutation: true,
      body: {
        localId: "u",
        email: "u@example.test",
        password: "p",
        customAttributes: '{"admin":true}',
      },
    },
  ],
  [
    "a batch delete without force or with too many ids",
    {
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:batchDelete`,
      mutation: true,
      body: { localIds: Array.from({ length: 11 }, (_, i) => `u${i}`), force: true },
    },
  ],
  [
    "a document with a field outside the fixture's",
    {
      method: "POST",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/fe_events_primary?documentId=e1`,
      mutation: true,
      body: { fields: { admin: { stringValue: "x" } } },
    },
  ],
  [
    "a patch without currentDocument.exists",
    {
      method: "PATCH",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/fe_events_primary/e1`,
      mutation: true,
      body: { fields: { value: { stringValue: "x" } } },
    },
  ],
  [
    "a query of another collection",
    {
      method: "POST",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents:runQuery`,
      mutation: false,
      body: { structuredQuery: { from: [{ collectionId: "users" }] } },
    },
  ],
  [
    "a publish of two messages",
    {
      method: "POST",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/fe-events-primary:publish`,
      mutation: true,
      body: { messages: [{ data: "a" }, { data: "b" }] },
    },
  ],
  [
    "a topic created with settings",
    {
      method: "PUT",
      url: `https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/fe-events-primary`,
      mutation: true,
      body: { messageRetentionDuration: "1s" },
    },
  ],
  [
    "a body on a read",
    {
      method: "GET",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/fe_events_primary/e1`,
      mutation: false,
      body: {},
    },
  ],
  [
    "an IAM read with a body",
    {
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      mutation: false,
      body: { options: { requestedPolicyVersion: 3 } },
    },
  ],
];
for (const [label, request] of refusedByValue) {
  test(`the guard refuses ${label}`, () => {
    assert.ok(destination(request).problem, label);
  });
}

test("the legitimate forms of those requests are still allowed", () => {
  const ok = [
    {
      method: "POST",
      url: `${BUCKET}?project=${PROJECT}`,
      mutation: true,
      body: { name: CONTROL_BUCKET, location: "US-CENTRAL1" },
    },
    {
      method: "PATCH",
      url: `${BUCKET}/${PRIMARY_BUCKET}?fields=versioning`,
      mutation: true,
      body: { versioning: { enabled: true } },
    },
    {
      method: "GET",
      url: `${BUCKET}?project=${PROJECT}&prefix=${CONTROL_BUCKET}`,
      mutation: false,
    },
    {
      method: "GET",
      url: `${BUCKET}/${PRIMARY_BUCKET}/o?versions=true&prefix=fe-events%2F`,
      mutation: false,
    },
    {
      method: "POST",
      url: "https://logging.googleapis.com/v2/entries:list",
      mutation: false,
      body: {
        resourceNames: [`projects/${PROJECT}`],
        filter: "x",
        orderBy: "timestamp asc",
        pageSize: 200,
      },
    },
  ];
  for (const request of ok)
    assert.equal(destination(request).problem, undefined, JSON.stringify(request).slice(0, 80));
});

test("x-goog-user-project is decided per destination and pinned: every API rule takes it, the client sign-in calls and the token refresh do not", () => {
  const without = RULES.filter(({ name }) => !quotaProjectFor(name)).map(({ name }) => name);
  assert.deepEqual(without.toSorted(), ["auth-key-project", "auth-sign-in", "auth-sign-up"]);
  for (const rule of RULES) assert.equal(typeof quotaProjectFor(rule.name), "boolean", rule.name);
  const answer = destination({
    method: "POST",
    url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
    mutation: true,
    body: { email: "e1@example.test", password: "p", returnSecureToken: true },
  });
  assert.equal(answer.quotaProject, false);
  assert.equal(
    destination({
      method: "GET",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)`,
      mutation: false,
    }).quotaProject,
    true,
  );
  // no rule reaches the userinfo endpoint, which refuses the header
  assert.ok(
    destination({
      method: "GET",
      url: "https://www.googleapis.com/oauth2/v2/userinfo",
      mutation: false,
    }).problem,
  );
});

const doubled = [
  [
    "documentId",
    {
      method: "POST",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/fe_events_primary?documentId=e1&documentId=e2`,
      mutation: true,
      body: { fields: { value: { stringValue: "x" } } },
    },
  ],
  [
    "uploadType",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=media&uploadType=resumable&name=fe-events%2Fx.txt`,
      mutation: true,
      body: "t",
    },
  ],
  [
    "name",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=media&name=fe-events%2Fx.txt&name=secrets%2Fy.txt`,
      mutation: true,
      body: "t",
    },
  ],
  [
    "ifGenerationMatch",
    {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=media&name=fe-events%2Fx.txt&ifGenerationMatch=0&ifGenerationMatch=5`,
      mutation: true,
      body: "t",
    },
  ],
  [
    "generation",
    {
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}/o/fe-events%2Fx.txt?generation=1&generation=2`,
      mutation: true,
    },
  ],
  [
    "fields",
    {
      method: "PATCH",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}?fields=versioning&fields=acl`,
      mutation: true,
      body: { versioning: { enabled: true } },
    },
  ],
  [
    "project",
    {
      method: "POST",
      url: `https://storage.googleapis.com/storage/v1/b?project=${PROJECT}&project=other-project`,
      mutation: true,
      body: { name: CONTROL_BUCKET, location: "US-CENTRAL1" },
    },
  ],
  [
    "prefix",
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}/o?versions=true&prefix=fe-events%2F&prefix=secrets%2F`,
      mutation: false,
    },
  ],
  [
    "versions",
    {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${PRIMARY_BUCKET}/o?versions=true&versions=false&prefix=fe-events%2F`,
      mutation: false,
    },
  ],
  [
    "currentDocument.exists",
    {
      method: "PATCH",
      url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/fe_events_primary/e1?currentDocument.exists=true&currentDocument.exists=false`,
      mutation: true,
      body: { fields: { value: { stringValue: "x" } } },
    },
  ],
  [
    "pageToken",
    {
      method: "GET",
      url: `https://cloudfunctions.googleapis.com/v1/projects/${PROJECT}/locations/us-central1/functions?pageToken=a&pageToken=b`,
      mutation: false,
    },
  ],
  [
    "key",
    {
      method: "POST",
      url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=a&key=b",
      mutation: true,
      body: { email: "e1@example.test", password: "p", returnSecureToken: true },
    },
  ],
];
for (const [name, request] of doubled) {
  test(`a repeated ${name} query parameter is refused, whichever value the check would read`, () => {
    const answer = destination(request);
    assert.ok(answer.problem && /more than once/.test(answer.problem), JSON.stringify(answer));
  });
}

test("the update mask is the one parameter that may repeat", () => {
  const answer = destination({
    method: "PATCH",
    url: `https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/fe_events_primary/e1?updateMask.fieldPaths=value&updateMask.fieldPaths=count&currentDocument.exists=true`,
    mutation: true,
    body: { fields: { value: { stringValue: "x" }, count: { integerValue: "2" } } },
  });
  assert.equal(answer.rule, "firestore-patch");
});

const uploadAsked = (query, headers) => ({
  method: "POST",
  url: `https://storage.googleapis.com/upload/storage/v1/b/${PRIMARY_BUCKET}/o?uploadType=media&name=fe-events%2Fx.txt${query}`,
  mutation: true,
  body: "t",
  ...(headers ? { headers } : {}),
});

test("an upload may carry ifGenerationMatch 0 (a create) or 1 (a write that production refuses), and nothing else", () => {
  for (const query of ["", "&ifGenerationMatch=0", "&ifGenerationMatch=1"])
    assert.equal(destination(uploadAsked(query)).problem, undefined, query);
  for (const value of ["2", "5", "", "01", "1x", "-1", "1790000000000000", "0%2C1"])
    assert.match(
      destination(uploadAsked(`&ifGenerationMatch=${value}`)).problem ?? "",
      /ifGenerationMatch may only be 0 or 1/,
      value,
    );
});

test("an upload adds no header at all: the x-goog-hash of v5 is gone", () => {
  assert.equal(destination(uploadAsked("", {})).problem, undefined);
  for (const headers of [
    { "x-goog-hash": "md5=x" },
    { "X-Goog-Hash": "md5=x" },
    { "x-other": "1" },
  ])
    assert.match(
      destination(uploadAsked("", headers)).problem ?? "",
      /an upload may not add a header/,
    );
});
