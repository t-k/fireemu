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

test("the API key goes only to the two client sign-in calls", () => {
  for (const tail of ["signUp", "signInWithPassword"]) {
    const answer = destination({
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/accounts:${tail}?key=abc`,
      mutation: true,
    });
    assert.ok(answer.rule, tail);
  }
  assert.ok(
    destination({
      method: "POST",
      url: `https://identitytoolkit.googleapis.com/v1/projects/${PROJECT}/accounts:lookup?key=abc`,
      mutation: false,
    }).problem,
  );
});

test("x-goog-user-project is decided per destination and pinned: every API rule takes it, the client sign-in calls and the token refresh do not", () => {
  const without = RULES.filter(({ name }) => !quotaProjectFor(name)).map(({ name }) => name);
  assert.deepEqual(without.toSorted(), ["auth-sign-in", "auth-sign-up", "oauth-token"]);
  for (const rule of RULES) assert.equal(typeof quotaProjectFor(rule.name), "boolean", rule.name);
  const answer = destination({
    method: "POST",
    url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
    mutation: true,
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
