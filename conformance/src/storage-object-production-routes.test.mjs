import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
const module = await import("./storage-object/production-routes.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const boundary = Object.freeze({
  projectId: "example-project",
  projectNumber: "123456789012",
  bucket: "example.appspot.com",
  prefix: "storage-object/example0001/",
  apiKeyResource: "projects/123456789012/locations/global/keys/example-key-id",
  rulesetResource: "projects/example-project/rulesets/example-ruleset-id",
});
const control = (kind, parameters = {}, config = boundary) => {
  assert.equal(
    typeof module.resolveProductionControlRoute,
    "function",
    "production control routes are missing",
  );
  return module.resolveProductionControlRoute(kind, config, parameters);
};
const storage = (step, config = boundary) => {
  assert.equal(
    typeof module.resolveProductionStorageRoute,
    "function",
    "production Storage routes are missing",
  );
  return module.resolveProductionStorageRoute(step, config);
};

test("control route inventory fixes the method, service, path, credential and quota profile", () => {
  const expected = {
    "owner-exchange": ["POST", "oauth2", "/token", "none", null],
    "owner-tokeninfo": ["POST", "oauth2", "/tokeninfo", "admin", null],
    "project-binding": [
      "GET",
      "cloudresourcemanager",
      "/v1/projects/example-project",
      "admin",
      "example-project",
    ],
    "default-bucket": [
      "GET",
      "firebasestorage",
      "/v1alpha/projects/example-project/defaultBucket",
      "admin",
      "example-project",
    ],
    "auth-config": [
      "GET",
      "identitytoolkit",
      "/admin/v2/projects/example-project/config",
      "admin",
      "example-project",
    ],
    "api-key-metadata": [
      "GET",
      "apikeys",
      "/v2/projects/123456789012/locations/global/keys/example-key-id",
      "admin",
      "example-project",
    ],
    "api-key-value": [
      "GET",
      "apikeys",
      "/v2/projects/123456789012/locations/global/keys/example-key-id/keyString",
      "admin",
      "example-project",
    ],
    "rules-release": [
      "GET",
      "firebaserules",
      "/v1/projects/example-project/releases/firebase.storage/example.appspot.com",
      "admin",
      "example-project",
    ],
    "rules-bucketless": [
      "GET",
      "firebaserules",
      "/v1/projects/example-project/releases/firebase.storage",
      "admin",
      "example-project",
    ],
    "rules-ruleset": [
      "GET",
      "firebaserules",
      "/v1/projects/example-project/rulesets/example-ruleset-id",
      "admin",
      "example-project",
    ],
    "rules-release-delete": [
      "DELETE",
      "firebaserules",
      "/v1/projects/example-project/releases/firebase.storage/example.appspot.com",
      "admin",
      "example-project",
    ],
    "rules-ruleset-delete": [
      "DELETE",
      "firebaserules",
      "/v1/projects/example-project/rulesets/example-ruleset-id",
      "admin",
      "example-project",
    ],
    "auth-admin-lookup": [
      "POST",
      "identitytoolkit",
      "/v1/projects/example-project/accounts:lookup",
      "admin",
      "example-project",
    ],
    "auth-admin-delete": [
      "POST",
      "identitytoolkit",
      "/v1/projects/example-project/accounts:delete",
      "admin",
      "example-project",
    ],
  };
  for (const [kind, [method, service, path, credential, quotaProject]] of Object.entries(
    expected,
  )) {
    const result = control(kind);
    assert.equal(result.method, method);
    assert.equal(result.url, `https://${service}.googleapis.com${path}`);
    assert.equal(result.credential, credential);
    assert.equal(result.quotaProject, quotaProject);
    assert.ok(Object.isFrozen(result));
  }
});

test("client Auth uses only the explicit key query and has no owner or quota header", () => {
  for (const [kind, service, path] of [
    ["auth-signup", "identitytoolkit", "/v1/accounts:signUp"],
    ["auth-token-lookup", "identitytoolkit", "/v1/accounts:lookup"],
    ["auth-signin", "identitytoolkit", "/v1/accounts:signInWithPassword"],
    ["auth-refresh", "securetoken", "/v1/token"],
  ]) {
    const result = control(kind, { apiKey: "NEW_FIXTURE_KEY" });
    assert.equal(result.method, "POST");
    assert.equal(result.url, `https://${service}.googleapis.com${path}?key=NEW_FIXTURE_KEY`);
    assert.equal(result.credential, "none");
    assert.equal(result.quotaProject, null);
    assert.throws(() => control(kind), /^Error: invalid production control route$/);
  }
});

test("Rules pagination declares pageSize100 and only a supplied bounded continuation token", () => {
  assert.equal(
    control("rules-list").url,
    "https://firebaserules.googleapis.com/v1/projects/example-project/releases?pageSize=100",
  );
  assert.equal(
    new URL(control("rules-list", { pageToken: "NEW+/PAGE=" }).url).searchParams.get("pageToken"),
    "NEW+/PAGE=",
  );
  assert.throws(
    () => control("rules-list", { pageSize: "1000" }),
    /^Error: invalid production control route$/,
  );
});

test("unknown control routes, query parameters and cross-project resource names fail without echoing values", () => {
  for (const kind of ["constructor", "NEW_SECRET", "api-key-value:NEW_SECRET"])
    assert.throws(() => control(kind), /^Error: invalid production control route$/);
  for (const change of [
    { apiKeyResource: "projects/999999999999/locations/global/keys/NEW_SECRET" },
    { rulesetResource: "projects/other-project/rulesets/NEW_SECRET" },
    { bucket: "NEW_SECRET/path" },
    { projectId: "NEW_SECRET" },
  ])
    assert.throws(
      () => control("project-binding", {}, { ...boundary, ...change }),
      /^Error: invalid production control route$/,
    );
  assert.throws(
    () => control("owner-tokeninfo", { access_token: "NEW_SECRET" }),
    /^Error: invalid production control route$/,
  );
});

test("all direct static Storage routes retain their exact path and query after reference resolution", () => {
  let direct = 0,
    sessions = 0;
  for (const recipe of buildCorpus({ bucket: boundary.bucket, prefix: boundary.prefix }).recipes) {
    for (const original of [...recipe.preflight, ...recipe.steps, ...recipe.cleanup]) {
      const step = structuredClone(original);
      for (const [key, value] of Object.entries(step.query ?? {}))
        if (typeof value !== "string") step.query[key] = "7";
      if (step.sessionUriReference) {
        assert.throws(() => storage(step), /^Error: invalid production Storage route$/);
        sessions++;
        continue;
      }
      const result = storage(step);
      const service = step.dialect === "firebase" ? "firebasestorage" : "storage";
      const url = new URL(result.url);
      assert.equal(url.origin, `https://${service}.googleapis.com`);
      assert.equal(url.pathname, step.path);
      assert.equal(result.method, step.method);
      assert.deepEqual(Object.fromEntries(url.searchParams), step.query);
      assert.equal(result.objectName, step.collection === true ? null : step.objectName);
      assert.ok(Object.isFrozen(result));
      direct++;
    }
  }
  assert.equal(direct + sessions, 1891);
  assert.ok(sessions > 0);
});

test("owned bucket, prefix, path and query are checked independently of credentials", () => {
  const name = boundary.prefix + "example.bin";
  const step = {
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/${boundary.bucket}/o/${encodeURIComponent(name)}`,
    query: {},
  };
  for (const change of [
    { path: "https://NEW_SECRET.example/path" },
    { path: step.path.replace(boundary.bucket, "other.appspot.com") },
    { objectName: "other/NEW_SECRET" },
    { method: "TRACE" },
    { dialect: "NEW_SECRET" },
    { query: { unknown: "NEW_SECRET" } },
    { query: { generation: { kind: "unresolved-reference" } } },
    { query: { prefix: "other/NEW_SECRET" } },
  ])
    assert.throws(
      () => storage({ ...step, ...change }),
      /^Error: invalid production Storage route$/,
    );
  assert.equal(
    storage({ ...step, query: { ifMetagenerationMatch: "not-a-number" } }).url.includes(
      "not-a-number",
    ),
    true,
  );
});

test("route inputs are copied from data descriptors without running accessors", () => {
  let calls = 0;
  const accessor = Object.defineProperty({}, "projectId", {
    enumerable: true,
    get() {
      calls++;
      throw new Error("NEW_GETTER_SECRET");
    },
  });
  assert.throws(
    () => control("project-binding", {}, accessor),
    /^Error: invalid production control route$/,
  );
  const query = Object.defineProperty({}, "name", {
    enumerable: true,
    get() {
      calls++;
      throw new Error("NEW_GETTER_SECRET");
    },
  });
  assert.throws(
    () =>
      storage({
        dialect: "gcs",
        method: "POST",
        objectName: boundary.prefix + "example.bin",
        path: `/upload/storage/v1/b/${boundary.bucket}/o`,
        query,
      }),
    /^Error: invalid production Storage route$/,
  );
  assert.equal(calls, 0);
});

test("Storage methods and query names cannot migrate to another route family", () => {
  const name = boundary.prefix + "example.bin";
  const step = {
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/${boundary.bucket}/o/${encodeURIComponent(name)}`,
    query: {},
  };
  for (const change of [
    { method: "POST" },
    { query: { token: "NEW_SECRET" } },
    { query: { uploadType: "media" } },
    { query: { rewriteToken: "NEW_SECRET" } },
    { query: { prefix: boundary.prefix } },
    {
      method: "PATCH",
      path: `/upload/storage/v1/b/${boundary.bucket}/o`,
      query: { name, uploadType: "media" },
    },
  ])
    assert.throws(
      () => storage({ ...step, ...change }),
      /^Error: invalid production Storage route$/,
    );
});

test("an owned object declaration cannot be used for a bucket-wide collection read", () => {
  for (const [dialect, path] of [
    ["gcs", `/storage/v1/b/${boundary.bucket}/o`],
    ["firebase", `/v0/b/${boundary.bucket}/o`],
  ]) {
    for (const query of [{}, { prefix: boundary.prefix }])
      assert.throws(
        () =>
          storage({
            dialect,
            method: "GET",
            objectName: boundary.prefix + "example.bin",
            path,
            query,
          }),
        /^Error: invalid production Storage route$/,
      );
  }
});
