import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-rules/corpus.mjs";
import { buildFullRequestManifest } from "./storage-rules/full-manifest.mjs";
import { NO_QUOTA_PROJECT_ROUTES, quotaProjectRequired } from "./storage-rules/quota-project.mjs";

// The quota project header (x-goog-user-project) is a property of the route, not of the credential: the owner's bearer
// carries it wherever a project is billed for the API, and never where the endpoint is not a project-billed API.
// A production run stopped at its first delegated request because userinfo carried it (403 USER_PROJECT_DENIED).
const closure = JSON.parse(readFileSync(new URL("../../spec/compatibility/closure/STORAGE-RULES.json", import.meta.url)));
const options = { runId: "local-run", sourceCommit: "a".repeat(40), queryProjectNumber: "1".repeat(12), idpProjectNumber: "2".repeat(12), queryApiKeyId: "00000000-0000-4000-8000-000000000001", idpApiKeyId: "00000000-0000-4000-8000-000000000002" };
const binding = { bucket: "synthetic-rules-bucket", prefix: "STORAGE-RULES/local-run/", uidA: "storage-rules-local-run-user-a", uidB: "storage-rules-local-run-user-b" };
const manifest = buildFullRequestManifest(buildCorpus(binding), closure, options);
const spec = (method, url) => ({ method, url });

test("userinfo is the only route without the quota project header", () => {
  assert.deepEqual([...NO_QUOTA_PROJECT_ROUTES], ["GET https://www.googleapis.com/oauth2/v2/userinfo"]);
  assert.ok(Object.isFrozen(NO_QUOTA_PROJECT_ROUTES));
  assert.equal(quotaProjectRequired(spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo")), false);
  assert.equal(quotaProjectRequired(spec("GET", "https://www.googleapis.com/oauth2/v2/userinfo?alt=json")), false);
  // The rule is exact: another method, path, host or scheme on the same endpoint is not exempted.
  for (const [method, url] of [["POST", "https://www.googleapis.com/oauth2/v2/userinfo"], ["GET", "https://www.googleapis.com/oauth2/v2/userinfo/x"], ["GET", "https://www.googleapis.com/oauth2/v3/userinfo"], ["GET", "https://oauth2.googleapis.com/oauth2/v2/userinfo"], ["GET", "https://www.googleapis.com/OAuth2/v2/userinfo"], ["GET", "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"]]) {
    assert.equal(quotaProjectRequired(spec(method, url)), true, `${method} ${url}`);
  }
});

test("an unparsable target has no exemption", () => {
  for (const url of ["", "not a url", "//www.googleapis.com/oauth2/v2/userinfo"]) assert.equal(quotaProjectRequired(spec("GET", url)), true, url);
});

test("the header set of every delegated route of the manifest is pinned by host, method and path shape", () => {
  const shape = (row) => {
    const request = row.request;
    const path = String(request.path ?? "").replace(/\/projects\/[^/:]+/g, "/projects/{p}").replace(/\/b\/[^/]+/g, "/b/{bucket}").replace(/\/o\/[^/?]+/g, "/o/{object}").replace(/\/keys\/[^/]+/g, "/keys/{key}").replace(/\/rulesets\/[^/]+/g, "/rulesets/{ruleset}").replace(/\/releases\/[^/]+.*/g, "/releases/{release}").replace(/\/documents\/.*/g, "/documents/{doc}").replace(/\/accounts:.*/g, "/accounts:{op}").replace(/:test$/, ":test");
    return `${request.method} ${request.origin}${path}`;
  };
  const owner = manifest.rows.filter((row) => row.request.credential === "admin");
  const shapes = new Map();
  for (const row of owner) {
    const url = `${row.request.origin}${row.request.path ?? "/x"}`;
    const required = quotaProjectRequired({ method: row.request.method, url });
    const key = shape(row);
    assert.ok(!shapes.has(key) || shapes.get(key) === required, key);
    shapes.set(key, required);
  }
  const without = [...shapes].filter(([, required]) => !required).map(([key]) => key);
  assert.deepEqual(without, ["GET https://www.googleapis.com/oauth2/v2/userinfo"]);
  // Every project-billed API the run calls with the owner's bearer keeps the header.
  const hosts = new Set(owner.map((row) => row.request.origin));
  for (const host of ["https://apikeys.googleapis.com", "https://cloudresourcemanager.googleapis.com", "https://firestore.googleapis.com", "https://firebaserules.googleapis.com", "https://storage.googleapis.com"]) {
    assert.ok([...hosts].some((origin) => origin === host || origin.startsWith(host)), host);
  }
  for (const row of owner.filter((r) => r.request.origin !== "https://www.googleapis.com")) {
    assert.equal(quotaProjectRequired({ method: row.request.method, url: `${row.request.origin}${row.request.path ?? "/x"}` }), true, row.id);
  }
  assert.equal(owner.filter((row) => row.request.origin === "https://www.googleapis.com").map((row) => row.id).join(), "preflight/owner/identity");
});
