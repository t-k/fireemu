import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  GuardError,
  classifyRequest,
  isUnknownStatus,
  ownedName,
  validateBaseline,
} from "./storage-rules-s9/guard.mjs";
import { recordingPrefix, runRoot } from "./storage-rules-s9/plan.mjs";

const project = "fireemu-oracle-query";
const bucket = "fireemu-oracle-query.firebasestorage.app";
const runId = "sr-0123abcd";
const root = runRoot(runId);
const P = recordingPrefix(runId, 1);
const baselineName = `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`;
const ownName = `projects/${project}/rulesets/00000001-0000-4000-8000-000000000000`;
const state = (extra = {}) => ({
  runId,
  root,
  ownRulesets: new Set([ownName]),
  baseline: baselineName,
  ...extra,
});
const production = { name: "production", bucket, project };
const local = {
  name: "local",
  bucket: "demo-storage-s9.appspot.com",
  origin: "http://127.0.0.1:9199",
};
const owner = { authorization: "Bearer t", "x-goog-user-project": project };
const enc = encodeURIComponent;
const json = (value) => Buffer.from(JSON.stringify(value));
const gcs = (suffix) => `https://storage.googleapis.com/storage/v1/b/${bucket}${suffix}`;
const v0 = (suffix) => `https://firebasestorage.googleapis.com/v0/b/${bucket}${suffix}`;
const rules = (suffix) => `https://firebaserules.googleapis.com/v1/projects/${project}${suffix}`;
const releasePath = `/releases/firebase.storage/${bucket}`;
function multipartCreate(name, metadata, { jsonName = name, extraKey = false, contentType } = {}) {
  const boundary = "s9boundary0123";
  const meta = JSON.stringify({ name: jsonName, metadata, ...(extraKey ? { acl: [] } : {}) });
  const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n--${boundary}\r\nContent-Type: text/plain\r\n\r\nx\r\n--${boundary}--`;
  return {
    method: "POST",
    url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=multipart&name=${enc(name)}&ifGenerationMatch=0`,
    headers: { ...owner, "content-type": contentType ?? `multipart/related; boundary=${boundary}` },
    body: Buffer.from(body),
  };
}
const kind = (request, target = production, st = state()) => classifyRequest(target, request, st);
const refused = (request, target = production, st = state()) =>
  assert.throws(() => kind(request, target, st), GuardError, `${request.method} ${request.url}`);

describe("storage rules s9 request guard", () => {
  it("allows each recorded form once, with the owner headers where the credential applies", () => {
    const name = `${P}/pub//x`;
    assert.equal(kind({ method: "GET", url: gcs(""), headers: owner }), "bucket-get");
    assert.equal(
      kind({
        method: "GET",
        url: gcs(`/o?prefix=${enc(P + "/")}&maxResults=1000`),
        headers: owner,
      }),
      "gcs-list",
    );
    assert.equal(kind({ method: "GET", url: gcs(`/o/${enc(name)}`), headers: owner }), "gcs-get");
    assert.equal(
      kind({
        method: "DELETE",
        url: gcs(`/o/${enc(name)}?ifGenerationMatch=1790000000000001`),
        headers: owner,
      }),
      "gcs-delete",
    );
    assert.equal(kind(multipartCreate(name, { k: "v" })), "gcs-create");
    assert.equal(
      kind({
        method: "POST",
        url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=media&name=${enc(`/${P}/pub/x`)}&ifGenerationMatch=0`,
        headers: owner,
      }),
      "gcs-create",
    );
    assert.equal(kind({ method: "GET", url: v0(`/o/${enc(name)}`) }), "v0-meta");
    assert.equal(kind({ method: "GET", url: v0(`/o/${enc(name)}?alt=media`) }), "v0-media");
    assert.equal(
      kind({ method: "GET", url: v0(`/o?prefix=${enc(P + "/pub/")}&delimiter=%2F`) }),
      "v0-list",
    );
    assert.equal(
      kind({
        method: "POST",
        url: rules("/rulesets"),
        headers: owner,
        body: json({ source: { files: [{ name: "storage.rules", content: "x" }] } }),
      }),
      "ruleset-create",
    );
    assert.equal(
      kind({ method: "GET", url: rules("/rulesets?pageSize=100"), headers: owner }),
      "ruleset-list",
    );
    assert.equal(
      kind({
        method: "GET",
        url: `https://firebaserules.googleapis.com/v1/${ownName}`,
        headers: owner,
      }),
      "ruleset-get",
    );
    assert.equal(
      kind({
        method: "DELETE",
        url: `https://firebaserules.googleapis.com/v1/${ownName}`,
        headers: owner,
      }),
      "ruleset-delete",
    );
    assert.equal(kind({ method: "GET", url: rules(releasePath), headers: owner }), "release-get");
    assert.equal(
      kind({ method: "GET", url: rules("/releases/firebase.storage"), headers: owner }),
      "release-bucketless-get",
    );
    const releaseName = `projects/${project}${releasePath}`.slice(1 - 1);
    assert.equal(
      kind({
        method: "PATCH",
        url: rules(releasePath),
        headers: owner,
        body: json({
          release: {
            name: `projects/${project}/releases/firebase.storage/${bucket}`,
            rulesetName: ownName,
          },
          updateMask: "rulesetName",
        }),
      }),
      "release-patch",
    );
    assert.equal(
      kind({
        method: "PATCH",
        url: rules(releasePath),
        headers: owner,
        body: json({
          release: {
            name: `projects/${project}/releases/firebase.storage/${bucket}`,
            rulesetName: baselineName,
          },
          updateMask: "rulesetName",
        }),
      }),
      "release-patch",
    );
    assert.equal(
      kind({
        method: "POST",
        url: rules("/releases"),
        headers: owner,
        body: json({
          name: `projects/${project}/releases/firebase.storage/${bucket}`,
          rulesetName: ownName,
        }),
      }),
      "release-create",
    );
    assert.ok(releaseName);
  });

  it("refuses an object or prefix outside the run root, and dot or control names", () => {
    for (const bad of [
      "other/x",
      `${root}`,
      `//${root}x`,
      `${root}../x`,
      `${root}./x`,
      `${root}a\u0001b`,
      "/other",
    ]) {
      refused({ method: "GET", url: v0(`/o/${enc(bad)}`) });
      refused({ method: "GET", url: gcs(`/o/${enc(bad)}`), headers: owner });
    }
    refused({ method: "GET", url: v0(`/o?prefix=${enc("other/")}`) });
    refused({ method: "GET", url: gcs(`/o?prefix=${enc("")}`), headers: owner });
    refused({ method: "GET", url: gcs(`/o?maxResults=5`), headers: owner });
    assert.equal(ownedName(`/${root}x`, root), true);
    assert.equal(ownedName(`${root}a//b/`, root), true);
    assert.equal(ownedName(`${root}`, root), false);
  });

  it("refuses a v0 request with credentials and an owner request without them", () => {
    const name = `${P}/pub/x`;
    refused({ method: "GET", url: v0(`/o/${enc(name)}`), headers: { authorization: "Bearer t" } });
    refused({ method: "GET", url: gcs(`/o/${enc(name)}`) });
    refused({ method: "GET", url: gcs(`/o/${enc(name)}`), headers: { authorization: "Bearer t" } });
    refused({ method: "GET", url: rules(releasePath), headers: { authorization: "Bearer t" } });
  });

  it("refuses unrecorded query parameters, methods and hosts", () => {
    const name = `${P}/pub/x`;
    refused({ method: "GET", url: v0(`/o/${enc(name)}?alt=json`) });
    refused({ method: "GET", url: v0(`/o/${enc(name)}?token=abc`) });
    refused({ method: "POST", url: v0(`/o/${enc(name)}`) });
    refused({ method: "DELETE", url: v0(`/o/${enc(name)}`) });
    refused({ method: "DELETE", url: gcs(`/o/${enc(name)}`), headers: owner });
    refused({
      method: "DELETE",
      url: gcs(`/o/${enc(name)}?ifGenerationMatch=abc`),
      headers: owner,
    });
    refused({
      method: "PATCH",
      url: gcs(`/o/${enc(name)}?ifGenerationMatch=1`),
      headers: owner,
      body: json({ metadata: { k: "v" } }),
    });
    refused(multipartCreate(name, { k: "v" }, { jsonName: `${name}x` }));
    refused(multipartCreate(name, { k: "v" }, { extraKey: true }));
    refused(multipartCreate(name, { k: "v" }, { contentType: "multipart/related" }));
    refused(multipartCreate(name, "v"));
    refused({ ...multipartCreate(name, { k: "v" }), body: Buffer.from("not multipart") });
    refused({
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=media&name=${enc(name)}`,
      headers: owner,
    });
    refused({
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=resumable&name=${enc(name)}&ifGenerationMatch=0`,
      headers: owner,
    });
    refused({
      method: "GET",
      url: v0(`/o/${enc(name)}`).replace("firebasestorage.googleapis.com", "evil.example"),
    });
    refused({
      method: "GET",
      url: v0(`/o/${enc(name)}`).replace(
        "firebasestorage.googleapis.com",
        "storage.googleapis.com",
      ),
    });
    refused({
      method: "GET",
      url: `https://firebasestorage.googleapis.com/v0/b/other-bucket/o/${enc(name)}`,
    });
    refused({
      method: "GET",
      url: `http://firebasestorage.googleapis.com/v0/b/${bucket}/o/${enc(name)}`,
    });
    refused({
      method: "GET",
      url: `https://firebasestorage.googleapis.com:8443/v0/b/${bucket}/o/${enc(name)}`,
    });
    refused({
      method: "GET",
      url: `https://user:pw@firebasestorage.googleapis.com/v0/b/${bucket}/o/${enc(name)}`,
    });
    refused({ method: "GET", url: `${v0(`/o/${enc(name)}`)}?alt=media&alt=media` });
  });

  it("allows a ruleset delete only for a ruleset this run created, and a release delete only without a baseline release", () => {
    refused({
      method: "DELETE",
      url: `https://firebaserules.googleapis.com/v1/${baselineName}`,
      headers: owner,
    });
    refused({
      method: "DELETE",
      url: `https://firebaserules.googleapis.com/v1/projects/${project}/rulesets/other`,
      headers: owner,
    });
    refused({ method: "DELETE", url: rules(releasePath), headers: owner });
    assert.equal(
      kind(
        { method: "DELETE", url: rules(releasePath), headers: owner },
        production,
        state({ baseline: "absent" }),
      ),
      "release-delete",
    );
  });

  it("allows a release body only with an own ruleset or the baseline, and an exact shape", () => {
    const releaseName = `projects/${project}/releases/firebase.storage/${bucket}`;
    const patch = (body) => ({
      method: "PATCH",
      url: rules(releasePath),
      headers: owner,
      body: json(body),
    });
    refused(
      patch({
        release: { name: releaseName, rulesetName: `projects/${project}/rulesets/foreign` },
        updateMask: "rulesetName",
      }),
    );
    refused(patch({ release: { name: releaseName, rulesetName: ownName } }));
    refused(
      patch({
        release: { name: releaseName, rulesetName: ownName },
        updateMask: "rulesetName",
        extra: 1,
      }),
    );
    refused(
      patch({
        release: { name: `${releaseName}x`, rulesetName: ownName },
        updateMask: "rulesetName",
      }),
    );
    refused({
      method: "PATCH",
      url: rules(releasePath),
      headers: owner,
      body: Buffer.from("not json"),
    });
    // With baseline absent there is no baseline ruleset to patch back to.
    refused(
      patch({
        release: { name: releaseName, rulesetName: baselineName },
        updateMask: "rulesetName",
      }),
      production,
      state({ baseline: "absent" }),
    );
    refused({
      method: "POST",
      url: rules("/releases"),
      headers: owner,
      body: json({ name: releaseName, rulesetName: baselineName }),
    });
    refused({
      method: "POST",
      url: rules("/releases"),
      headers: owner,
      body: json({ name: `${releaseName}x`, rulesetName: ownName }),
    });
    refused({
      method: "POST",
      url: rules("/rulesets"),
      headers: owner,
      body: json({ source: { files: [{ name: "firestore.rules", content: "x" }] } }),
    });
    refused({
      method: "POST",
      url: rules("/rulesets"),
      headers: owner,
      body: json({ source: { files: [] } }),
    });
    refused({
      method: "GET",
      url: "https://firebaserules.googleapis.com/v1/projects/other-project/rulesets",
      headers: owner,
    });
  });

  it("serves the local target from its origin only, with setRules and no Rules API", () => {
    const name = `${P}/pub/x`;
    const at = (path) => `http://127.0.0.1:9199${path}`;
    assert.equal(
      kind(
        {
          method: "PUT",
          url: at("/internal/setRules"),
          headers: { authorization: "Bearer owner" },
          body: json({}),
        },
        local,
      ),
      "local-set-rules",
    );
    assert.equal(
      kind({ method: "GET", url: at(`/v0/b/${local.bucket}/o/${enc(name)}`) }, local),
      "v0-meta",
    );
    assert.equal(
      kind(
        {
          method: "GET",
          url: at(`/storage/v1/b/${local.bucket}/o/${enc(name)}`),
          headers: { authorization: "Bearer owner" },
        },
        local,
      ),
      "gcs-get",
    );
    refused(
      { method: "GET", url: `http://127.0.0.1:9200/v0/b/${local.bucket}/o/${enc(name)}` },
      local,
    );
    refused(
      {
        method: "GET",
        url: at(`/v1/projects/${project}/rulesets`),
        headers: { authorization: "Bearer owner" },
      },
      local,
    );
    refused(
      { method: "POST", url: at("/internal/setRules"), headers: { authorization: "Bearer owner" } },
      local,
    );
    // A production request has no setRules.
    refused({
      method: "PUT",
      url: "https://storage.googleapis.com/internal/setRules",
      headers: owner,
    });
  });

  it("validates the baseline and treats unknown statuses as the shared rule does", () => {
    assert.equal(validateBaseline("absent", project), "absent");
    assert.equal(validateBaseline(baselineName, project), baselineName);
    for (const bad of [
      "",
      "present",
      `projects/other/rulesets/x`,
      `${baselineName}/x`,
      undefined,
      null,
    ])
      assert.throws(() => validateBaseline(bad, project), GuardError);
    for (const status of [0, 100, 199, 301, 304, 399, 500, 503, Number.NaN])
      assert.equal(isUnknownStatus(status), true, `${status}`);
    for (const status of [200, 204, 400, 403, 404, 412, 429])
      assert.equal(isUnknownStatus(status), false, `${status}`);
  });
});
