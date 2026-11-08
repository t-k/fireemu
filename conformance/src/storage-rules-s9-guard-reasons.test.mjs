import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { GuardError, classifyRequest, validateBaseline } from "./storage-rules-s9/guard.mjs";
import { recordingPrefix, runRoot } from "./storage-rules-s9/plan.mjs";

// Every refusal of the guard has its own near miss here, and each is checked by the reason it
// gives, so a guard that refuses for another reason (or accepts) fails the test.
const project = "fireemu-oracle-query";
const bucket = "fireemu-oracle-query.firebasestorage.app";
const runId = "sr-0123abcd";
const root = runRoot(runId);
const P = recordingPrefix(runId, 1);
const baselineName = `projects/${project}/rulesets/22b746af-0000-4000-8000-000000000001`;
const ownName = `projects/${project}/rulesets/00000001-0000-4000-8000-000000000000`;
const releaseName = `projects/${project}/releases/firebase.storage/${bucket}`;
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
const name = `${P}/pub/x`;
const gcs = (suffix) => `https://storage.googleapis.com/storage/v1/b/${bucket}${suffix}`;
const upload = (query) => `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o${query}`;
const v0 = (suffix) => `https://firebasestorage.googleapis.com/v0/b/${bucket}${suffix}`;
const rules = (suffix) => `https://firebaserules.googleapis.com/v1/projects/${project}${suffix}`;
const releasePath = `/releases/firebase.storage/${bucket}`;
const createBody = (content = "x") =>
  json({ source: { files: [{ name: "storage.rules", content }] } });
const patchBody = (rulesetName, extra = {}) =>
  json({ release: { name: releaseName, rulesetName }, updateMask: "rulesetName", ...extra });

function multipart(jsonPart, contentType, boundary = "s9boundary0123") {
  return {
    method: "POST",
    url: upload(`?uploadType=multipart&name=${enc(name)}&ifGenerationMatch=0`),
    headers: { ...owner, "content-type": contentType ?? `multipart/related; boundary=${boundary}` },
    body: Buffer.from(
      `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${jsonPart}\r\n--${boundary}\r\nContent-Type: text/plain\r\n\r\nx\r\n--${boundary}--`,
    ),
  };
}

const refuses = (reason, request, target = production, st = state()) =>
  assert.throws(
    () => classifyRequest(target, request, st),
    (error) => error instanceof GuardError && reason.test(error.message),
    `${request.method} ${request.url} should be refused as ${reason}`,
  );

describe("storage rules s9 guard reasons", () => {
  it("names the reason for a bad run root, target, URL or host", () => {
    const get = { method: "GET", url: v0(`/o/${enc(name)}`) };
    refuses(/bad run root/, get, production, state({ root: "other/sr-0123abcd/" }));
    refuses(/bad run root/, get, production, state({ root: `${root}x` }));
    refuses(/unknown target/, get, { name: "staging", bucket, project });
    refuses(/credentials in URL/, {
      method: "GET",
      url: v0(`/o/${enc(name)}`).replace("https://", "https://u:p@"),
    });
    refuses(/credentials in URL/, {
      method: "GET",
      url: v0(`/o/${enc(name)}`).replace("https://", "https://u@"),
    });
    refuses(/host not allowed/, {
      method: "GET",
      url: v0(`/o/${enc(name)}`).replace("https:", "http:"),
    });
    refuses(/host not allowed/, {
      method: "GET",
      url: v0(`/o/${enc(name)}`).replace(".com", ".com:444"),
    });
    refuses(/host not allowed/, {
      method: "GET",
      url: `https://firebasestorage.googleapis.com.evil.example/v0/b/${bucket}/o/${enc(name)}`,
    });
    assert.equal(
      classifyRequest(
        local,
        { method: "GET", url: `http://127.0.0.1:9199/v0/b/${local.bucket}/o/${enc(name)}` },
        state(),
      ),
      "v0-meta",
    );
    refuses(
      /host not allowed/,
      { method: "GET", url: `http://127.0.0.1:9199/v0/b/${local.bucket}/o/${enc(name)}` },
      { ...local, origin: "http://127.0.0.1:9100" },
    );
    refuses(/host not allowed/, {
      method: "GET",
      url: gcs(`/o/${enc(name)}`).replace(
        "storage.googleapis.com",
        "firebasestorage.googleapis.com",
      ),
      headers: owner,
    });
    refuses(/host not allowed/, {
      method: "POST",
      url: rules("/rulesets").replace("firebaserules", "storage"),
      headers: owner,
      body: createBody(),
    });
    refuses(/host not allowed/, {
      method: "POST",
      url: upload("?uploadType=media").replace("storage.googleapis", "firebasestorage.googleapis"),
      headers: owner,
    });
    refuses(/undecodable path segment/, { method: "GET", url: v0("/o/%E0%A4%A") });
    refuses(/path/, { method: "GET", url: "https://storage.googleapis.com/other" });
  });

  it("names the reason for a bad object name, prefix or body", () => {
    refuses(/object outside the run root/, { method: "GET", url: v0(`/o/${enc("elsewhere/x")}`) });
    refuses(/object outside the run root/, { method: "GET", url: v0(`/o/${enc(root)}`) });
    refuses(/object outside the run root/, { method: "GET", url: v0(`/o/${enc(`//${root}x`)}`) });
    refuses(/object outside the run root/, {
      method: "GET",
      url: v0(`/o/${enc(`${root}a/../b`)}`),
    });
    refuses(/object outside the run root/, { method: "GET", url: v0(`/o/${enc(`${root}./b`)}`) });
    refuses(/object outside the run root/, {
      method: "GET",
      url: v0(`/o/${enc(`${root}b\u007f`)}`),
    });
    refuses(/object outside the run root/, {
      method: "GET",
      url: v0(`/o/${enc(`${root}b\u001f`)}`),
    });
    refuses(/prefix outside the run root/, {
      method: "GET",
      url: v0(`/o?prefix=${enc("elsewhere/")}`),
    });
    refuses(/list without a prefix/, { method: "GET", url: v0("/o") });
    refuses(/list without a prefix/, { method: "GET", url: gcs("/o"), headers: owner });
    refuses(/control character in prefix/, {
      method: "GET",
      url: v0(`/o?prefix=${enc(`${root}a\u0007`)}`),
    });
    refuses(/control character in prefix/, {
      method: "GET",
      url: v0(`/o?prefix=${enc(`${root}a\u007f`)}`),
    });
    refuses(/dot segment in prefix/, {
      method: "GET",
      url: v0(`/o?prefix=${enc(`${root}a/../`)}`),
    });
    refuses(/dot segment in prefix/, { method: "GET", url: v0(`/o?prefix=${enc(`${root}./`)}`) });
    assert.equal(
      classifyRequest(
        production,
        { method: "GET", url: v0(`/o?prefix=${enc(`/${root}`)}`) },
        state(),
      ),
      "v0-list",
    );
    refuses(/body is not JSON/, {
      method: "POST",
      url: rules("/rulesets"),
      headers: owner,
      body: Buffer.from("{"),
    });
    refuses(/body is not JSON/, { method: "POST", url: rules("/releases"), headers: owner });
  });

  it("names the reason for owner and anonymous credentials", () => {
    refuses(/owner request without Authorization/, { method: "GET", url: gcs(`/o/${enc(name)}`) });
    refuses(/owner request without the quota project/, {
      method: "GET",
      url: gcs(`/o/${enc(name)}`),
      headers: { authorization: "Bearer t" },
    });
    refuses(/owner request without the quota project/, {
      method: "GET",
      url: gcs(`/o/${enc(name)}`),
      headers: { authorization: "Bearer t", "x-goog-user-project": "other-project" },
    });
    refuses(/owner request without Authorization/, {
      method: "GET",
      url: rules(releasePath),
      headers: { "x-goog-user-project": project },
    });
    refuses(/owner request without Authorization/, {
      method: "POST",
      url: upload("?uploadType=media"),
      headers: {},
    });
    refuses(/anonymous request with Authorization/, {
      method: "GET",
      url: v0(`/o/${enc(name)}`),
      headers: { Authorization: "Bearer t" },
    });
    // Local owner requests need the credential but no quota project.
    const at = (path) => `http://127.0.0.1:9199${path}`;
    assert.equal(
      classifyRequest(
        local,
        {
          method: "GET",
          url: at(`/storage/v1/b/${local.bucket}/o/${enc(name)}`),
          headers: { authorization: "Bearer owner" },
        },
        state(),
      ),
      "gcs-get",
    );
    refuses(
      /owner request without Authorization/,
      { method: "GET", url: at(`/storage/v1/b/${local.bucket}/o/${enc(name)}`) },
      local,
    );
  });

  it("refuses an extra or repeated query parameter on every form", () => {
    const forms = [
      { method: "GET", url: gcs(""), headers: owner },
      { method: "GET", url: gcs(`/o?prefix=${enc(`${P}/`)}`), headers: owner },
      { method: "GET", url: gcs(`/o/${enc(name)}`), headers: owner },
      { method: "DELETE", url: gcs(`/o/${enc(name)}?ifGenerationMatch=5`), headers: owner },
      {
        method: "POST",
        url: upload(`?uploadType=media&name=${enc(name)}&ifGenerationMatch=0`),
        headers: owner,
      },
      { method: "GET", url: v0(`/o/${enc(name)}`) },
      { method: "GET", url: v0(`/o/${enc(name)}?alt=media`) },
      { method: "GET", url: v0(`/o?prefix=${enc(`${P}/`)}`) },
      { method: "POST", url: rules("/rulesets"), headers: owner, body: createBody() },
      { method: "GET", url: rules("/rulesets?pageSize=100"), headers: owner },
      { method: "GET", url: `https://firebaserules.googleapis.com/v1/${ownName}`, headers: owner },
      {
        method: "DELETE",
        url: `https://firebaserules.googleapis.com/v1/${ownName}`,
        headers: owner,
      },
      {
        method: "POST",
        url: rules("/releases"),
        headers: owner,
        body: json({ name: releaseName, rulesetName: ownName }),
      },
      { method: "GET", url: rules("/releases/firebase.storage"), headers: owner },
      { method: "GET", url: rules(releasePath), headers: owner },
      { method: "PATCH", url: rules(releasePath), headers: owner, body: patchBody(ownName) },
    ];
    const joined = (url, extra) => `${url}${url.includes("?") ? "&" : "?"}${extra}`;
    for (const form of forms) {
      assert.ok(classifyRequest(production, form, state()), `${form.method} ${form.url}`);
      refuses(/query parameter not allowed/, { ...form, url: joined(form.url, "zz=1") });
    }
    refuses(
      /query parameter not allowed/,
      {
        method: "DELETE",
        url: rules(releasePath).replace("/releases", "/releases") + "?x=1",
        headers: owner,
      },
      production,
      state({ baseline: "absent" }),
    );
    for (const repeated of [
      { method: "GET", url: v0(`/o?prefix=${enc(`${P}/`)}&prefix=${enc(`${P}/`)}`) },
      { method: "GET", url: v0(`/o?prefix=${enc(`${P}/`)}&delimiter=%2F&delimiter=%2F`) },
      { method: "GET", url: v0(`/o/${enc(name)}?alt=media&alt=media`) },
      {
        method: "GET",
        url: gcs(`/o?prefix=${enc(`${P}/`)}&prefix=${enc(`${P}/`)}`),
        headers: owner,
      },
    ])
      refuses(/repeated query parameter/, repeated);
    refuses(
      /query parameter not allowed/,
      {
        method: "PUT",
        url: "http://127.0.0.1:9199/internal/setRules?x=1",
        headers: { authorization: "Bearer owner" },
      },
      local,
    );
  });

  it("names the reason for a Cloud Storage JSON API request that is not one of the forms", () => {
    refuses(/bucket not allowed/, {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/other-bucket`,
      headers: owner,
    });
    refuses(/bucket not allowed/, {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/x/${bucket}`,
      headers: owner,
    });
    refuses(/bucket method/, { method: "DELETE", url: gcs(""), headers: owner });
    refuses(/list method/, {
      method: "POST",
      url: gcs(`/o?prefix=${enc(`${P}/`)}`),
      headers: owner,
    });
    refuses(/delete without a generation precondition/, {
      method: "DELETE",
      url: gcs(`/o/${enc(name)}`),
      headers: owner,
    });
    refuses(/delete without a generation precondition/, {
      method: "DELETE",
      url: gcs(`/o/${enc(name)}?ifGenerationMatch=0`),
      headers: owner,
    });
    refuses(/delete without a generation precondition/, {
      method: "DELETE",
      url: gcs(`/o/${enc(name)}?ifGenerationMatch=12x`),
      headers: owner,
    });
    refuses(/delete without a generation precondition/, {
      method: "DELETE",
      url: gcs(`/o/${enc(name)}?ifGenerationMatch=123456789012345678901`),
      headers: owner,
    });
    assert.equal(
      classifyRequest(
        production,
        {
          method: "DELETE",
          url: gcs(`/o/${enc(name)}?ifGenerationMatch=12345678901234567890`),
          headers: owner,
        },
        state(),
      ),
      "gcs-delete",
    );
    refuses(/storage JSON path/, { method: "PUT", url: gcs(`/o/${enc(name)}`), headers: owner });
    refuses(/storage JSON path/, {
      method: "PATCH",
      url: gcs(`/o/${enc(name)}?ifGenerationMatch=1`),
      headers: owner,
      body: json({ metadata: {} }),
    });
    refuses(/storage JSON path/, { method: "GET", url: gcs(`/iam`), headers: owner });
    refuses(/storage JSON path/, {
      method: "GET",
      url: gcs(`/o/${enc(name)}/acl`),
      headers: owner,
    });
    refuses(/path/, {
      method: "GET",
      url: `https://storage.googleapis.com/storage/v2/b/${bucket}`,
      headers: owner,
    });
    refuses(/path/, {
      method: "GET",
      url: `https://storage.googleapis.com/other/v1/b/${bucket}`,
      headers: owner,
    });
  });

  it("names the reason for an upload that is not the recorded form", () => {
    const at = (query, extra = {}) => ({
      method: "POST",
      url: upload(query),
      headers: owner,
      ...extra,
    });
    const good = `?uploadType=media&name=${enc(name)}&ifGenerationMatch=0`;
    assert.equal(classifyRequest(production, at(good), state()), "gcs-create");
    refuses(/upload path/, {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/other-bucket/o${good}`,
      headers: owner,
    });
    refuses(/upload path/, {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}${good}`,
      headers: owner,
    });
    refuses(/upload path/, {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/x${good}`,
      headers: owner,
    });
    refuses(/upload path/, {
      method: "POST",
      url: `https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o/x${good}`,
      headers: owner,
    });
    refuses(/upload method/, { method: "PUT", url: upload(good), headers: owner });
    refuses(/upload type/, at(`?uploadType=resumable&name=${enc(name)}&ifGenerationMatch=0`));
    refuses(/upload type/, at(`?name=${enc(name)}&ifGenerationMatch=0`));
    refuses(/upload without ifGenerationMatch=0/, at(`?uploadType=media&name=${enc(name)}`));
    refuses(
      /upload without ifGenerationMatch=0/,
      at(`?uploadType=media&name=${enc(name)}&ifGenerationMatch=1`),
    );
    refuses(
      /object outside the run root/,
      at(`?uploadType=media&name=${enc("elsewhere/x")}&ifGenerationMatch=0`),
    );
    refuses(/object outside the run root/, at("?uploadType=media&ifGenerationMatch=0"));
    refuses(/multipart content type/, multipart("{}", "multipart/related"));
    refuses(/multipart content type/, multipart("{}", "multipart/related; boundary=short"));
    refuses(/multipart content type/, multipart("{}", "multipart/mixed; boundary=s9boundary0123"));
    refuses(
      /multipart content type/,
      multipart("{}", "multipart/related; boundary=s9 boundary0123"),
    );
    refuses(/multipart metadata part/, multipart("not json"));
    refuses(/multipart metadata part/, {
      ...multipart("{}"),
      body: Buffer.from("no boundary here"),
    });
    refuses(/multipart metadata/, multipart(JSON.stringify({ name, metadata: [] })));
    refuses(/multipart metadata/, multipart(JSON.stringify({ name, metadata: "v" })));
    refuses(/multipart metadata/, multipart(JSON.stringify({ name: `${name}x`, metadata: {} })));
    refuses(/multipart metadata/, multipart(JSON.stringify({ name })));
    refuses(/multipart metadata/, multipart(JSON.stringify({ name, metadata: {}, acl: [] })));
    refuses(/multipart metadata/, multipart(JSON.stringify({ metadata: {} })));
    assert.equal(
      classifyRequest(
        production,
        multipart(JSON.stringify({ name, metadata: { k: "v" } })),
        state(),
      ),
      "gcs-create",
    );
    assert.equal(
      classifyRequest(production, multipart(JSON.stringify({ name, metadata: {} })), state()),
      "gcs-create",
    );
  });

  it("names the reason for a v0 request that is not one of the forms", () => {
    refuses(/bucket not allowed/, {
      method: "GET",
      url: `https://firebasestorage.googleapis.com/v0/b/other/o/${enc(name)}`,
    });
    refuses(/bucket not allowed/, {
      method: "GET",
      url: `https://firebasestorage.googleapis.com/v0/x/${bucket}/o/${enc(name)}`,
    });
    refuses(/v0 method/, { method: "POST", url: v0(`/o/${enc(name)}`) });
    refuses(/v0 method/, { method: "DELETE", url: v0(`/o?prefix=${enc(`${P}/`)}`) });
    refuses(/alt/, { method: "GET", url: v0(`/o/${enc(name)}?alt=json`) });
    refuses(/delimiter/, { method: "GET", url: v0(`/o?prefix=${enc(`${P}/`)}&delimiter=a`) });
    assert.equal(
      classifyRequest(
        production,
        { method: "GET", url: v0(`/o?prefix=${enc(`${P}/`)}&delimiter=%2F`) },
        state(),
      ),
      "v0-list",
    );
    assert.equal(
      classifyRequest(production, { method: "GET", url: v0(`/o/${enc(name)}?alt=media`) }, state()),
      "v0-media",
    );
    assert.equal(
      classifyRequest(production, { method: "GET", url: v0(`/o/${enc(name)}`) }, state()),
      "v0-meta",
    );
    refuses(/v0 path/, { method: "GET", url: v0(`/x/${enc(name)}`) });
    refuses(/v0 path/, { method: "GET", url: v0(`/o/${enc(name)}/x`) });
    refuses(/v0 path/, { method: "GET", url: v0("") });
  });

  it("names the reason for the setRules route", () => {
    const at = (path, method = "PUT") => ({
      method,
      url: `http://127.0.0.1:9199${path}`,
      headers: { authorization: "Bearer owner" },
    });
    assert.equal(classifyRequest(local, at("/internal/setRules"), state()), "local-set-rules");
    refuses(/setRules method/, at("/internal/setRules", "POST"), local);
    refuses(/setRules method/, at("/internal/setRules", "GET"), local);
    refuses(/path/, at("/internal/other"), local);
    refuses(/rules API on a local target/, at(`/v1/projects/${project}/rulesets`, "GET"), local);
    refuses(/path/, {
      method: "PUT",
      url: "https://storage.googleapis.com/internal/setRules",
      headers: owner,
    });
  });

  it("names the reason for a Rules API request that is not one of the forms", () => {
    refuses(/project not allowed/, {
      method: "GET",
      url: "https://firebaserules.googleapis.com/v1/projects/other/rulesets",
      headers: owner,
    });
    refuses(/rules API path/, { method: "GET", url: rules("/other"), headers: owner });
    refuses(/rules API path/, { method: "PUT", url: rules("/rulesets"), headers: owner });
    refuses(/rules API path/, { method: "GET", url: rules("/releases"), headers: owner });
    refuses(/rules API path/, { method: "POST", url: rules(releasePath), headers: owner });
    refuses(/rules API path/, { method: "POST", url: rules("/rulesets/x"), headers: owner });
    refuses(/rules API path/, { method: "GET", url: rules(`${releasePath}/x`), headers: owner });
    refuses(/path/, {
      method: "GET",
      url: `https://firebaserules.googleapis.com/v2/projects/${project}/rulesets`,
      headers: owner,
    });
    refuses(/ruleset id/, { method: "GET", url: rules("/rulesets/a.b"), headers: owner });
    refuses(/ruleset id/, {
      method: "GET",
      url: rules(`/rulesets/${"a".repeat(129)}`),
      headers: owner,
    });
    refuses(/ruleset id/, { method: "GET", url: rules("/rulesets/a%20b"), headers: owner });
    assert.equal(
      classifyRequest(
        production,
        { method: "GET", url: rules(`/rulesets/${"a".repeat(128)}`), headers: owner },
        state(),
      ),
      "ruleset-get",
    );
    refuses(/page size/, { method: "GET", url: rules("/rulesets?pageSize=50"), headers: owner });
    assert.equal(
      classifyRequest(
        production,
        { method: "GET", url: rules("/rulesets"), headers: owner },
        state(),
      ),
      "ruleset-list",
    );
    refuses(/bucketless release method/, {
      method: "DELETE",
      url: rules("/releases/firebase.storage"),
      headers: owner,
    });
    refuses(/bucketless release method/, {
      method: "PATCH",
      url: rules("/releases/firebase.storage"),
      headers: owner,
      body: patchBody(ownName),
    });
  });

  it("names the reason for a bad ruleset create body", () => {
    const post = (body) => ({ method: "POST", url: rules("/rulesets"), headers: owner, body });
    const file = { name: "storage.rules", content: "x" };
    for (const bad of [
      json({}),
      json({ source: {} }),
      json({ source: { files: [file] }, extra: 1 }),
      json({ source: { files: [file], extra: 1 } }),
      json({ source: { files: file } }),
      json({ source: { files: [] } }),
      json({ source: { files: [file, file] } }),
      json({ source: { files: [{ name: "storage.rules" }] } }),
      json({ source: { files: [{ ...file, extra: 1 }] } }),
      json({ source: { files: [{ name: "firestore.rules", content: "x" }] } }),
      json({ source: { files: [{ name: "storage.rules", content: 5 }] } }),
      json(null),
      json([]),
    ])
      refuses(/ruleset body/, post(bad));
    assert.equal(classifyRequest(production, post(createBody("")), state()), "ruleset-create");
  });

  it("names the reason for a ruleset delete of a ruleset this run did not create", () => {
    refuses(/delete of a ruleset this run did not create/, {
      method: "DELETE",
      url: `https://firebaserules.googleapis.com/v1/${baselineName}`,
      headers: owner,
    });
    refuses(
      /delete of a ruleset this run did not create/,
      {
        method: "DELETE",
        url: `https://firebaserules.googleapis.com/v1/${ownName}`,
        headers: owner,
      },
      production,
      state({ ownRulesets: new Set() }),
    );
    refuses(/rules API path/, {
      method: "PATCH",
      url: `https://firebaserules.googleapis.com/v1/${ownName}`,
      headers: owner,
    });
  });

  it("names the reason for a bad release body or method", () => {
    const patch = (body) => ({ method: "PATCH", url: rules(releasePath), headers: owner, body });
    for (const bad of [
      json({}),
      json({ release: { name: releaseName, rulesetName: ownName } }),
      patchBody(ownName, { extra: 1 }),
      json({ release: { name: releaseName }, updateMask: "rulesetName" }),
      json({
        release: { name: releaseName, rulesetName: ownName, extra: 1 },
        updateMask: "rulesetName",
      }),
      json({
        release: { name: `${releaseName}x`, rulesetName: ownName },
        updateMask: "rulesetName",
      }),
      json({ release: { name: releaseName, rulesetName: ownName }, updateMask: "name" }),
      json({ release: [], updateMask: "rulesetName" }),
    ])
      refuses(/release patch body/, patch(bad));
    refuses(
      /release patch to a ruleset that is neither/,
      patch(patchBody(`projects/${project}/rulesets/foreign`)),
    );
    refuses(
      /release patch to a ruleset that is neither/,
      patch(patchBody(baselineName)),
      production,
      state({ baseline: "absent" }),
    );
    assert.equal(
      classifyRequest(production, patch(patchBody(baselineName)), state()),
      "release-patch",
    );
    const post = (body) => ({ method: "POST", url: rules("/releases"), headers: owner, body });
    for (const bad of [
      json({}),
      json({ name: releaseName }),
      json({ name: releaseName, rulesetName: ownName, extra: 1 }),
      json({ name: `${releaseName}x`, rulesetName: ownName }),
      json({ name: releaseName, rulesetName: baselineName }),
      json({ name: releaseName, rulesetName: `projects/${project}/rulesets/foreign` }),
    ])
      refuses(/release create body/, post(bad));
    assert.equal(
      classifyRequest(production, post(json({ name: releaseName, rulesetName: ownName })), state()),
      "release-create",
    );
    refuses(/release delete with a baseline release/, {
      method: "DELETE",
      url: rules(releasePath),
      headers: owner,
    });
    assert.equal(
      classifyRequest(
        production,
        { method: "DELETE", url: rules(releasePath), headers: owner },
        state({ baseline: "absent" }),
      ),
      "release-delete",
    );
    refuses(/rules API path/, { method: "PUT", url: rules(releasePath), headers: owner });
  });

  it("names the reason for a baseline that is not a ruleset of the project", () => {
    for (const bad of [
      "",
      "present",
      "projects/other/rulesets/x",
      `${baselineName}/x`,
      `${baselineName}.`,
      "projects/fireemu-oracle-query/rulesets/",
      undefined,
      null,
      5,
    ])
      assert.throws(
        () => validateBaseline(bad, project),
        (error) => error instanceof GuardError && /baseline is neither/.test(error.message),
      );
    assert.equal(
      validateBaseline(`projects/${project}/rulesets/${"a".repeat(128)}`, project),
      `projects/${project}/rulesets/${"a".repeat(128)}`,
    );
    assert.throws(
      () => validateBaseline(`projects/${project}/rulesets/${"a".repeat(129)}`, project),
      GuardError,
    );
  });
});
