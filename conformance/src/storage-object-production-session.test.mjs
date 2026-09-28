import assert from "node:assert/strict";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const sessionModule = await import("./storage-object/production-session.mjs").catch(() => ({}));
const boundary = {
  bucket: "example.appspot.com",
  prefix: "storage-object/recordone/",
  dialect: "gcs",
  objectName: "storage-object/recordone/gcs/resumable.bin",
};
const origin = (dialect) =>
  `https://${dialect === "gcs" ? "storage" : "firebasestorage"}.googleapis.com`;
const path = (dialect) =>
  dialect === "gcs" ? `/upload/storage/v1/b/${boundary.bucket}/o` : `/v0/b/${boundary.bucket}/o`;
const uri = (dialect = "gcs", query = "upload_id=SYNTHETIC%2fCAPABILITY") =>
  `${origin(dialect)}${path(dialect)}?${query}&${dialect === "gcs" ? "uploadType" : "upload_protocol"}=resumable`;
const validate = (value, config = boundary) => {
  assert.equal(typeof sessionModule.validateProductionSessionUri, "function");
  return sessionModule.validateProductionSessionUri(value, config);
};

test("closed session URI validation preserves the opaque request target for both dialects", () => {
  for (const dialect of ["gcs", "firebase"]) {
    const config = { ...boundary, dialect };
    for (const value of [
      uri(dialect),
      uri(
        dialect,
        `name=${encodeURIComponent(config.objectName).replaceAll("%2F", "%2f")}&upload_id=SYNTHETIC%2fCAPABILITY`,
      ),
    ]) {
      const result = validate(value, config);
      assert.equal(result.url, value);
      assert.equal(result.uploadId, "SYNTHETIC/CAPABILITY");
      assert.equal(result.objectName, config.objectName);
      assert.match(result.uriSha256, /^[a-f0-9]{64}$/);
      assert.equal(Object.isFrozen(result), true);
    }
  }
});

test("session URI validation rejects foreign, ambiguous and normalized routes", () => {
  const good = uri();
  for (const value of [
    good.replace("https:", "http:"),
    good.replace("storage.googleapis.com", "storage.googleapis.com.evil.example"),
    good.replace("storage.googleapis.com", "owner@storage.googleapis.com"),
    good.replace("storage.googleapis.com", "storage.googleapis.com:443"),
    good.replace(boundary.bucket, "foreign.appspot.com"),
    `${good}&name=foreign`,
    `${good}&unknown=value`,
    `${good}&upload_id=SECOND`,
    `${good}&uploadType=resumable`,
    `${good}#fragment`,
    `${good}#`,
    `${good}\n`,
    good.replace("SYNTHETIC%2fCAPABILITY", ""),
    good.replace("SYNTHETIC%2fCAPABILITY", "bad%20id"),
    good.replace("SYNTHETIC%2fCAPABILITY", "bad%00id"),
    good.replace("SYNTHETIC%2fCAPABILITY", "bad%ZZid"),
    good.replace("uploadType=resumable", "uploadType=media"),
    good.replace("uploadType=resumable", "upload_protocol=resumable"),
    good.replace("/upload/storage/v1/", "/upload/./storage/v1/"),
    good.replace("storage.googleapis.com", "STORAGE.googleapis.com"),
  ])
    assert.throws(() => validate(value), /invalid production session URI/);
  for (const change of [
    { dialect: "unknown" },
    { objectName: "storage-object/recordtwo/gcs/resumable.bin" },
    { prefix: "foreign/" },
    { origin: "https://foreign.example" },
  ])
    assert.throws(() => validate(good, { ...boundary, ...change }), /session URI/);
});

test("session configuration rejects coercion, accessors and Proxy hooks without invoking them", () => {
  let hooks = 0;
  const coercion = {
    toString: () => {
      hooks++;
      return uri();
    },
  };
  assert.throws(() => validate(coercion), /session URI/);
  for (const key of Object.keys(boundary)) {
    const config = { ...boundary };
    Object.defineProperty(config, key, {
      enumerable: true,
      get: () => {
        hooks++;
        return boundary[key];
      },
    });
    assert.throws(() => validate(uri(), config), /session URI/);
  }
  const config = new Proxy(boundary, {
    getPrototypeOf: () => {
      hooks++;
      return Object.prototype;
    },
  });
  assert.throws(() => validate(uri(), config), /session URI/);
  assert.equal(hooks, 0);
});

function stepFor(dialect, command = "query") {
  const config = { ...boundary, dialect };
  return {
    id: "continuation",
    dialect,
    method: dialect === "gcs" ? "PUT" : "POST",
    objectName: config.objectName,
    credential: "admin",
    query: {},
    headers:
      dialect === "gcs"
        ? { "content-length": "0", "content-range": "bytes */262147" }
        : { "x-goog-upload-command": command },
    sessionUriReference: {
      kind: dialect === "gcs" ? "gcs-resumable-location" : "firebase-resumable-url",
      initiateStep: "initiate",
      expectedOrigin: origin(dialect),
      expectedPath: path(dialect),
      expectedName: config.objectName,
      secretHandling: "private-only",
    },
  };
}
const resolve = (step, binding) => {
  assert.equal(typeof sessionModule.resolveProductionSessionRoute, "function");
  return sessionModule.resolveProductionSessionRoute(step, binding);
};
const bindingFor = (dialect) => ({
  ...boundary,
  dialect,
  uri: uri(dialect),
  initiateStep: "initiate",
});

test("session continuation routes distinguish mutation from query without reconstructing the URI", () => {
  for (const dialect of ["gcs", "firebase"]) {
    const step = stepFor(dialect),
      binding = bindingFor(dialect);
    const query = resolve(step, binding);
    assert.equal(query.url, binding.uri);
    assert.equal(query.mutation, false);
    assert.equal(query.objectName, binding.objectName);
    const upload =
      dialect === "gcs"
        ? { ...step, headers: { "content-length": "3", "content-range": "bytes 0-2/3" } }
        : {
            ...step,
            headers: { "x-goog-upload-command": "upload, finalize", "x-goog-upload-offset": "0" },
          };
    assert.equal(resolve(upload, binding).mutation, true);
    const cancel =
      dialect === "gcs"
        ? { ...step, method: "DELETE", headers: { "content-length": "0" } }
        : { ...step, headers: { "x-goog-upload-command": "cancel" } };
    assert.equal(resolve(cancel, binding).mutation, true);
  }
});

test("session continuation routes reject undeclared credentials, queries, headers and references", () => {
  const step = stepFor("gcs"),
    binding = bindingFor("gcs");
  const changes = [
    { path: path("gcs") },
    { credential: undefined },
    { credential: "none" },
    { credential: "admin", credentialRef: { kind: "owner-oauth" } },
    { method: "GET" },
    { query: { upload_id: "FORGED" } },
    { headers: { ...step.headers, authorization: "Bearer SYNTHETIC_OWNER" } },
    { headers: { ...step.headers, "x-unknown": "1" } },
    { headers: { "content-length": "1", "content-range": "bytes */262147" } },
    { headers: { "content-length": "3", "content-range": "bytes 2-0/3" } },
    { sessionUriReference: { ...step.sessionUriReference, initiateStep: "foreign" } },
    { sessionUriReference: { ...step.sessionUriReference, expectedName: "foreign" } },
    { sessionUriReference: { ...step.sessionUriReference, expectedOrigin: origin("firebase") } },
    { sessionUriReference: { ...step.sessionUriReference, extra: "value" } },
  ];
  for (const change of changes)
    assert.throws(() => resolve({ ...step, ...change }, binding), /session route/);
  const firebase = stepFor("firebase");
  for (const headers of [
    { "x-goog-upload-command": "start" },
    { "x-goog-upload-command": "query", "x-goog-upload-offset": "0" },
    { "x-goog-upload-command": "upload", "x-goog-upload-offset": "-1" },
  ])
    assert.throws(() => resolve({ ...firebase, headers }, bindingFor("firebase")), /session route/);
});

test("every frozen session continuation and cleanup route fits the closed family", () => {
  const corpus = buildCorpus({ bucket: boundary.bucket, prefix: boundary.prefix });
  let checked = 0;
  for (const recipe of corpus.recipes)
    for (const step of [...recipe.steps, ...recipe.cleanup]) {
      if (!step.sessionUriReference) continue;
      const binding = {
        ...bindingFor(step.dialect),
        objectName: step.objectName,
        initiateStep: step.sessionUriReference.initiateStep,
      };
      assert.equal(resolve(step, binding).url, binding.uri);
      checked++;
    }
  assert.ok(checked > 15);
});

test("continuation descriptors, nested Proxy objects and value coercion cannot invoke hooks", () => {
  let hooks = 0;
  const step = stepFor("gcs"),
    binding = bindingFor("gcs");
  for (const key of ["headers", "query", "sessionUriReference"]) {
    const nested = new Proxy(step[key], {
      getPrototypeOf: () => {
        hooks++;
        return Object.prototype;
      },
    });
    assert.throws(() => resolve({ ...step, [key]: nested }, binding), /session route/);
    const candidate = { ...step };
    Object.defineProperty(candidate, key, {
      enumerable: true,
      get: () => {
        hooks++;
        return step[key];
      },
    });
    assert.throws(() => resolve(candidate, binding), /session route/);
  }
  const revoked = Proxy.revocable(binding, {});
  revoked.revoke();
  assert.throws(() => resolve(step, revoked.proxy), /session route/);
  const coercion = {
    toString: () => {
      hooks++;
      return "bytes */262147";
    },
  };
  assert.throws(
    () => resolve({ ...step, headers: { ...step.headers, "content-range": coercion } }, binding),
    /session route/,
  );
  const symbol = { ...binding, [Symbol("override")]: "foreign" };
  assert.throws(() => resolve(step, symbol), /session route/);
  assert.equal(hooks, 0);
});
