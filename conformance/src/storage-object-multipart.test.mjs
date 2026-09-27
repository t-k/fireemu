import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/run-012345/" };
const find = (suffix) => {
  const recipe = buildCorpus(input).recipes.find((r) => r.id === `storage-object/${suffix}`);
  assert.ok(recipe, `missing ${suffix}`);
  return recipe;
};
const bytes = (request) => Buffer.from(request.body.base64, "base64");

function decodeParts(request) {
  const match = /^multipart\/related; boundary=([A-Za-z0-9-]+)$/.exec(request.headers["content-type"]);
  assert.ok(match, "explicit MIME boundary");
  const boundary = match[1];
  // Latin-1 makes framing comparisons byte preserving, including non-UTF-8 media.
  const body = bytes(request).toString("latin1");
  assert.ok(body.startsWith(`--${boundary}\r\n`));
  assert.ok(body.endsWith(`\r\n--${boundary}--\r\n`));
  const parts = body.slice(boundary.length + 4, -(boundary.length + 8)).split(`\r\n--${boundary}\r\n`);
  return parts.map((part) => {
    const divider = part.indexOf("\r\n\r\n");
    assert.ok(divider >= 0);
    return { headers: part.slice(0, divider), body: Buffer.from(part.slice(divider + 4), "latin1") };
  });
}

test("multipart recipes isolate valid and malformed attempts and read back both APIs", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = find(dialect === "firebase" ? "firebase/multipart-upload" : "gcs/simple-multipart-upload");
    const attempts = recipe.steps.filter((s) => s.method === "POST");
    assert.deepEqual(attempts.map((s) => s.id), dialect === "firebase"
      ? ["valid", "invalid-json", "missing-media"] : ["media", "valid", "invalid-json", "missing-media"]);
    assert.equal(new Set(attempts.map((s) => s.objectName)).size, attempts.length);
    assert.deepEqual(new Set(attempts.map((s) => s.objectName)), new Set(recipe.objects));
    for (const request of attempts) {
      assert.equal(request.dialect, dialect);
      assert.equal(request.query.name, request.objectName);
      const i = recipe.steps.indexOf(request);
      assert.deepEqual(recipe.steps.slice(i + 1, i + 5).map((s) => [s.objectName, s.dialect, s.method, s.query.alt ?? null]),
        ["firebase", "gcs"].flatMap((api) => [[request.objectName, api, "GET", null], [request.objectName, api, "GET", "media"]]));
      if (request.id === "media") {
        assert.equal(request.query.uploadType, "media");
        assert.deepEqual(bytes(request), Buffer.from([0, 1, 127, 128, 255]));
        continue;
      }
      assert.equal(request.query.uploadType, dialect === "gcs" ? "multipart" : undefined);
      assert.equal(request.headers["x-goog-upload-protocol"], dialect === "firebase" ? "multipart" : undefined);
      const parts = decodeParts(request);
      assert.equal(parts[0].headers, "Content-Type: application/json; charset=utf-8");
      if (request.id === "invalid-json") assert.throws(() => JSON.parse(parts[0].body.toString("utf8")));
      else {
        const metadata = JSON.parse(parts[0].body.toString("utf8"));
        assert.equal(metadata.name, request.objectName);
        assert.equal(metadata.contentType, "application/octet-stream");
        assert.deepEqual(metadata.metadata, { marker: "multipart-observation" });
      }
      assert.equal(parts.length, request.id === "missing-media" ? 1 : 2);
      if (parts.length === 2) {
        assert.equal(parts[1].headers, "Content-Type: application/octet-stream");
        assert.deepEqual(parts[1].body, Buffer.from([0, 1, 127, 128, 255]));
      }
    }
  }
});

test("checksum declarations distinguish each valid, mismatched and malformed field", () => {
  const recipe = find("gcs/checksums");
  const attempts = recipe.steps.filter((s) => s.method === "POST");
  assert.deepEqual(attempts.map((s) => s.id), ["valid-md5", "valid-crc32c", "valid-both", "mismatch-md5", "mismatch-crc32c", "malformed-md5", "malformed-crc32c"]);
  assert.equal(new Set(attempts.map((s) => s.objectName)).size, 7);
  const md5 = createHash("md5").update("123456789").digest("base64");
  const valid = { md5Hash: md5, crc32c: "4waSgw==" }; // CRC32C check vector: 0xe3069283.
  const declarations = [
    { md5Hash: md5 }, { crc32c: valid.crc32c }, valid,
    { md5Hash: Buffer.alloc(16).toString("base64") }, { crc32c: Buffer.alloc(4).toString("base64") },
    { md5Hash: "!not-base64!" }, { crc32c: "!not-base64!" },
  ];
  for (const [i, request] of attempts.entries()) {
    assert.equal(request.dialect, "gcs");
    assert.equal(request.query.uploadType, "multipart");
    const [metadata, media] = decodeParts(request);
    const value = JSON.parse(metadata.body.toString("utf8"));
    assert.equal(value.name, request.objectName);
    assert.deepEqual(Object.fromEntries(Object.entries(value).filter(([key]) => ["md5Hash", "crc32c"].includes(key))), declarations[i]);
    assert.deepEqual(media.body, Buffer.from("123456789"));
    const at = recipe.steps.indexOf(request);
    assert.deepEqual(recipe.steps.slice(at + 1, at + 5).map((s) => [s.dialect, s.method, s.objectName, s.query.alt ?? null]),
      ["firebase", "gcs"].flatMap((api) => [[api, "GET", request.objectName, null], [api, "GET", request.objectName, "media"]]));
  }
});

test("every multipart and checksum object has independent baseline and cleanup declarations", () => {
  for (const suffix of ["firebase/multipart-upload", "gcs/simple-multipart-upload", "gcs/checksums"]) {
    const recipe = find(suffix);
    for (const name of recipe.objects) {
      assert.ok(name.startsWith(input.prefix));
      assert.deepEqual(recipe.preflight.filter((s) => s.objectName === name).map((s) => [s.dialect, s.method]), [["firebase", "GET"], ["gcs", "GET"]]);
      assert.deepEqual(recipe.cleanup.filter((s) => s.objectName === name).map((s) => [s.dialect, s.method]), [["gcs", "DELETE"], ["firebase", "GET"], ["gcs", "GET"]]);
    }
  }
});
