import assert from "node:assert/strict";
import { test } from "node:test";
import {
  attemptInvalidChecksumUpload,
  runStorageScenario,
} from "./functions-events/storage-driver.mjs";

test("invalid checksum upload stays on loopback and returns a typed refusal", async () => {
  const calls = [];
  const request = async (url, init) => {
    calls.push({ url, init });
    return { status: 400, ok: false };
  };
  const result = await attemptInvalidChecksumUpload({
    host: "127.0.0.1:1234",
    bucket: "demo-conformance-events-primary",
    name: "fe-events/object-1",
    request,
  });
  assert.equal(result, "typed-refusal");
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /^http:\/\/127\.0\.0\.1:1234\/upload\/storage\/v1\/b\//);
  assert.equal(calls[0].init.method, "POST");
  assert.match(calls[0].init.headers["x-goog-hash"], /^md5=/);
  await assert.rejects(
    attemptInvalidChecksumUpload({
      host: "storage.googleapis.com:443",
      bucket: "demo-conformance-events-primary",
      name: "fe-events/object-1",
      request,
    }),
    /loopback Storage emulator/,
  );
  assert.equal(calls.length, 1);
});

test("archive stops before mutation when bucket versioning cannot be read back", async () => {
  const mutations = [];
  const missing = Object.assign(new Error("bucket absent"), { code: 404 });
  const bucket = {
    file() {
      return {
        async getMetadata() {
          throw missing;
        },
      };
    },
    async getMetadata() {
      throw missing;
    },
    async getFiles() {
      return [[]];
    },
    async create() {
      mutations.push("create");
    },
    async setMetadata() {
      mutations.push("versioning");
    },
  };
  await assert.rejects(
    runStorageScenario({
      scenario: { id: "storage-archive", resource: "bucket-primary" },
      capture: {},
      storage: { bucket: () => bucket },
    }),
    /versioning configuration readback is unavailable/,
  );
  assert.deepEqual(mutations, []);
});
