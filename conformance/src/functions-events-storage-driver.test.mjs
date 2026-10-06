import assert from "node:assert/strict";
import { test } from "node:test";
import {
  attemptInvalidChecksumUpload,
  readBucketMetadata,
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

const notFound = () => Object.assign(new Error("bucket absent"), { code: 404 });

test("a bucket nobody created is created, once, before its metadata is read (the strict profile answers 404 for it)", async () => {
  const calls = [];
  let exists = false;
  const bucket = {
    async getMetadata() {
      calls.push("getMetadata");
      if (!exists) throw notFound();
      return [{ versioning: { enabled: false } }];
    },
    async create() {
      calls.push("create");
      exists = true;
    },
  };
  assert.deepEqual(await readBucketMetadata(bucket), { versioning: { enabled: false } });
  assert.deepEqual(calls, ["getMetadata", "create", "getMetadata"]);
});

test("a bucket that exists is read without being created", async () => {
  const calls = [];
  const bucket = {
    async getMetadata() {
      calls.push("getMetadata");
      return [{ versioning: { enabled: true } }];
    },
    async create() {
      calls.push("create");
    },
  };
  assert.deepEqual(await readBucketMetadata(bucket), { versioning: { enabled: true } });
  assert.deepEqual(calls, ["getMetadata"]);
});

test("only an absent bucket is created: any other failure of the read is the unavailable readback, with nothing created", async () => {
  for (const failure of [
    Object.assign(new Error("denied"), { code: 403 }),
    Object.assign(new Error("server"), { code: 500 }),
    new Error("no code"),
  ]) {
    const calls = [];
    const bucket = {
      async getMetadata() {
        calls.push("getMetadata");
        throw failure;
      },
      async create() {
        calls.push("create");
      },
    };
    await assert.rejects(
      readBucketMetadata(bucket),
      /versioning configuration readback is unavailable/,
      failure.message,
    );
    assert.deepEqual(calls, ["getMetadata"], failure.message);
  }
});

test("a bucket that cannot be created, or still cannot be read after it is, is the unavailable readback", async () => {
  for (const [label, create, again] of [
    [
      "create fails",
      async () => {
        throw new Error("create refused");
      },
      notFound,
    ],
    ["still absent", async () => {}, notFound],
  ]) {
    const calls = [];
    const bucket = {
      async getMetadata() {
        calls.push("getMetadata");
        throw again();
      },
      async create() {
        calls.push("create");
        return create();
      },
    };
    await assert.rejects(
      readBucketMetadata(bucket),
      /versioning configuration readback is unavailable/,
      label,
    );
    assert.deepEqual(calls.slice(0, 2), ["getMetadata", "create"], label);
  }
});

test("archive stops before mutation when bucket versioning cannot be read back", async () => {
  const mutations = [];
  const bucket = {
    file() {
      return {
        async getMetadata() {
          throw notFound();
        },
      };
    },
    async getMetadata() {
      throw notFound();
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
  // The absent bucket was created for the readback; versioning was never touched.
  assert.deepEqual(mutations, ["create"]);
});
