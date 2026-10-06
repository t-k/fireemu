import assert from "node:assert/strict";
import { test } from "node:test";
import {
  attemptPreconditionUpload,
  readBucketMetadata,
  runStorageScenario,
} from "./functions-events/storage-driver.mjs";

test("a precondition-failed upload stays on loopback, carries ifGenerationMatch=1 and no extra header, and reads the answer", async () => {
  const calls = [];
  const answer = (status) => async (url, init) => {
    calls.push({ url, init });
    return { status, ok: status < 300 };
  };
  const refused = await attemptPreconditionUpload({
    host: "127.0.0.1:1234",
    bucket: "demo-conformance-events-primary",
    name: "fe-events/object-1",
    request: answer(412),
  });
  assert.deepEqual(refused, { status: 412, sourceResult: "typed-refusal" });
  assert.equal(calls.length, 1);
  const url = new URL(calls[0].url);
  assert.equal(url.origin, "http://127.0.0.1:1234");
  assert.equal(url.pathname, "/upload/storage/v1/b/demo-conformance-events-primary/o");
  assert.equal(url.searchParams.get("uploadType"), "media");
  assert.equal(url.searchParams.get("name"), "fe-events/object-1");
  assert.equal(url.searchParams.get("ifGenerationMatch"), "1");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.body, "refused");
  assert.deepEqual(Object.keys(calls[0].init.headers).toSorted(), [
    "authorization",
    "content-type",
  ]);
  // a profile that completes the write (the official emulator ignores the precondition) is recorded as it is
  assert.deepEqual(
    await attemptPreconditionUpload({
      host: "127.0.0.1:1234",
      bucket: "b",
      name: "n",
      request: answer(200),
    }),
    { status: 200, sourceResult: "typed-success" },
  );
  assert.deepEqual(
    await attemptPreconditionUpload({
      host: "localhost:9",
      bucket: "b",
      name: "n",
      request: answer(400),
    }),
    { status: 400, sourceResult: "typed-refusal" },
  );
  // anything else is an error, never a result
  for (const status of [301, 500, 503])
    await assert.rejects(
      attemptPreconditionUpload({
        host: "127.0.0.1:1234",
        bucket: "b",
        name: "n",
        request: answer(status),
      }),
      new RegExp(`HTTP ${status}`),
    );
  const before = calls.length;
  await assert.rejects(
    attemptPreconditionUpload({
      host: "storage.googleapis.com:443",
      bucket: "demo-conformance-events-primary",
      name: "fe-events/object-1",
      request: answer(412),
    }),
    /loopback Storage emulator/,
  );
  assert.equal(calls.length, before);
});

function failedUploadWorld({ status }) {
  const events = [];
  const generations = [];
  const file = {
    name: "",
    async save(body) {
      events.push(`save:${body}`);
      generations.unshift(`g${generations.length + 1}`);
    },
    async getMetadata() {
      if (generations.length === 0) throw Object.assign(new Error("absent"), { code: 404 });
      return [{ generation: generations[0], metageneration: "1", contentType: "text/plain" }];
    },
    async delete() {
      events.push("delete");
    },
  };
  const bucket = {
    file: (name) => Object.assign(file, { name }),
    async getFiles() {
      return [[]];
    },
  };
  const capture = {
    async barrier() {
      return { cursor: 0 };
    },
    since() {
      return ["storageFinalizedV1", "storageFinalizedV2"].map((handler) => ({
        frame: {
          handler,
          event: { data: { bucket: "demo-conformance-events-primary", name: file.name } },
        },
      }));
    },
  };
  const requests = [];
  const request = async (url, init) => {
    requests.push({ url, init });
    if (status < 300) generations.unshift("g-after");
    return { status, ok: status < 300 };
  };
  return { events, requests, request, capture, storage: { bucket: () => bucket }, generations };
}

test("storage-failed-upload seeds first, then writes with a failing precondition, and the object is unchanged", async () => {
  const world = failedUploadWorld({ status: 412 });
  process.env.FIREBASE_STORAGE_EMULATOR_HOST = "127.0.0.1:1234";
  const result = await runStorageScenario({
    scenario: { id: "storage-failed-upload", resource: "bucket-primary", objectRole: "primary" },
    capture: world.capture,
    storage: world.storage,
    request: world.request,
  });
  assert.deepEqual(world.events.slice(0, 1), ["save:before"], "the seed is the first write");
  assert.equal(world.requests.length, 1);
  assert.equal(new URL(world.requests[0].url).searchParams.get("ifGenerationMatch"), "1");
  assert.equal(result.sourceResult, "typed-refusal");
  assert.equal(result.readback.exists, true);
  assert.equal(result.readback.generation, "g1", "the seed generation is still the object's");
  assert.equal(result.matchKey.kind, "storage");
  // the production script names this scenario's object with a 28-character id: fe-events/<28>.txt is 42 characters
  assert.equal(result.matchKey.value.length, 42);
  assert.match(result.matchKey.value, /^fe-events\/e[0-9a-f]{24}o\d+\.txt$/);
});

test("storage-failed-upload where the write completes is a typed success with the new generation (the official emulator's behaviour)", async () => {
  const world = failedUploadWorld({ status: 200 });
  process.env.FIREBASE_STORAGE_EMULATOR_HOST = "127.0.0.1:1234";
  const result = await runStorageScenario({
    scenario: { id: "storage-failed-upload", resource: "bucket-primary", objectRole: "primary" },
    capture: world.capture,
    storage: world.storage,
    request: world.request,
  });
  assert.equal(result.sourceResult, "typed-success");
  assert.equal(result.readback.generation, "g-after");
});

test("storage-failed-upload fails when a refused write changed the object", async () => {
  const world = failedUploadWorld({ status: 412 });
  const request = async (url, init) => {
    world.generations.unshift("g-changed");
    return world.request(url, init);
  };
  process.env.FIREBASE_STORAGE_EMULATOR_HOST = "127.0.0.1:1234";
  await assert.rejects(
    runStorageScenario({
      scenario: { id: "storage-failed-upload", resource: "bucket-primary", objectRole: "primary" },
      capture: world.capture,
      storage: world.storage,
      request,
    }),
    /refused write changed the Storage object/,
  );
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
