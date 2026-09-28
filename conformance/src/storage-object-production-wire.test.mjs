import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import tls from "node:tls";
import test, { afterEach, beforeEach } from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const module = await import("./storage-object/production-wire-transport.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const argv = [...process.execArgv];
beforeEach(() => {
  process.execArgv = [];
});
afterEach(() => {
  process.execArgv = [...argv];
});
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const ownerToken = "SYNTHETIC_OWNER_ACCESS_TOKEN_123456789";
const firebaseToken = "SYNTHETIC_FIREBASE_ID_TOKEN_123456789";
const key = "SYNTHETIC_API_KEY_123456789";
const objectName = "storage-object/recordone/test.bin";
let operationSequence = 0;
const step = (changes = {}) => ({
  dialect: "gcs",
  method: "GET",
  path: `/storage/v1/b/${plan.bucket}/o/${encodeURIComponent(objectName)}`,
  objectName,
  query: {},
  credential: "admin",
  ...changes,
});
const init = (changes = {}) => ({
  operationId: `r1/p1/${(++operationSequence).toString(16).padStart(64, "0")}`,
  accountingPhase: "subject",
  ...changes,
});

function fixture(changes = {}) {
  assert.equal(
    typeof module.createProductionWireTransport,
    "function",
    "production wire factory is missing",
  );
  const directory = mkdtempSync(join(tmpdir(), "storage-object-production-wire-"));
  chmodSync(directory, 0o700);
  const reservations = [];
  const config = {
    plan,
    resources: {
      projectNumber: "123456789012",
      apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
      rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
    },
    captureDirectory: directory,
    onByteReserve: async (row) => reservations.push(row),
    verifyAdmission: () => true,
    ownerAuthorization: () => `Bearer ${ownerToken}`,
    accountAuthorization: () => `Firebase ${firebaseToken}`,
    ...changes,
  };
  try {
    const wire = module.createProductionWireTransport(config);
    return {
      wire,
      directory,
      reservations,
      async close() {
        await wire.close();
        rmSync(directory, { recursive: true });
      },
    };
  } catch (error) {
    rmSync(directory, { recursive: true });
    throw error;
  }
}

async function withMemoryTls(responseBody, action) {
  const original = tls.connect;
  const connections = [];
  tls.connect = (options) => {
    const connection = { options, request: Buffer.alloc(0), dispatchTimeMs: performance.now() };
    connections.push(connection);
    let responded = false;
    const socket = new Duplex({
      read() {},
      write(bytes, encoding, done) {
        connection.request = Buffer.concat([connection.request, bytes]);
        socket.bytesWritten += bytes.length;
        const boundary = connection.request.indexOf("\r\n\r\n");
        const length = /content-length: (\d+)/i.exec(connection.request.toString())?.[1];
        if (
          !responded &&
          boundary >= 0 &&
          connection.request.length === boundary + 4 + Number(length)
        ) {
          responded = true;
          queueMicrotask(() => {
            const body = Buffer.from(responseBody);
            const response = Buffer.concat([
              Buffer.from(
                `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
              ),
              body,
            ]);
            for (let offset = 0; offset < response.length; offset += 37)
              options.onread.callback(
                Math.min(37, response.length - offset),
                response.subarray(offset, offset + 37),
              );
            socket.push(null);
          });
        }
        done();
      },
    });
    Object.assign(socket, {
      bytesWritten: 0,
      authorized: true,
      alpnProtocol: "http/1.1",
      encrypted: true,
      setTimeout() {
        return this;
      },
      setNoDelay() {
        return this;
      },
      setKeepAlive() {
        return this;
      },
    });
    queueMicrotask(() => socket.emit("secureConnect"));
    return socket;
  };
  try {
    return await action(connections);
  } finally {
    tls.connect = original;
  }
}

test("production factory accepts no provider, CA, timeout, origin or budget overrides", async () => {
  for (const changes of [
    { origins: ["http://localhost:9000"] },
    { localCa: Buffer.from("fixture") },
    { timeoutMs: 1 },
    { fetchImpl: () => assert.fail() },
    { limits: { maxRequestBytes: 1 } },
    { plan: { ...plan, maxRequests: 6600, recoveryReserveRequests: 600 } },
    { verifyAdmission: null },
  ])
    assert.throws(() => fixture(changes), /invalid production wire configuration/);
});

test("invalid route, phase, credential and admission dispatch no request or byte reservation", async () => {
  for (const [request, options, changes] of [
    [step({ credential: undefined }), init(), {}],
    [step({ path: "https://unlisted.example/path" }), init(), {}],
    [step({ objectName: "foreign/object" }), init(), {}],
    [step({ query: { unknown: "value" } }), init(), {}],
    [step(), init({ accountingPhase: "recovery" }), {}],
    [step(), init({ operationId: "SYNTHETIC_OPERATION_SECRET" }), {}],
    [step(), init({ headers: { Authorization: "Bearer PREFILLED_SECRET" } }), {}],
    [step(), init({ verifyBeforeDispatch: () => true }), {}],
    [step(), init(), { verifyAdmission: () => false }],
    [
      step(),
      init(),
      {
        ownerAuthorization: () => {
          throw new Error("RAW_PROVIDER_SECRET");
        },
      },
    ],
  ]) {
    const f = fixture(changes);
    try {
      await withMemoryTls("{}", async (connections) => {
        await assert.rejects(
          f.wire.fetchStorage(1, request, options),
          /PRODUCTION_WIRE_REQUEST_REJECTED/,
        );
        assert.equal(connections.length, 0);
      });
      assert.equal(f.reservations.length, 0);
      assert.deepEqual(readdirSync(f.directory), []);
    } finally {
      await f.close();
    }
  }
});

test("all eight production origins use only their fixed route and real-host TLS policy", async () => {
  const f = fixture();
  try {
    await withMemoryTls("{}", async (connections) => {
      for (const kind of [
        "bucket-config",
        "default-bucket",
        "auth-config",
        "auth-refresh",
        "owner-tokeninfo",
        "rules-release",
        "api-key-metadata",
        "project-binding",
      ])
        await f.wire.fetchControl(
          1,
          kind,
          kind === "auth-refresh" ? { apiKey: key } : {},
          init({
            body:
              kind === "auth-refresh"
                ? "grant_type=refresh_token&refresh_token=SYNTHETIC_REFRESH_SECRET"
                : Buffer.alloc(0),
          }),
        );
      assert.equal(connections.length, 8);
      assert.deepEqual(
        new Set(connections.map((row) => row.options.servername)),
        new Set([
          "storage.googleapis.com",
          "firebasestorage.googleapis.com",
          "identitytoolkit.googleapis.com",
          "securetoken.googleapis.com",
          "oauth2.googleapis.com",
          "firebaserules.googleapis.com",
          "apikeys.googleapis.com",
          "cloudresourcemanager.googleapis.com",
        ]),
      );
      for (const connection of connections) {
        assert.equal(connection.options.rejectUnauthorized, true);
        assert.equal(connection.options.checkServerIdentity, tls.checkServerIdentity);
        assert.equal(connection.options.onread.buffer.length, 8192);
      }
    });
  } finally {
    await f.close();
  }
});

test("factory input Proxy traps and accessors are not invoked", () => {
  let reads = 0;
  for (const changes of [
    {
      plan: new Proxy(plan, {
        get() {
          reads++;
          throw new Error("SYNTHETIC_PROXY_SECRET");
        },
        ownKeys() {
          reads++;
          throw new Error();
        },
      }),
    },
    {
      resources: Object.defineProperty({}, "projectNumber", {
        enumerable: true,
        get() {
          reads++;
          throw new Error("SYNTHETIC_GETTER_SECRET");
        },
      }),
    },
  ])
    assert.throws(() => fixture(changes), /^Error: invalid production wire configuration$/);
  assert.equal(reads, 0);
});

test("actual shared core uses real-host TLS and persists commitments without original secrets", async () => {
  const f = fixture();
  try {
    f.wire.registerSecret(key);
    await withMemoryTls(
      JSON.stringify({
        name: objectName,
        bucket: plan.bucket,
        generation: "1",
        metageneration: "1",
        size: "4",
        downloadTokens: key,
      }),
      async (connections) => {
        const response = await f.wire.fetchStorage(1, step(), init());
        assert.equal(response.status, 200);
        assert.equal(
          JSON.parse(Buffer.from(await response.arrayBuffer()).toString()).downloadTokens,
          key,
        );
        assert.equal(connections.length, 1);
        const { options, request } = connections[0];
        assert.equal(options.servername, "storage.googleapis.com");
        assert.equal(options.rejectUnauthorized, true);
        assert.equal(options.checkServerIdentity, tls.checkServerIdentity);
        assert.deepEqual(options.ca, tls.getCACertificates("bundled"));
        assert.match(request.toString(), new RegExp(`Authorization: Bearer ${ownerToken}`, "i"));
        assert.match(request.toString(), /x-goog-user-project: example-project/i);
        assert.match(request.toString(), /Connection: close/i);
        assert.equal(f.reservations.length, 1);
        assert.equal(f.reservations[0].recording, 1);
        assert.equal(f.reservations[0].requestReservedBytes, request.length);
      },
    );
    assert.equal(readdirSync(f.directory).length, 4);
    for (const file of readdirSync(f.directory)) {
      const path = join(f.directory, file),
        bytes = readFileSync(path);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      for (const secret of [key, ownerToken, firebaseToken]) {
        assert.equal(bytes.includes(Buffer.from(secret)), false);
        assert.equal(bytes.includes(Buffer.from(Buffer.from(secret).toString("base64"))), false);
        function inspect(value) {
          if (typeof value === "string")
            assert.equal(Buffer.from(value, "base64").includes(Buffer.from(secret)), false);
          else if (value && typeof value === "object")
            for (const child of Object.values(value)) inspect(child);
        }
        inspect(JSON.parse(bytes.toString()));
      }
    }
    assert.equal(f.wire.snapshot().attempts, 1);
    assert.equal(f.wire.snapshot().largestResponseReadBytes, 37);
  } finally {
    await f.close();
  }
});

test("control header profiles exclude client quota and require empty tokeninfo body", async () => {
  const f = fixture();
  try {
    await withMemoryTls("{}", async (connections) => {
      await f.wire.fetchControl(1, "owner-tokeninfo", {}, init({ body: Buffer.alloc(0) }));
      await f.wire.fetchControl(
        1,
        "auth-signup",
        { apiKey: key },
        init({ body: '{"email":"fixture@example.com"}' }),
      );
      const tokeninfo = connections[0].request.toString(),
        signup = connections[1].request.toString();
      assert.match(tokeninfo, /POST \/tokeninfo HTTP\/1.1/);
      assert.match(tokeninfo, /content-type: application\/x-www-form-urlencoded;charset=UTF-8/i);
      assert.match(tokeninfo, /content-length: 0/i);
      assert.equal(/x-goog-user-project/i.test(tokeninfo), false);
      assert.equal(/authorization:|x-goog-user-project:/i.test(signup), false);
      assert.match(signup, /content-type: application\/json/i);
      assert.match(signup, new RegExp(`key=${key}`));
      await f.wire.fetchControl(1, "bucket-config", {}, init());
      assert.equal(connections.length, 3);
      assert.match(
        connections[2].request.toString(),
        /GET \/storage\/v1\/b\/example.appspot.com HTTP\/1.1/,
      );
      assert.match(connections[2].request.toString(), /x-goog-user-project: example-project/i);
    });
  } finally {
    await f.close();
  }
  for (const [kind, parameters, body] of [
    ["owner-tokeninfo", {}, "not-empty"],
    ["auth-signup", {}, "{}"],
    ["unknown", {}, ""],
  ]) {
    const rejected = fixture();
    try {
      await assert.rejects(
        rejected.wire.fetchControl(1, kind, parameters, init({ body })),
        /PRODUCTION_WIRE_REQUEST_REJECTED/,
      );
      assert.equal(rejected.reservations.length, 0);
    } finally {
      await rejected.close();
    }
  }
});

test("fresh admission is rechecked after durable capture and failure prevents future dispatch", async () => {
  let calls = 0;
  const f = fixture({ verifyAdmission: () => ++calls === 1 });
  try {
    await withMemoryTls("{}", async (connections) => {
      await assert.rejects(
        f.wire.fetchStorage(1, step(), init()),
        /PRODUCTION_WIRE_REQUEST_REJECTED/,
      );
      assert.equal(connections.length, 0);
      assert.equal(f.reservations.length, 1);
      assert.equal(calls, 2);
      await assert.rejects(f.wire.fetchStorage(1, step(), init()), /PRODUCTION_WIRE_HALTED/);
      assert.equal(f.reservations.length, 1);
    });
  } finally {
    await f.close();
  }
});

test("changed owner or Firebase credentials reject after capture before a socket and halt future requests", async () => {
  for (const owner of [true, false]) {
    let providers = 0,
      admissions = 0;
    const authorization = () =>
      `${owner ? "Bearer" : "Firebase"} ${++providers === 1 ? ownerToken : firebaseToken}`;
    const f = fixture({
      verifyAdmission: () => {
        admissions++;
        return true;
      },
      ownerAuthorization: owner ? authorization : () => assert.fail("unexpected owner provider"),
      accountAuthorization: owner
        ? () => assert.fail("unexpected account provider")
        : authorization,
    });
    const request = step();
    if (!owner) {
      delete request.credential;
      request.dialect = "firebase";
      request.path = `/v0/b/${plan.bucket}/o/${encodeURIComponent(objectName)}`;
      request.credentialRef = {
        kind: "valid",
        accountRef: "owned-account:recordone:authorization-errors:valid",
      };
    }
    try {
      await withMemoryTls("{}", async (connections) => {
        await assert.rejects(
          f.wire.fetchStorage(1, request, init()),
          /PRODUCTION_WIRE_REQUEST_REJECTED/,
        );
        assert.equal(providers, 2);
        assert.equal(admissions, 2);
        assert.equal(f.reservations.length, 1);
        assert.equal(connections.length, 0);
        await assert.rejects(f.wire.fetchStorage(1, request, init()), /PRODUCTION_WIRE_HALTED/);
        assert.equal(f.reservations.length, 1);
      });
      for (const file of readdirSync(f.directory))
        for (const secret of [ownerToken, firebaseToken])
          assert.equal(readFileSync(join(f.directory, file)).includes(Buffer.from(secret)), false);
    } finally {
      await f.close();
    }
  }
});

test("the wire factory enforces a real one-second mutation interval with no retry", async () => {
  const f = fixture();
  const mutation = step({ method: "DELETE", query: { ifGenerationMatch: "1" } });
  try {
    await withMemoryTls("{}", async (connections) => {
      await f.wire.fetchStorage(1, mutation, init());
      await f.wire.fetchStorage(1, mutation, init());
      assert.ok(connections[1].dispatchTimeMs - connections[0].dispatchTimeMs >= 1000);
      assert.equal(connections.length, 2);
      assert.equal(f.reservations.length, 2);
    });
  } finally {
    await f.close();
  }
});
