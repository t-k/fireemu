import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  realpathSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import tls from "node:tls";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildProductionControlInventory } from "./storage-object/production-controls.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createProductionWireTransport } from "./storage-object/production-wire-transport.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";

const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
const owner = "SYNTHETIC_REGISTRY_OWNER_abcdefgh123456789";
const fixtureRegistries = new WeakMap();

async function fixture(
  action,
  responder,
  { registryProfile = {}, responseHeaders = [], responseWire, chunkSize = 37, status = 200 } = {},
) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "storage-object-secret-registry-")));
  chmodSync(directory, 0o700);
  const originalConnect = tls.connect,
    argv = [...process.execArgv],
    calls = [],
    reservations = [];
  let wire;
  process.execArgv = [];
  tls.connect = (options) => {
    const row = { options, bytes: Buffer.alloc(0) };
    calls.push(row);
    let responded = false;
    const socket = new Duplex({
      read() {},
      write(bytes, encoding, done) {
        row.bytes = Buffer.concat([row.bytes, bytes]);
        socket.bytesWritten += bytes.length;
        const boundary = row.bytes.indexOf("\r\n\r\n"),
          length = /content-length: (\d+)/i.exec(row.bytes.toString())?.[1];
        if (!responded && boundary >= 0 && row.bytes.length === boundary + 4 + Number(length)) {
          responded = true;
          try {
            const body = Buffer.from(JSON.stringify(responder(calls.length)));
            const response = responseWire
              ? responseWire(body, calls.length)
              : Buffer.concat([
                  Buffer.from(
                    `HTTP/1.1 ${status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n${responseHeaders.map(([name, value]) => `${name}: ${value}\r\n`).join("")}\r\n`,
                  ),
                  body,
                ]);
            queueMicrotask(() => {
              for (let offset = 0; offset < response.length; offset += chunkSize)
                options.onread.callback(
                  Math.min(chunkSize, response.length - offset),
                  response.subarray(offset, offset + chunkSize),
                );
              socket.push(null);
            });
          } catch (error) {
            done(error);
            return;
          }
        }
        done();
      },
    });
    Object.assign(socket, {
      bytesWritten: 0,
      authorized: true,
      encrypted: true,
      alpnProtocol: "http/1.1",
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
    const registry = createProductionSecretRegistry({
      maxValues: 81,
      maxUtf8Bytes: 65536,
      maxIndexNodes: 200000,
      maxScanCodeUnits: 16777216,
      ...registryProfile,
    });
    wire = createProductionWireTransport({
      plan,
      resources: {
        projectNumber: "123456789012",
        apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
        rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
      },
      captureDirectory: directory,
      onByteReserve: async (row) => {
        reservations.push(row);
      },
      verifyAdmission: () => true,
      ownerAuthorization: () => `Bearer ${owner}`,
      accountAuthorization: () => assert.fail("no account provider is used"),
      secretRegistry: registry,
    });
    fixtureRegistries.set(wire, registry);
    await action({ wire, directory, calls, reservations });
  } finally {
    await wire?.close();
    tls.connect = originalConnect;
    process.execArgv = argv;
    rmSync(directory, { recursive: true, force: true });
  }
}

function readMetadata(wire, { recording = 1, media = false, id = "private-read" } = {}) {
  const objectName = `${plan.recordings[recording - 1].prefix}registry/object`;
  return wire.fetchStorage(
    recording,
    {
      id,
      dialect: "gcs",
      credential: "admin",
      method: "GET",
      objectName,
      path: `/storage/v1/b/${plan.bucket}/o/${encodeURIComponent(objectName)}`,
      query: media ? { alt: "media" } : {},
      headers: {},
    },
    {
      method: "GET",
      body: Buffer.alloc(0),
      operationId: `r${recording}/p1/${hash(id)}`,
      accountingPhase: "subject",
    },
  );
}

// Pure UNAVAILABLE projections are tested in storage-object-task-capture.test.mjs.
// This integration verifies the exact persistence stage and irreversible dispatch halt.
function assertUnavailablePersistence(wire, directory, dispatched = true, exhausted = false) {
  const registry = fixtureRegistries.get(wire);
  assert.ok(registry);
  assert.equal(registry.snapshot().closed, true);
  assert.equal(registry.snapshot().failed, !dispatched || exhausted);
  assert.throws(() => registry.openScan(), /SECRET_REGISTRY_UNAVAILABLE/);
  assert.equal(wire.snapshot().failed, true);
  const files = readdirSync(directory).toSorted();
  assert.deepEqual(files, dispatched ? ["000001-intent.json", "000001-request.json"] : []);
  const rows = [];
  for (const file of files) {
    const path = join(directory, file);
    const stat = statSync(path);
    assert.equal(stat.isFile(), true);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(stat.uid, process.getuid());
    assert.equal(stat.nlink, 1);
    const bytes = readFileSync(path);
    assert.equal(bytes.length, stat.size);
    const row = JSON.parse(bytes);
    assert.equal(row.sequence, 1);
    if (file.endsWith("-request.json")) {
      assert.equal(row.capture.taskSecretStatus, "AVAILABLE");
      assert.ok(["GET", "POST"].includes(row.method));
      assert.match(row.requestWire.sha256, /^[a-f0-9]{64}$/);
      assert.ok(Number.isSafeInteger(row.requestWire.byteLength) && row.requestWire.byteLength > 0);
    } else {
      assert.equal(row.phase, "subject");
      assert.equal(row.boundary, "HTTP_PLAINTEXT_COMMITMENT_AND_SANITIZED_BODY");
      assert.match(row.operationId.sha256, /^[a-f0-9]{64}$/);
      assert.ok(Number.isSafeInteger(row.operationId.byteLength) && row.operationId.byteLength > 0);
    }
    rows.push(row);
  }
  return rows;
}

for (const channel of [
  "100",
  "102",
  "103",
  "103-empty",
  "multiple",
  "no-final",
  "trailer-known",
  "trailer-unknown",
])
  test(`auxiliary responses withhold unchecked capture and halt the task (${channel})`, async () => {
    const secret = "SYNTHETIC_AUXILIARY_PRIVATE_abcdefgh123456789";
    await fixture(
      async ({ wire, directory, calls, reservations }) => {
        await assert.rejects(() => readMetadata(wire), /PRODUCTION_WIRE_REQUEST_REJECTED/);
        const saved = assertUnavailablePersistence(wire, directory);
        assert.equal(JSON.stringify(saved).includes(secret), false);
        for (const file of readdirSync(directory)) {
          const path = join(directory, file),
            bytes = readFileSync(path);
          assert.equal(statSync(path).mode & 0o777, 0o600);
          const inspect = (node) => {
            if (typeof node === "string") {
              assert.equal(node.includes(secret), false);
              assert.equal(Buffer.from(node, "base64").includes(Buffer.from(secret)), false);
            } else if (node && typeof node === "object") {
              for (const child of Object.values(node)) inspect(child);
            }
          };
          inspect(JSON.parse(bytes));
        }
        await assert.rejects(() => readMetadata(wire, { recording: 2 }), /PRODUCTION_WIRE_HALTED/);
        assert.equal(calls.length, 1);
        assert.equal(reservations.length, 1);
      },
      () => ({ name: `${plan.recordings[0].prefix}registry/object`, contentDisposition: secret }),
      {
        chunkSize: 8192,
        responseWire(body) {
          const final = Buffer.concat([
            Buffer.from(
              `HTTP/1.1 200 Synthetic\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
            ),
            body,
          ]);
          if (channel.startsWith("trailer"))
            return Buffer.concat([
              Buffer.from(
                `HTTP/1.1 200 Synthetic\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${body.length.toString(16)}\r\n`,
              ),
              body,
              Buffer.from(
                `\r\n0\r\n${channel === "trailer-known" ? "X-Guploader-Uploadid" : "X-New-Opaque-Capability"}: wrapper-${secret}-suffix\r\n\r\n`,
              ),
            ]);
          const auxiliary = Buffer.from(
            `HTTP/1.1 ${/^(100|102)$/.test(channel) ? channel : "103"} Synthetic\r\n${channel === "103-empty" ? "" : `X-Guploader-Uploadid: ${secret}\r\n`}\r\n`,
          );
          return channel === "no-final"
            ? auxiliary
            : Buffer.concat([auxiliary, ...(channel === "multiple" ? [auxiliary] : []), final]);
        },
      },
    );
  });

test("a normal chunked response without trailers preserves original nonsecret body bytes", async () => {
  let originalWire;
  const value = { name: `${plan.recordings[0].prefix}registry/object`, generation: "1" };
  await fixture(
    async ({ wire, directory, calls }) => {
      const response = await readMetadata(wire);
      assert.equal(response.status, 200);
      const saved = JSON.parse(readFileSync(join(directory, "000001-result.json")));
      assert.equal(saved.complete, true);
      assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
      assert.equal(saved.response.mode, "RAW_BODY");
      assert.deepEqual(
        Buffer.from(saved.response.bodyBase64, "base64"),
        Buffer.from(JSON.stringify(value)),
      );
      assert.equal(saved.responseWire.sha256, hash(originalWire));
      assert.equal(saved.responseWire.byteLength, originalWire.length);
      assert.equal(calls.length, 1);
    },
    () => value,
    {
      responseWire(body) {
        originalWire = Buffer.concat([
          Buffer.from(
            `HTTP/1.1 200 Synthetic\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n${body.length.toString(16)}\r\n`,
          ),
          body,
          Buffer.from("\r\n0\r\n\r\n"),
        ]);
        return originalWire;
      },
    },
  );
});

test("request discovery exhaustion withholds artifacts and starts no socket", async () => {
  await fixture(
    async ({ wire, directory, calls, reservations }) => {
      await assert.rejects(() => readMetadata(wire), /PRODUCTION_WIRE_REQUEST_REJECTED/);
      assert.equal(calls.length, 0);
      assert.equal(reservations.length, 1);
      assertUnavailablePersistence(wire, directory, false);
      await assert.rejects(() => readMetadata(wire, { id: "later" }), /PRODUCTION_WIRE_HALTED/);
      assert.equal(calls.length, 0);
      assert.equal(reservations.length, 1);
    },
    () => assert.fail("no response expected"),
    { registryProfile: { maxValues: 1 } },
  );
});

test("response discovery exhaustion withholds unchecked response and result before halting", async () => {
  await fixture(
    async ({ wire, directory, calls, reservations }) => {
      await assert.rejects(() => readMetadata(wire), /PRODUCTION_WIRE_REQUEST_REJECTED/);
      const saved = assertUnavailablePersistence(wire, directory, true, true);
      assert.equal(JSON.stringify(saved).includes("SYNTHETIC_RESPONSE_PRIVATE"), false);
      await assert.rejects(() => readMetadata(wire, { id: "later" }), /PRODUCTION_WIRE_HALTED/);
      assert.equal(calls.length, 1);
      assert.equal(reservations.length, 1);
    },
    () => ({
      name: `${plan.recordings[0].prefix}registry/object`,
      downloadTokens: ["SYNTHETIC_RESPONSE_PRIVATE_ONE", "SYNTHETIC_RESPONSE_PRIVATE_TWO"],
    }),
    { registryProfile: { maxValues: 3 } },
  );
});

for (const kind of ["unknown-json", "unknown-header", "opaque-public-header", "unapproved-media"])
  test(`unapproved discovery shapes withhold artifacts and stop future requests (${kind})`, async () => {
    await fixture(
      async ({ wire, directory, calls, reservations }) => {
        await assert.rejects(
          () => readMetadata(wire, { media: kind === "unapproved-media" }),
          /PRODUCTION_WIRE_REQUEST_REJECTED/,
        );
        const saved = assertUnavailablePersistence(wire, directory);
        assert.equal(JSON.stringify(saved).includes("SYNTHETIC_UNKNOWN_PRIVATE"), false);
        await assert.rejects(() => readMetadata(wire, { id: "later" }), /PRODUCTION_WIRE_HALTED/);
        assert.equal(calls.length, 1);
        assert.equal(reservations.length, 1);
      },
      () =>
        kind === "unknown-json"
          ? { unknownCapability: "SYNTHETIC_UNKNOWN_PRIVATE" }
          : { name: `${plan.recordings[0].prefix}registry/object`, generation: "1" },
      {
        responseHeaders:
          kind === "unknown-header"
            ? [["X-New-Opaque-Capability", "wrapper-SYNTHETIC_UNKNOWN_PRIVATE-suffix"]]
            : kind === "opaque-public-header"
              ? [["Server", "wrapper-SYNTHETIC_UNKNOWN_PRIVATE-suffix"]]
              : [],
      },
    );
  });

test("a media request with a declared JSON authorization denial commits its body and stays usable", async () => {
  await fixture(
    async ({ wire, directory, calls, reservations }) => {
      const response = await readMetadata(wire, { media: true });
      assert.equal(response.status, 403);
      const saved = JSON.parse(readFileSync(join(directory, "000001-result.json")));
      assert.equal(saved.complete, true);
      assert.equal(saved.response.bodyBase64, null);
      assert.equal(saved.response.mode, "COMMITMENT_ONLY");
      assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
      await readMetadata(wire, { recording: 2, media: true });
      assert.equal(calls.length, 2);
      assert.equal(reservations.length, 2);
    },
    () => ({ error: { code: 403, message: "Forbidden" } }),
    { status: 403 },
  );
});

for (const [kind, value, body, parameters] of [
  [
    "project-binding",
    {
      projectId: plan.projectId,
      projectNumber: "123456789012",
      lifecycleState: "ACTIVE",
      name: "Example Project",
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "default-bucket",
    {
      name: `projects/${plan.projectId}/defaultBucket`,
      bucket: { name: plan.bucket },
      location: "US-CENTRAL1",
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "bucket-config",
    {
      kind: "storage#bucket",
      name: plan.bucket,
      projectNumber: "123456789012",
      iamConfiguration: {
        uniformBucketLevelAccess: { enabled: true },
        bucketPolicyOnly: { enabled: true },
        publicAccessPrevention: "inherited",
      },
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "auth-config",
    {
      name: `projects/${plan.projectId}/config`,
      subtype: "FIREBASE_AUTH",
      signIn: {
        email: { enabled: true, passwordRequired: true },
        hashConfig: {
          algorithm: "SCRYPT",
          signerKey: Buffer.from("SYNTHETIC_SIGNER_PRIVATE").toString("base64"),
          saltSeparator: Buffer.from("SYNTHETIC_SEPARATOR_PRIVATE").toString("base64"),
          rounds: 8,
          memoryCost: 14,
        },
      },
      client: { apiKey: "SYNTHETIC_CLIENT_KEY_PRIVATE" },
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "api-key-metadata",
    {
      name: "projects/123456789012/locations/global/keys/fixture-key",
      restrictions: {
        apiTargets: [
          { service: "identitytoolkit.googleapis.com" },
          { service: "securetoken.googleapis.com" },
        ],
      },
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "owner-tokeninfo",
    {
      sub: "synthetic-subject",
      azp: "synthetic-client",
      aud: "synthetic-client",
      scope: "synthetic-scope",
      expires_in: "3600",
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "owner-exchange",
    { access_token: "SYNTHETIC_ACCESS_PRIVATE", expires_in: 3600, token_type: "Bearer" },
    "grant_type=refresh_token&client_id=synthetic-client&client_secret=SYNTHETIC_CLIENT_PRIVATE&refresh_token=SYNTHETIC_REFRESH_PRIVATE",
    {},
  ],
  [
    "rules-release",
    {
      name: "projects/example-project/releases/firebase.storage/example.appspot.com",
      rulesetName: "projects/example-project/rulesets/fixture-ruleset",
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "rules-ruleset",
    {
      name: "projects/example-project/rulesets/fixture-ruleset",
      source: { files: [{ name: "storage.rules", content: "synthetic rules source" }] },
    },
    Buffer.alloc(0),
    {},
  ],
  [
    "auth-admin-lookup",
    {
      users: [
        {
          localId: "synthetic-uid",
          email: "storage-object@example.com",
          passwordHash: "SYNTHETIC_HASH_PRIVATE",
          salt: "SYNTHETIC_SALT_PRIVATE",
        },
      ],
    },
    JSON.stringify({ localId: ["synthetic-uid"], targetProjectId: plan.projectId }),
    {},
  ],
  [
    "auth-signup",
    {
      localId: "synthetic-uid",
      email: "storage-object@example.com",
      idToken: "SYNTHETIC_ID_PRIVATE",
      refreshToken: "SYNTHETIC_REFRESH_PRIVATE",
      expiresIn: "3600",
    },
    JSON.stringify({
      email: "storage-object@example.com",
      password: "SYNTHETIC_PASSWORD_PRIVATE",
      returnSecureToken: true,
    }),
    { apiKey: "SYNTHETIC_API_KEY" },
  ],
])
  for (const unknown of [false, true])
    test(`control commitment uses the exact closed family (${kind}, unknown=${unknown})`, async () => {
      await fixture(
        async ({ wire, directory, calls, reservations }) => {
          const send = () =>
            wire.fetchControl(1, kind, parameters, {
              operationId: `r1/control/${hash(kind)}`,
              accountingPhase: "subject",
              body,
            });
          if (unknown) {
            await assert.rejects(send, /PRODUCTION_WIRE_REQUEST_REJECTED/);
            assertUnavailablePersistence(wire, directory);
            await assert.rejects(() => readMetadata(wire), /PRODUCTION_WIRE_HALTED/);
          } else {
            assert.equal((await send()).status, 200);
            const saved = JSON.parse(readFileSync(join(directory, "000001-result.json")));
            assert.equal(saved.complete, true);
            assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
            assert.equal(saved.response.mode, "COMMITMENT_ONLY");
            assert.equal(saved.response.bodyBase64, null);
          }
          assert.equal(calls.length, 1);
          assert.equal(reservations.length, 1);
        },
        () => ({
          ...value,
          ...(unknown ? { futureCapability: "SYNTHETIC_UNKNOWN_CONTROL_PRIVATE" } : {}),
        }),
      );
    });

test("one task registry accepts all declared distinct credential and session values from both recordings", async () => {
  const values = [
    "SYNTHETIC_ADC_CLIENT_SECRET",
    "SYNTHETIC_ADC_REFRESH_TOKEN",
    "SYNTHETIC_API_KEY",
  ];
  const slots = buildProductionControlInventory(plan);
  for (const slot of slots.filter((s) => s.kind === "owner-exchange"))
    for (const kind of ["access", "optional-id"]) values.push(`SYNTHETIC_${kind}_${slot.id}`);
  for (const slot of slots.filter((s) => s.kind === "auth-signup"))
    for (const kind of [
      "password",
      "signup-id",
      "refreshed-id",
      "signup-refresh",
      "rotated-refresh",
      "unused-access",
    ])
      values.push(`SYNTHETIC_${kind}_${slot.id}`);
  for (const recording of plan.recordings) {
    values.push(`SYNTHETIC_MALFORMED_${recording.runId}`);
    for (const recipe of buildCorpus({ bucket: plan.bucket, prefix: recording.prefix }).recipes)
      for (const step of recipe.steps ?? [])
        if (
          recipe.id.endsWith("/resumable-upload") &&
          step.method === "POST" &&
          !step.sessionUriReference
        )
          for (const kind of ["session-uri", "upload-id"])
            values.push(`SYNTHETIC_${kind}_${recording.runId}_${recipe.id}_${step.id}`);
  }
  assert.equal(values.length, 81);
  assert.equal(new Set(values).size, 81);
  await fixture(
    async ({ wire, calls, reservations }) => {
      for (const value of values) assert.doesNotThrow(() => wire.registerSecret(value));
      assert.equal(calls.length, 0);
      assert.equal(reservations.length, 0);
    },
    () => assert.fail("no HTTP is expected"),
  );
});

test("an unused admin rawPassword is private when copied into a later recording", async () => {
  const secret = "SYNTHETIC_RAW_PASSWORD_PRIVATE_abcdef123456789";
  await fixture(
    async ({ wire, directory, calls, reservations }) => {
      await wire.fetchControl(
        1,
        "auth-admin-lookup",
        {},
        {
          operationId: `r1/control/${hash("raw-password")}`,
          accountingPhase: "subject",
          body: JSON.stringify({ localId: ["synthetic-uid"], targetProjectId: plan.projectId }),
        },
      );
      await readMetadata(wire, { recording: 2 });
      const saved = JSON.parse(readFileSync(join(directory, "000002-result.json")));
      assert.equal(saved.complete, true);
      assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
      assert.equal(saved.response.bodyBase64, null);
      assert.equal(JSON.stringify(saved).includes(secret), false);
      assert.equal(calls.length, 2);
      assert.equal(reservations.length, 2);
    },
    (sequence) =>
      sequence === 1
        ? {
            users: [
              {
                localId: "synthetic-uid",
                email: "storage-object@example.com",
                rawPassword: secret,
              },
            ],
          }
        : { name: `${plan.recordings[1].prefix}registry/object`, contentDisposition: secret },
  );
});
for (const field of ["signerKey", "saltSeparator"])
  test(`an encoded configuration credential protects its decoded copy in a later recording (${field})`, async () => {
    const secret = `SYNTHETIC_${field}_DECODED_PRIVATE\0suffix`;
    await fixture(
      async ({ wire, directory, calls }) => {
        await wire.fetchControl(
          1,
          "auth-config",
          {},
          {
            operationId: `r1/control/${hash(field)}`,
            accountingPhase: "subject",
            body: Buffer.alloc(0),
          },
        );
        await readMetadata(wire, { recording: 2 });
        const saved = JSON.parse(readFileSync(join(directory, "000002-result.json")));
        assert.equal(saved.complete, true);
        assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
        assert.equal(saved.response.bodyBase64, null);
        assert.equal(calls.length, 2);
      },
      (sequence) =>
        sequence === 1
          ? {
              name: `projects/${plan.projectId}/config`,
              subtype: "FIREBASE_AUTH",
              signIn: {
                email: { enabled: true, passwordRequired: true },
                hashConfig: {
                  algorithm: "SCRYPT",
                  [field]: Buffer.from(secret).toString("base64"),
                },
              },
            }
          : { name: `${plan.recordings[1].prefix}registry/object`, contentDisposition: secret },
    );
  });
for (const [kind, map] of [
  ["project-binding", "labels"],
  ["project-binding", "tags"],
  ["bucket-config", "labels"],
  ["api-key-metadata", "annotations"],
])
  test(`unbound configuration maps stop before a later opaque copy (${kind}/${map})`, async () => {
    const values = {
      "project-binding": { projectId: plan.projectId, projectNumber: "123456789012" },
      "bucket-config": { kind: "storage#bucket", name: plan.bucket },
      "api-key-metadata": { name: "projects/123456789012/locations/global/keys/fixture-key" },
    };
    await fixture(
      async ({ wire, directory, calls }) => {
        await assert.rejects(
          () =>
            wire.fetchControl(
              1,
              kind,
              {},
              {
                operationId: `r1/control/${hash(`${kind}-${map}`)}`,
                accountingPhase: "subject",
                body: Buffer.alloc(0),
              },
            ),
          /PRODUCTION_WIRE_REQUEST_REJECTED/,
        );
        const saved = assertUnavailablePersistence(wire, directory);
        assert.equal(JSON.stringify(saved).includes("opaquecomponent"), false);
        await assert.rejects(() => readMetadata(wire, { recording: 2 }), /PRODUCTION_WIRE_HALTED/);
        assert.equal(calls.length, 1);
      },
      () => ({
        ...values[kind],
        [map]: {
          opaque: map === "annotations" ? "wrapper[opaquecomponent]suffix" : "opaquecomponent",
        },
      }),
    );
  });

for (const dialect of ["gcs", "firebase"])
  test(`an original session response binds a canonical empty query capture (${dialect})`, async () => {
    const corpus = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix });
    const ordinal =
      corpus.recipes.findIndex((row) => row.id === `storage-object/${dialect}/resumable-upload`) +
      1;
    const recipe = corpus.recipes[ordinal - 1],
      initiate = recipe.steps.find((row) => row.id === "initiate"),
      query = recipe.steps.find(
        (row) => row.id === (dialect === "gcs" ? "query-progress" : "query-initial"),
      );
    const path =
      dialect === "gcs" ? `/upload/storage/v1/b/${plan.bucket}/o` : `/v0/b/${plan.bucket}/o`;
    const uri = `https://${dialect === "gcs" ? "storage" : "firebasestorage"}.googleapis.com${path}?${dialect === "gcs" ? "uploadType" : "upload_protocol"}=resumable&name=${encodeURIComponent(initiate.objectName)}&upload_id=SYNTHETIC%2fCAPABILITY`;
    const init = (step) => ({
      method: step.method,
      headers: step.headers,
      body: step.body?.json ? JSON.stringify(step.body.json) : Buffer.alloc(0),
      operationId: `r1/p${ordinal}/${hash(step.id)}`,
      accountingPhase: "subject",
    });
    await fixture(
      async ({ wire, directory, calls, reservations }) => {
        const response = await wire.fetchStorage(1, initiate, init(initiate));
        const capability = wire.bindSession(1, response);
        assert.equal(
          (await wire.fetchSession(1, capability, query, init(query))).status,
          dialect === "gcs" ? 308 : 200,
        );
        for (const sequence of [1, 2]) {
          const saved = JSON.parse(
            readFileSync(join(directory, `${String(sequence).padStart(6, "0")}-result.json`)),
          );
          assert.equal(saved.complete, true);
          assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
          assert.equal(JSON.stringify(saved).includes("SYNTHETIC/CAPABILITY"), false);
          assert.equal(JSON.stringify(saved).includes(uri), false);
        }
        assert.equal(calls.length, 2);
        assert.equal(reservations.length, 2);
      },
      () => ({}),
      {
        responseWire(body, sequence) {
          const status = sequence === 1 || dialect === "firebase" ? 200 : 308;
          const headers =
            sequence === 1
              ? `${dialect === "gcs" ? "Location" : "X-Goog-Upload-URL"}: ${uri}\r\n${dialect === "firebase" ? "X-Goog-Upload-Status: active\r\n" : ""}`
              : dialect === "gcs"
                ? "Range: bytes=0-262143\r\n"
                : "X-Goog-Upload-Status: active\r\nX-Goog-Upload-Size-Received: 0\r\n";
          return Buffer.from(
            `HTTP/1.1 ${status} Synthetic\r\nContent-Length: 0\r\nConnection: close\r\n${headers}\r\n`,
          );
        },
      },
    );
  });

for (const [recipeId, stepId] of [
  ["storage-object/firebase/simple-upload", "upload"],
  ["storage-object/firebase/multipart-upload", "valid"],
  ["storage-object/firebase/multipart-upload", "invalid-json"],
])
  test(`canonical binary or multipart bytes reach their private capture (${recipeId}/${stepId})`, async () => {
    const corpus = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }),
      ordinal = corpus.recipes.findIndex((row) => row.id === recipeId) + 1,
      step = corpus.recipes[ordinal - 1].steps.find((row) => row.id === stepId),
      body = Buffer.from(step.body.base64, "base64"),
      status = stepId === "invalid-json" ? 400 : 200;
    await fixture(
      async ({ wire, directory, calls, reservations }) => {
        assert.equal(
          (
            await wire.fetchStorage(1, step, {
              method: step.method,
              headers: step.headers,
              body,
              operationId: `r1/p${ordinal}/${hash(step.id)}`,
              accountingPhase: "subject",
            })
          ).status,
          status,
        );
        const saved = JSON.parse(readFileSync(join(directory, "000001-request.json")));
        assert.equal(saved.capture.taskSecretStatus, "AVAILABLE");
        assert.equal(saved.capture.mode, "RAW_BODY");
        assert.deepEqual(Buffer.from(saved.capture.bodyBase64, "base64"), body);
        assert.equal(saved.capture.originalSha256, hash(body));
        assert.equal(calls.length, 1);
        assert.equal(reservations.length, 1);
      },
      () =>
        status === 400
          ? { error: { code: 400, message: "Bad Request" } }
          : { name: step.objectName, generation: "1" },
      { status },
    );
  });

test("an original canonical media read preserves its approved fixture bytes", async () => {
  const corpus = buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }),
    ordinal =
      corpus.recipes.findIndex((row) => row.id === "storage-object/firebase/simple-upload") + 1,
    recipe = corpus.recipes[ordinal - 1],
    upload = recipe.steps.find((row) => row.body?.base64),
    step = recipe.steps.find((row) => row.query?.alt === "media"),
    body = Buffer.from(upload.body.base64, "base64");
  await fixture(
    async ({ wire, directory, calls }) => {
      const response = await wire.fetchStorage(1, step, {
        method: step.method,
        headers: step.headers,
        body: Buffer.alloc(0),
        operationId: `r1/p${ordinal}/${hash(step.id)}`,
        accountingPhase: "subject",
      });
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), body);
      const saved = JSON.parse(readFileSync(join(directory, "000001-result.json")));
      assert.equal(saved.complete, true);
      assert.equal(saved.response.mode, "RAW_BODY");
      assert.equal(saved.response.taskSecretStatus, "AVAILABLE");
      assert.deepEqual(Buffer.from(saved.response.bodyBase64, "base64"), body);
      assert.equal(saved.response.originalSha256, hash(body));
      assert.equal(calls.length, 1);
    },
    () => ({}),
    {
      responseWire() {
        return Buffer.concat([
          Buffer.from(
            `HTTP/1.1 200 Synthetic\r\nContent-Type: application/octet-stream\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
          ),
          body,
        ]);
      },
    },
  );
});

test("an unregistered credential-looking value stops the task before an encoded later copy", async () => {
  await fixture(
    async ({ wire, directory, calls, reservations }) => {
      await assert.rejects(() => readMetadata(wire), /PRODUCTION_WIRE_REQUEST_REJECTED/);
      assertUnavailablePersistence(wire, directory);
      await assert.rejects(() => readMetadata(wire, { recording: 2 }), /PRODUCTION_WIRE_HALTED/);
      assert.equal(calls.length, 1);
      assert.equal(reservations.length, 1);
    },
    () => ({
      name: `${plan.recordings[0].prefix}registry/object`,
      contentDisposition: "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",
    }),
  );
});

for (const encoding of ["raw", "percent", "base64", "base64url-suffix"])
  test(`an overlapping credential halts actual memory wire before a suffix copy (${encoding})`, async () => {
    const prefix = "SYNTHETIC_EXISTING_PREFIX",
      suffix = "SYNTHETIC_NEW_CREDENTIAL_SUFFIX";
    const token = `GOCSPX-${prefix}_${suffix}`;
    const copy = {
      raw: suffix,
      percent: [...Buffer.from(suffix)]
        .map((byte) => `%${byte.toString(16).padStart(2, "0")}`)
        .join(""),
      base64: Buffer.from(suffix).toString("base64"),
      "base64url-suffix": `prefix[${Buffer.from(suffix).toString("base64url")}]backup`,
    }[encoding];
    await fixture(
      async ({ wire, directory, calls, reservations }) => {
        wire.registerSecret(prefix);
        await assert.rejects(() => readMetadata(wire), /PRODUCTION_WIRE_REQUEST_REJECTED/);
        assertUnavailablePersistence(wire, directory);
        await assert.rejects(() => readMetadata(wire, { recording: 2 }), /PRODUCTION_WIRE_HALTED/);
        assert.equal(calls.length, 1);
        assert.equal(reservations.length, 1);
        assert.equal(
          readdirSync(directory).some((name) => name.startsWith("000002")),
          false,
        );
      },
      (sequence) => ({
        name: `${plan.recordings[sequence === 1 ? 0 : 1].prefix}registry/object`,
        contentDisposition: sequence === 1 ? token : copy,
      }),
    );
  });

for (const encoding of ["plain", "percent", "base64", "base64url-suffix"])
  test(`an unconsumed response capability remains private in a later recording (${encoding})`, async () => {
    const secret = "SYNTHETIC_DYNAMIC_CAPABILITY+/abc_xyz-123456789",
      name = `${plan.recordings[0].prefix}registry/object`;
    const copy = {
      plain: secret,
      percent: encodeURIComponent(secret),
      base64: Buffer.from(secret).toString("base64"),
      "base64url-suffix": `prefix-${Buffer.from(secret).toString("base64url")}xx`,
    }[encoding];
    await fixture(
      async ({ wire, directory, calls, reservations }) => {
        wire.registerSecret(owner);
        for (const recording of [1, 2]) {
          const objectName = `${plan.recordings[recording - 1].prefix}registry/object`;
          await wire.fetchStorage(
            recording,
            {
              id: `registry-${recording}`,
              dialect: "gcs",
              credential: "admin",
              method: "GET",
              objectName,
              path: `/storage/v1/b/${plan.bucket}/o/${encodeURIComponent(objectName)}`,
              query: {},
              headers: {},
            },
            {
              method: "GET",
              body: Buffer.alloc(0),
              operationId: `r${recording}/p1/${hash(`registry-${recording}`)}`,
              accountingPhase: "subject",
            },
          );
        }
        assert.equal(calls.length, 2);
        assert.equal(reservations.length, 2);
        const first = JSON.parse(readFileSync(join(directory, "000001-result.json"))),
          last = JSON.parse(readFileSync(join(directory, "000002-result.json")));
        assert.equal(
          Buffer.from(first.response.bodyBase64 ?? "", "base64")
            .toString()
            .includes(secret),
          false,
        );
        assert.equal(
          Buffer.from(last.response.bodyBase64 ?? "", "base64")
            .toString()
            .includes(copy),
          false,
        );
      },
      (sequence) => ({
        bucket: plan.bucket,
        name: sequence === 1 ? name : `${plan.recordings[1].prefix}registry/object`,
        generation: "1",
        metageneration: "1",
        size: "0",
        ...(sequence === 1 ? { downloadTokens: secret } : { contentDisposition: copy }),
      }),
    );
  });
