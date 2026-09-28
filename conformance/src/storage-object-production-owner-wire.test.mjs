import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import tls from "node:tls";
import test, { afterEach, beforeEach } from "node:test";
import { createProductionOwnerState } from "./storage-object/production-owner.mjs";
import { createProductionControlDispatcher } from "./storage-object/production-controls.mjs";
import { createProductionWireTransport } from "./storage-object/production-wire-transport.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const originalArgv = [...process.execArgv];
beforeEach(() => {
  process.execArgv = [];
});
afterEach(() => {
  process.execArgv = [...originalArgv];
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const principal = {
  subject: "fixture-owner-subject",
  clientId: "fixture-client.apps.googleusercontent.com",
  requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
};
const adc = {
  type: "authorized_user",
  client_id: principal.clientId,
  client_secret: "SYNTHETIC_WIRE_CLIENT_SECRET",
  refresh_token: "SYNTHETIC_WIRE_REFRESH_SECRET",
  quota_project_id: plan.projectId,
};
const token = "SYNTHETIC_WIRE_ACCESS_TOKEN";
const recipeId = "storage-object/simple-upload";

async function withMemoryTls(responder, action) {
  const originalConnect = tls.connect,
    connections = [];
  tls.connect = (options) => {
    const row = { options, bytes: Buffer.alloc(0) };
    connections.push(row);
    let responded = false;
    const socket = new Duplex({
      read() {},
      write(bytes, encoding, done) {
        row.bytes = Buffer.concat([row.bytes, bytes]);
        socket.bytesWritten += bytes.length;
        const boundary = row.bytes.indexOf("\r\n\r\n");
        const length = /content-length: (\d+)/i.exec(row.bytes.toString())?.[1];
        if (!responded && boundary >= 0 && row.bytes.length === boundary + 4 + Number(length)) {
          responded = true;
          try {
            row.head = row.bytes.subarray(0, boundary).toString();
            row.body = row.bytes.subarray(boundary + 4);
            const result = responder(row),
              body = Buffer.from(JSON.stringify(result.data));
            const response = Buffer.concat([
              Buffer.from(
                `HTTP/1.1 ${result.status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
              ),
              body,
            ]);
            queueMicrotask(() => {
              for (let offset = 0; offset < response.length; offset += 37)
                options.onread.callback(
                  Math.min(37, response.length - offset),
                  response.subarray(offset, offset + 37),
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
    tls.connect = originalConnect;
  }
}

async function fixture(action, tokeninfoChanges = {}) {
  const directory = mkdtempSync(join(tmpdir(), "storage-object-owner-wire-"));
  chmodSync(directory, 0o700);
  const path = join(directory, "adc.json"),
    adcBytes = Buffer.from(JSON.stringify(adc));
  writeFileSync(path, adcBytes, { mode: 0o600 });
  const captureDirectory = join(directory, "wire"),
    reservations = [],
    byteReservations = [],
    controlsProofs = [],
    ownerProofs = [],
    events = [];
  mkdirSync(captureDirectory, { mode: 0o700 });
  let owner,
    wire,
    admitted = false;
  const counter = createStage3RequestCounter(plan, {
    onStart: async (row) => {
      events.push(row);
      admitted = true;
    },
    onReserve: async (row) => {
      assert.equal(admitted, true);
      reservations.push(row);
    },
    recipeLifecycle: {
      recipeIds: Array.from({ length: 26 }, (_, index) =>
        index === 0 ? recipeId : `storage-object/fixture-${index}`,
      ),
      onBegin: async () => {},
      onFinish: async () => {},
      verifyTerminal: async () => false,
    },
  });
  const verifyAdmission = (context) =>
    admitted &&
    counter.snapshot().recording === context.recording &&
    counter.snapshot().mode === context.phase;
  try {
    wire = createProductionWireTransport({
      plan,
      resources: {
        projectNumber: "123456789012",
        apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
        rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
      },
      captureDirectory,
      onByteReserve: async (row) => {
        byteReservations.push(row);
      },
      verifyAdmission,
      ownerAuthorization: (context) => owner.ownerAuthorization(context),
      accountAuthorization: () => assert.fail("no Firebase credential is needed"),
    });
    const controls = createProductionControlDispatcher({
      plan,
      counter,
      wire,
      onProof: async (row) => {
        controlsProofs.push(row);
      },
    });
    owner = createProductionOwnerState({
      recording: 1,
      adcInput: {
        path,
        expectedSha256: hash(adcBytes),
        expectedClientId: principal.clientId,
        expectedQuotaProjectId: plan.projectId,
      },
      principal,
      controls,
      verifyAdmission,
      onProof: async (row) => {
        ownerProofs.push(row);
      },
      onSecret: (value) => {
        wire.registerSecret(value);
      },
    });
    await withMemoryTls(
      (row) => {
        assert.equal(row.options.rejectUnauthorized, true);
        assert.equal(row.options.servername, row.options.host);
        if (row.head.startsWith("POST /token HTTP/1.1")) {
          assert.equal(row.options.host, "oauth2.googleapis.com");
          assert.equal(/authorization:|x-goog-user-project:/i.test(row.head), false);
          const form = new URLSearchParams(row.body.toString());
          assert.equal(form.get("client_secret"), adc.client_secret);
          assert.equal(form.get("refresh_token"), adc.refresh_token);
          return {
            status: 200,
            data: { access_token: token, token_type: "Bearer", expires_in: 3600 },
          };
        }
        if (row.head.startsWith("POST /tokeninfo HTTP/1.1")) {
          assert.equal(row.options.host, "oauth2.googleapis.com");
          assert.match(row.head, new RegExp(`authorization: Bearer ${token}`, "i"));
          assert.equal(/x-goog-user-project:/i.test(row.head), false);
          assert.equal(row.body.length, 0);
          assert.equal(owner.snapshot().hasVerifiedOwner, false);
          return {
            status: 200,
            data: {
              sub: principal.subject,
              aud: principal.clientId,
              azp: principal.clientId,
              scope: principal.requiredScopes.join(" "),
              expires_in: 3600,
              ...tokeninfoChanges,
            },
          };
        }
        assert.equal(row.options.host, "storage.googleapis.com");
        assert.match(row.head, /^GET \/storage\/v1\/b\//);
        assert.match(row.head, new RegExp(`authorization: Bearer ${token}`, "i"));
        assert.match(row.head, /x-goog-user-project: example-project/i);
        assert.equal(owner.snapshot().hasVerifiedOwner, true);
        return { status: 404, data: { error: { code: 404, message: "synthetic object absent" } } };
      },
      (connections) =>
        action({
          owner,
          controls,
          wire,
          counter,
          directory,
          captureDirectory,
          connections,
          reservations,
          byteReservations,
          controlsProofs,
          ownerProofs,
          events,
          revoke() {
            admitted = false;
          },
        }),
    );
  } finally {
    owner?.close();
    await wire?.close();
    rmSync(directory, { recursive: true });
  }
}

function assertSafePersistence(directory, proofs, expectedAttempts) {
  const files = readdirSync(directory);
  assert.equal(files.length, expectedAttempts * 4);
  const persisted = [];
  for (const file of files) {
    const path = join(directory, file);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const text = readFileSync(path, "utf8");
    persisted.push(text);
    const walk = (value) => {
      if (value === null || typeof value !== "object") return;
      for (const [key, item] of Object.entries(value)) {
        if (key.endsWith("Base64") && typeof item === "string")
          persisted.push(Buffer.from(item, "base64").toString());
        else walk(item);
      }
    };
    walk(JSON.parse(text));
  }
  persisted.push(JSON.stringify(proofs));
  for (const secret of [adc.client_secret, adc.refresh_token, token])
    for (const text of persisted) {
      assert.equal(text.includes(secret), false);
      assert.equal(text.includes(encodeURIComponent(secret)), false);
      assert.equal(text.includes(Buffer.from(secret).toString("base64")), false);
    }
}

test("actual owner, control, counter and wire producers share the proved token and safe persistence", async () => {
  await fixture(async (f) => {
    await f.counter.start();
    await f.owner.exchangeAndProve("initial");
    assert.equal(f.owner.snapshot().hasVerifiedOwner, true);
    assert.equal(f.connections.length, 2);
    const capability = await f.counter.beginRecipe(recipeId);
    const operationId = `r1/p1/${hash("fixture-read")}`,
      objectName = "storage-object/recordone/missing.bin";
    const response = await f.counter.send(
      operationId,
      () =>
        f.wire.fetchStorage(
          1,
          {
            dialect: "gcs",
            method: "GET",
            path: `/storage/v1/b/${plan.bucket}/o/${encodeURIComponent(objectName)}`,
            objectName,
            query: {},
            credential: "admin",
          },
          { operationId, accountingPhase: "subject" },
        ),
      capability,
    );
    assert.equal(response.status, 404);
    assert.equal(f.connections.length, 3);
    assert.equal(f.events.length, 1);
    assert.deepEqual(
      f.reservations.map((row) => row.sequence),
      [1, 2, 3],
    );
    assert.deepEqual(
      f.controlsProofs.map((row) => row.sequence),
      [1, 2],
    );
    assert.equal(f.counter.snapshot().total, 3);
    assert.equal(f.byteReservations.length, 3);
    assert.equal(f.ownerProofs.length, 1);
    assert.equal(f.ownerProofs[0].accessTokenSha256, hash(token));
    assert.deepEqual(readdirSync(f.directory).toSorted(), ["adc.json", "wire"]);
    assertSafePersistence(
      f.captureDirectory,
      [...f.controlsProofs, ...f.ownerProofs, ...f.reservations, ...f.byteReservations],
      3,
    );
  });
});

test("a real control response with a foreign principal cannot publish or dispatch an owner request", async () => {
  await fixture(
    async (f) => {
      await f.counter.start();
      await assert.rejects(
        f.owner.exchangeAndProve("initial"),
        /^Error: production owner is unavailable$/,
      );
      assert.equal(f.owner.snapshot().hasVerifiedOwner, false);
      assert.equal(f.owner.snapshot().failed, true);
      assert.equal(f.ownerProofs.length, 0);
      await assert.rejects(f.owner.exchangeAndProve("initial"), /unavailable/);
      assert.equal(f.connections.length, 2);
      assert.equal(f.counter.snapshot().total, 2);
      assertSafePersistence(f.captureDirectory, f.controlsProofs, 2);
    },
    { sub: "foreign-owner" },
  );
});

test("revoked admission blocks the owner before an exchange, reservation or capture", async () => {
  await fixture(async (f) => {
    await f.counter.start();
    f.revoke();
    await assert.rejects(f.owner.exchangeAndProve("initial"), /unavailable/);
    assert.equal(f.connections.length, 0);
    assert.equal(f.counter.snapshot().total, 0);
    assert.equal(f.byteReservations.length, 0);
    assert.deepEqual(readdirSync(f.directory).toSorted(), ["adc.json", "wire"]);
    assert.deepEqual(readdirSync(f.captureDirectory), []);
  });
});
