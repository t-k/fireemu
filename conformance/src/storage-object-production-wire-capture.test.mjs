import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  MAX_RESPONSE_WIRE_BYTES,
  HTTP_RESPONSE_READ_UNIT_BYTES,
} from "./storage-object/wire-limits.mjs";

const module = await import("./storage-object/production-wire-capture.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const digest = (value) => createHash("sha256").update(value).digest("hex");
const withDirectory = (fn) => {
  const directory = mkdtempSync(join(tmpdir(), "storage-production-capture-"));
  try {
    fn(directory);
  } finally {
    rmSync(directory, { recursive: true });
  }
};
const create = (directory, changes = {}) => {
  assert.equal(
    typeof module.createProductionWireAttempt,
    "function",
    "production capture is missing",
  );
  return module.createProductionWireAttempt({
    directory,
    sequence: 1,
    request: {
      url: "https://storage.googleapis.com/storage/v1/b/fixture/o/owned%2Fobject",
      method: "GET",
      headers: [["Authorization", "Bearer OWNER_SECRET"]],
      body: Buffer.alloc(0),
      wire: Buffer.from("GET / HTTP/1.1\r\nAuthorization: Bearer OWNER_SECRET\r\n\r\n"),
    },
    metadata: { operationId: "r1/p1/fixture-operation", phase: "subject" },
    policy: {
      expectedBucket: "fixture",
      expectedObjectNames: ["owned/object"],
      expectedEmails: ["owned@example.com"],
    },
    ...changes,
  });
};
const finish = (attempt, changes = {}) =>
  attempt.finish({
    complete: true,
    reason: null,
    status: 200,
    finishConfirmed: true,
    socketReportedWrittenBytes: attempt.snapshot().requestWireBytes,
    requestReservedBytes: attempt.snapshot().requestWireBytes,
    responseObservedBytes: attempt.snapshot().responseWireBytes,
    rawResponseHeaders: ["Content-Type", "application/json"],
    responseBodyBase64: Buffer.from('{"name":"owned/object"}').toString("base64"),
    ...changes,
  });
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
function assertAbsent(directory, secrets) {
  for (const name of readdirSync(directory)) {
    const bytes = readFileSync(join(directory, name));
    for (const secret of secrets) {
      for (const form of [
        secret,
        encodeURIComponent(secret),
        Buffer.from(secret).toString("base64"),
        JSON.stringify(secret).slice(1, -1),
      ])
        assert.ok(!bytes.includes(Buffer.from(form)), `${name} leaked a credential`);
    }
    if (name.endsWith(".json") && bytes.length) {
      const saved = readJson(join(directory, name));
      for (const copy of [saved.capture, saved.response]) {
        if (!copy?.bodyBase64) continue;
        const decoded = Buffer.from(copy.bodyBase64, "base64");
        for (const secret of secrets) assert.ok(!decoded.includes(Buffer.from(secret)));
      }
    }
  }
}

test("production persistence retains safe Storage body bytes and only original wire commitments", () =>
  withDirectory((directory) => {
    const attempt = create(directory);
    const body = Buffer.from(
      '{ "name" : "owned/object", "downloadTokens" : ["NEW_CAPABILITY"] }\n',
    );
    const wire = Buffer.concat([
      Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"),
      body,
    ]);
    attempt.appendResponse(wire.subarray(0, 10));
    attempt.appendResponse(wire.subarray(10));
    finish(attempt, {
      responseObservedBytes: wire.length,
      responseBodyBase64: body.toString("base64"),
    });
    const saved = readJson(attempt.files.result);
    assert.equal(saved.responseWire.sha256, digest(wire));
    assert.equal(saved.responseWire.byteLength, wire.length);
    assert.equal(saved.response.originalSha256, digest(body));
    assert.deepEqual(saved.response.headers, [["Content-Type", "application/json"]]);
    assert.equal(saved.response.mode, "CAPABILITY_FIELDS_REPLACED");
    const projected = Buffer.from(saved.response.bodyBase64, "base64").toString();
    assert.ok(projected.startsWith('{ "name" : "owned/object", "downloadTokens" : ['));
    assert.ok(projected.endsWith(" }\n"));
    assertAbsent(directory, ["OWNER_SECRET", "NEW_CAPABILITY"]);
    for (const file of Object.values(attempt.files))
      assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(
      readJson(attempt.files.request).requestWire.sha256,
      digest("GET / HTTP/1.1\r\nAuthorization: Bearer OWNER_SECRET\r\n\r\n"),
    );
  }));

test("OAuth and Auth request, intent, split response and base64 copies never persist credential bytes", () =>
  withDirectory((directory) => {
    const requestBody = Buffer.from(
      '{"email":"owned@example.com","password":"NEW_PASSWORD","returnSecureToken":true}',
    );
    const attempt = create(directory, {
      request: {
        url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=NEW_API_KEY",
        method: "POST",
        headers: [
          ["Authorization", "Bearer OWNER_SECRET"],
          ["Content-Type", "application/json"],
        ],
        body: requestBody,
        wire: Buffer.concat([Buffer.from("POST /?key=NEW_API_KEY HTTP/1.1\r\n\r\n"), requestBody]),
      },
    });
    const body = Buffer.from(
      '{"localId":"fixtureUid","email":"owned@example.com","idToken":"NEW_ID_TOKEN","refreshToken":"NEW_REFRESH_TOKEN"}',
    );
    const wire = Buffer.concat([
      Buffer.from("HTTP/1.1 200 OK\r\nSet-Cookie: NEW_COOKIE\r\n\r\n"),
      body,
    ]);
    for (let offset = 0; offset < wire.length; offset += 3)
      attempt.appendResponse(wire.subarray(offset, offset + 3));
    finish(attempt, {
      responseObservedBytes: wire.length,
      rawResponseHeaders: ["Set-Cookie", "NEW_COOKIE", "Content-Type", "application/json"],
      responseBodyBase64: body.toString("base64"),
    });
    const saved = readJson(attempt.files.result);
    assert.equal(saved.response.mode, "COMMITMENT_ONLY");
    assert.equal(saved.response.bodyBase64, null);
    assert.equal(saved.response.observation.localId, "fixtureUid");
    assert.equal(saved.response.observation.idToken.sha256, digest("NEW_ID_TOKEN"));
    assert.equal(saved.responseWire.sha256, digest(wire));
    assertAbsent(directory, [
      "OWNER_SECRET",
      "NEW_PASSWORD",
      "NEW_API_KEY",
      "NEW_ID_TOKEN",
      "NEW_REFRESH_TOKEN",
      "NEW_COOKIE",
    ]);
  }));

test("incomplete responses persist no raw prefix or unknown error text", () =>
  withDirectory((directory) => {
    const attempt = create(directory);
    const raw = Buffer.from("HTTP/1.1 200 OK\r\n\r\nNEW_PARTIAL_TOKEN");
    attempt.appendResponse(raw);
    finish(attempt, {
      complete: false,
      reason: "NEW_ERROR_TOKEN",
      status: null,
      responseObservedBytes: raw.length,
      rawResponseHeaders: [],
      responseBodyBase64: Buffer.from("NEW_PARTIAL_TOKEN").toString("base64"),
    });
    const saved = readJson(attempt.files.result);
    assert.equal(saved.reason, "WIRE_RESPONSE_FAILED");
    assert.equal(saved.responseWire.sha256, digest(raw));
    assert.equal(saved.response.bodyBase64, null);
    assert.equal(saved.response.observation, null);
    assertAbsent(directory, ["OWNER_SECRET", "NEW_PARTIAL_TOKEN", "NEW_ERROR_TOKEN"]);
  }));

test("overshoot bytes remain hashed and prevent a complete receipt", () =>
  withDirectory((directory) => {
    const attempt = create(directory);
    const unit = Buffer.alloc(HTTP_RESPONSE_READ_UNIT_BYTES, 0x78);
    for (let offset = 0; offset < MAX_RESPONSE_WIRE_BYTES; offset += unit.length)
      attempt.appendResponse(unit);
    assert.throws(() => attempt.appendResponse(Buffer.from("NEW_OVERSHOOT_TOKEN")), /wire cap/);
    finish(attempt, {
      complete: true,
      responseObservedBytes: MAX_RESPONSE_WIRE_BYTES + 19,
      responseBodyBase64: "",
    });
    const saved = readJson(attempt.files.result);
    assert.equal(saved.complete, false);
    assert.equal(saved.reason, "WIRE_RESPONSE_CAP_EXCEEDED");
    assert.equal(saved.responseWire.byteLength, MAX_RESPONSE_WIRE_BYTES + 19);
    assert.equal(saved.response.bodyBase64, null);
    assertAbsent(directory, ["OWNER_SECRET", "NEW_OVERSHOOT_TOKEN"]);
  }));

test("untrusted directories, metadata and malformed receipts reject without raw persistence", () =>
  withDirectory((directory) => {
    chmodSync(directory, 0o755);
    assert.throws(() => create(directory), /production wire capture/);
    assert.deepEqual(readdirSync(directory), []);
    chmodSync(directory, 0o700);
    const link = join(directory, "link");
    symlinkSync(directory, link);
    assert.throws(() => create(link), /production wire capture/);
    unlinkSync(link);
    assert.throws(
      () =>
        create(directory, {
          metadata: { operationId: "known", phase: "subject", token: "NEW_META_SECRET" },
        }),
      /production wire capture/,
    );
    const attempt = create(directory);
    assert.throws(
      () => finish(attempt, { unexpected: "NEW_RECEIPT_SECRET" }),
      /production wire capture/,
    );
    assertAbsent(directory, ["OWNER_SECRET", "NEW_META_SECRET", "NEW_RECEIPT_SECRET"]);
  }));

test("exclusive outputs and closed lifecycle never overwrite or append late data", () =>
  withDirectory((directory) => {
    const attempt = create(directory);
    const original = readFileSync(attempt.files.request);
    assert.throws(() => create(directory), /production wire capture/);
    assert.deepEqual(readFileSync(attempt.files.request), original);
    finish(attempt);
    assert.throws(() => finish(attempt), /closed/);
    assert.throws(() => attempt.appendResponse(Buffer.from("LATE_SECRET")), /closed/);
    assertAbsent(directory, ["OWNER_SECRET", "LATE_SECRET"]);
  }));

test("changing request method and metadata phase cannot alter validated persistence fields", () =>
  withDirectory((directory) => {
    let methods = 0;
    let phases = 0;
    const request = {
      url: "https://storage.googleapis.com/storage/v1/b/fixture/o/owned%2Fobject",
      headers: [],
      body: Buffer.alloc(0),
      wire: Buffer.from("GET / HTTP/1.1\r\n\r\n"),
      get method() {
        return methods++ === 0 ? "GET" : "NEW_METHOD_SECRET";
      },
    };
    const metadata = {
      operationId: "known",
      get phase() {
        return phases++ === 0 ? "subject" : "NEW_PHASE_SECRET";
      },
    };
    const attempt = create(directory, { request, metadata });
    finish(attempt);
    assert.equal(readJson(attempt.files.request).method, "GET");
    assert.equal(readJson(attempt.files.intent).phase, "subject");
    assertAbsent(directory, ["NEW_METHOD_SECRET", "NEW_PHASE_SECRET"]);
  }));

test("receipt accessors and non-data records reject before any fixed field is persisted", () => {
  for (const [field, first] of [
    ["complete", true],
    ["reason", "WIRE_TRUNCATED"],
    ["status", 200],
    ["finishConfirmed", true],
    ["socketReportedWrittenBytes", 0],
  ])
    withDirectory((directory) => {
      const attempt = create(directory);
      let reads = 0;
      const receipt = {
        complete: false,
        reason: "WIRE_TRUNCATED",
        status: 200,
        finishConfirmed: true,
        socketReportedWrittenBytes: attempt.snapshot().requestWireBytes,
        requestReservedBytes: attempt.snapshot().requestWireBytes,
        responseObservedBytes: 0,
        rawResponseHeaders: [],
        responseBodyBase64: "",
      };
      Object.defineProperty(receipt, field, {
        enumerable: true,
        get() {
          return reads++ < 3 ? first : "NEW_RECEIPT_SECRET";
        },
      });
      assert.throws(() => attempt.finish(receipt), /production wire capture receipt failed/);
      assert.equal(reads, 0, "receipt validation must not execute accessors");
      assert.equal(attempt.snapshot().closed, true);
      assertAbsent(directory, ["OWNER_SECRET", "NEW_RECEIPT_SECRET"]);
      assert.equal(readJson(attempt.files.response).responseWire.byteLength, 0);
    });
});

test("raw header array accessors are rejected before producing a persistence copy", () =>
  withDirectory((directory) => {
    const attempt = create(directory);
    let reads = 0;
    const headers = ["Content-Type", "application/json"];
    Object.defineProperty(headers, "1", {
      enumerable: true,
      get() {
        reads++;
        return "NEW_HEADER_SECRET";
      },
    });
    assert.throws(
      () => finish(attempt, { rawResponseHeaders: headers }),
      /production wire capture receipt failed/,
    );
    assert.equal(reads, 0, "header snapshot must not execute array accessors");
    assertAbsent(directory, ["OWNER_SECRET", "NEW_HEADER_SECRET"]);
  }));
