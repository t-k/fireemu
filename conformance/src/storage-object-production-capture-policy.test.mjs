import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

const module = await import("./storage-object/production-capture-policy.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const storageUrl = "https://storage.googleapis.com/storage/v1/b/fixture/o/owned%2Fobject";
const sanitize = (changes = {}) => {
  assert.equal(typeof module.sanitizeProductionCapture, "function", "capture policy is missing");
  return module.sanitizeProductionCapture({
    url: storageUrl,
    direction: "response",
    complete: true,
    headers: [],
    body: Buffer.from('{"name":"owned/object","generation":"1"}'),
    expectedObjectNames: ["owned/object"],
    expectedBucket: "fixture",
    expectedEmails: ["storage-object@example.com"],
    ...changes,
  });
};

test("secrets first observed in a header or query also protect the same capture body", () => {
  const token = "SYNTHETIC_CONTEXT_CAPABILITY_/abc+def=123456789";
  const session = `https://storage.googleapis.com/upload/storage/v1/b/fixture/o?uploadType=resumable&upload_id=${encodeURIComponent(token).replaceAll("%2F", "%2f")}`;
  const cases = [
    { headers: [["Authorization", `Bearer ${token}`]], secret: token },
    { headers: [["Location", session]], secret: session },
    { headers: [["X-Goog-Upload-URL", session]], secret: token },
    { headers: [["X-Guploader-Uploadid", token]], secret: token },
    { headers: [["X-Firebase-Storage-Download-Tokens", `${token},SECOND_TOKEN`]], secret: token },
    { url: `${storageUrl}?token=${encodeURIComponent(token)}`, secret: token },
    { url: `${storageUrl}?pageToken=${encodeURIComponent(token)}`, secret: token },
    { url: `${storageUrl}?rewriteToken=${encodeURIComponent(token)}`, secret: token },
  ];
  for (const { secret, ...changes } of cases)
    for (const copy of [
      secret,
      encodeURIComponent(secret),
      encodeURIComponent(secret).replaceAll("%2F", "%2f"),
      Buffer.from(secret).toString("base64"),
      Buffer.from(encodeURIComponent(secret).replaceAll("%2F", "%2f")).toString("base64"),
    ]) {
      const result = sanitize({
        ...changes,
        body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: copy })),
      });
      assert.equal(result.mode, "COMMITMENT_ONLY");
      assert.equal(result.body, null);
      assert.deepEqual(result.observation, {
        byteLength: result.originalByteLength,
        sha256: result.originalSha256,
      });
      assert.ok(!JSON.stringify(result).includes(secret));
    }
});

test("context discovery overflow commits every value and suppresses typed observations", () => {
  for (const count of [64, 65]) {
    const result = sanitize({
      url: `${storageUrl}?alt=media`,
      headers: [
        ["Content-Type", "application/json"],
        ...Array.from({ length: count }, (_, index) => [
          "X-Guploader-Uploadid",
          `SYNTHETIC_CONTEXT_BOUND_${index}_abcdefgh`,
        ]),
      ],
    });
    assert.equal(result.mode, count === 64 ? "RAW_BODY" : "COMMITMENT_ONLY");
    assert.equal(result.body === null, count === 65);
    assert.equal(result.observation, null);
    if (count === 65) {
      assert.equal(typeof result.url.pathname, "object");
      assert.equal(typeof result.url.query[0][1], "object");
      assert.ok(result.headers.every(([, value]) => typeof value === "object"));
    }
  }
});

test("Authorization schemes and separators cannot leave an unrecognized credential body raw", () => {
  const token = "SYNTHETIC_SCHEME_SECRET_abcdefgh123456789";
  for (const scheme of ["Bearer", "bearer", "BEARER", "Firebase", "firebase", "FIREBASE"])
    for (const separator of [" ", "  ", "\t"])
      for (const name of ["Authorization", "proxy-authorization"]) {
        const result = sanitize({
          headers: [[name, `${scheme}${separator}${token}`]],
          body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: token })),
        });
        assert.equal(result.mode, "COMMITMENT_ONLY");
        assert.equal(result.body, null);
        assert.ok(!JSON.stringify(result).includes(token));
        if (separator !== "\t") {
          const safe = sanitize({ headers: [[name, `${scheme}${separator}${token}`]] });
          assert.equal(safe.mode, "RAW_BODY");
          assert.deepEqual(safe.body, Buffer.from('{"name":"owned/object","generation":"1"}'));
        }
      }
  for (const value of [
    `Basic ${Buffer.from("user:secret").toString("base64")}`,
    `DPoP ${token}`,
    "UnrecognizedShape",
    `Bearer ${token} trailing`,
    `Bearer ${token} `,
  ]) {
    const result = sanitize({
      headers: [["Authorization", value]],
      body: Buffer.from(JSON.stringify({ name: "owned/object", contentDisposition: token })),
    });
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.equal(result.observation, null);
  }
});

test("Storage preserves body bytes and ordered headers while hashing an authorization value", () => {
  const original = Buffer.from('{ "name" : "owned/object" }\n');
  const result = sanitize({
    body: original,
    headers: [
      ["Content-Type", "application/json"],
      ["Authorization", "Bearer NEW_SECRET"],
    ],
  });
  assert.equal(result.mode, "RAW_BODY");
  assert.deepEqual(result.body, original);
  assert.deepEqual(result.headers[0], ["Content-Type", "application/json"]);
  assert.equal(result.headers[1][1].sha256, digest("Bearer NEW_SECRET"));
  assert.equal(result.originalByteLength, original.length);
  assert.equal(result.originalSha256, digest(original));
  assert.ok(!JSON.stringify(result).includes("NEW_SECRET"));
});

test("OAuth request forms and unknown newly issued response tokens use typed commitments", () => {
  for (const [direction, headers, body] of [
    [
      "request",
      [["content-type", "application/x-www-form-urlencoded"]],
      "grant_type=refresh_token&refresh_token=fixture-refresh&client_secret=fixture-client-secret&client_id=client.apps.googleusercontent.com",
    ],
    [
      "response",
      [["content-type", "application/json"]],
      '{"access_token":"NEW_RESPONSE_SECRET","token_type":"Bearer","expires_in":3600}',
    ],
  ]) {
    const result = sanitize({
      url: "https://oauth2.googleapis.com/token",
      direction,
      headers,
      body: Buffer.from(body),
    });
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.ok(result.observation);
    for (const secret of ["fixture-refresh", "fixture-client-secret", "NEW_RESPONSE_SECRET"])
      assert.ok(!JSON.stringify(result).includes(secret));
    const field =
      direction === "request" ? result.observation.refresh_token : result.observation.access_token;
    assert.equal(
      field.sha256,
      digest(direction === "request" ? "fixture-refresh" : "NEW_RESPONSE_SECRET"),
    );
  }
});

test("Firebase Auth responses preserve the ownership UID while hashing API key and all credential fields", () => {
  const result = sanitize({
    url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=fixture-api-key",
    body: Buffer.from(
      '{"localId":"fixtureUid123","email":"storage-object@example.com","idToken":"NEW_ID_TOKEN","refreshToken":"NEW_REFRESH_TOKEN"}',
    ),
  });
  assert.equal(result.mode, "COMMITMENT_ONLY");
  assert.equal(result.observation.localId, "fixtureUid123");
  assert.equal(result.observation.email, "storage-object@example.com");
  assert.equal(result.url.query[0][1].sha256, digest("fixture-api-key"));
  for (const secret of ["fixture-api-key", "NEW_ID_TOKEN", "NEW_REFRESH_TOKEN"])
    assert.ok(!JSON.stringify(result).includes(secret));
});

test("known session headers and page query values are replaced individually without losing the body", () => {
  const session =
    "https://storage.googleapis.com/upload/storage/v1/b/fixture/o?upload_id=SESSION_CAPABILITY";
  const result = sanitize({
    url: `${storageUrl}?pageToken=PAGE_CAPABILITY&alt=media`,
    headers: [
      ["Location", session],
      ["x-goog-upload-url", session],
      ["Content-Length", String(Buffer.byteLength('{"name":"owned/object","generation":"1"}'))],
    ],
  });
  assert.equal(result.mode, "RAW_BODY");
  assert.equal(result.headers[0][1].sha256, digest(session));
  assert.equal(result.headers[1][1].sha256, digest(session));
  assert.deepEqual(result.headers[2], [
    "Content-Length",
    String(Buffer.byteLength('{"name":"owned/object","generation":"1"}')),
  ]);
  assert.equal(result.url.query[0][1].sha256, digest("PAGE_CAPABILITY"));
  assert.deepEqual(result.url.query[1], ["alt", "media"]);
  assert.deepEqual(result.replacedHeaders, ["/headers/0/Location", "/headers/1/x-goog-upload-url"]);
  assert.ok(!JSON.stringify(result).includes("SESSION_CAPABILITY"));
});

test("unknown header names and secret-shaped safe headers never preserve their values", () => {
  const result = sanitize({
    headers: [
      ["x-unknown-secret", "NEW_OPAQUE_SECRET"],
      ["etag", "AMf-v-new-secret"],
    ],
  });
  assert.equal(result.mode, "RAW_BODY");
  assert.equal(result.headers[0][0].sha256, digest("x-unknown-secret"));
  for (const secret of ["NEW_OPAQUE_SECRET", "AMf-v-new-secret"])
    assert.ok(!JSON.stringify(result).includes(secret));
});

test("partial body and unknown JSON fields remain commitments regardless of safe URL or headers", () => {
  for (const changes of [
    { body: Buffer.from('{"name":"PARTIAL_SECRET'), complete: false },
    { body: Buffer.from('{"unknown":"NEW_SECRET"}') },
  ]) {
    const result = sanitize(changes);
    assert.equal(result.body, null);
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.ok(!JSON.stringify(result).includes("PARTIAL_SECRET"));
    assert.ok(!JSON.stringify(result).includes("NEW_SECRET"));
  }
});

test("tokeninfo, secure token and API key retrieval are always credential exchanges", () => {
  for (const url of [
    "https://oauth2.googleapis.com/tokeninfo?access_token=fixture-access-token",
    "https://securetoken.googleapis.com/v1/token?key=fixture-api-key",
    "https://apikeys.googleapis.com/v2/projects/fixture/locations/global/keys/key:getKeyString",
  ])
    assert.equal(sanitize({ url, body: Buffer.from('{"keyString":"NEW_KEY_SECRET"}') }).body, null);
});

test("unlisted origins, credentials in authority and invalid captures reject before persistence", () => {
  for (const changes of [
    { url: "https://unlisted.example/path" },
    { url: "http://storage.googleapis.com/path" },
    { url: "https://storage.googleapis.com:444/path" },
    { url: "https://secret@storage.googleapis.com/path" },
    { url: `${storageUrl}#secret` },
    { direction: "unknown" },
    { body: "raw-secret" },
    { headers: [["name", null]] },
  ])
    assert.throws(() => sanitize(changes), /^Error: invalid production capture$/);
});

test("unknown credential shapes cannot reuse raw account identity exceptions", () => {
  for (const [url, body, secret] of [
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
      '{"refreshToken":{"localId":"NewOpaqueSecret123"}}',
      "NewOpaqueSecret123",
    ],
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
      '{"idToken":{"email":"NewOpaqueSecret123@example.com"}}',
      "NewOpaqueSecret123",
    ],
    ["https://oauth2.googleapis.com/token", '{"access_token":1234567890123}', "1234567890123"],
    [storageUrl, '{"localId":"NewOpaqueSecret123"}', "NewOpaqueSecret123"],
  ]) {
    const result = sanitize({ url, body: Buffer.from(body) });
    assert.equal(result.body, null);
    assert.ok(!JSON.stringify(result).includes(secret));
  }
});

test("duplicate JSON and form fields retain only the whole original body commitment", () => {
  for (const [headers, body] of [
    [
      [],
      '{"localId":"NewOpaqueSecret123","localId":"fixtureUid123","email":"storage-object@example.com"}',
    ],
    [[], '{"localId":"first","local\\u0049d":"second"}'],
    [
      [["content-type", "application/x-www-form-urlencoded"]],
      "refresh_token=first&refresh_token=second",
    ],
  ]) {
    const result = sanitize({
      url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
      headers,
      body: Buffer.from(body),
    });
    assert.deepEqual(result.observation, {
      byteLength: Buffer.byteLength(body),
      sha256: digest(body),
    });
  }
});

test("unrecognized endpoint paths and public query or header shapes never preserve opaque values", () => {
  for (const changes of [
    { url: "https://oauth2.googleapis.com/token/NewOpaqueSecret123" },
    { url: `${storageUrl}?alt=NewOpaqueSecret123` },
    { headers: [["Content-Type", "application/json;token=NewOpaqueSecret123"]] },
    { headers: [["Content-Length", "NewOpaqueSecret123"]] },
  ]) {
    const result = sanitize(changes);
    assert.ok(!JSON.stringify(result).includes("NewOpaqueSecret123"));
  }
});

test("invalid Unicode in typed credentials retains original-body hashes without ambiguous field hashes", () => {
  for (const value of ["\ud800", "\ud801"]) {
    const body = JSON.stringify({ idToken: value });
    const result = sanitize({
      url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
      body: Buffer.from(body),
    });
    assert.deepEqual(result.observation, {
      byteLength: Buffer.byteLength(body),
      sha256: digest(body),
    });
  }
  const result = sanitize({
    url: "https://oauth2.googleapis.com/token",
    body: Buffer.from('{"access_token":"雪😀"}'),
  });
  assert.equal(result.observation.access_token.sha256, digest(Buffer.from("雪😀")));
});

test("account identities are limited to declared response paths, shapes and emails", () => {
  const body = '{"users":[{"localId":"fixture_uid-123","email":"storage-object@example.com"}]}';
  const result = sanitize({
    url: "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
    body: Buffer.from(body),
  });
  assert.equal(result.observation.users[0].localId, "fixture_uid-123");
  assert.equal(result.observation.users[0].email, "storage-object@example.com");
  for (const changes of [
    { direction: "request" },
    { url: "https://identitytoolkit.googleapis.com/v1/accounts:unknown" },
    { expectedEmails: [] },
    { body: Buffer.from('{"users":"NewOpaqueSecret123"}') },
  ]) {
    const observed = sanitize({
      url: "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
      body: Buffer.from(body),
      ...changes,
    });
    assert.ok(!JSON.stringify(observed.observation).includes("fixture_uid-123"));
    assert.ok(!JSON.stringify(observed.observation).includes("storage-object@example.com"));
    assert.ok(!JSON.stringify(observed.observation).includes("NewOpaqueSecret123"));
  }
});

test("OAuth form duplicates, invalid percent encoding and invalid UTF-8 never generate field observations", () => {
  for (const body of [
    Buffer.from("refresh_token=first&refresh%5Ftoken=second"),
    Buffer.from("refresh_token=%E0%A4%A"),
    Buffer.from([0xff, 0x00]),
  ]) {
    const result = sanitize({
      url: "https://oauth2.googleapis.com/token",
      direction: "request",
      headers: [["content-type", "application/x-www-form-urlencoded"]],
      body,
    });
    assert.deepEqual(result.observation, { byteLength: body.length, sha256: digest(body) });
  }
});

test("unknown names, duplicate or invalid query encodings and unimplemented header values stay commitments", () => {
  for (const changes of [
    { url: "https://storage.googleapis.com/storage/v1/b/unknown-bucket/o/NewOpaqueSecret123" },
    { url: `${storageUrl}?alt=media&alt=NewOpaqueSecret123` },
    { url: `${storageUrl}?alt=media&%61lt=NewOpaqueSecret123` },
    {
      headers: [
        ["ETag", "NewOpaqueSecret123"],
        ["Server", "NewOpaqueSecret123"],
      ],
    },
  ])
    assert.ok(!JSON.stringify(sanitize(changes)).includes("NewOpaqueSecret123"));
  for (const query of ["?alt=%E0%A4%A", "?alt=%ED%A0%80"]) {
    const result = sanitize({ url: `${storageUrl}${query}` });
    assert.deepEqual(result.url.query, {
      byteLength: Buffer.byteLength(query),
      sha256: digest(query),
    });
  }
  const result = sanitize({
    headers: [
      ["Host", "storage.googleapis.com"],
      ["Connection", "close"],
      ["Content-Type", "application/json; charset=UTF-8"],
    ],
  });
  assert.deepEqual(result.headers, [
    ["Host", "storage.googleapis.com"],
    ["Connection", "close"],
    ["Content-Type", "application/json; charset=UTF-8"],
  ]);
});

test("UID disclosure requires the same record to contain a declared email", () => {
  for (const [url, value, expectedEmails] of [
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
      { localId: "NewOpaqueSecret123" },
      [],
    ],
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:signUp",
      { localId: "NewOpaqueSecret123" },
      ["storage-object@example.com"],
    ],
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
      { users: [{ localId: "NewOpaqueSecret123" }] },
      [],
    ],
    [
      "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
      {
        users: [
          { localId: "fixtureUid", email: "storage-object@example.com" },
          { localId: "NewOpaqueSecret123" },
        ],
      },
      ["storage-object@example.com"],
    ],
  ]) {
    const body = Buffer.from(JSON.stringify(value));
    assert.deepEqual(sanitize({ url, body, expectedEmails }).observation, {
      byteLength: body.length,
      sha256: digest(body),
    });
  }
});

test("API Keys endpoints never reinterpret unexpected response bodies as raw Storage metadata", () => {
  for (const path of ["key/keyString", "key:getKeyString", "key", "unknown"]) {
    const result = sanitize({
      url: `https://apikeys.googleapis.com/v2/projects/fixture/locations/global/keys/${path}`,
      body: Buffer.from('{"etag":"NewOpaqueSecret123"}'),
    });
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.ok(!JSON.stringify(result).includes("NewOpaqueSecret123"));
  }
});
