import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

const module = await import("./storage-object/production-capture-body.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const digest = (value) => createHash("sha256").update(value).digest("hex");
const sanitize = (bytes, options = {}) => {
  assert.equal(
    typeof module.sanitizeStorageCaptureBody,
    "function",
    "capture sanitizer is missing",
  );
  return module.sanitizeStorageCaptureBody(Buffer.from(bytes), {
    expectedObjectNames: ["owned/object"],
    expectedBucket: "fixture",
    ...options,
  });
};

test("new capability values cannot escape through another leaf in the same response", () => {
  const token = "SYNTHETIC_DYNAMIC_CAPABILITY_/abc+def=123456789";
  const mixed = encodeURIComponent(token).replaceAll("%2F", "%2f");
  const copies = [
    token,
    encodeURIComponent(token),
    mixed,
    Buffer.from(token).toString("base64"),
    Buffer.from(mixed).toString("base64"),
    Buffer.from(mixed).toString("base64url"),
  ];
  for (const copy of copies)
    for (const publicFirst of [true, false]) {
      const fields = publicFirst
        ? { contentDisposition: copy, downloadTokens: [token] }
        : { downloadTokens: [token], contentDisposition: copy };
      const original = JSON.stringify({ name: "owned/object", ...fields });
      const result = sanitize(original);
      assert.equal(result.mode, "COMMITMENT_ONLY");
      assert.equal(result.body, null);
      assert.equal(result.originalSha256, digest(original));
    }
  const escaped = JSON.stringify({
    name: "owned/object",
    contentDisposition: token,
    downloadTokens: [token],
  }).replace(
    `"contentDisposition":${JSON.stringify(token)}`,
    `"contentDisposition":"${[...token].map((character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`).join("")}"`,
  );
  assert.equal(sanitize(escaped).mode, "COMMITMENT_ONLY");
  assert.equal(
    sanitize(
      JSON.stringify({
        name: "owned/object",
        contentDisposition: token,
        metadata: { firebaseStorageDownloadTokens: `${token},SECOND_DYNAMIC_TOKEN` },
      }),
    ).mode,
    "COMMITMENT_ONLY",
  );
  assert.equal(
    sanitize(
      JSON.stringify({
        kind: "storage#objects",
        nextPageToken: token,
        items: [{ name: "owned/object", contentDisposition: token }],
      }),
    ).mode,
    "COMMITMENT_ONLY",
  );
  assert.equal(
    sanitize(
      JSON.stringify({
        kind: "storage#rewriteResponse",
        rewriteToken: token,
        resource: { name: "owned/object", contentDisposition: token },
      }),
    ).mode,
    "COMMITMENT_ONLY",
  );
});

test("local capability discovery is bounded and retains safe field replacement within the bound", () => {
  for (const count of [64, 65]) {
    const result = sanitize(
      JSON.stringify({
        name: "owned/object",
        downloadTokens: Array.from(
          { length: count },
          (_, index) => `SYNTHETIC_BOUND_CAPABILITY_${index}_abcdefgh`,
        ),
      }),
    );
    assert.equal(result.mode, count === 64 ? "CAPABILITY_FIELDS_REPLACED" : "COMMITMENT_ONLY");
    assert.equal(result.body === null, count === 65);
  }
});

test("canonical encoded copies embedded in a metadata wrapper cannot persist", () => {
  const token = "SYNTHETIC_EMBEDDED_CAPABILITY_/abc+def=123456789";
  const mixed = encodeURIComponent(token).replaceAll("%2F", "%2f");
  for (const encoding of ["base64", "base64url"])
    for (const publicFirst of [true, false]) {
      const encoded = Buffer.from(mixed).toString(encoding);
      for (const wrapper of [
        `attachment; filename="${encoded}"`,
        `attachment; filename="prefix_${encoded}"`,
      ]) {
        const fields = publicFirst
          ? { contentDisposition: wrapper, downloadTokens: [token] }
          : { downloadTokens: [token], contentDisposition: wrapper };
        const original = JSON.stringify({ name: "owned/object", ...fields });
        const result = sanitize(original);
        assert.equal(result.mode, "COMMITMENT_ONLY");
        assert.equal(result.body, null);
        assert.equal(result.originalSha256, digest(original));
      }
    }
});

test("embedded reversible capabilities cannot escape detection through Base64 alphabet suffixes", () => {
  for (let padding = 0; padding < 3; padding++) {
    const token = `SYNTHETIC_EMBEDDED_CAPABILITY_/abc+def=123456789${"x".repeat(padding)}`;
    const mixed = encodeURIComponent(token).replaceAll("%2F", "%2f");
    for (const encoding of ["base64", "base64url"])
      for (const prefix of ["", "prefix_"])
        for (const suffix of ["x", "xx", "xxx", "backup"])
          for (const publicFirst of [true, false]) {
            const wrapper = `attachment; filename="${prefix}${Buffer.from(mixed).toString(encoding)}${suffix}"`;
            const fields = publicFirst
              ? { contentDisposition: wrapper, downloadTokens: [token] }
              : { downloadTokens: [token], contentDisposition: wrapper };
            const original = JSON.stringify({ name: "owned/object", ...fields });
            const result = sanitize(original);
            assert.equal(result.mode, "COMMITMENT_ONLY");
            assert.equal(result.body, null);
            assert.equal(result.originalSha256, digest(original));
          }
  }
});

test("a known nonsecret metadata body preserves every original byte", () => {
  const original = '{ "name" : "owned/object", "generation":"1", "metadata":{"marker":"first"} }\n';
  const result = sanitize(original);
  assert.equal(result.mode, "RAW_BODY");
  assert.deepEqual(result.body, Buffer.from(original));
  assert.equal(result.originalSha256, digest(original));
  assert.equal(result.originalByteLength, Buffer.byteLength(original));
});

test("fixed capability paths replace only their values and preserve the surrounding bytes", () => {
  const token = "fixture-capability-123";
  const original = `{ "name":"owned/object", "downloadTokens" : "${token}", "generation" : "1" }\n`;
  const result = sanitize(original, { knownSecrets: [token] });
  assert.equal(result.mode, "CAPABILITY_FIELDS_REPLACED");
  assert.deepEqual(
    result.replacedFields.map((field) => field.path),
    ["/downloadTokens"],
  );
  const saved = JSON.parse(result.body);
  assert.equal(saved.downloadTokens.sha256, digest(token));
  assert.equal(saved.downloadTokens.byteLength, Buffer.byteLength(token));
  assert.equal(saved.downloadTokens.codePointLength, token.length);
  assert.equal(saved.downloadTokens.characterClasses.digit, true);
  assert.ok(result.body.toString().startsWith('{ "name":"owned/object", "downloadTokens" : '));
  assert.ok(result.body.toString().endsWith(', "generation" : "1" }\n'));
  assert.ok(!result.body.includes(Buffer.from(token)));
  assert.equal(result.originalSha256, digest(original));
});

test("all supported capability paths are fixed, including each token in a download array", () => {
  const originals = [
    {
      downloadTokens: ["first-token", "second-token"],
      metadata: { firebaseStorageDownloadTokens: "metadata-token" },
    },
    {
      nextPageToken: "page-token",
      items: [
        {
          downloadTokens: "item-token",
          metadata: { firebaseStorageDownloadTokens: "nested-token" },
        },
      ],
    },
    {
      rewriteToken: "rewrite-token",
      resource: { metadata: { firebaseStorageDownloadTokens: "resource-token" } },
    },
  ];
  const results = originals.map((original) => sanitize(JSON.stringify(original)));
  for (const result of results) assert.equal(result.mode, "CAPABILITY_FIELDS_REPLACED");
  assert.deepEqual(
    results.flatMap((result) => result.replacedFields.map((field) => field.path)),
    [
      "/downloadTokens/0",
      "/downloadTokens/1",
      "/metadata/firebaseStorageDownloadTokens",
      "/nextPageToken",
      "/items/0/downloadTokens",
      "/items/0/metadata/firebaseStorageDownloadTokens",
      "/rewriteToken",
      "/resource/metadata/firebaseStorageDownloadTokens",
    ],
  );
  assert.equal(JSON.parse(results[0].body).downloadTokens.length, 2);
  assert.equal(JSON.parse(results[1].body).items.length, 1);
});

test("JSON escapes are decoded before hashing a capability", () => {
  const result = sanitize('{"downloadTokens":"fixture\\u002dtoken","name":"owned/object"}');
  assert.equal(JSON.parse(result.body).downloadTokens.sha256, digest("fixture-token"));
  assert.ok(!result.body.toString().includes("fixture"));
});

test("unknown fields and capability shapes fall back to commitments without a raw body", () => {
  for (const original of [
    '{"access_token":"NEW_RESPONSE_SECRET"}',
    '{"name":"owned/object","unexpected":"UNKNOWN_SECRET"}',
    '{"downloadTokens":{"secret":"UNKNOWN_SECRET"}}',
    '{"metadata":{"nested":{"downloadTokens":"UNKNOWN_SECRET"}}}',
    '{"downloadTokens":"first","downloadTokens":"second"}',
  ]) {
    const result = sanitize(original);
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.equal(result.originalSha256, digest(original));
    assert.ok(!JSON.stringify(result).includes("UNKNOWN_SECRET"));
    assert.ok(!JSON.stringify(result).includes("NEW_RESPONSE_SECRET"));
  }
});

test("known secrets and credential forms outside a capability never survive raw preservation", () => {
  const secret = "fixture-owned-password";
  for (const original of [
    JSON.stringify({ name: secret }),
    JSON.stringify({ name: Buffer.from(secret).toString("base64") }),
    JSON.stringify({ name: encodeURIComponent(secret) }),
    '{"name":"1//fixture-refresh-token"}',
    '{"name":"AMf-v-fixture-refresh-token"}',
    '{"name":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1aWQifQ.signature"}',
  ]) {
    const result = sanitize(original, { knownSecrets: [secret] });
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
    assert.ok(!JSON.stringify(result).includes(secret));
  }
});

test("incomplete, malformed, invalid UTF-8 and unapproved media never fall back to raw", () => {
  for (const [bytes, options] of [
    ['{"name":"partial-secret', {}],
    ['{"name":"complete"}', { complete: false }],
    [Buffer.from([0xff, 0x00]), {}],
    [Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"name":"object"}')]), {}],
    ["opaque-new-token", {}],
  ]) {
    const result = sanitize(bytes, options);
    assert.equal(result.mode, "COMMITMENT_ONLY");
    assert.equal(result.body, null);
  }
});

test("invalid limits and non-byte input reject without exposing supplied values", () => {
  assert.equal(
    typeof module.sanitizeStorageCaptureBody,
    "function",
    "capture sanitizer is missing",
  );
  for (const [bytes, options] of [
    ["secret-input", {}],
    [Buffer.alloc(2 * 1024 * 1024 + 1), {}],
    [Buffer.alloc(0), { knownSecrets: [null] }],
    [Buffer.alloc(0), { approvedBodySha256: ["secret-hash-input"] }],
    [Buffer.alloc(0), { complete: "true" }],
  ])
    assert.throws(
      () => module.sanitizeStorageCaptureBody(bytes, options),
      /^Error: invalid capture body configuration$/,
    );
});

test("an exact approved media hash preserves bytes but cannot override secret or completeness checks", () => {
  const bytes = Buffer.from([0x00, 0x01, 0xfe, 0xff]);
  const result = sanitize(bytes, { bodyKind: "media", approvedBodySha256: [digest(bytes)] });
  assert.equal(result.mode, "RAW_BODY");
  assert.deepEqual(result.body, bytes);
  const secret = "fixture-secret";
  assert.equal(
    sanitize(secret, { approvedBodySha256: [digest(secret)], knownSecrets: [secret] }).body,
    null,
  );
  assert.equal(
    sanitize(bytes, { approvedBodySha256: [digest(bytes)], complete: false }).body,
    null,
  );
  const metadata = '{"name":"owned/object","generation":"1"}';
  assert.equal(
    sanitize(metadata, { bodyKind: "media", approvedBodySha256: [] }).mode,
    "COMMITMENT_ONLY",
  );
  assert.equal(sanitize("", { bodyKind: "media", approvedBodySha256: [] }).mode, "COMMITMENT_ONLY");
});

test("an approved hash never overrides escaped secrets, duplicate keys, unknown fields or malformed JSON", () => {
  for (const original of [
    '{"name":"fixture\\u002dsecret"}',
    '{"name":"first","name":"second"}',
    '{"unexpected":"UNKNOWN_SECRET"}',
    '{"name":"partial-secret',
  ]) {
    for (const bodyKind of ["json", "media"]) {
      const result = sanitize(original, {
        bodyKind,
        knownSecrets: ["fixture-secret"],
        approvedBodySha256: [digest(original)],
      });
      assert.equal(result.mode, "COMMITMENT_ONLY");
      assert.equal(result.body, null);
    }
  }
});

test("known field names at unknown paths and unknown container or leaf types are commitments", () => {
  for (const original of [
    '{"items":"unrecognized-page-capability"}',
    '{"resource":false}',
    '{"metadata":{"name":"unrecognized-capability"}}',
    '{"prefixes":[{"name":"unrecognized-capability"}]}',
    '{"generation":false}',
    '{"size":"not-a-size"}',
    '{"name":123}',
    '{"error":{"code":"unrecognized-capability"}}',
  ])
    assert.equal(sanitize(original).mode, "COMMITMENT_ONLY");
});

test("URL fields require closed origins and queries and decode equivalent percent representations", () => {
  for (const original of [
    '{"mediaLink":"https://example.invalid/?token=private%2ftoken"}',
    '{"mediaLink":"https://storage.googleapis.com/path?upload_id=unrecognized-session-capability"}',
    '{"selfLink":"https://storage.googleapis.com/path?token=unrecognized-capability"}',
    '{"location":"https://storage.googleapis.com/path?unexpected=unrecognized-capability"}',
  ])
    assert.equal(sanitize(original, { knownSecrets: ["private/token"] }).mode, "COMMITMENT_ONLY");
  const safe =
    '{"selfLink":"https://www.googleapis.com/storage/v1/b/fixture/o/owned%2Fobject","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/fixture/o/owned%2fobject?generation=1&alt=media"}';
  assert.equal(sanitize(safe).mode, "RAW_BODY");
  assert.deepEqual(sanitize(safe).body, Buffer.from(safe));
});

test("invalid Unicode cannot produce ambiguous decoded-value commitments", () => {
  assert.throws(
    () => sanitize("{}", { knownSecrets: ["\ud800"] }),
    /^Error: invalid capture body configuration$/,
  );
  for (const value of ["\ud800", "\ud801"])
    assert.equal(sanitize(JSON.stringify({ downloadTokens: value })).mode, "COMMITMENT_ONLY");
  const result = sanitize('{"downloadTokens":"雪😀"}');
  assert.equal(JSON.parse(result.body).downloadTokens.sha256, digest(Buffer.from("雪😀")));
  assert.equal(JSON.parse(result.body).downloadTokens.codePointLength, 2);
  assert.equal(JSON.parse(result.body).downloadTokens.characterClasses.nonAscii, true);
  assert.equal(
    sanitize('{"downloadTokens":"first","download\\u0054okens":"second"}').mode,
    "COMMITMENT_ONLY",
  );
});

test("secret-free error structure and metadata are preserved while unknown messages use commitments", () => {
  const original = '{"error":{"code":404,"message":"Not Found","errors":[{"reason":"notFound"}]}}';
  assert.equal(sanitize(original).mode, "RAW_BODY");
  assert.equal(
    sanitize('{"error":{"code":404,"message":"UNKNOWN_MESSAGE_SECRET"}}').mode,
    "COMMITMENT_ONLY",
  );
});
