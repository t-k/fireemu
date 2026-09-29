import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

const salt = "9".repeat(64);
const CANARIES = {
  downloadToken: "0f1e2d3c-CANARYDOWNLOADTOKEN-4b5a6978",
  idToken: "eyJhbGciOiJSUzI1NiIsImtpZCI6IkNBTkFSWSJ9.eyJzdWIiOiJDQU5BUlktVUlEIiwiYXVkIjoiQ0FOQVJZIn0.Q0FOQVJZU0lHTkFUVVJFMDEyMzQ1Njc4OQ",
  accessToken: "ya29.CANARYaccessToken0123456789abcdefABCDEF",
  refreshToken: "1//CANARYrefreshToken0123456789abcdefABCDEFghij",
  apiKey: "AIzaCANARYAPIKEY0123456789abcdefghijklm",
  sessionUrl: "https://firebasestorage.googleapis.com/v0/b/bucket/o?name=x%2Fy&upload_id=CANARYUPLOADID0123456789&upload_protocol=resumable",
  passwordHash: "CANARYPASSWORDHASH0123456789abcdef==",
  passwordSalt: "CANARYSALTvalue0123456789",
  keyString: "CANARYKEYSTRINGVALUE0123456789abcdef",
  pem: "-----BEGIN PRIVATE KEY-----\nQ0FOQVJZUEVNS0VZQk9EWTAxMjM0NTY3ODlhYmNkZWY=\n-----END PRIVATE KEY-----",
  bearer: "CANARYBEARERTOKEN0123456789abcdef",
};
const load = async () => {
  const module = await import("./storage-rules/redaction.mjs").catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return {}; throw error; });
  assert.equal(typeof module.createRedactor, "function");
  return module;
};
const redactor = async () => (await load()).createRedactor({ digestSalt: salt });
const secrets = Object.values(CANARIES);
const leaks = (text) => secrets.filter((secret) => text.includes(secret) || text.includes(encodeURIComponent(secret)) || text.includes(Buffer.from(secret).toString("base64")) || text.includes(JSON.stringify(secret).slice(1, -1)));

test("JSON secret fields lose their string values and keep the surrounding structure", async () => {
  const r = await redactor();
  const body = JSON.stringify({ name: "STORAGE-RULES/run/a.bin", downloadTokens: CANARIES.downloadToken, metadata: { firebaseStorageDownloadTokens: `${CANARIES.downloadToken},second-token-value` }, idToken: CANARIES.idToken, refreshToken: CANARIES.refreshToken, access_token: CANARIES.accessToken, passwordHash: CANARIES.passwordHash, salt: CANARIES.passwordSalt, keyString: CANARIES.keyString, size: "4" });
  const out = r.bytes(Buffer.from(body));
  const text = out.bytes.toString();
  assert.deepEqual(leaks(text), []);
  assert.equal(text.includes("second-token-value"), false);
  const parsed = JSON.parse(text);
  assert.equal(parsed.name, "STORAGE-RULES/run/a.bin");
  assert.equal(parsed.size, "4");
  assert.match(parsed.downloadTokens, /^<redacted:json-field>$/);
  assert.ok(out.spans.length >= 8);
  for (const span of out.spans) assert.deepEqual(Object.keys(span).sort(), ["kind", "length", "start", "valueSha256"]);
});

test("a span records the original offset and length and a salted digest, never the value", async () => {
  const r = await redactor();
  const body = Buffer.from(`{"a":1,"downloadTokens":"${CANARIES.downloadToken}"}`);
  const { spans, originalSha256 } = r.bytes(body);
  assert.equal(spans.length, 1);
  const start = body.indexOf(CANARIES.downloadToken);
  assert.deepEqual({ start: spans[0].start, length: spans[0].length, kind: spans[0].kind }, { start, length: CANARIES.downloadToken.length, kind: "json-field" });
  assert.equal(spans[0].valueSha256, createHash("sha256").update([salt, "json-field", CANARIES.downloadToken].join("\0")).digest("hex"));
  assert.equal(originalSha256, createHash("sha256").update([salt, body.toString("latin1")].join("\0")).digest("hex"));
  assert.equal(JSON.stringify({ spans, originalSha256 }).includes(CANARIES.downloadToken), false);
});

test("URLs, tokens and keys are found wherever they appear", async () => {
  const r = await redactor();
  const text = [
    `mediaLink: https://storage.googleapis.com/download/storage/v1/b/b/o/x?generation=1&alt=media&token=${CANARIES.downloadToken}`,
    `escaped: https://x/o?a=1\\u0026token=${CANARIES.downloadToken}\\u0026b=2`,
    `session: ${CANARIES.sessionUrl}`, `jwt in prose ${CANARIES.idToken} end`, `access ${CANARIES.accessToken} refresh ${CANARIES.refreshToken}`,
    `key ${CANARIES.apiKey} and https://x/v1/accounts:signUp?key=${CANARIES.apiKey}`, `Authorization: Bearer ${CANARIES.bearer}`, CANARIES.pem,
    `signed https://x/o?X-Goog-Signature=CANARYSIGNATURE0123456789&X-Goog-Credential=CANARYCRED`,
  ].join("\n");
  const out = r.bytes(Buffer.from(text)).bytes.toString();
  assert.deepEqual(leaks(out), []);
  for (const canary of ["CANARYSIGNATURE0123456789", "CANARYCRED", "CANARYUPLOADID0123456789"]) assert.equal(out.includes(canary), false);
  assert.ok(out.includes("generation=1&alt=media"));
});

test("plain assignments of a secret name are redacted, and placeholders and ordinary words are not", async () => {
  const r = await redactor();
  const text = `failed: token=${CANARIES.downloadToken}; password: hunter2CANARY, api_key=${CANARIES.apiKey} (secret=abc123CANARY) upload_id=CANARYUPLOAD9999`;
  const out = r.text(text);
  for (const canary of [CANARIES.downloadToken, "hunter2CANARY", CANARIES.apiKey, "abc123CANARY", "CANARYUPLOAD9999"]) assert.equal(out.includes(canary), false, canary);
  const benign = "ifGenerationMatch=<ref:generation> pageToken=<ref:page-token> the token bucket is full and a secret garden";
  assert.equal(r.text(benign), benign);
});

test("email addresses are personal data and are removed from bodies, headers and text", async () => {
  const r = await redactor();
  const body = JSON.stringify({ id: "1234567890", email: "owner.name+tag@example.co.uk", verified_email: true, bindings: [{ role: "roles/owner", members: ["user:owner@example.com", "serviceAccount:svc@project.iam.gserviceaccount.com", "group:team@example.org"] }], note: "contact a@b.io" });
  const out = r.bytes(Buffer.from(body));
  const text = out.bytes.toString();
  for (const address of ["owner.name+tag@example.co.uk", "owner@example.com", "svc@project.iam.gserviceaccount.com", "team@example.org", "a@b.io"]) assert.equal(text.includes(address), false, address);
  assert.equal(JSON.parse(text).verified_email, true);
  assert.ok(text.includes("user:<redacted:email>"));
  assert.equal(r.headers(["X-Goog-Authenticated-User-Email", "accounts.google.com:owner@example.com"])[1].includes("owner@example.com"), false);
  assert.equal(r.text("sent to owner@example.com today").includes("owner@example.com"), false);
  const certificate = "GET https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
  assert.equal(r.text(certificate), certificate);
  const plain = "no address here, price 5 @ 3 and user@localhost";
  assert.equal(r.text(plain), plain);
  assert.ok(out.spans.some((span) => span.kind === "email"));
});

test("bodies without secrets, including binary media, pass through byte for byte", async () => {
  const r = await redactor();
  for (const body of [Buffer.from("allow"), Buffer.from([0, 255, 128, 7, 10]), Buffer.from(JSON.stringify({ error: { code: 403, message: "Permission denied. Could not perform this operation" } })), Buffer.alloc(0)]) {
    const out = r.bytes(body);
    assert.deepEqual(out.bytes, body);
    assert.deepEqual(out.spans, []);
  }
  const jwtLike = r.bytes(Buffer.from("eyJshort.eyJshort")).bytes.toString();
  assert.equal(jwtLike, "eyJshort.eyJshort");
});

test("response headers are redacted by name and by content", async () => {
  const r = await redactor();
  const raw = [
    "Content-Type", "application/json", "Authorization", `Bearer ${CANARIES.bearer}`, "Set-Cookie", "SID=CANARYCOOKIE; HttpOnly", "Cookie", "a=CANARYCOOKIE",
    "X-Goog-Upload-URL", CANARIES.sessionUrl, "X-Goog-Generation", "1700000000000001", "Location", `https://x/o?token=${CANARIES.downloadToken}`, "X-Goog-Api-Key", CANARIES.apiKey, "X-Custom", `has ${CANARIES.accessToken} inside`,
  ];
  const out = r.headers(raw);
  assert.equal(out.length, raw.length);
  assert.deepEqual(out.filter((_, index) => index % 2 === 0), raw.filter((_, index) => index % 2 === 0));
  const text = out.join("\n");
  assert.deepEqual(leaks(text), []);
  assert.equal(text.includes("CANARYCOOKIE"), false);
  assert.equal(out[out.indexOf("X-Goog-Generation") + 1], "1700000000000001");
  assert.equal(out[out.indexOf("Content-Type") + 1], "application/json");
  assert.match(out[out.indexOf("Authorization") + 1], /^<redacted:header:[0-9a-f]{64}>$/);
});

test("free text such as a target or an error message is redacted the same way", async () => {
  const r = await redactor();
  const text = `POST https://x/o?upload_id=CANARYUPLOADID0123456789&key=${CANARIES.apiKey} failed with ${CANARIES.accessToken}`;
  const out = r.text(text);
  assert.deepEqual(leaks(out), []);
  assert.equal(out.includes("CANARYUPLOADID0123456789"), false);
  assert.equal(r.text("GET https://storage.googleapis.com/storage/v1/b/b/o/x"), "GET https://storage.googleapis.com/storage/v1/b/b/o/x");
  assert.throws(() => r.text(7), /invalid redaction input/);
});

test("overlapping matches merge and every secret stays hidden", async () => {
  const r = await redactor();
  const body = `{"downloadTokens":"${CANARIES.downloadToken}","link":"https://x/o?token=${CANARIES.downloadToken}&upload_id=CANARYUPLOADID0123456789","jwt":"${CANARIES.idToken}","idToken":"${CANARIES.idToken}"}`;
  const out = r.bytes(Buffer.from(body));
  assert.deepEqual(leaks(out.bytes.toString()), []);
  const sorted = [...out.spans].sort((a, b) => a.start - b.start);
  for (let index = 1; index < sorted.length; index++) assert.ok(sorted[index].start >= sorted[index - 1].start + sorted[index - 1].length);
  JSON.parse(out.bytes.toString());
});

test("inputs and options are closed", async () => {
  const { createRedactor } = await load();
  for (const bad of [null, {}, { digestSalt: "short" }, { digestSalt: "Z".repeat(64) }, { digestSalt: salt, extra: 1 }]) assert.throws(() => createRedactor(bad), /invalid redactor options/);
  const r = createRedactor({ digestSalt: salt });
  for (const bad of ["x", null, new Uint8Array(3), Buffer.alloc(3, 1).toString()]) assert.throws(() => r.bytes(bad), /invalid redaction input/);
  for (const bad of [null, ["a"], ["a", 1], "x", ["a", "b", "c"]]) assert.throws(() => r.headers(bad), /invalid redaction input/);
  assert.throws(() => r.bytes(Buffer.alloc(2 * 1024 * 1024 + 1)), /invalid redaction input/);
});

// The canaries below have no shape of their own (no JWT, ya29., 1//, AIza or Bearer prefix), so only the named rule can hide them.
const OPAQUE = "CANARYOPAQUEVALUE0123456789";

test("every secret JSON field hides an opaque value by its name alone", async () => {
  const r = await redactor();
  for (const field of ["downloadTokens", "firebaseStorageDownloadTokens", "idToken", "id_token", "refreshToken", "refresh_token", "access_token", "accessToken", "passwordHash", "salt", "keyString", "sessionInfo", "password", "secret", "apiKey", "api_key", "token", "privateKey", "private_key", "client_secret"]) {
    const out = r.bytes(Buffer.from(JSON.stringify({ [field]: OPAQUE, size: "4" })));
    assert.equal(out.bytes.toString(), JSON.stringify({ [field]: "<redacted:json-field>", size: "4" }), field);
    assert.deepEqual(out.spans.map((span) => span.kind), ["json-field"], field);
  }
});

test("every secret URL parameter hides an opaque value by its name alone", async () => {
  const r = await redactor();
  for (const parameter of ["token", "key", "upload_id", "access_token", "id_token", "refresh_token", "sig", "signature", "X-Goog-Signature", "X-Goog-Credential", "X-Amz-Signature", "X-Amz-Credential"]) {
    assert.equal(r.text(`GET /o?alt=media&${parameter}=${OPAQUE}&b=2`), `GET /o?alt=media&${parameter}=<redacted:url-parameter>&b=2`, parameter);
  }
});

test("every bearer header hides an opaque value by its name alone, whatever its case", async () => {
  const r = await redactor();
  for (const name of ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-goog-upload-url", "x-goog-api-key", "x-firebase-appcheck", "x-goog-iam-authorization-token"]) {
    for (const spelled of [name, name.toUpperCase(), name.replace(/(^|-)([a-z])/g, (_, dash, letter) => `${dash}${letter.toUpperCase()}`)]) {
      const out = r.headers([spelled, OPAQUE, "Content-Type", "text/plain"]);
      assert.match(out[1], /^<redacted:header:[0-9a-f]{64}>$/, spelled);
      assert.deepEqual([out[0], out[2], out[3]], [spelled, "Content-Type", "text/plain"]);
    }
  }
});

test("a resumable session URL is a bearer capability and is removed whole, not only its upload ID", async () => {
  const r = await redactor();
  assert.equal(r.text(`session ${CANARIES.sessionUrl} end`), "session <redacted:session-url> end");
  const body = Buffer.from(`{"location":"${CANARIES.sessionUrl}"}`);
  const out = r.bytes(body);
  assert.equal(out.bytes.toString(), '{"location":"<redacted:session-url>"}');
  assert.deepEqual(out.spans.map(({ kind, start, length }) => ({ kind, start, length })), [{ kind: "session-url", start: body.indexOf("https://"), length: CANARIES.sessionUrl.length }]);
  assert.equal(out.bytes.toString().includes("upload_protocol"), false);
});

test("a secret that starts inside another match and runs past its end stays hidden to its last byte", async () => {
  const r = await redactor();
  const pemBody = "CANARYPEMBODYTHATMUSTNOTLEAK0123456789";
  const text = `token=x-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY----- tail`;
  const out = r.text(text);
  assert.equal(out, "token=<redacted:assignment> tail");
  assert.equal(out.includes(pemBody), false);
  const spans = r.bytes(Buffer.from(text)).spans;
  assert.deepEqual(spans.map(({ start, length }) => ({ start, length })), [{ start: 6, length: text.length - 6 - " tail".length }]);
});

test("at one start the longest match names the span, and at equal length the earlier pattern does", async () => {
  const r = await redactor();
  // A service-account key file: the JSON value is the PEM block plus its trailing newline, so it is longer than the PEM match.
  const keyFile = Buffer.from(JSON.stringify({ private_key: `${CANARIES.pem}\n`, client_email: "svc" }));
  const out = r.bytes(keyFile);
  assert.equal(out.bytes.toString(), JSON.stringify({ private_key: "<redacted:json-field>", client_email: "svc" }));
  assert.deepEqual(out.spans.map(({ kind, start, length }) => ({ kind, start, length })), [{ kind: "json-field", start: keyFile.indexOf("-----BEGIN"), length: JSON.stringify(`${CANARIES.pem}\n`).length - 2 }]);
  // The idToken value is exactly a JWT: the JSON field rule comes first and names it.
  const token = r.bytes(Buffer.from(JSON.stringify({ idToken: CANARIES.idToken })));
  assert.deepEqual(token.spans.map((span) => span.kind), ["json-field"]);
});

// Header capture is an allowlist: a public header keeps its (text-redacted) value, every other header keeps only a salted digest.
const PUBLIC = ["accept", "accept-encoding", "host", "connection", "date", "server", "content-type", "content-length", "content-range", "content-encoding", "content-disposition", "cache-control", "expires", "last-modified", "etag", "vary", "transfer-encoding", "range", "user-agent", "x-goog-user-project", "x-goog-hash", "x-goog-generation", "x-goog-metageneration", "x-goog-storage-class", "x-goog-stored-content-length", "x-goog-stored-content-encoding", "x-goog-upload-protocol", "x-goog-upload-command", "x-goog-upload-offset", "x-goog-upload-header-content-length", "x-goog-upload-header-content-type", "x-goog-upload-status", "x-goog-upload-size-received", "x-content-type-options"];

test("every public header keeps its value whatever its case", async () => {
  const r = await redactor();
  for (const name of PUBLIC) for (const spelled of [name, name.toUpperCase(), name.replace(/(^|-)([a-z])/g, (_, dash, letter) => `${dash}${letter.toUpperCase()}`)]) {
    assert.deepEqual(r.headers([spelled, "plain-value-1"]), [spelled, "plain-value-1"], spelled);
  }
});

test("every header outside the public list is reduced to a salted digest, including the upload and download capabilities", async () => {
  const r = await redactor();
  const secretNames = ["x-guploader-uploadid", "x-goog-upload-control-url", "location", "x-firebase-storage-download-tokens", "x-goog-upload-url", "authorization", "set-cookie", "x-firebase-appcheck", "x-custom", "x-plain", "x-goog-upload-chunk-granularity", "access-control-allow-origin", "alt-svc", "x-goog-request-id", "content-language"];
  for (const name of secretNames) {
    for (const spelled of [name, name.toUpperCase()]) {
      const out = r.headers([spelled, OPAQUE]);
      assert.equal(out[0], spelled);
      assert.match(out[1], /^<redacted:header:[0-9a-f]{64}>$/, spelled);
      assert.equal(out[1].includes(OPAQUE), false, spelled);
    }
  }
  // The digest is stable for one value, differs between values and between salts, and is the same whatever the header's name.
  const one = r.headers(["X-A", "value-1"])[1];
  assert.equal(r.headers(["X-A", "value-1"])[1], one);
  assert.equal(r.headers(["X-B", "value-1"])[1], one);
  assert.notEqual(r.headers(["X-A", "value-2"])[1], one);
  const other = (await import("./storage-rules/redaction.mjs")).createRedactor({ digestSalt: "8".repeat(64) });
  assert.notEqual(other.headers(["X-A", "value-1"])[1], one);
  // An empty value is a value too.
  assert.match(r.headers(["X-A", ""])[1], /^<redacted:header:[0-9a-f]{64}>$/);
});

test("a public header whose value carries a secret pattern still has the pattern removed", async () => {
  const r = await redactor();
  const out = r.headers(["Content-Disposition", `attachment; filename="${CANARIES.downloadToken}"; token=${OPAQUE}`, "ETag", `"${CANARIES.idToken}"`]);
  assert.equal(out.join("\n").includes(OPAQUE), false);
  assert.equal(out.join("\n").includes(CANARIES.idToken), false);
});

// The owner's Google account ID (the userinfo answer's `id`, a 21-digit subject) identifies a person: it is removed from bodies.
test("a numeric account ID under an id key is removed from a body, and ordinary ids and numbers stay", async () => {
  const r = await redactor();
  const subject = "107364905517293846281";
  for (const body of [`{"id":"${subject}","email":"o@x.example","verified_email":true}`, `{ "id" : "${subject}" }`, `{"id":${subject}}`, `{"a":{"id":"${subject}"}}`, `{"id":"${"9".repeat(15)}"}`, `{"id":"${"9".repeat(25)}"}`]) {
    const out = r.bytes(Buffer.from(body)).bytes.toString();
    assert.equal(/\d{15}/.test(out), false, body);
    assert.match(out, /<redacted:account-id>/, body);
  }
  for (const body of [`{"id":"${"9".repeat(14)}"}`, `{"id":"${"9".repeat(26)}"}`, `{"id":"bucket/${subject}/17000"}`, `{"id":"abc${subject}"}`, `{"identifier":"${subject}"}`, `{"userid":"${subject}"}`, `{"generation":"${subject}"}`, `{"id":"${subject}x"}`]) {
    assert.equal(r.bytes(Buffer.from(body)).bytes.toString(), body, body);
  }
  // Only the digits go, so the key and the quoting stay readable.
  assert.equal(r.bytes(Buffer.from(`{"id":"${subject}","x":1}`)).bytes.toString(), '{"id":"<redacted:account-id>","x":1}');
  assert.equal(r.bytes(Buffer.from(`{ "id" : ${subject} }`)).bytes.toString(), '{ "id" : <redacted:account-id> }');
  const text = r.text(`owner ${JSON.stringify({ id: subject })} end`);
  assert.equal(text.includes(subject), false);
});
