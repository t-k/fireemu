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
  assert.match(out[out.indexOf("Authorization") + 1], /^<redacted:header>$/);
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
