import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const alternate = generateKeyPairSync("rsa", { modulusLength: 2048 });
const nowSeconds = 1790553600;
const runId = "fixture-test";
const digestSalt = "a1".repeat(32);
const keySet = { fetchedAt: nowSeconds - 10, expiresAt: nowSeconds + 100, publicKeys: { test: publicKey.export({ type: "spki", format: "pem" }) } };
const names = ["user-a", "user-b", "user-plain", "revoked-token", "foreign-project-token"];

function claims(principal = "user-a") {
  const account = principal === "user-plain" ? "user-a" : principal;
  const project = principal === "foreign-project-token" ? "fireemu-oracle-idp" : "fireemu-oracle-query";
  const email = `storage-rules-${runId}-${account}@example.com`;
  return {
    iss: `https://securetoken.google.com/${project}`, aud: project, sub: `uid-${account}`, user_id: `uid-${account}`,
    iat: nowSeconds - 2, exp: nowSeconds + 3600, auth_time: nowSeconds - 2,
    email, email_verified: ["user-a", "user-plain"].includes(principal),
    firebase: { identities: { email: [email] }, sign_in_provider: "password" },
    ...(principal === "user-a" ? { role: "reader", level: 7 } : {}),
    ...(principal === "user-b" ? { role: "writer", level: "7" } : {}),
  };
}

function jwt(payload = claims(), header = { alg: "RS256", kid: "test", typ: "JWT" }, key = privateKey) {
  const data = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}`;
  return `${data}.${sign("RSA-SHA256", Buffer.from(data), key).toString("base64url")}`;
}

function options(principal = "user-a") {
  return { token: jwt(claims(principal)), principal, runId, expectedUid: claims(principal).sub, keySet, nowSeconds, validSince: principal === "revoked-token" ? nowSeconds - 1 : null, digestSalt };
}

async function load() {
  const module = await import("./storage-rules/fixture-proof.mjs").catch((error) => {
    if (error.code === "ERR_MODULE_NOT_FOUND") return {};
    throw error;
  });
  assert.equal(typeof module.verifyFixtureIdToken, "function");
  return module.verifyFixtureIdToken;
}

for (const principal of names) {
  test(`a signed ${principal} snapshot yields a frozen non-sending proof without token bytes`, async () => {
    const verify = await load();
    const input = options(principal);
    const proof = verify(input);
    assert.equal(proof.status, "SIGNED_FIXTURE_LOCAL_ONLY");
    assert.equal(proof.sendAuthorized, false);
    assert.equal(proof.principal, principal);
    assert.equal(proof.uid, input.expectedUid);
    assert.equal(proof.project, claims(principal).aud);
    assert.equal(proof.revocationBoundary, input.validSince);
    assert.match(proof.tokenDigest, /^[a-f0-9]{64}$/);
    assert.ok(Object.isFrozen(proof));
    assert.ok(Object.isFrozen(proof.claims));
    assert.ok(!JSON.stringify(proof).includes(input.token));
    assert.ok(!JSON.stringify(proof).includes(digestSalt));
  });
}

test("salt changes the digest while the signed snapshot stays unchanged", async () => {
  const verify = await load();
  const input = options();
  assert.notEqual(verify(input).tokenDigest, verify({ ...input, digestSalt: "b2".repeat(32) }).tokenDigest);
});

test("a token issued in the current second is valid", async () => {
  const verify = await load();
  const input = { ...options(), token: jwt({ ...claims(), iat: nowSeconds }) };
  assert.equal(verify(input).issuedAt, nowSeconds);
});

test("authentication and issuance in the current second are valid", async () => {
  const verify = await load();
  const input = { ...options(), token: jwt({ ...claims(), auth_time: nowSeconds, iat: nowSeconds }) };
  assert.equal(verify(input).authenticatedAt, nowSeconds);
});

test("a key snapshot fetched in the current second is valid", async () => {
  const verify = await load();
  assert.equal(verify({ ...options(), keySet: { ...keySet, fetchedAt: nowSeconds } }).keyFetchedAt, nowSeconds);
});

test("a revoked fixture may bind validSince to the current second", async () => {
  const verify = await load();
  assert.equal(verify({ ...options("revoked-token"), validSince: nowSeconds }).revocationBoundary, nowSeconds);
});

for (const [name, delta] of [
  ["issuer", { iss: "https://securetoken.google.com/fireemu-oracle-idp" }],
  ["audience", { aud: "fireemu-oracle-idp" }],
  ["subject", { sub: "other-uid" }],
  ["user_id", { user_id: "other-uid" }],
  ["email", { email: "other@example.com" }],
  ["email_verified", { email_verified: false }],
  ["role", { role: "writer" }],
  ["level type", { level: "7" }],
  ["missing custom claim", { role: undefined }],
  ["unexpected custom claim", { admin: true }],
  ["provider", { firebase: { ...claims().firebase, sign_in_provider: "custom" } }],
  ["tenant", { firebase: { ...claims().firebase, tenant: "other" } }],
  ["identity email", { firebase: { ...claims().firebase, identities: { email: ["other@example.com"] } } }],
]) {
  test(`a freshly signed token with wrong ${name} cannot be a user-a fixture`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options(), token: jwt({ ...claims(), ...delta }) }), /invalid fixture claims/);
  });
}

test("a plain snapshot cannot retain user-a's role and level", async () => {
  const verify = await load();
  assert.throws(() => verify({ ...options("user-plain"), token: jwt(claims()) }), /invalid fixture claims/);
});

test("user-b requires a string level rather than numeric seven", async () => {
  const verify = await load();
  assert.throws(() => verify({ ...options("user-b"), token: jwt({ ...claims("user-b"), level: 7 }) }), /invalid fixture claims/);
});

test("a query-issued token cannot substitute for the foreign-project fixture", async () => {
  const verify = await load();
  const foreign = claims("foreign-project-token");
  assert.throws(() => verify({ ...options("foreign-project-token"), token: jwt({ ...foreign, iss: claims().iss, aud: claims().aud }) }), /invalid fixture claims/);
});

for (const [name, delta] of [
  ["expired", { exp: nowSeconds }], ["future issuance", { iat: nowSeconds + 1 }],
  ["future authentication", { auth_time: nowSeconds + 1 }], ["authentication after issuance", { auth_time: nowSeconds - 1 }],
  ["string issuance", { iat: String(nowSeconds - 2) }], ["fractional expiry", { exp: nowSeconds + 0.5 }],
  ["missing authentication", { auth_time: undefined }], ["expiry before issuance", { exp: nowSeconds - 3 }],
]) {
  test(`a ${name} signed token is refused`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options(), token: jwt({ ...claims(), ...delta }) }), /invalid fixture time/);
  });
}

for (const boundary of [null, nowSeconds - 2, nowSeconds + 1, String(nowSeconds - 1)]) {
  test(`a revoked fixture rejects invalid validSince ${boundary}`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options("revoked-token"), validSince: boundary }), /invalid revocation boundary/);
  });
}

test("an ordinary fixture cannot acquire a revocation boundary", async () => {
  const verify = await load();
  assert.throws(() => verify({ ...options(), validSince: nowSeconds - 1 }), /invalid revocation boundary/);
});

for (const header of [{ alg: "none", kid: "test" }, { alg: "HS256", kid: "test" }, { alg: "RS256", kid: "unknown" }, { alg: "RS256", kid: "test", jku: "https://example.com/keys" }]) {
  test(`unsupported token header ${JSON.stringify(header)} is refused`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options(), token: jwt(claims(), header) }), /invalid fixture header/);
  });
}

test("a valid-shape signature from another RSA key is refused", async () => {
  const verify = await load();
  assert.throws(() => verify({ ...options(), token: jwt(claims(), undefined, alternate.privateKey) }), /invalid fixture signature/);
});

test("changing a signed payload without resigning is refused", async () => {
  const verify = await load();
  const input = options();
  const pieces = input.token.split(".");
  pieces[1] = Buffer.from(JSON.stringify({ ...claims(), role: "changed" })).toString("base64url");
  assert.throws(() => verify({ ...input, token: pieces.join(".") }), /invalid fixture signature/);
});

for (const delta of [{ expiresAt: nowSeconds }, { fetchedAt: nowSeconds + 1 }, { expiresAt: Infinity }]) {
  test(`a stale or invalid key snapshot ${Object.keys(delta)[0]} is refused`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options(), keySet: { ...keySet, ...delta } }), /invalid key snapshot/);
  });
}

for (const token of ["not-a-token", "a.b.c", `${jwt()}.extra`, jwt().replace(".", "=."), "a".repeat(16385)]) {
  test(`a malformed token of length ${token.length} is refused without leaking it`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options(), token }), (error) => error.message === "invalid fixture token");
  });
}

test("an option getter is rejected before token acquisition", async () => {
  const verify = await load();
  let called = false;
  const input = Object.defineProperty(options(), "token", { get() { called = true; return jwt(); }, enumerable: true });
  assert.throws(() => verify(input), /invalid fixture input/);
  assert.equal(called, false);
});

test("a public-key getter is rejected without invoking it", async () => {
  const verify = await load();
  let called = false;
  const publicKeys = Object.defineProperty({}, "test", { get() { called = true; return keySet.publicKeys.test; }, enumerable: true });
  assert.throws(() => verify({ ...options(), keySet: { ...keySet, publicKeys } }), /invalid key snapshot/);
  assert.equal(called, false);
});

test("a weak RSA key cannot establish a fixture proof", async () => {
  const verify = await load();
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const publicKeys = { test: weak.publicKey.export({ type: "spki", format: "pem" }) };
  assert.throws(() => verify({ ...options(), token: jwt(claims(), undefined, weak.privateKey), keySet: { ...keySet, publicKeys } }), /invalid signing key/);
});

test("private PEM material cannot be used as the public-key snapshot", async () => {
  const verify = await load();
  const publicKeys = { test: privateKey.export({ type: "pkcs8", format: "pem" }) };
  assert.throws(() => verify({ ...options(), keySet: { ...keySet, publicKeys } }), /invalid key snapshot/);
});

test("hidden input fields cannot hold unreviewed credential data", async () => {
  const verify = await load();
  const input = Object.defineProperty(options(), "extra", { value: "unreviewed" });
  assert.throws(() => verify(input), /invalid fixture input/);
});

for (const delta of [{ runId: "../foreign" }, { expectedUid: "" }, { principal: "expired-token" }, { nowSeconds: NaN }, { digestSalt: "weak" }]) {
  test(`invalid fixture input ${Object.keys(delta)[0]} is refused`, async () => {
    const verify = await load();
    assert.throws(() => verify({ ...options(), ...delta }), /invalid fixture input/);
  });
}
