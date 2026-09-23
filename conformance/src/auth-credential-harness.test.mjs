import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { test } from "node:test";

import { createContext } from "./auth-account/harness.mjs";
import { PROGRAMS } from "./auth-credential/corpus.mjs";
import {
  SIGNER_ACCOUNTS,
  guardCredentialRequest,
  harnessRequest,
  validateCredentialCorpus,
} from "./auth-credential/harness.mjs";
import { materialize } from "./auth-credential/session.mjs";
import {
  CUSTOM_TOKEN_AUDIENCE,
  customTokenClaims,
  decodeJwt,
  describeJwt,
  normalizeCredentialResponse,
  relate,
  signLocally,
  tamper,
  tokenPath,
} from "./auth-credential/tokens.mjs";

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (header, claims, signature = "c2ln") => `${b64(header)}.${b64(claims)}.${signature}`;

const local = createContext({
  run: "1790000000000",
  project: "fireemu-oracle-idp",
  target: { kind: "local", origin: "http://127.0.0.1:32297", projectNumber: "123456789012" },
  startedMs: 1_790_000_000_000,
});

test("a JWT is recorded as header shape and claims relative to its own iat", () => {
  const token = jwt(
    { alg: "RS256", kid: "abc", typ: "JWT" },
    {
      iss: "https://securetoken.google.com/fireemu-oracle-idp",
      aud: "fireemu-oracle-idp",
      auth_time: 1_790_000_010,
      user_id: "ztoT8ScH0cerjrt7nKyEvHAkd9s2",
      sub: "ztoT8ScH0cerjrt7nKyEvHAkd9s2",
      iat: 1_790_000_012,
      exp: 1_790_003_612,
      role: "admin",
    },
  );
  const recorded = normalizeCredentialResponse(
    200,
    JSON.stringify({ idToken: token, refreshToken: "AMf-xyz", expiresIn: "3600" }),
    local,
  );
  assert.deepEqual(recorded, {
    status: 200,
    body: {
      idToken: {
        "<jwt>": {
          header: { alg: "RS256", kid: "<present>", typ: "JWT" },
          signature: "<present>",
          claims: {
            iss: "https://securetoken.google.com/demo-auth-account",
            aud: "demo-auth-account",
            auth_time: "before-iat",
            user_id: "<generated-localId>",
            sub: "<generated-localId>",
            iat: "<iat>",
            exp: "iat+3600",
            role: "admin",
          },
        },
      },
      refreshToken: "<refreshToken>",
      expiresIn: "3600",
    },
  });
});

test("a header without kid or typ and an unsigned token are recorded as such", () => {
  const described = describeJwt(`${b64({ alg: "none" })}.${b64({ iat: 5, exp: 5 })}.`);
  assert.deepEqual(described, {
    header: { alg: "none", kid: "<absent>", typ: "<absent>" },
    signature: "<absent>",
    claims: { iat: "<iat>", exp: "iat" },
  });
  assert.equal(describeJwt("not-a-jwt"), undefined);
  assert.equal(
    normalizeCredentialResponse(200, '{"idToken":"garbage"}', local).body.idToken,
    "<idToken>",
  );
});

test("relations compare seconds and identity, never wall-clock values", () => {
  assert.equal(relate("time", 10, 10), "equal");
  assert.equal(relate("time", "9", 10), "earlier");
  assert.equal(relate("time", 11, 10), "later");
  assert.equal(relate("same", "a", "a"), "same");
  assert.equal(relate("same", "a", "b"), "different");
  assert.equal(relate("time", undefined, 1), "missing");
  assert.equal(relate("time", "x", 1), "not-a-time");
});

test("token paths descend into a JWT's claims", () => {
  const token = jwt({ alg: "RS256" }, { auth_time: 7, nested: { a: 1 } });
  assert.equal(tokenPath({ idToken: token }, "idToken.auth_time"), 7);
  assert.equal(tokenPath({ idToken: token }, "idToken.nested.a"), 1);
  assert.equal(tokenPath({ users: [{ validSince: "8" }] }, "users.0.validSince"), "8");
  assert.equal(tokenPath({ idToken: "garbage" }, "idToken.iat"), undefined);
});

test("tampering changes exactly the declared part", () => {
  const token = jwt(
    { alg: "RS256", kid: "k" },
    { uid: "u" },
    Buffer.alloc(8, 1).toString("base64url"),
  );
  const [h, p, s] = token.split(".");
  const flipped = tamper(token, "signature").split(".");
  assert.deepEqual([flipped[0], flipped[1]], [h, p]);
  assert.notEqual(flipped[2], s);
  assert.equal(tamper(token, "strip-signature"), `${h}.${p}.`);
  assert.equal(decodeJwt(tamper(token, "alg-none")).header.alg, "none");
  const changed = tamper(token, "payload").split(".");
  assert.equal(changed[0], h);
  assert.equal(changed[2], s);
  assert.equal(decodeJwt(changed.join(".")).claims.fireemu_tampered, true);
});

test("custom-token claims follow the Admin SDK layout with declared overrides", () => {
  const claims = customTokenClaims(
    { uid: "UID(x)", claims: { role: "r" }, iatOffset: 10, lifetime: 60 },
    "sa@p.iam.gserviceaccount.com",
    1000,
    (t) => t.replace("UID(x)", "aa-1-x"),
  );
  assert.deepEqual(claims, {
    iss: "sa@p.iam.gserviceaccount.com",
    sub: "sa@p.iam.gserviceaccount.com",
    aud: CUSTOM_TOKEN_AUDIENCE,
    iat: 1010,
    exp: 1070,
    uid: "aa-1-x",
    claims: { role: "r" },
  });
  const trimmed = customTokenClaims({ omit: ["exp"], set: { uid: 5 } }, "s", 1, (t) => t);
  assert.deepEqual(trimmed, { iss: "s", sub: "s", aud: CUSTOM_TOKEN_AUDIENCE, iat: 1, uid: 5 });
});

test("a locally signed custom token verifies with its public key", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const token = signLocally(
    { uid: "u" },
    privateKey.export({ type: "pkcs8", format: "pem" }),
    "kid1",
  );
  const [h, p, s] = token.split(".");
  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${h}.${p}`);
  assert.equal(verifier.verify(publicKey, Buffer.from(s, "base64url")), true);
  assert.deepEqual(decodeJwt(token).header, { alg: "RS256", kid: "kid1", typ: "JWT" });
});

test("materialize resolves token forms before the request builder sees the value", () => {
  const idToken = jwt({ alg: "RS256" }, { auth_time: 100 });
  const raw = new Map([["sign-up", { idToken, refreshToken: "AMf-0123456789" }]]);
  const tokens = new Map([["t", idToken]]);
  assert.deepEqual(
    materialize(
      {
        at: { $from: "sign-up:idToken.auth_time" },
        next: { $string: { $sum: [{ $from: "sign-up:idToken.auth_time" }, 1] } },
        token: { $token: "t" },
        stripped: { $token: "t", tamper: "strip-signature" },
        chopped: { $chop: "sign-up:refreshToken", drop: 4 },
        plain: "EMAIL(x)",
      },
      raw,
      tokens,
    ),
    {
      at: 100,
      next: "101",
      token: idToken,
      stripped: tamper(idToken, "strip-signature"),
      chopped: "AMf-012345",
      plain: "EMAIL(x)",
    },
  );
  assert.throws(() => materialize({ $from: "sign-up:nothing" }, raw, tokens), /recorded nothing/);
});

test("the guard admits reviewed families only and never another project", () => {
  const request = (path, body, auth = {}) => ({
    url: `http://127.0.0.1:32297/identitytoolkit.googleapis.com/${path}`,
    init: {
      method: "POST",
      headers: { "content-type": "application/json", ...auth },
      body: JSON.stringify(body),
    },
  });
  guardCredentialRequest(request("v1/projects/fireemu-oracle-idp:createSessionCookie", {}), local);
  guardCredentialRequest(request("v1/accounts:signInWithCustomToken", { token: "x" }), local);
  assert.throws(
    () => guardCredentialRequest(request("v1/projects/other:createSessionCookie", {}), local),
    /reviewed family/,
  );
  assert.throws(
    () =>
      guardCredentialRequest(
        request("v1/projects/fireemu-oracle-idp/accounts:batchDelete", {}),
        local,
      ),
    /reviewed family/,
  );
  guardCredentialRequest(
    request("v1/projects/fireemu-oracle-idp/accounts:batchDelete", {}),
    local,
    {
      harness: true,
    },
  );
  assert.throws(
    () => guardCredentialRequest(request("v1/accounts:sendOobCode", {}), local),
    /reviewed family/,
  );
  assert.throws(
    () => guardCredentialRequest(request("v1/accounts:signUp", { email: "a@gmail.com" }), local),
    /outside example.com/,
  );
  assert.throws(
    () =>
      guardCredentialRequest(request("v1/accounts:lookup", { targetProjectId: "other" }), local),
    /another project/,
  );
  assert.throws(
    () =>
      guardCredentialRequest(
        request("v1/accounts:sendVerificationCode", { phoneNumber: "+15551234567" }),
        local,
      ),
    /test phone/,
  );
});

test("signJwt goes only to a reviewed signer and only from production", () => {
  const production = createContext({
    run: "1",
    project: "fireemu-oracle-idp",
    target: {
      kind: "production",
      apiKey: "k",
      adminToken: "t",
      quotaProject: "fireemu-oracle-idp",
      projectNumber: "1234",
    },
  });
  const { url } = harnessRequest.signJwt(production, SIGNER_ACCOUNTS.project, { uid: "u" });
  assert.match(
    url,
    /^https:\/\/iamcredentials\.googleapis\.com\/v1\/projects\/-\/serviceAccounts\//,
  );
  assert.throws(
    () => harnessRequest.signJwt(production, "x@evil.iam.gserviceaccount.com", {}),
    /reviewed signer/,
  );
  assert.throws(
    () => harnessRequest.signJwt(local, SIGNER_ACCOUNTS.project, {}),
    /production-only/,
  );
  assert.throws(() => harnessRequest.advanceClock(production, 1), /fireemu-only/);
});

test("the corpus passes its own validation and waits only in its last program", () => {
  assert.ok(validateCredentialCorpus(PROGRAMS) > 0);
  const waiting = PROGRAMS.filter(({ steps }) => steps.some((s) => s.waitSeconds));
  assert.deepEqual(
    waiting.map(({ id }) => id),
    [PROGRAMS.at(-1).id],
  );
  const moved = [PROGRAMS.at(-1), ...PROGRAMS.slice(0, -1)];
  assert.throws(() => validateCredentialCorpus(moved), /only the last program may wait/);
});
