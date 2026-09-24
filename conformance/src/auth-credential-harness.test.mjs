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
import { recentAbort } from "./auth-credential/run.mjs";
import { createSession, materialize, runCorpus } from "./auth-credential/session.mjs";
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
          subIsUserId: true,
          claims: {
            iss: "https://securetoken.google.com/demo-auth-account",
            aud: "demo-auth-account",
            auth_time: "<auth_time>",
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
  // A verification mail only for the account behind a token, never to a named address.
  guardCredentialRequest(
    request("v1/accounts:sendOobCode", { requestType: "VERIFY_EMAIL", idToken: "t" }),
    local,
  );
  for (const body of [
    {},
    { requestType: "PASSWORD_RESET", email: "a@example.com" },
    { requestType: "VERIFY_EMAIL", idToken: "t", email: "a@example.com" },
  ]) {
    assert.throws(
      () => guardCredentialRequest(request("v1/accounts:sendOobCode", body), local),
      /VERIFY_EMAIL/,
    );
  }
  guardCredentialRequest(
    request("v2/accounts/mfaEnrollment:start", { idToken: "t", totpEnrollmentInfo: {} }),
    local,
  );
  assert.throws(
    () => guardCredentialRequest(request("v2/accounts/mfaEnrollment:finalize", {}), local),
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

test("auth_time is never recorded against the token's own iat, so latency is not compared", () => {
  const at = (authTime) =>
    describeJwt(jwt({ alg: "RS256" }, { iat: 100, exp: 3700, auth_time: authTime })).claims;
  assert.deepEqual(at(100), at(97));
  assert.equal(at(100).auth_time, "<auth_time>");
  assert.equal(at(100).exp, "iat+3600");
});

test("a numeric project number and an undecodable token never reach the recording", () => {
  const token = jwt({ alg: "RS256" }, { iat: 1, project_number: 123456789012 });
  const recorded = normalizeCredentialResponse(
    200,
    JSON.stringify({ idToken: token, sessionCookie: "eyJhbGciOi.broken" }),
    local,
  );
  assert.equal(recorded.body.idToken["<jwt>"].claims.project_number, "<project-number>");
  assert.equal(recorded.body.sessionCookie, "<undecodable-jwt>");
});

const productionContext = (refresh) =>
  createContext({
    run: "1",
    project: "fireemu-oracle-idp",
    target: {
      kind: "production",
      apiKey: "k",
      adminToken: "t",
      quotaProject: "fireemu-oracle-idp",
      projectNumber: "1234",
      refresh,
    },
  });

async function withFetch(handler, body) {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => handler(String(url), init);
  try {
    return await body();
  } finally {
    globalThis.fetch = original;
  }
}

const json = (value, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });

test("a signer that signs other claims than requested stops the run", async () => {
  const ctx = productionContext();
  const session = createSession(ctx, {
    signers: { project: { serviceAccount: SIGNER_ACCOUNTS.project } },
  });
  await withFetch(
    (url, init) => {
      if (url.includes(":signJwt")) {
        const requested = JSON.parse(JSON.parse(init.body).payload);
        return json({ signedJwt: jwt({ alg: "RS256" }, { ...requested, exp: 1 }) });
      }
      return json({ users: [] });
    },
    () =>
      assert.rejects(
        session.runProgram({ id: "p", tokens: { t: { uid: "u", omit: ["exp"] } }, steps: [] }),
        (error) => error.fatal && /other than the requested/.test(error.message),
      ),
  );
});

test("an owner credential that cannot be renewed stops the whole run", async () => {
  const ctx = productionContext(async () => {
    throw new Error("reauthentication required");
  });
  await withFetch(
    () => json({ users: [] }),
    () =>
      assert.rejects(
        runCorpus(
          [
            { id: "a", steps: [] },
            { id: "b", steps: [] },
          ],
          ctx,
        ),
        (error) => error.fatal && /credential refresh failed/.test(error.message),
      ),
  );
});

test("the expiry program asks everything of the live account before deleting it", () => {
  const expiry = PROGRAMS.find(({ id }) => id === "auth-credential/expiry/one-hour");
  const ids = expiry.steps.map(({ id }) => id);
  assert.equal(ids.indexOf("delete-expired"), ids.length - 2);
  assert.ok(ids.indexOf("refresh-after-hour") < ids.indexOf("delete-expired"));
  const waited = expiry.steps.reduce((total, step) => total + (step.waitSeconds ?? 0), 0);
  assert.ok(waited > 3600, "past exp");
  // The edge of the allowance is reached exactly, then passed.
  const edges = expiry.steps.filter((step) => step.waitUntil).map((step) => step.waitUntil.plus);
  assert.deepEqual(edges, [299, 300, 299, 300]);
  const edge = ids.indexOf("lookup-at-exp-plus-300");
  assert.ok(edge < ids.indexOf("lookup-expired-later"));
});

test("every validSince later than a session's auth_time is written after a second boundary", () => {
  const laterValidSince = (step) => {
    const sum = step.body?.validSince?.$string?.$sum;
    return Array.isArray(sum) && sum.some((term) => typeof term === "number" && term > 0);
  };
  const steps = PROGRAMS.flatMap(({ steps: all }) => all).filter(laterValidSince);
  assert.ok(steps.length > 0);
  for (const step of steps.filter(({ id }) => id !== "valid-since-future")) {
    assert.ok((step.delayMs ?? 0) >= 1100, step.id);
  }
});

test("a run is refused within an hour of this task's last aborted run", () => {
  const line = (outcome, ts, taskId = "AUTH-CREDENTIAL-SANDBOX") =>
    JSON.stringify({ ts, outcome, taskId });
  const now = Date.parse("2026-09-24T12:00:00Z");
  const ledger = (...lines) => `${lines.join("\n")}\n`;
  assert.ok(recentAbort(ledger(line("aborted-fatal", "2026-09-24T11:30:00Z")), now));
  assert.equal(recentAbort(ledger(line("aborted", "2026-09-24T10:59:00Z")), now), undefined);
  assert.equal(
    recentAbort(
      ledger(line("aborted", "2026-09-24T11:30:00Z"), line("recorded", "2026-09-24T11:40:00Z")),
      now,
    ),
    undefined,
  );
  assert.equal(
    recentAbort(ledger(line("aborted", "2026-09-24T11:30:00Z", "AUTH-ACCOUNT-SANDBOX")), now),
    undefined,
  );
});

test("an answer records whether its token's sub is the account it names", () => {
  const token = jwt({ alg: "RS256" }, { iat: 1, sub: "u1", user_id: "u1" });
  const other = jwt({ alg: "RS256" }, { iat: 1, sub: "u2", user_id: "u1" });
  const named = normalizeCredentialResponse(
    200,
    JSON.stringify({ localId: "u1", idToken: token }),
    local,
  );
  assert.equal(named.body.idToken["<jwt>"].subIsLocalId, true);
  assert.equal(named.body.idToken["<jwt>"].subIsUserId, true);
  const refresh = normalizeCredentialResponse(
    200,
    JSON.stringify({ user_id: "u1", id_token: other }),
    local,
  );
  assert.equal(refresh.body.id_token["<jwt>"].subIsLocalId, false);
  assert.equal(refresh.body.id_token["<jwt>"].subIsUserId, false);
  const unnamed = normalizeCredentialResponse(200, JSON.stringify({ sessionCookie: token }), local);
  assert.equal(unnamed.body.sessionCookie["<jwt>"].subIsLocalId, undefined);
});

test("fireemu's clock moves to an absolute instant for a timed step", () => {
  const withControl = {
    ...local,
    target: { ...local.target, control: { url: "http://127.0.0.1:9/v1/", token: "c" } },
  };
  const { url, init } = harnessRequest.advanceClockTo(
    withControl,
    Date.parse("2026-09-24T00:00:00.300Z"),
  );
  assert.equal(url, "http://127.0.0.1:9/v1/sessions/default/clock:advanceTo");
  assert.deepEqual(JSON.parse(init.body), { instant: "2026-09-24T00:00:00.300Z" });
  assert.equal(init.headers.authorization, "Bearer c");
});

test("the corpus check refuses a mis-scoped wait, mail, enrollment or timed reference", () => {
  const step = (extra) => ({ id: "s", path: "v1/accounts:lookup", auth: "key", ...extra });
  const last = (steps, tokens) => [{ id: "only", steps, ...(tokens ? { tokens } : {}) }];
  assert.throws(
    () =>
      validateCredentialCorpus([
        {
          id: "a",
          steps: [step({ waitUntil: { of: "token:t:exp", plus: 1 } })],
          tokens: { t: {} },
        },
        { id: "b", steps: [] },
      ]),
    /only the last program may wait/,
  );
  assert.throws(
    () =>
      validateCredentialCorpus(
        last([
          step({
            path: "v1/accounts:sendOobCode",
            body: { requestType: "PASSWORD_RESET", email: "EMAIL(x)" },
          }),
        ]),
      ),
    /VERIFY_EMAIL/,
  );
  assert.throws(
    () =>
      validateCredentialCorpus(
        last([
          step({
            path: "v2/accounts/mfaEnrollment:start",
            body: { idToken: "t", phoneEnrollmentInfo: { phoneNumber: "PHONE(0)" } },
          }),
        ]),
      ),
    /empty TOTP enrollment/,
  );
  assert.throws(
    () =>
      validateCredentialCorpus(
        last([step({ waitUntil: { of: "token:missing:exp", plus: 1 } })], { t: {} }),
      ),
    /waitUntil must name/,
  );
  assert.throws(
    () =>
      validateCredentialCorpus(
        last([step({ id: "late", waitUntil: { of: "never:idToken.exp", plus: 1 } })]),
      ),
    /waitUntil must name/,
  );
  assert.ok(
    validateCredentialCorpus(
      last([
        step({ id: "sign-up" }),
        step({ id: "timed", waitUntil: { of: "sign-up:idToken.exp", plus: 299 } }),
      ]),
    ),
  );
});

test("the runtime guard refuses a phone enrollment and a spaced real number", () => {
  const request = (path, body) => ({
    url: `http://127.0.0.1:32297/identitytoolkit.googleapis.com/${path}`,
    init: {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    },
  });
  guardCredentialRequest(
    request("v2/accounts/mfaEnrollment:start", { idToken: "t", totpEnrollmentInfo: {} }),
    local,
  );
  assert.throws(
    () =>
      guardCredentialRequest(
        request("v2/accounts/mfaEnrollment:start", { idToken: "t", phoneEnrollmentInfo: {} }),
        local,
      ),
    /empty totpEnrollmentInfo/,
  );
  assert.throws(
    () =>
      guardCredentialRequest(
        request("v1/accounts:update", { displayName: "+1 (555) 123-4567" }),
        local,
      ),
    /test phone/,
  );
});

test("an enrollment secret is masked and the fixture scan refuses one", async () => {
  const { scanFixture } = await import("./auth-account/fixture-scan.mjs");
  const recorded = normalizeCredentialResponse(
    200,
    JSON.stringify({ totpSessionInfo: { sharedSecretKey: "JBSWY3DPEHPK3PXP" } }),
    local,
  );
  assert.equal(recorded.body.totpSessionInfo.sharedSecretKey, "<sharedSecretKey>");
  scanFixture(JSON.stringify(recorded), []);
  assert.throws(() => scanFixture('{"sharedSecretKey": "JBSWY3DPEHPK3PXP"}', []), /TOTP secret/);
});

test("a legacy token records whether its user_id is the account the answer names", () => {
  const legacy = jwt({ alg: "RS256" }, { iat: 1, user_id: "u1" });
  const recorded = normalizeCredentialResponse(
    200,
    JSON.stringify({ localId: "u1", idToken: legacy }),
    local,
  );
  assert.equal(recorded.body.idToken["<jwt>"].userIdIsLocalId, true);
  assert.equal(recorded.body.idToken["<jwt>"].subIsLocalId, undefined);
});

test("production records only with a second factor disabled", async () => {
  const { mfaDisabled } = await import("./auth-credential/run.mjs");
  assert.equal(mfaDisabled(undefined), true);
  assert.equal(mfaDisabled({ state: "DISABLED" }), true);
  assert.equal(mfaDisabled({ state: "ENABLED" }), false);
  assert.equal(mfaDisabled({ state: "DISABLED", providerConfigs: [{ state: "ENABLED" }] }), false);
  assert.equal(mfaDisabled({ providerConfigs: [{ state: "DISABLED" }] }), true);
});

test("a timed step moves fireemu's clock to the named instant plus 300 ms", async () => {
  const ctx = {
    ...local,
    target: { ...local.target, control: { url: "http://127.0.0.1:9/v1/", token: "c" } },
  };
  const idToken = jwt({ alg: "RS256" }, { iat: 100, exp: 3700, sub: "u" });
  const clock = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes("clock:advanceTo")) {
      clock.push(JSON.parse(init.body).instant);
      return new Response("{}", { status: 200 });
    }
    if (String(url).includes("accounts:batchGet"))
      return new Response('{"users":[]}', { status: 200 });
    return new Response(JSON.stringify({ idToken }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const session = createSession(ctx, {});
    await session.runProgram({
      id: "p",
      steps: [
        { id: "sign-up", path: "v1/accounts:signUp", auth: "key", body: {} },
        {
          id: "edge",
          path: "v1/accounts:lookup",
          auth: "key",
          body: {},
          waitUntil: { of: "sign-up:idToken.exp", plus: 299 },
        },
      ],
    });
  } finally {
    globalThis.fetch = original;
  }
  assert.deepEqual(clock, [new Date((3700 + 299) * 1000 + 300).toISOString()]);
});

test("a program fails before its wait when an earlier answer was indeterminate", async () => {
  const ctx = {
    ...local,
    target: { ...local.target, control: { url: "http://127.0.0.1:9/v1/", token: "c" } },
  };
  let advanced = false;
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("clock:")) advanced = true;
    if (String(url).includes("accounts:batchGet"))
      return new Response('{"users":[]}', { status: 200 });
    return new Response('{"error":{"message":"TOO_MANY_ATTEMPTS_TRY_LATER"}}', { status: 429 });
  };
  try {
    await assert.rejects(
      createSession(ctx, {}).runProgram({
        id: "p",
        steps: [
          { id: "sign-up", path: "v1/accounts:signUp", auth: "key", body: {} },
          { id: "late", path: "v1/accounts:lookup", auth: "key", body: {}, waitSeconds: 3610 },
        ],
      }),
      /sign-up was indeterminate/,
    );
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(advanced, false);
});
