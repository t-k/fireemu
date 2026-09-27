import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";

import { SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import { TASK_ID, limitedFetch } from "./auth-federation/hosting.mjs";
import {
  approvedAttempts,
  attemptRefusal,
  guardSamlSignIn,
  LIMITS,
  samlRecover,
  samlRunToRecover,
  samlSmoke,
  scriptDigest,
  SOURCES,
} from "./auth-federation/saml-smoke.mjs";

const RUN = "a1b2c3";
const PROVIDER = `saml.fireemu-${RUN}-s`;
const CERT_BODY = "MIIBfakeCERTa1b2c3";
const CERT = `-----BEGIN CERTIFICATE-----\n${CERT_BODY}\n-----END CERTIFICATE-----\n`;
const CONFIG = JSON.stringify({ name: `projects/${SANDBOX_PROJECT}/config`, signIn: {} });

const reply = (status, body) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), { status });

/**
 * A fake Identity Toolkit. `accept(n)` decides the n-th signInWithIdp (0-based); `overrides`
 * replace named answers.
 */
function fakeToolkit({ accept = (n) => n > 0, overrides = {} } = {}) {
  const calls = [];
  const state = { provider: false, users: [], signIns: 0, requests: 0, config: CONFIG };
  const answer = (name, fallback) => (overrides[name] ? overrides[name](state) : fallback());
  const fetchImpl = async (url, init = {}) => {
    const method = init.method ?? "GET";
    const body = init.body === undefined ? undefined : JSON.parse(init.body);
    calls.push({ method, url, body, headers: init.headers ?? {} });
    const { pathname } = new URL(url);
    if (pathname.endsWith("/config")) return answer("config", () => reply(200, state.config));
    if (pathname.endsWith("/inboundSamlConfigs") && method === "GET") {
      return answer("list", () =>
        reply(200, {
          inboundSamlConfigs: state.provider
            ? [{ name: `projects/${SANDBOX_PROJECT}/inboundSamlConfigs/${PROVIDER}` }]
            : [],
        }),
      );
    }
    if (pathname.endsWith("/inboundSamlConfigs") && method === "POST") {
      return answer("create", () => {
        state.provider = true;
        return reply(200, { name: PROVIDER });
      });
    }
    if (pathname.endsWith(`/inboundSamlConfigs/${PROVIDER}`)) {
      if (method === "DELETE") {
        const had = state.provider;
        state.provider = false;
        return reply(had ? 200 : 404, {});
      }
      return reply(state.provider ? 200 : 404, {});
    }
    if (pathname.endsWith("accounts:batchGet")) {
      return answer("accounts", () => reply(200, state.users.length ? { users: state.users } : {}));
    }
    if (pathname.endsWith("accounts:delete")) {
      state.users = state.users.filter((user) => user.localId !== body.localId);
      return reply(200, {});
    }
    if (pathname.endsWith("accounts:createAuthUri")) {
      state.requests += 1;
      const id = `_req-${state.requests}`;
      const saml = deflateRawSync(Buffer.from(`<samlp:AuthnRequest ID="${id}"/>`)).toString(
        "base64",
      );
      return reply(200, {
        authUri: `https://${SANDBOX_PROJECT}.web.app/saml/${RUN}/sso?SAMLRequest=${encodeURIComponent(saml)}&RelayState=rs-${state.requests}`,
        sessionId: `session-${state.requests}`,
      });
    }
    if (pathname.endsWith("accounts:signInWithIdp")) {
      const n = state.signIns;
      state.signIns += 1;
      if (!accept(n)) return reply(400, { error: { message: "INVALID_IDP_RESPONSE" } });
      if (!state.users.length) {
        state.users.push({ localId: "local-1", providerUserInfo: [{ providerId: PROVIDER }] });
      }
      return reply(200, { localId: "local-1", idToken: "a.b.c", providerId: PROVIDER });
    }
    return reply(500, { unexpected: `${method} ${url}` });
  };
  return { fetchImpl, calls, state };
}

const KEYS = generateKeyPairSync("rsa", { modulusLength: 2048 });

function signer() {
  return { privateKey: KEYS.privateKey, certificatePem: CERT };
}

/**
 * Whether the first signature of a response verifies with the run's key. Each element of
 * SignedInfo carries at most one attribute, so its canonical form is the document's text with
 * the inherited ds namespace declared on it.
 */
function signatureVerifies(xml) {
  const signedInfo = /<ds:SignedInfo>[\s\S]*?<\/ds:SignedInfo>/
    .exec(xml)[0]
    .replace("<ds:SignedInfo>", '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">');
  const value = /<ds:SignatureValue>([^<]*)</.exec(xml)[1];
  return verify("sha256", Buffer.from(signedInfo), KEYS.publicKey, Buffer.from(value, "base64"));
}

async function smoke(fake, extra = {}) {
  const ledger = [];
  const { call, used } = limitedFetch(fake.fetchImpl, { run: RUN, limits: LIMITS });
  const result = await samlSmoke({
    api: call,
    run: RUN,
    signer: signer(),
    attempt: 1,
    now: () => 1_800_000_000,
    stop: { check() {} },
    meta: {
      adminToken: "admin-token",
      apiKey: "fake-api-key",
      projectNumber: "123456789012",
      gitSha: "abc",
      digest: "d".repeat(64),
    },
    appendLedger: async (entry) => ledger.push(entry),
    ...extra,
  }).catch((error) => ({ thrown: error }));
  return { ...result, ledger, used };
}

const signInCalls = (fake) => fake.calls.filter(({ url }) => url.includes("signInWithIdp"));
const samlOf = (call) =>
  Buffer.from(new URLSearchParams(call.body.postBody).get("SAMLResponse"), "base64").toString();

test("a feasible smoke signs in with each signature position and removes what it made", async () => {
  const fake = fakeToolkit();
  const { entry, recorded, ledger, used } = await smoke(fake);
  assert.equal(entry.outcome, "smoke-passed", JSON.stringify(entry));
  assert.equal(entry.feasible, true);
  assert.deepEqual(Object.keys(entry.rows), [
    "create-provider",
    "tampered-auth-uri",
    "tampered",
    "assertion-signed-auth-uri",
    "assertion-signed",
    "response-signed-auth-uri",
    "response-signed",
    "both-signed-auth-uri",
    "both-signed",
  ]);
  assert.deepEqual(entry.rows.tampered, { status: 400, error: "INVALID_IDP_RESPONSE" });
  // Each response answers its own AuthnRequest and carries only the run's certificate.
  const signIns = signInCalls(fake);
  signIns.forEach((call, index) => {
    const xml = samlOf(call);
    assert.match(xml, new RegExp(`InResponseTo="_req-${index + 1}"`));
    assert.equal(call.body.sessionId, `session-${index + 1}`);
    assert.equal(new URLSearchParams(call.body.postBody).get("RelayState"), `rs-${index + 1}`);
    assert.ok([...xml.matchAll(/<ds:X509Certificate>([^<]*)</g)].every((m) => m[1] === CERT_BODY));
    assert.equal(call.headers.authorization, undefined, "client calls carry no admin token");
    assert.match(call.url, /[?&]key=fake-api-key/);
  });
  assert.equal((samlOf(signIns[3]).match(/<ds:Signature /g) ?? []).length, 2);
  // Only the tampered row carries a signature that does not verify.
  assert.deepEqual(
    signIns.map((call) => signatureVerifies(samlOf(call))),
    [false, true, true, true],
  );
  // Nothing writes the config; the provider and the account are gone and read back.
  assert.ok(!fake.calls.some(({ method, url }) => method !== "GET" && url.endsWith("/config")));
  assert.equal(entry.providerReadBack, 404);
  assert.deepEqual(entry.providersLeft, []);
  assert.equal(entry.accountsLeft, 0);
  assert.equal(entry.configUnchanged, true);
  assert.deepEqual(entry.accountsDeleted, [200]);
  // The started line holds the config's digest, never the config.
  assert.equal(ledger[0].event, "started");
  assert.equal(ledger[0].configDigestBefore, createHash("sha256").update(CONFIG).digest("hex"));
  assert.ok(!JSON.stringify(ledger).includes("signIn"));
  assert.ok(used.api <= LIMITS.api, JSON.stringify(used));
  // The recording keeps no token.
  assert.ok(!JSON.stringify(recorded).includes("a.b.c"));
});

test("an unaccepted signed response ends the smoke after two sign-ins, cleaned", async () => {
  const fake = fakeToolkit({ accept: () => false });
  const { entry } = await smoke(fake);
  assert.equal(entry.outcome, "failed-cleaned");
  assert.equal(entry.feasible, false);
  assert.equal(signInCalls(fake).length, 2);
  assert.equal(entry.providerReadBack, 404);
});

test("a provider create whose answer is lost is still deleted and read back", async () => {
  const fake = fakeToolkit({
    overrides: {
      create: (state) => {
        state.provider = true;
        throw new TypeError("fetch failed");
      },
    },
  });
  const { entry } = await smoke(fake);
  assert.equal(entry.outcome, "failed-cleaned", JSON.stringify(entry));
  assert.equal(entry.providerDelete, 200);
  assert.equal(entry.providerReadBack, 404);
});

test("a changed config or an account left needs recovery", async () => {
  let reads = 0;
  const changed = fakeToolkit({
    overrides: {
      config: () => reply(200, (reads += 1) === 1 ? CONFIG : `${CONFIG} `),
    },
  });
  assert.equal((await smoke(changed)).entry.outcome, "needs-recovery");
  const kept = fakeToolkit({
    overrides: {
      accounts: (state) => reply(200, state.signIns ? { users: [{ localId: "other" }] } : {}),
    },
  });
  const left = await smoke(kept);
  assert.equal(left.entry.outcome, "needs-recovery");
  assert.equal(left.entry.accountsLeft, 1);
});

test("prechecks stop before the started line on a provider or account left", async () => {
  for (const overrides of [
    {
      list: () =>
        reply(200, {
          inboundSamlConfigs: [
            { name: `projects/${SANDBOX_PROJECT}/inboundSamlConfigs/saml.fireemu-d4e5f6-s` },
          ],
        }),
    },
    { accounts: () => reply(200, { users: [{ localId: "someone" }] }) },
    { config: () => reply(403, {}) },
  ]) {
    const fake = fakeToolkit({ overrides });
    const { thrown, ledger } = await smoke(fake);
    assert.ok(thrown);
    assert.deepEqual(ledger, []);
    assert.ok(fake.calls.every(({ method }) => method === "GET"));
  }
});

test("attempts: owner-approved, the second by hand after a cleaned first, never a third", async () => {
  const digest = await scriptDigest();
  const line = (extra = "") =>
    `- 2026-09-27 | AUTH-FEDERATION | saml-smoke APPROVED ${digest}${extra} | オーナー（直接の返答「承認」） | x`;
  assert.equal(approvedAttempts(line(), digest), 1);
  assert.equal(approvedAttempts(line("（attempts 2）"), digest), 2);
  assert.equal(approvedAttempts(line().replace("オーナー", "Claude"), digest), 0);
  assert.equal(approvedAttempts(line().replace("saml-smoke", "hosting-smoke"), digest), 0);
  assert.ok(SOURCES.some((path) => path.endsWith("/auth-account/harness.mjs")));
  const entry = (extra) =>
    JSON.stringify({
      ts: "t",
      project: SANDBOX_PROJECT,
      taskId: TASK_ID,
      action: "saml-smoke",
      ...extra,
    });
  assert.equal(attemptRefusal("", 1), undefined);
  assert.match(attemptRefusal("", 2), /exactly one earlier attempt/);
  const cleaned = entry({ outcome: "failed-cleaned" });
  assert.match(attemptRefusal(cleaned, 1), /already ran/);
  assert.equal(attemptRefusal(cleaned, 2), undefined);
  assert.match(attemptRefusal(entry({ outcome: "smoke-passed" }), 2), /not failed-cleaned/);
  assert.match(attemptRefusal(`${cleaned}\n${cleaned}`, 2), /exactly one/);
  assert.match(attemptRefusal(cleaned, 3), /not 1 or 2/);
});

test("a sign-in is refused before sending when its response carries another certificate", () => {
  const ctx = {
    project: SANDBOX_PROJECT,
    run: RUN,
    target: { kind: "production" },
    runKids: [],
    runCertificates: [CERT_BODY],
    defaultIdpWrites: [],
  };
  const body = (certificate) =>
    JSON.stringify({
      requestUri: `https://${SANDBOX_PROJECT}.firebaseapp.com/__/auth/handler`,
      postBody: new URLSearchParams({
        SAMLResponse: Buffer.from(
          `<x><ds:X509Certificate>${certificate}</ds:X509Certificate></x>`,
        ).toString("base64"),
      }).toString(),
    });
  const url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithIdp?key=k";
  assert.doesNotThrow(() => guardSamlSignIn(url, body(CERT_BODY), ctx));
  assert.throws(() => guardSamlSignIn(url, body("MIIBsomeoneelse"), ctx), /did not make/);
  assert.throws(
    () => guardSamlSignIn(url, JSON.stringify({ postBody: "SAMLResponse=" }), ctx),
    /did not make/,
  );
});

test("recover deletes the run's provider and its accounts and checks the config digest", async () => {
  const line = (extra) =>
    JSON.stringify({ ts: "t", project: SANDBOX_PROJECT, taskId: TASK_ID, ...extra });
  const configDigestBefore = createHash("sha256").update(CONFIG).digest("hex");
  const started = line({
    event: "started",
    action: "saml-smoke",
    run: RUN,
    scriptDigest: "d".repeat(64),
    configDigestBefore,
  });
  assert.deepEqual(samlRunToRecover(started), {
    run: RUN,
    digest: "d".repeat(64),
    configDigestBefore,
  });
  assert.equal(
    samlRunToRecover(
      `${started}\n${line({ action: "saml-smoke", run: RUN, outcome: "failed-cleaned" })}`,
    ),
    undefined,
  );
  assert.ok(
    samlRunToRecover(
      `${started}\n${line({ action: "saml-recover", run: RUN, outcome: "needs-recovery" })}`,
    ),
  );

  const fake = fakeToolkit();
  fake.state.provider = true;
  fake.state.users = [
    { localId: "local-1", providerUserInfo: [{ providerId: PROVIDER }] },
    { localId: "unrelated", providerUserInfo: [{ providerId: "password" }] },
  ];
  const ledger = [];
  const { call } = limitedFetch(fake.fetchImpl, { run: RUN, limits: LIMITS });
  const recover = (digest) =>
    samlRecover({
      api: call,
      run: RUN,
      meta: { adminToken: "admin-token" },
      appendLedger: async (entry) => ledger.push(entry),
      configDigestBefore: digest,
    });
  const entry = await recover(configDigestBefore);
  assert.equal(entry.outcome, "recovered", JSON.stringify(entry));
  assert.deepEqual(
    fake.state.users.map((user) => user.localId),
    ["unrelated"],
  );
  assert.equal(entry.providerReadBack, 404);
  // A config that differs from its digest, or a read that fails, stays for the owner.
  assert.equal((await recover("0".repeat(64))).outcome, "needs-recovery");
  const broken = fakeToolkit({ overrides: { accounts: () => reply(503, {}) } });
  const { call: brokenCall } = limitedFetch(broken.fetchImpl, { run: RUN, limits: LIMITS });
  const failed = await samlRecover({
    api: brokenCall,
    run: RUN,
    meta: { adminToken: "admin-token" },
    appendLedger: async (recorded) => ledger.push(recorded),
    configDigestBefore,
  });
  assert.equal(failed.outcome, "needs-recovery");
  assert.match(failed.error, /accounts read: 503/);
  assert.ok(ledger.every((recorded) => recorded.action === "saml-recover"));
  assert.ok(!fake.calls.some(({ method, url }) => method !== "GET" && url.endsWith("/config")));
});
