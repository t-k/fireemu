import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, verify } from "node:crypto";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";

import { SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import { TASK_ID, limitedFetch } from "./auth-federation/hosting.mjs";
import {
  approvedAttempts,
  attemptRefusal,
  configKeyDigests,
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
const NOW = 1_800_000_000;
const CONFIG = JSON.stringify({
  name: `projects/${SANDBOX_PROJECT}/config`,
  signIn: {},
  authorizedDomains: [`${SANDBOX_PROJECT}.firebaseapp.com`, `${SANDBOX_PROJECT}.web.app`],
  subtype: "IDENTITY_PLATFORM",
});

const reply = (status, body, headers = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { date: new Date(NOW * 1000).toUTCString(), ...headers },
  });

/**
 * A fake Identity Toolkit. `accept(n)` decides the n-th signInWithIdp (0-based); `overrides`
 * replace named answers.
 */
function fakeToolkit({
  accept = (n) => n > 0,
  overrides = {},
  authn = (id) => `<samlp:AuthnRequest ID="${id}"/>`,
} = {}) {
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
      if (overrides.deleteAccount) return overrides.deleteAccount(state);
      state.users = state.users.filter((user) => user.localId !== body.localId);
      return reply(200, {});
    }
    if (pathname.endsWith("accounts:createAuthUri")) {
      state.requests += 1;
      const id = `_req-${state.requests}`;
      const saml = deflateRawSync(Buffer.from(authn(id))).toString("base64");
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
  // Member names and digests only: no value of the config reaches the ledger.
  assert.deepEqual(Object.keys(ledger[0].configKeyDigestsBefore), [
    "authorizedDomains",
    "name",
    "signIn",
    "subtype",
  ]);
  assert.ok(!JSON.stringify(ledger).includes("IDENTITY_PLATFORM"));
  assert.ok(used.api <= LIMITS.api, JSON.stringify(used));
  // The recording keeps no token.
  assert.ok(!JSON.stringify(recorded).includes("a.b.c"));
});

test("unaccepted signed responses end the smoke after three sign-ins, cleaned", async () => {
  const fake = fakeToolkit({ accept: () => false });
  const { entry } = await smoke(fake);
  assert.equal(entry.outcome, "failed-cleaned");
  assert.equal(entry.feasible, false);
  // The response-signed row is sent whatever the assertion-signed one answered.
  assert.equal(signInCalls(fake).length, 3);
  assert.ok(signInCalls(fake)[2].body.postBody.length > 0);
  assert.match(
    samlOf(signInCalls(fake)[2]),
    /<samlp:Response[^>]*><saml:Issuer>[^<]*<\/saml:Issuer><ds:Signature /,
  );
  assert.equal(entry.providerReadBack, 404);
});

test("a response-signed acceptance is feasible; an accepted tampered row is not", async () => {
  const responseOnly = fakeToolkit({ accept: (n) => n === 2 || n === 3 });
  const one = await smoke(responseOnly);
  assert.equal(one.entry.outcome, "smoke-passed", JSON.stringify(one.entry));
  assert.equal(one.entry.feasible, true);
  assert.equal(signInCalls(responseOnly).length, 4, "both-signed follows an acceptance");
  const unchecked = fakeToolkit({ accept: () => true });
  const two = await smoke(unchecked);
  assert.equal(two.entry.outcome, "smoke-unexpected");
  assert.equal(two.entry.feasible, false);
  assert.equal(two.entry.tamperedRejected, false);
});

test("a request for another ACS or audience stops its row before any sign-in", async () => {
  for (const authn of [
    (id) =>
      `<samlp:AuthnRequest ID="${id}" AssertionConsumerServiceURL="https://elsewhere.example.test/acs"/>`,
    (id) =>
      `<samlp:AuthnRequest ID="${id}"><saml:Issuer>other-sp</saml:Issuer></samlp:AuthnRequest>`,
  ]) {
    const fake = fakeToolkit({ authn });
    const { entry } = await smoke(fake);
    assert.equal(signInCalls(fake).length, 0);
    assert.equal(entry.outcome, "failed-cleaned");
    assert.match(entry.rows["tampered-auth-uri"].stopped, /another ACS or audience/);
  }
  // The expected ACS and audience are recorded and signed for.
  const expected = fakeToolkit({
    authn: (id) =>
      `<samlp:AuthnRequest ID="${id}" AssertionConsumerServiceURL="https://${SANDBOX_PROJECT}.firebaseapp.com/__/auth/handler"><saml:Issuer>fireemu-${RUN}-sp</saml:Issuer></samlp:AuthnRequest>`,
  });
  const { entry } = await smoke(expected);
  assert.equal(entry.outcome, "smoke-passed");
  assert.deepEqual(entry.rows["tampered-auth-uri"].authnRequest, {
    acs: `https://${SANDBOX_PROJECT}.firebaseapp.com/__/auth/handler`,
    issuer: `fireemu-${RUN}-sp`,
  });
});

test("every cleanup step runs and the rows are kept whatever an earlier step met", async () => {
  const cases = {
    "an account delete that fails": {
      deleteAccount: () => {
        throw new TypeError("fetch failed");
      },
    },
    "a provider list that fails": {
      list: (state) => (state.signIns ? reply(503, {}) : reply(200, { inboundSamlConfigs: [] })),
    },
    "a config read that fails": {
      config: (state) => {
        if (state.signIns) throw new TypeError("fetch failed");
        return reply(200, CONFIG);
      },
    },
  };
  for (const [name, overrides] of Object.entries(cases)) {
    const fake = fakeToolkit({ overrides });
    const { entry, ledger, used } = await smoke(fake);
    assert.equal(entry.outcome, "needs-recovery", name);
    assert.equal(entry.feasible, true, name);
    assert.equal(entry.rows["assertion-signed"].status, 200, name);
    assert.ok(
      fake.calls.some(({ method, url }) => method === "DELETE" && url.includes(PROVIDER)),
      name,
    );
    assert.deepEqual(ledger.at(-1), entry, name);
    assert.ok(used.api <= LIMITS.api, name);
  }
});

test("a delete whose answer is lost is clean when the read-backs confirm it", async () => {
  const fake = fakeToolkit({
    overrides: {
      deleteAccount: (state) => {
        state.users = [];
        throw new TypeError("fetch failed");
      },
    },
  });
  const { entry } = await smoke(fake);
  assert.equal(entry.outcome, "smoke-passed", JSON.stringify(entry));
  assert.match(entry.errors[0], /delete account: fetch failed/);
  assert.equal(entry.accountsLeft, 0);
});

test("a changed config names only its changed members", async () => {
  let reads = 0;
  const changed = fakeToolkit({
    overrides: {
      config: () =>
        reply(
          200,
          (reads += 1) === 1
            ? CONFIG
            : JSON.stringify({ ...JSON.parse(CONFIG), signIn: { secretish: "value-x" } }),
        ),
    },
  });
  const { entry, ledger } = await smoke(changed);
  assert.equal(entry.outcome, "needs-recovery");
  assert.deepEqual(entry.configChangedKeys, ["signIn"]);
  assert.ok(!JSON.stringify(ledger).includes("value-x"));
});

test("the answers are written before the terminal line, and a failure to write is recorded", async () => {
  const order = [];
  const { entry } = await smoke(fakeToolkit(), {
    writeAnswers: async () => order.push("answers"),
    appendLedger: async (line) => order.push(line.event ?? line.outcome),
  });
  assert.deepEqual(order, ["started", "answers", "smoke-passed"]);
  assert.equal(entry.answersWritten, true);
  const failing = await smoke(fakeToolkit(), {
    writeAnswers: async () => {
      throw new Error("disk full");
    },
  });
  assert.equal(failing.entry.answersWritten, false);
  assert.equal(failing.entry.outcome, "smoke-passed");
});

test("the config read first must allow the attempt, or nothing is written", async () => {
  const config = (change) => JSON.stringify({ ...JSON.parse(CONFIG), ...change });
  const cases = {
    "no firebaseapp.com domain": { config: () => reply(200, config({ authorizedDomains: [] })) },
    "a blocking function": {
      config: () =>
        reply(
          200,
          config({ blockingFunctions: { triggers: { beforeSignIn: { functionUri: "x" } } } }),
        ),
    },
    "Firebase Auth only": { config: () => reply(200, config({ subtype: "FIREBASE_AUTH" })) },
    "a clock two minutes off": {
      config: () => reply(200, CONFIG, { date: new Date((NOW + 120) * 1000).toUTCString() }),
    },
  };
  for (const [name, overrides] of Object.entries(cases)) {
    const fake = fakeToolkit({ overrides });
    const { thrown, ledger } = await smoke(fake);
    assert.match(String(thrown?.message), /precheck/, name);
    assert.deepEqual(ledger, [], name);
    assert.ok(
      fake.calls.every(({ method }) => method === "GET"),
      name,
    );
  }
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
  const started = (run) => entry({ event: "started", run });
  const ended = (run, outcome) => entry({ run, outcome });
  const cleaned = `${started("aaaaaa")}\n${ended("aaaaaa", "failed-cleaned")}`;
  assert.match(attemptRefusal(cleaned, 1), /already started/);
  assert.equal(attemptRefusal(cleaned, 2), undefined);
  assert.match(
    attemptRefusal(`${started("aaaaaa")}\n${ended("aaaaaa", "smoke-passed")}`, 2),
    /not failed-cleaned/,
  );
  assert.match(
    attemptRefusal(`${cleaned}\n${started("bbbbbb")}\n${ended("bbbbbb", "failed-cleaned")}`, 2),
    /exactly one/,
  );
  assert.match(attemptRefusal(cleaned, 3), /not 1 or 2/);
  // An attempt that ended in an exception and was recovered still counts: no attempt after it.
  const recovered = `${started("aaaaaa")}\n${JSON.stringify({ ts: "t", project: SANDBOX_PROJECT, taskId: TASK_ID, action: "saml-recover", run: "aaaaaa", outcome: "recovered" })}`;
  assert.match(attemptRefusal(recovered, 1), /already started/);
  assert.match(attemptRefusal(recovered, 2), /without a terminal line/);
  assert.ok(SOURCES.some((path) => path.endsWith("/auth-federation/idp.mjs")));
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
    configKeyDigestsBefore: {},
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
  const recover = (digest, keys = {}) =>
    samlRecover({
      api: call,
      run: RUN,
      meta: { adminToken: "admin-token" },
      appendLedger: async (entry) => ledger.push(entry),
      configDigestBefore: digest,
      configKeyDigestsBefore: keys,
    });
  const entry = await recover(configDigestBefore);
  assert.equal(entry.outcome, "recovered", JSON.stringify(entry));
  assert.deepEqual(
    fake.state.users.map((user) => user.localId),
    ["unrelated"],
  );
  assert.equal(entry.providerReadBack, 404);
  // A config that differs from its digest, or a read that fails, stays for the owner.
  const differs = await recover("0".repeat(64), {
    ...configKeyDigests(CONFIG),
    subtype: "0".repeat(64),
  });
  assert.equal(differs.outcome, "needs-recovery");
  assert.deepEqual(differs.configChangedKeys, ["subtype"]);
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
