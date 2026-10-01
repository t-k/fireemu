import assert from "node:assert/strict";
import { test } from "node:test";

import { SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import { guardHttp, isRunCredential, validateFederationCorpus } from "./auth-federation/guard.mjs";
import { generateSigningKey, signIdToken } from "./auth-federation/idp.mjs";

const RUN = "a1b2c3";
const CHANNEL = `${SANDBOX_PROJECT}--fed-${RUN}-abc123.web.app`;
const production = (extra = {}) => ({
  project: SANDBOX_PROJECT,
  run: RUN,
  target: { kind: "production" },
  runKids: [],
  defaultIdpWrites: [],
  ...extra,
});
const ITK = "https://identitytoolkit.googleapis.com";
const send = (ctx, method, path, body, role = "step") =>
  guardHttp({ url: `${ITK}${path}`, method, body: body && JSON.stringify(body) }, ctx, { role });
const idp = (postBody) => ({
  requestUri: "http://localhost",
  postBody: new URLSearchParams(postBody).toString(),
  returnSecureToken: true,
});

test("only the federation families of the sandbox are reviewed", () => {
  const ctx = production();
  assert.doesNotThrow(() =>
    send(
      ctx,
      "POST",
      "/v1/accounts:signInWithIdp",
      idp({ providerId: "oidc.fireemu-a1b2c3-a", id_token: "fireemu-garbage" }),
    ),
  );
  assert.doesNotThrow(() =>
    send(ctx, "GET", `/admin/v2/projects/${SANDBOX_PROJECT}/oauthIdpConfigs`),
  );
  assert.doesNotThrow(() => send(ctx, "GET", "/v2/defaultSupportedIdps"));
  assert.throws(() => send(ctx, "POST", "/v1/accounts:signUp", {}), /not a reviewed family/);
  assert.throws(() => send(ctx, "POST", "/v1/accounts:sendOobCode", {}), /not a reviewed family/);
  assert.throws(
    () => send(ctx, "GET", "/admin/v2/projects/other-project/oauthIdpConfigs"),
    /not a reviewed family/,
  );
  assert.throws(
    () =>
      guardHttp({ url: "https://evil.example/v1/token", method: "POST" }, ctx, { role: "step" }),
    /not reviewed/,
  );
});

test("provider writes touch only the run's providers and declared default IdPs", () => {
  const ctx = production({ defaultIdpWrites: ["google.com"] });
  const base = `/admin/v2/projects/${SANDBOX_PROJECT}`;
  const oidc = {
    clientId: "c",
    issuer: `https://${SANDBOX_PROJECT}.web.app/oidc/run`,
    enabled: true,
  };
  assert.doesNotThrow(() =>
    send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-a1b2c3-a`, oidc),
  );
  assert.throws(
    () => send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.corp`, oidc),
    /not one of the run's/,
  );
  assert.throws(
    () => send(ctx, "DELETE", `${base}/inboundSamlConfigs/saml.corp`),
    /not one of the run's/,
  );
  // A malformed ID is sent to be refused by the service.
  assert.doesNotThrow(() =>
    send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=bad id`, oidc),
  );
  assert.throws(
    () =>
      send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-a1b2c3-b`, {
        ...oidc,
        issuer: "https://issuer.example.org",
      }),
    /issuer host issuer.example.org is not reviewed/,
  );
  assert.doesNotThrow(() =>
    send(ctx, "PATCH", `${base}/defaultSupportedIdpConfigs/google.com?updateMask=enabled`, {
      enabled: false,
    }),
  );
  assert.throws(
    () =>
      send(ctx, "PATCH", `${base}/defaultSupportedIdpConfigs/facebook.com?updateMask=enabled`, {}),
    /not declared/,
  );
  assert.throws(
    () => send(ctx, "PATCH", `${base}/config?updateMask=signIn.email.enabled`, {}),
    /not written by AUTH-FEDERATION/,
  );
  assert.throws(() => send(ctx, "PATCH", `${base}/config`, {}), /non-empty updateMask/);
  assert.doesNotThrow(() =>
    send(ctx, "PATCH", `${base}/config?updateMask=signIn.allowDuplicateEmails`, {
      signIn: { allowDuplicateEmails: true },
    }),
  );
});

test("the run's issuer host is allowed only as the run's preview channel of the sandbox", () => {
  const ctx = production({ issuerHost: CHANNEL });
  const base = `/admin/v2/projects/${SANDBOX_PROJECT}`;
  const oidc = (issuer) => ({ clientId: "c", issuer, enabled: true });
  assert.doesNotThrow(() =>
    send(
      ctx,
      "POST",
      `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-a1b2c3-a`,
      oidc(`https://${CHANNEL}/oidc/${RUN}`),
    ),
  );
  assert.throws(
    () =>
      send(
        production(),
        "POST",
        `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-a1b2c3-a`,
        oidc(`https://${CHANNEL}/oidc/${RUN}`),
      ),
    /not reviewed/,
  );
  for (const host of [
    "evil--x.web.app",
    `${SANDBOX_PROJECT}--x.evil.web.app`,
    `${SANDBOX_PROJECT}--.web.app`,
    `${SANDBOX_PROJECT}--anything-at-all.web.app`,
    `${SANDBOX_PROJECT}--fed-d4e5f6-abc123.web.app`,
    `${SANDBOX_PROJECT}--fed-${RUN}-abc.def.web.app`,
    `${SANDBOX_PROJECT}--live-${RUN}-abc123.web.app`,
    `${SANDBOX_PROJECT}.web.app`,
  ]) {
    assert.throws(
      () => send(production({ issuerHost: host }), "GET", `${base}/oauthIdpConfigs`),
      /not the run's preview channel of the sandbox/,
      host,
    );
  }
});

test("a run is named by six hex digits and touches only its own providers", () => {
  const base = `/admin/v2/projects/${SANDBOX_PROJECT}`;
  const oidc = {
    clientId: "c",
    issuer: `https://${SANDBOX_PROJECT}.web.app/oidc/x`,
    enabled: true,
  };
  for (const run of [undefined, "r1", "../../escape", "A1B2C3", "a1b2c3d"]) {
    assert.throws(
      () => send(production({ run }), "GET", `${base}/oauthIdpConfigs`),
      /six hex digits/,
      String(run),
    );
  }
  // Another run's or another lane's provider is neither written nor deleted.
  for (const id of ["oidc.fireemu-d4e5f6-a", "oidc.fireemu-a", "saml.fireemu-tenant-a"]) {
    assert.throws(
      () => send(production(), "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=${id}`, oidc),
      /not one of the run's/,
      id,
    );
    assert.throws(
      () => send(production(), "DELETE", `${base}/oauthIdpConfigs/${id}`),
      /not one of the run's/,
      id,
    );
  }
  // A sign-in may name the run's provider in another case; another run's is refused.
  assert.doesNotThrow(() =>
    send(
      production(),
      "POST",
      "/v1/accounts:signInWithIdp",
      idp({ providerId: "oidc.fireemu-a1b2c3-V", id_token: "fireemu-garbage" }),
    ),
  );
  assert.throws(
    () =>
      send(
        production(),
        "POST",
        "/v1/accounts:signInWithIdp",
        idp({ providerId: "oidc.fireemu-d4e5f6-v", id_token: "fireemu-garbage" }),
      ),
    /not the run's/,
  );
  // Only the run's lower-case ID may be written, even though the service may fold case.
  assert.throws(
    () =>
      send(
        production(),
        "POST",
        `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-a1b2c3-V`,
        oidc,
      ),
    /not one of the run's/,
  );
});

test("no real third-party credential and no address outside example.com is sent", () => {
  const key = generateSigningKey({ kid: "run-kid" });
  const ctx = production({ runKids: ["run-kid"] });
  const own = signIdToken(key, { sub: "s" });
  const foreign = signIdToken(generateSigningKey({ kid: "google-kid" }), { sub: "s" });
  assert.ok(isRunCredential(own, ctx));
  assert.ok(!isRunCredential(foreign, ctx));
  assert.doesNotThrow(() =>
    send(
      ctx,
      "POST",
      "/v1/accounts:signInWithIdp",
      idp({ providerId: "google.com", id_token: own }),
    ),
  );
  assert.throws(
    () =>
      send(
        ctx,
        "POST",
        "/v1/accounts:signInWithIdp",
        idp({ providerId: "google.com", id_token: foreign }),
      ),
    /not a credential this run made/,
  );
  assert.throws(
    () =>
      send(
        ctx,
        "POST",
        "/v1/accounts:signInWithIdp",
        idp({ providerId: "linkedin.com", id_token: own }),
      ),
    /not the run's or a reviewed third party/,
  );
  assert.throws(
    () =>
      send(ctx, "POST", "/v1/accounts:signInWithIdp", {
        ...idp({ providerId: "oidc.fireemu-a1b2c3-a", id_token: own }),
        requestUri: "https://evil.example.org/cb",
      }),
    /requestUri host/,
  );
  assert.throws(
    () =>
      send(ctx, "POST", "/v1/projects/" + SANDBOX_PROJECT + "/accounts:lookup", {
        email: ["someone@gmail.com"],
      }),
    /outside example.com/,
  );
});

test("a corpus declares its providers, default IdPs and config paths", () => {
  assert.doesNotThrow(() =>
    validateFederationCorpus(
      [
        {
          id: "auth-federation/x",
          providers: ["oidc.fireemu-a1b2c3-x"],
          touches: ["signIn.allowDuplicateEmails"],
          steps: [{ id: "a" }, { id: "b" }],
        },
      ],
      { run: RUN },
    ),
  );
  assert.throws(
    () =>
      validateFederationCorpus([{ id: "auth-federation/x", providers: ["oidc.corp"], steps: [] }], {
        run: RUN,
      }),
    /provider oidc.corp/,
  );
  assert.throws(
    () =>
      validateFederationCorpus([{ id: "auth-federation/x", steps: [{ id: "a" }, { id: "a" }] }], {
        run: RUN,
      }),
    /duplicate step/,
  );
  assert.throws(
    () =>
      validateFederationCorpus([{ id: "auth-federation/x", touches: ["mfa"], steps: [] }], {
        run: RUN,
      }),
    /touches mfa/,
  );
  assert.throws(
    () =>
      validateFederationCorpus(
        [
          {
            id: "auth-federation/x",
            providers: [],
            steps: [
              { id: "c", method: "POST", query: { oauthIdpConfigId: "oidc.fireemu-a1b2c3-x" } },
            ],
          },
        ],
        { run: RUN },
      ),
    /creates undeclared oidc.fireemu-a1b2c3-x/,
  );
  assert.throws(
    () =>
      validateFederationCorpus(
        [{ id: "auth-federation/x", providers: ["oidc.fireemu-d4e5f6-x"], steps: [] }],
        { run: RUN },
      ),
    /provider oidc.fireemu-d4e5f6-x/,
  );
  assert.throws(
    () =>
      validateFederationCorpus(
        [
          {
            id: "auth-federation/x",
            steps: [{ id: "c", method: "POST", query: { idpId: "google.com" } }],
          },
        ],
        { run: RUN },
      ),
    /undeclared default IdP google.com/,
  );
});

test("the draft corpus resolves to requests the guard lets through", async () => {
  const { PROGRAMS, resolveCorpus } = await import("./auth-federation/corpus.mjs");
  const { materialize, mintTokens } = await import("./auth-federation/run.mjs");
  const keys = { run: generateSigningKey({ kid: "run-kid" }), other: generateSigningKey() };
  for (const issuerHost of [
    undefined,
    `${SANDBOX_PROJECT}.web.app`,
    `${SANDBOX_PROJECT}--fed-d4e5f6-abc123.web.app`,
  ]) {
    assert.throws(
      () => resolveCorpus(PROGRAMS, { project: SANDBOX_PROJECT, run: RUN, issuerHost }),
      /not the run's preview channel/,
      String(issuerHost),
    );
  }
  const resolved = resolveCorpus(PROGRAMS, {
    project: SANDBOX_PROJECT,
    run: RUN,
    issuerHost: CHANNEL,
    certificates: { "saml-a": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" },
    tokens: {
      missing: signIdToken(keys.run, { sub: "m" }),
      off: signIdToken(keys.run, { sub: "o" }),
    },
  });
  assert.doesNotThrow(() => validateFederationCorpus(resolved, { run: RUN }));
  const earlier = signIdToken(keys.run, { sub: "earlier" });
  // Every earlier answer holds what a later step may read from it.
  const raw = {
    get: () => ({
      localId: "local-1",
      idToken: earlier,
      id_token: earlier,
      refreshToken: "fireemu-refresh",
      pendingToken: "fireemu-pending",
      sessionId: "fireemu-session",
    }),
  };
  for (const program of resolved) {
    const minted = mintTokens(program, {
      issuer: `https://${CHANNEL}/oidc/${RUN}`,
      keys,
      now: 1_800_000_000,
    });
    const ctx = production({
      runKids: ["run-kid"],
      issuerHost: CHANNEL,
      defaultIdpWrites: program.defaultIdpWrites ?? [],
    });
    for (const step of program.steps) {
      const query = step.query ? `?${new URLSearchParams(step.query)}` : "";
      const body = step.body === undefined ? undefined : materialize(step.body, raw, minted);
      const path = step.path.startsWith("v1/token") ? null : `/${step.path}${query}`;
      if (path === null) {
        assert.doesNotThrow(
          () =>
            guardHttp(
              {
                url: `https://securetoken.googleapis.com/${step.path}`,
                method: "POST",
                body: JSON.stringify(body),
              },
              ctx,
              { role: "step" },
            ),
          `${program.id}#${step.id}`,
        );
        continue;
      }
      assert.doesNotThrow(
        () => send(ctx, step.method ?? "POST", path, body),
        `${program.id}#${step.id}`,
      );
    }
  }
  assert.ok(!JSON.stringify(resolved).includes("RUN"), "every placeholder is resolved");
});

test("recordings replace the run's identifiers in object keys as well as in values", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const ctx = {
    run: RUN,
    project: SANDBOX_PROJECT,
    projectNumber: "123456789012",
    issuerHost: CHANNEL,
  };
  const provider = `saml.fireemu-${RUN}-s`;
  assert.deepEqual(
    normalize(
      {
        identities: { [provider]: [`fireemu-fed-${RUN}@example.com`], email: ["x@example.com"] },
        [`projects/${SANDBOX_PROJECT}`]: { [`https://${CHANNEL}/oidc/${RUN}`]: 1 },
      },
      ctx,
    ),
    {
      identities: {
        "saml.fireemu-<run>-s": ["fireemu-fed-<run>@example.com"],
        email: ["x@example.com"],
      },
      "projects/<project>": { "https://<issuer-host>/oidc/<run>": 1 },
    },
  );
  // A key the replacement would merge with another is refused rather than silently lost.
  assert.throws(() => normalize({ [`a-${RUN}`]: 1, "a-<run>": 2 }, ctx), /collides/);
});

test("recordings keep no absolute time: echoed claims are relative to iat, account times masked", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const ctx = { run: RUN, project: SANDBOX_PROJECT };
  const claims = {
    aud: "client-a",
    iat: 1_790_528_974,
    exp: 1_790_532_574,
    nbf: 1_790_528_970,
    sub: "s",
  };
  assert.deepEqual(
    normalize(
      {
        signInAttributes: { ...claims },
        rawUserInfo: JSON.stringify(claims),
        users: [
          {
            createdAt: "1790528975104",
            lastLoginAt: "1790528975104",
            lastRefreshAt: "2026-09-28T01:02:03.456Z",
            passwordUpdatedAt: 1_790_528_975_104,
            validSince: "1790528975",
            email: "x@example.com",
          },
        ],
      },
      ctx,
    ),
    {
      signInAttributes: {
        aud: "client-a",
        iat: "<iat>",
        exp: "iat+3600",
        nbf: "iat-4",
        sub: "<subject>",
      },
      rawUserInfo: {
        "<json>": {
          aud: "client-a",
          iat: "<iat>",
          exp: "iat+3600",
          nbf: "iat-4",
          sub: "<subject>",
        },
      },
      users: [
        {
          createdAt: "<time>",
          lastLoginAt: "<time>",
          lastRefreshAt: "<time>",
          passwordUpdatedAt: "<time>",
          validSince: "<time>",
          email: "x@example.com",
        },
      ],
    },
  );
  // A rawUserInfo that is not JSON stays text.
  assert.deepEqual(normalize({ rawUserInfo: "not json" }, ctx), { rawUserInfo: "not json" });
});

test("recordings keep no per-request value: the authorization state and times in messages", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const ctx = { run: RUN, project: SANDBOX_PROJECT, issuerHost: CHANNEL };
  const authUri = `https://${CHANNEL}/oidc/${RUN}/authorize?response_type=id_token&client_id=client-q&state=AMbdmDmLyPCC-x_y&scope=openid&nonce=n-1`;
  assert.deepEqual(normalize({ authUri }, ctx), {
    authUri:
      "https://<issuer-host>/oidc/<run>/authorize?response_type=id_token&client_id=client-q&state=<state>&scope=openid&nonce=n-1",
  });
  // A nonce the service made (64 hex digits) is masked with its form kept; another is kept.
  const generated = `${authUri.replace("nonce=n-1", `nonce=${"9d".repeat(32)}`)}#x`;
  assert.deepEqual(normalize({ authUri: generated }, ctx), {
    authUri:
      "https://<issuer-host>/oidc/<run>/authorize?response_type=id_token&client_id=client-q&state=<state>&scope=openid&nonce=<nonce:hex64>#x",
  });
  const stale = "INVALID_IDP_RESPONSE : ID Token issued at 1790552633 is stale to sign-in.";
  const unnamed = `INVALID_IDP_RESPONSE : ID Token does not contain user's identity in 'sub' claim: {"aud":"client-v","exp":1790563433,"iat":1790559833,"iss":"https://${CHANNEL}/oidc/${RUN}"}`;
  assert.deepEqual(normalize({ error: { message: stale, errors: [{ message: unnamed }] } }, ctx), {
    error: {
      message: "INVALID_IDP_RESPONSE : ID Token issued at <time> is stale to sign-in.",
      errors: [
        {
          message: `INVALID_IDP_RESPONSE : ID Token does not contain user's identity in 'sub' claim: {"aud":"client-v","exp":"iat+3600","iat":"<iat>","iss":"https://<issuer-host>/oidc/<run>"}`,
        },
      ],
    },
  });
  // Numbers that are not plausible Unix times stay as answered.
  assert.deepEqual(normalize({ message: "code 400, 12 attempts, 1234567" }, ctx), {
    message: "code 400, 12 attempts, 1234567",
  });
});

test("recordings keep no key ID: a token's kid names a key of that run or service", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const ctx = { run: RUN, project: SANDBOX_PROJECT };
  const jwt = (header) =>
    [header, { iat: 1_790_528_974, exp: 1_790_532_574 }, {}]
      .map((part) => Buffer.from(JSON.stringify(part)).toString("base64url"))
      .join(".");
  for (const key of ["idToken", "id_token", "access_token", "sessionCookie", "oauthIdToken"]) {
    assert.deepEqual(
      normalize({ [key]: jwt({ alg: "RS256", kid: "801d4a207307b4f3", typ: "JWT" }) }, ctx)[key][
        "<jwt>"
      ].header,
      { alg: "RS256", kid: "<kid>", typ: "JWT" },
      key,
    );
  }
  // A header without a kid stays without one.
  assert.deepEqual(normalize({ idToken: jwt({ alg: "none" }) }, ctx).idToken["<jwt>"].header, {
    alg: "none",
  });
});

test("a token minted after the sign-in records auth_time only as not after iat", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const ctx = { run: RUN, project: SANDBOX_PROJECT };
  const iat = 1_790_528_974;
  const jwt = (authTime) =>
    [{ alg: "RS256", typ: "JWT" }, { iat, exp: iat + 3600, auth_time: authTime }, {}]
      .map((part) => Buffer.from(JSON.stringify(part)).toString("base64url"))
      .join(".");
  const authTime = (key, value) =>
    normalize({ [key]: jwt(value) }, ctx)[key]["<jwt>"].claims.auth_time;
  // A refresh or session cookie may be minted in the sign-in's second or a later one: which
  // depends on when it was sent (AUTH-FEDERATION Q1, 2026-09-29).
  for (const key of ["id_token", "access_token", "sessionCookie"]) {
    assert.equal(authTime(key, iat), "<=iat", key);
    assert.equal(authTime(key, iat - 1), "<=iat", key);
    assert.equal(authTime(key, iat - 7200), "<=iat", key);
    // An auth_time after the token's iat stays visible.
    assert.equal(authTime(key, iat + 2), "iat+2", key);
  }
  // The sign-in's own token keeps its exact offset, and so does the IdP's.
  for (const key of ["idToken", "oauthIdToken"]) {
    assert.equal(authTime(key, iat), "iat+0", key);
    assert.equal(authTime(key, iat - 1), "iat-1", key);
  }
});

test("a SAMLResponse is the run's only when every certificate it carries is the run's", () => {
  const response = (...certificates) =>
    Buffer.from(
      `<samlp:Response>${certificates
        .map((c) => `<ds:X509Certificate>${c}</ds:X509Certificate>`)
        .join("")}</samlp:Response>`,
    ).toString("base64");
  const ctx = production({ runCertificates: ["UlVOLUNFUlQ=", "RVhQSVJFRA=="] });
  assert.ok(isRunCredential(response("UlVOLUNFUlQ="), ctx));
  assert.ok(isRunCredential(response("UlVOLUNFUlQ=", "RVhQSVJFRA=="), ctx));
  assert.ok(!isRunCredential(response("UlVOLUNFUlQ=", "T1RIRVI="), ctx), "a foreign certificate");
  assert.ok(!isRunCredential(response(), ctx), "no certificate");
  assert.ok(!isRunCredential(response("UlVOLUNFUlQ="), production()), "no run certificates");
  const body = (value) =>
    send(ctx, "POST", "/v1/accounts:signInWithIdp", {
      requestUri: `https://${SANDBOX_PROJECT}.firebaseapp.com/__/auth/handler`,
      postBody: new URLSearchParams({
        providerId: `saml.fireemu-${RUN}-s`,
        SAMLResponse: value,
      }).toString(),
    });
  assert.doesNotThrow(() => body(response("UlVOLUNFUlQ=")));
  assert.throws(() => body(response("T1RIRVI=")), /SAMLResponse is not a credential this run made/);
});

test("a $saml value is a response signed at the step, naming the AuthnRequest it answers", async () => {
  const { materialize } = await import("./auth-federation/run.mjs");
  const { generateKeyPairSync } = await import("node:crypto");
  const { deflateRawSync } = await import("node:zlib");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const saml = {
    keys: {
      run: {
        privateKey,
        certificatePem: "-----BEGIN CERTIFICATE-----\nUlVOLUNFUlQ=\n-----END CERTIFICATE-----",
      },
    },
    now: () => 1_790_000_000,
  };
  const request =
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req42" AssertionConsumerServiceURL="https://sp.example/acs"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>';
  const authUri = `https://idp.example/sso?SAMLRequest=${encodeURIComponent(deflateRawSync(Buffer.from(request)).toString("base64"))}&RelayState=relay-1`;
  const raw = new Map([["auth-uri", { authUri, sessionId: "s-1" }]]);
  const spec = {
    request: "auth-uri",
    issuer: "https://idp.example/saml",
    audience: "sp",
    destination: "https://sp.example/acs",
    nameId: "user@example.com",
  };
  const decode = (value) => Buffer.from(value, "base64").toString("utf8");
  const xml = decode(materialize({ $saml: spec }, raw, {}, saml));
  assert.ok(xml.includes('InResponseTo="_req42"'), xml);
  assert.ok(xml.includes("<saml:Audience>sp</saml:Audience>"), xml);
  assert.ok(xml.includes('Recipient="https://sp.example/acs"'), xml);
  assert.ok(xml.includes('IssueInstant="2026-09-21T14:13:20Z"'), xml);
  assert.ok(xml.includes("<ds:X509Certificate>UlVOLUNFUlQ=</ds:X509Certificate>"), xml);
  // Overrides, relative times and an absent InResponseTo.
  const other = decode(
    materialize(
      {
        $saml: {
          ...spec,
          inResponseTo: null,
          audience: "other-sp",
          conditions: { notBefore: 600 },
          confirmationNotOnOrAfter: -600,
          status: "urn:oasis:names:tc:SAML:2.0:status:Requester",
        },
      },
      raw,
      {},
      saml,
    ),
  );
  assert.ok(!other.includes("InResponseTo"), other);
  assert.ok(other.includes("<saml:Audience>other-sp</saml:Audience>"), other);
  assert.ok(other.includes('<saml:Conditions NotBefore="2026-09-21T14:23:20Z"'), other);
  assert.ok(other.includes('NotOnOrAfter="2026-09-21T14:03:20Z" Recipient='), other);
  assert.ok(other.includes('Value="urn:oasis:names:tc:SAML:2.0:status:Requester"'), other);
  // The relay state the AuthnRequest came with, and a key the run did not make is refused.
  assert.equal(materialize({ $relayState: "auth-uri" }, raw, {}, saml), "relay-1");
  assert.throws(
    () => materialize({ $saml: { ...spec, key: "missing" } }, raw, {}, saml),
    /key missing/,
  );
});

test("a run stops before a step that could create an account past its limit", async () => {
  const { runPrograms } = await import("./auth-federation/run.mjs");
  const sent = [];
  let next = 0;
  const fetchImpl = async (url, init = {}) => {
    sent.push(`${init.method ?? "GET"} ${new URL(url).pathname}`);
    const body = url.includes(":signInWithIdp") ? { localId: `local-${(next += 1)}` } : {};
    return new Response(JSON.stringify(body), { status: 200 });
  };
  const signInStep = (id) => ({
    id,
    auth: "key",
    path: "v1/accounts:signInWithIdp",
    body: {
      requestUri: "http://localhost",
      postBody: { $form: { providerId: `oidc.fireemu-${RUN}-a`, id_token: "fireemu-token" } },
      returnSecureToken: true,
    },
  });
  const programs = [
    { id: "p1", steps: [signInStep("first")] },
    { id: "p2", steps: [signInStep("second")] },
  ];
  const origin = "http://127.0.0.1:9";
  await assert.rejects(
    runPrograms(programs, {
      run: RUN,
      project: SANDBOX_PROJECT,
      issuerHost: CHANNEL,
      apiKey: "fake",
      adminAuthorization: "Bearer owner",
      origin,
      target: { kind: "local", origin },
      fetch: fetchImpl,
      accountLimit: 1,
    }),
    /account limit 1/,
  );
  assert.equal(sent.filter((line) => line.includes(":signInWithIdp")).length, 1, sent.join("\n"));
});

test("the run's SAML signers are a current and an expired certificate with their keys in memory", async () => {
  const { prepareSamlSigners } = await import("./auth-federation/run.mjs");
  const { mkdtemp, readdir, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { X509Certificate, KeyObject } = await import("node:crypto");
  const dir = await mkdtemp(join(tmpdir(), "fireemu-saml-signers-"));
  try {
    const signers = await prepareSamlSigners(dir);
    const now = Date.now();
    const current = new X509Certificate(signers.certificates["saml-a"]);
    const expired = new X509Certificate(signers.certificates["saml-expired"]);
    assert.ok(Date.parse(current.validTo) > now && Date.parse(current.validFrom) <= now);
    assert.ok(Date.parse(expired.validTo) < now, expired.validTo);
    assert.ok(signers.keys.run.privateKey instanceof KeyObject);
    assert.equal(signers.keys.run.certificatePem, signers.certificates["saml-a"]);
    assert.equal(signers.keys.expired.certificatePem, signers.certificates["saml-expired"]);
    assert.ok(current.checkPrivateKey(signers.keys.run.privateKey));
    assert.ok(expired.checkPrivateKey(signers.keys.expired.privateKey));
    // The run's certificates as a SAMLResponse carries them (base64 of the DER).
    assert.deepEqual(signers.runCertificates, [
      current.raw.toString("base64"),
      expired.raw.toString("base64"),
    ]);
    // Nothing is left on disk: the keys live in memory for the run only.
    assert.deepEqual(await readdir(dir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a SAML authUri is recorded as its AuthnRequest, the request ID, time and relay state masked", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const { deflateRawSync } = await import("node:zlib");
  const ctx = { run: RUN, project: SANDBOX_PROJECT };
  const request = `<?xml version="1.0" encoding="UTF-8"?><saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://${SANDBOX_PROJECT}.firebaseapp.com/__/auth/handler" Destination="https://${SANDBOX_PROJECT}.web.app/saml/${RUN}/sso" ID="_ed0d4770c630176df01d0df9cf1e494f" IssueInstant="2026-09-27T16:57:13.876Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">fireemu-${RUN}-sp</saml2:Issuer></saml2p:AuthnRequest>`;
  const encoded = encodeURIComponent(deflateRawSync(Buffer.from(request)).toString("base64"));
  const authUri = `https://${SANDBOX_PROJECT}.web.app/saml/${RUN}/sso?SAMLRequest=${encoded}&RelayState=AMbdmDkLCfxgT-2G`;
  assert.deepEqual(normalize({ authUri }, ctx), {
    authUri: {
      "<saml-authn-request>": {
        endpoint: "https://<project>.web.app/saml/<run>/sso",
        request:
          '<?xml version="1.0" encoding="UTF-8"?><saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://<project>.firebaseapp.com/__/auth/handler" Destination="https://<project>.web.app/saml/<run>/sso" ID="<id:_hex>" IssueInstant="<time:millis>" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">fireemu-<run>-sp</saml2:Issuer></saml2p:AuthnRequest>',
        relayState: "<relay-state>",
      },
    },
  });
});

test("recordings mask ISO times in messages and an AuthnRequest ID of any hex length", async () => {
  const { normalize } = await import("./auth-federation/harness.mjs");
  const { deflateRawSync } = await import("node:zlib");
  const ctx = { run: RUN, project: SANDBOX_PROJECT };
  assert.deepEqual(
    normalize(
      {
        message:
          "INVALID_IDP_RESPONSE : Current instant, 2026-09-28T07:36:05.177Z, is before NotBefore attribute, 2026-09-28T07:46:04.000Z",
      },
      ctx,
    ),
    {
      message:
        "INVALID_IDP_RESPONSE : Current instant, <time>, is before NotBefore attribute, <time>",
    },
  );
  // A request ID whose leading zero the service dropped is the same shape.
  const uri = (id) =>
    `https://${SANDBOX_PROJECT}.web.app/saml/${RUN}/sso?SAMLRequest=${encodeURIComponent(
      deflateRawSync(
        Buffer.from(`<saml2p:AuthnRequest ID="${id}" IssueInstant="2026-09-28T07:36:05.177Z"/>`),
      ).toString("base64"),
    )}&RelayState=r`;
  const request = (id) =>
    normalize({ authUri: uri(id) }, ctx).authUri["<saml-authn-request>"].request;
  assert.equal(request(`_${"a".repeat(32)}`), request(`_${"b".repeat(31)}`));
  assert.ok(request(`_${"a".repeat(32)}`).includes('ID="<id:_hex>"'));
});

test("the follow-up corpus sends a tampered and an unsigned response of the run's IdP only", async () => {
  const { materialize } = await import("./auth-federation/run.mjs");
  const { generateKeyPairSync } = await import("node:crypto");
  const { deflateRawSync } = await import("node:zlib");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const certificate = "UlVOLUNFUlQ=";
  const saml = {
    keys: {
      run: {
        privateKey,
        certificatePem: `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`,
      },
    },
    now: () => 1_790_000_000,
  };
  const request =
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_req7" AssertionConsumerServiceURL="https://sp.example/acs"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>';
  const authUri = `https://idp.example/sso?SAMLRequest=${encodeURIComponent(deflateRawSync(Buffer.from(request)).toString("base64"))}&RelayState=relay-7`;
  const raw = new Map([["auth-uri", { authUri, sessionId: "s-7" }]]);
  const runIdp = `https://${SANDBOX_PROJECT}.web.app/saml/${RUN}`;
  const spec = {
    request: "auth-uri",
    issuer: runIdp,
    audience: "sp",
    destination: "https://sp.example/acs",
    nameId: "user@example.com",
  };
  const decode = (value) => Buffer.from(value, "base64").toString("utf8");
  // The two responses are made from the same inputs, so the same bytes: the response and assertion IDs
  // come from `randomBytes`, which is fixed here, and the clock is already fixed. RSA PKCS#1 v1.5 is
  // deterministic, so the signatures are equal until the tamper changes one. (Compared with a response
  // signed under other random IDs, the first character of the two signatures collides one time in 64.)
  const { createRequire, syncBuiltinESMExports } = await import("node:module");
  const crypto = createRequire(import.meta.url)("node:crypto");
  const realRandomBytes = crypto.randomBytes;
  crypto.randomBytes = (size) => Buffer.alloc(size, 7);
  syncBuiltinESMExports();
  let signed;
  let tampered;
  try {
    signed = decode(materialize({ $saml: spec }, raw, {}, saml));
    tampered = decode(materialize({ $saml: { ...spec, tamper: true } }, raw, {}, saml));
  } finally {
    crypto.randomBytes = realRandomBytes;
    syncBuiltinESMExports();
  }
  const signature = (xml) => xml.match(/<ds:SignatureValue>([^<]*)</)[1];
  // Only the first character of the signature differs from the signed response of the same inputs.
  assert.notEqual(signature(tampered)[0], signature(signed)[0]);
  assert.equal(signature(tampered).slice(1), signature(signed).slice(1));
  assert.equal(
    tampered,
    signed.replace(/<ds:SignatureValue>./, `<ds:SignatureValue>${signature(tampered)[0]}`),
  );
  const unsigned = decode(materialize({ $saml: { ...spec, sign: "none" } }, raw, {}, saml));
  assert.ok(!unsigned.includes("Signature") && !unsigned.includes("X509Certificate"), unsigned);
  assert.ok(unsigned.includes('InResponseTo="_req7"'), unsigned);
  // The guard sends a tampered response carrying the run's certificate, and an unsigned one
  // only when every issuer in it is the run's own IdP.
  const ctx = production({ runCertificates: [certificate] });
  const post = (xml) =>
    send(
      ctx,
      "POST",
      "/v1/accounts:signInWithIdp",
      idp({
        providerId: `saml.fireemu-${RUN}-sg`,
        SAMLResponse: Buffer.from(xml).toString("base64"),
      }),
    );
  assert.doesNotThrow(() => post(tampered));
  assert.doesNotThrow(() => post(unsigned));
  for (const foreign of [
    unsigned.replaceAll(runIdp, "https://idp.example/saml"),
    unsigned.replaceAll(runIdp, `https://${SANDBOX_PROJECT}.web.app/saml/d4e5f6`),
    unsigned.replaceAll(runIdp, `https://other-project.web.app/saml/${RUN}`),
  ]) {
    assert.throws(() => post(foreign), /credential/);
  }
  // A signature by another certificate is still refused, unsigned or not.
  assert.throws(() => post(signed.replaceAll(certificate, "T1RIRVI=")), /credential/);
});

test("the follow-up issuer lists its scopes in the discovery document it publishes", async () => {
  const { discoveryDocument, issuerSite } = await import("./auth-federation/idp.mjs");
  const { FOLLOWUP_DISCOVERY_SCOPES } = await import("./auth-federation/corpus-followup.mjs");
  const issuer = `https://${CHANNEL}/oidc/${RUN}`;
  assert.equal(discoveryDocument(issuer).scopes_supported, undefined);
  assert.deepEqual(
    discoveryDocument(issuer, { scopes: FOLLOWUP_DISCOVERY_SCOPES }).scopes_supported,
    ["profile", "openid", "email", "phone"],
  );
  const key = generateSigningKey({ kid: "run-kid" });
  const site = issuerSite({ issuer, run: RUN, jwks: [key.jwk], scopes: FOLLOWUP_DISCOVERY_SCOPES });
  const published = JSON.parse(site.files[`/oidc/${RUN}/.well-known/openid-configuration`]);
  assert.deepEqual(published.scopes_supported, FOLLOWUP_DISCOVERY_SCOPES);
  const plain = issuerSite({ issuer, run: RUN, jwks: [key.jwk] });
  assert.equal(
    JSON.parse(plain.files[`/oidc/${RUN}/.well-known/openid-configuration`]).scopes_supported,
    undefined,
  );
});

test("an unsigned response goes only when every Issuer in any spelling is the run's (pre-send review S1)", () => {
  const runIdp = `https://${SANDBOX_PROJECT}.web.app/saml/${RUN}`;
  const foreign = "https://idp.example/x";
  const response = (issuers, extra = "") =>
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${issuers[0]}<saml:Assertion>${issuers[1] ?? ""}${extra}</saml:Assertion></samlp:Response>`;
  const plain = (value) => `<saml:Issuer>${value}</saml:Issuer>`;
  const ctx = production({ runCertificates: ["UlVOLUNFUlQ="] });
  const post = (xml) =>
    send(
      ctx,
      "POST",
      "/v1/accounts:signInWithIdp",
      idp({
        providerId: `saml.fireemu-${RUN}-sg`,
        SAMLResponse: Buffer.from(xml).toString("base64"),
      }),
    );
  assert.doesNotThrow(() => post(response([plain(runIdp), plain(runIdp)])), "the run's own");
  // The run's own Issuer in another spelling is collected, and goes.
  assert.doesNotThrow(
    () => post(response([plain(runIdp), `<saml2:Issuer Format="urn:x">${runIdp}</saml2:Issuer>`])),
    "the run's own, another prefix and attributes",
  );
  for (const [name, xml] of Object.entries({
    "a mixed response: the run's Response Issuer, a foreign Assertion Issuer": response([
      plain(runIdp),
      plain(foreign),
    ]),
    "an Issuer with attributes": response([
      plain(runIdp),
      `<saml:Issuer Format="urn:x">${foreign}</saml:Issuer>`,
    ]),
    "an Issuer of another prefix": response([
      plain(runIdp),
      `<saml2:Issuer>${foreign}</saml2:Issuer>`,
    ]),
    "an Issuer without a prefix": response([plain(runIdp), `<Issuer>${foreign}</Issuer>`]),
    "an Issuer holding a comment": response([
      plain(runIdp),
      `<saml:Issuer>${foreign}<!-- --></saml:Issuer>`,
    ]),
    "an Issuer holding CDATA": response([
      plain(runIdp),
      `<saml:Issuer><![CDATA[${runIdp}]]></saml:Issuer>`,
    ]),
    "an unclosed Issuer": response([plain(runIdp), `<saml:Issuer>${runIdp}`]),
    "a signature without a certificate": response(
      [plain(runIdp), plain(runIdp)],
      "<ds:Signature><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>",
    ),
    "a lower-case signature value": response(
      [plain(runIdp), plain(runIdp)],
      "<ds:signaturevalue>AAAA</ds:signaturevalue>",
    ),
    "an X509 element of another spelling": response(
      [plain(runIdp), plain(runIdp)],
      "<ds:X509Data></ds:X509Data>",
    ),
    "no Issuer": response([""]),
  })) {
    assert.throws(() => post(xml), /credential/, name);
  }
});

test("the follow-up corpus's own SAML sign-ins, with its real names, get through the guard", async () => {
  // The unsigned row's NameID is fireemu-fed-<run>-saml-signature@example.com: the guard reads
  // signature markup, never text (pre-send re-review R-M1).
  const { FOLLOWUP_PROGRAMS } = await import("./auth-federation/corpus-followup.mjs");
  const { materialize, resolveRun } = await import("./auth-federation/run.mjs");
  const { generateKeyPairSync } = await import("node:crypto");
  const { deflateRawSync } = await import("node:zlib");
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const certificate = "UlVOLUNFUlQ=";
  const certificatePem = `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;
  const keys = { run: generateSigningKey({ kid: "run-kid" }), other: generateSigningKey() };
  const resolve = (programs) =>
    resolveRun({
      project: SANDBOX_PROJECT,
      run: RUN,
      issuerHost: CHANNEL,
      keys,
      certificates: { "saml-a": certificatePem },
      now: 1_790_000_000,
      programs,
    }).programs;
  const saml = { keys: { run: { privateKey, certificatePem } }, now: () => 1_790_000_000 };
  const authUri = (id) => {
    const request = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_${id}" AssertionConsumerServiceURL="https://sp.example/acs"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">sp</saml:Issuer></samlp:AuthnRequest>`;
    return `https://idp.example/sso?SAMLRequest=${encodeURIComponent(deflateRawSync(Buffer.from(request)).toString("base64"))}&RelayState=relay-${id}`;
  };
  const ctx = production({
    runCertificates: [certificate],
    runKids: ["run-kid"],
    issuerHost: CHANNEL,
  });
  const sendSignIns = (programs) => {
    const program = programs.find(({ id }) => id === "auth-federation/saml/signature");
    const raw = new Map(
      program.steps
        .filter(({ id }) => id.endsWith("-auth-uri"))
        .map(({ id }) => [id, { authUri: authUri(id.replace(/\W/g, "")), sessionId: `s-${id}` }]),
    );
    const signIns = program.steps.filter(({ id }) => id === "tampered" || id === "unsigned");
    assert.deepEqual(
      signIns.map(({ id }) => id),
      ["tampered", "unsigned"],
    );
    return signIns.map((step) => {
      const body = materialize(step.body, raw, program.minted, saml);
      const xml = Buffer.from(
        new URLSearchParams(body.postBody).get("SAMLResponse"),
        "base64",
      ).toString("utf8");
      assert.doesNotThrow(() => send(ctx, "POST", `/${step.path}`, body), step.id);
      return xml;
    });
  };
  const [tampered, unsigned] = sendSignIns(resolve(FOLLOWUP_PROGRAMS));
  assert.match(unsigned, /saml-signature@example\.com/, "the corpus's own NameID");
  assert.ok(!/<[\w-]*:?Signature\b/i.test(unsigned), "unsigned");
  assert.match(tampered, /<ds:Signature\b/, "tampered keeps its signature");
  // A NameID naming a signature in any case still goes.
  for (const name of ["Signature", "SIGNATURE", "SignatureValue", "x509"]) {
    const renamed = structuredClone(FOLLOWUP_PROGRAMS).map((program) => ({
      ...program,
      steps: program.steps.map((step) =>
        step.body?.postBody?.$form?.SAMLResponse?.$saml
          ? {
              ...step,
              body: {
                ...step.body,
                postBody: {
                  $form: {
                    ...step.body.postBody.$form,
                    SAMLResponse: {
                      $saml: {
                        ...step.body.postBody.$form.SAMLResponse.$saml,
                        nameId: `${name}@example.com`,
                      },
                    },
                  },
                },
              },
            }
          : step,
      ),
    }));
    sendSignIns(resolve(renamed));
  }
});

test("tampering a signature changes its first character whatever it was, and nothing else", async () => {
  const { tamperSignature } = await import("./auth-federation/saml.mjs");
  const xml = (first) =>
    `<r><ds:SignatureValue>${first}bcdef==</ds:SignatureValue><ds:Other>Aabc</ds:Other></r>`;
  assert.equal(tamperSignature(xml("A")), xml("B"));
  for (const first of ["B", "Q", "z", "0", "+", "/"]) {
    assert.equal(tamperSignature(xml(first)), xml("A"), first);
  }
  assert.throws(() => tamperSignature("<r/>"), /no signature to tamper with/);
});
