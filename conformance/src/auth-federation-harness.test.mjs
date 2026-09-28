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
    authUri: "https://<issuer-host>/oidc/<run>/authorize?response_type=id_token&client_id=client-q&state=<state>&scope=openid&nonce=n-1",
  });
  // A nonce the service made (64 hex digits) is masked with its form kept; another is kept.
  const generated = `${authUri.replace("nonce=n-1", `nonce=${"9d".repeat(32)}`)}#x`;
  assert.deepEqual(normalize({ authUri: generated }, ctx), {
    authUri: "https://<issuer-host>/oidc/<run>/authorize?response_type=id_token&client_id=client-q&state=<state>&scope=openid&nonce=<nonce:hex64>#x",
  });
  const stale = "INVALID_IDP_RESPONSE : ID Token issued at 1790552633 is stale to sign-in.";
  const unnamed = `INVALID_IDP_RESPONSE : ID Token does not contain user's identity in 'sub' claim: {"aud":"client-v","exp":1790563433,"iat":1790559833,"iss":"https://${CHANNEL}/oidc/${RUN}"}`;
  assert.deepEqual(
    normalize({ error: { message: stale, errors: [{ message: unnamed }] } }, ctx),
    {
      error: {
        message: "INVALID_IDP_RESPONSE : ID Token issued at <time> is stale to sign-in.",
        errors: [
          {
            message: `INVALID_IDP_RESPONSE : ID Token does not contain user's identity in 'sub' claim: {"aud":"client-v","exp":"iat+3600","iat":"<iat>","iss":"https://<issuer-host>/oidc/<run>"}`,
          },
        ],
      },
    },
  );
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
