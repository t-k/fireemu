import assert from "node:assert/strict";
import { test } from "node:test";

import { SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import { guardHttp, isRunCredential, validateFederationCorpus } from "./auth-federation/guard.mjs";
import { generateSigningKey, signIdToken } from "./auth-federation/idp.mjs";

const production = (extra = {}) => ({
  project: SANDBOX_PROJECT,
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
  assert.doesNotThrow(() => send(ctx, "POST", "/v1/accounts:signInWithIdp", idp({ providerId: "oidc.fireemu-a", id_token: "fireemu-garbage" })));
  assert.doesNotThrow(() => send(ctx, "GET", `/admin/v2/projects/${SANDBOX_PROJECT}/oauthIdpConfigs`));
  assert.doesNotThrow(() => send(ctx, "GET", "/v2/defaultSupportedIdps"));
  assert.throws(() => send(ctx, "POST", "/v1/accounts:signUp", {}), /not a reviewed family/);
  assert.throws(() => send(ctx, "POST", "/v1/accounts:sendOobCode", {}), /not a reviewed family/);
  assert.throws(() => send(ctx, "GET", "/admin/v2/projects/other-project/oauthIdpConfigs"), /not a reviewed family/);
  assert.throws(
    () => guardHttp({ url: "https://evil.example/v1/token", method: "POST" }, ctx, { role: "step" }),
    /not reviewed/,
  );
});

test("provider writes touch only the run's providers and declared default IdPs", () => {
  const ctx = production({ defaultIdpWrites: ["google.com"] });
  const base = `/admin/v2/projects/${SANDBOX_PROJECT}`;
  const oidc = { clientId: "c", issuer: `https://${SANDBOX_PROJECT}.web.app/oidc/run`, enabled: true };
  assert.doesNotThrow(() => send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-a`, oidc));
  assert.throws(() => send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.corp`, oidc), /not one of the run's/);
  assert.throws(() => send(ctx, "DELETE", `${base}/inboundSamlConfigs/saml.corp`), /not one of the run's/);
  // A malformed ID is sent to be refused by the service.
  assert.doesNotThrow(() => send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=bad id`, oidc));
  assert.throws(
    () => send(ctx, "POST", `${base}/oauthIdpConfigs?oauthIdpConfigId=oidc.fireemu-b`, { ...oidc, issuer: "https://issuer.example.org" }),
    /issuer host issuer.example.org is not reviewed/,
  );
  assert.doesNotThrow(() => send(ctx, "PATCH", `${base}/defaultSupportedIdpConfigs/google.com?updateMask=enabled`, { enabled: false }));
  assert.throws(() => send(ctx, "PATCH", `${base}/defaultSupportedIdpConfigs/facebook.com?updateMask=enabled`, {}), /not declared/);
  assert.throws(() => send(ctx, "PATCH", `${base}/config?updateMask=signIn.email.enabled`, {}), /not written by AUTH-FEDERATION/);
  assert.throws(() => send(ctx, "PATCH", `${base}/config`, {}), /non-empty updateMask/);
  assert.doesNotThrow(() => send(ctx, "PATCH", `${base}/config?updateMask=signIn.allowDuplicateEmails`, { signIn: { allowDuplicateEmails: true } }));
});

test("no real third-party credential and no address outside example.com is sent", () => {
  const key = generateSigningKey({ kid: "run-kid" });
  const ctx = production({ runKids: ["run-kid"] });
  const own = signIdToken(key, { sub: "s" });
  const foreign = signIdToken(generateSigningKey({ kid: "google-kid" }), { sub: "s" });
  assert.ok(isRunCredential(own, ctx));
  assert.ok(!isRunCredential(foreign, ctx));
  assert.doesNotThrow(() => send(ctx, "POST", "/v1/accounts:signInWithIdp", idp({ providerId: "google.com", id_token: own })));
  assert.throws(() => send(ctx, "POST", "/v1/accounts:signInWithIdp", idp({ providerId: "google.com", id_token: foreign })), /not a credential this run made/);
  assert.throws(() => send(ctx, "POST", "/v1/accounts:signInWithIdp", idp({ providerId: "linkedin.com", id_token: own })), /not the run's or a reviewed third party/);
  assert.throws(() => send(ctx, "POST", "/v1/accounts:signInWithIdp", { ...idp({ providerId: "oidc.fireemu-a", id_token: own }), requestUri: "https://evil.example.org/cb" }), /requestUri host/);
  assert.throws(() => send(ctx, "POST", "/v1/projects/" + SANDBOX_PROJECT + "/accounts:lookup", { email: ["someone@gmail.com"] }), /outside example.com/);
});

test("a corpus declares its providers, default IdPs and config paths", () => {
  assert.doesNotThrow(() =>
    validateFederationCorpus([
      { id: "auth-federation/x", providers: ["oidc.fireemu-x"], touches: ["signIn.allowDuplicateEmails"], steps: [{ id: "a" }, { id: "b" }] },
    ]),
  );
  assert.throws(() => validateFederationCorpus([{ id: "auth-federation/x", providers: ["oidc.corp"], steps: [] }]), /provider oidc.corp/);
  assert.throws(() => validateFederationCorpus([{ id: "auth-federation/x", steps: [{ id: "a" }, { id: "a" }] }]), /duplicate step/);
  assert.throws(() => validateFederationCorpus([{ id: "auth-federation/x", touches: ["mfa"], steps: [] }]), /touches mfa/);
});

test("the draft corpus resolves to requests the guard lets through", async () => {
  const { PROGRAMS, resolveCorpus } = await import("./auth-federation/corpus.mjs");
  const key = generateSigningKey({ kid: "run-kid" });
  const resolved = resolveCorpus(PROGRAMS, {
    project: SANDBOX_PROJECT,
    run: "r1",
    certificates: { "saml-a": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----" },
    tokens: { missing: signIdToken(key, { sub: "m" }), off: signIdToken(key, { sub: "o" }) },
  });
  assert.doesNotThrow(() => validateFederationCorpus(resolved));
  for (const program of resolved) {
    const ctx = production({ runKids: ["run-kid"], defaultIdpWrites: program.defaultIdpWrites ?? [] });
    for (const step of program.steps) {
      const query = step.query ? `?${new URLSearchParams(step.query)}` : "";
      assert.doesNotThrow(
        () => send(ctx, step.method ?? "POST", `/${step.path}${query}`, step.body),
        `${program.id}#${step.id}`,
      );
    }
  }
  assert.ok(!JSON.stringify(resolved).includes("RUN"), "every placeholder is resolved");
});
