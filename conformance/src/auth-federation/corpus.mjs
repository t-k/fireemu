// AUTH-FEDERATION corpus, draft. Only the programs that do not depend on the open owner
// decisions (O1 to O6 of the closure draft): provider configuration and the refusals of
// providers this parent does not sign in with. The controlled-IdP programs (signed OIDC and
// SAML sign-in, linking, collision and the session claims) are added once the decisions and
// the frozen closure conditions exist. Nothing here has been sent.
//
// Placeholders the harness resolves per run: `{project}`; `RUN` (a short run tag, so provider
// IDs are `oidc.fireemu-RUN-…`); `CERT(name)`, a PEM certificate of a key made for this run;
// `TOKEN(name)`, an ID token signed with the run's key.

import { issuerChannelHost } from "./guard.mjs";

export const admin = (id, method, path, extra = {}) => ({
  id,
  auth: "admin",
  method,
  path: `admin/v2/projects/{project}/${path}`,
  ...extra,
});
export const client = (id, method, body) => ({ id, auth: "key", path: `v1/accounts:${method}`, body });

/** The run's issuer: a Hosting preview channel of the sandbox (O1), resolved per run. */
export const ISSUER = "https://ISSUERHOST/oidc/RUN";

const oidcConfig = {
  id: "auth-federation/provider-config/oidc",
  providers: ["oidc.fireemu-RUN-a", "oidc.fireemu-RUN-b"],
  steps: [
    admin("create", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-a" },
      body: {
        clientId: "client-a",
        issuer: ISSUER,
        enabled: true,
        responseType: { idToken: true },
      },
    }),
    admin("create-duplicate", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-a" },
      body: { clientId: "client-a", issuer: ISSUER },
    }),
    admin("create-without-prefix", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "fireemu-RUN-noprefix" },
      body: { clientId: "c", issuer: ISSUER },
    }),
    admin("create-without-client", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-b" },
      body: { issuer: ISSUER },
    }),
    admin("create-both-responses", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-b" },
      body: { clientId: "c", issuer: ISSUER, responseType: { idToken: true, code: true } },
    }),
    admin("create-code-without-secret", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-b" },
      body: { clientId: "c", issuer: ISSUER, responseType: { code: true } },
    }),
    admin("create-http-issuer", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-b" },
      body: { clientId: "c", issuer: "http://{project}.web.app/oidc/RUN" },
    }),
    admin("get", "GET", "oauthIdpConfigs/oidc.fireemu-RUN-a"),
    admin("list", "GET", "oauthIdpConfigs", { query: { pageSize: "1" } }),
    admin("patch-display-name", "PATCH", "oauthIdpConfigs/oidc.fireemu-RUN-a", {
      query: { updateMask: "displayName" },
      body: { displayName: "Run A", clientId: "ignored" },
    }),
    admin("patch-secret", "PATCH", "oauthIdpConfigs/oidc.fireemu-RUN-a", {
      query: { updateMask: "clientSecret" },
      body: { clientSecret: "fireemu-secret" },
    }),
    admin("get-after-secret", "GET", "oauthIdpConfigs/oidc.fireemu-RUN-a"),
    admin("delete", "DELETE", "oauthIdpConfigs/oidc.fireemu-RUN-a"),
    admin("get-deleted", "GET", "oauthIdpConfigs/oidc.fireemu-RUN-a"),
  ],
};

const samlConfig = {
  id: "auth-federation/provider-config/saml",
  providers: ["saml.fireemu-RUN-a", "saml.fireemu-RUN-b"],
  steps: [
    admin("create", "POST", "inboundSamlConfigs", {
      query: { inboundSamlConfigId: "saml.fireemu-RUN-a" },
      body: {
        idpConfig: {
          idpEntityId: "https://{project}.web.app/saml/RUN",
          ssoUrl: "https://{project}.web.app/saml/RUN/sso",
          idpCertificates: [{ x509Certificate: "CERT(saml-a)" }],
        },
        spConfig: {
          spEntityId: "https://{project}.firebaseapp.com/saml/RUN",
          callbackUri: "https://{project}.firebaseapp.com/__/auth/handler",
        },
        enabled: true,
      },
    }),
    admin("create-bad-certificate", "POST", "inboundSamlConfigs", {
      query: { inboundSamlConfigId: "saml.fireemu-RUN-b" },
      body: {
        idpConfig: {
          idpEntityId: "https://{project}.web.app/saml/RUN",
          ssoUrl: "https://{project}.web.app/saml/RUN/sso",
          idpCertificates: [{ x509Certificate: "fireemu-not-a-certificate" }],
        },
        spConfig: {
          spEntityId: "https://{project}.firebaseapp.com/saml/RUN",
          callbackUri: "https://{project}.firebaseapp.com/__/auth/handler",
        },
      },
    }),
    admin("get", "GET", "inboundSamlConfigs/saml.fireemu-RUN-a"),
    admin("patch-sign-request", "PATCH", "inboundSamlConfigs/saml.fireemu-RUN-a", {
      query: { updateMask: "idpConfig.signRequest" },
      body: { idpConfig: { signRequest: true } },
    }),
    admin("get-after-sign-request", "GET", "inboundSamlConfigs/saml.fireemu-RUN-a"),
    admin("delete", "DELETE", "inboundSamlConfigs/saml.fireemu-RUN-a"),
  ],
};

const defaultSupported = {
  id: "auth-federation/provider-config/default-supported",
  defaultIdpWrites: ["facebook.com"],
  steps: [
    { id: "list-supported", auth: "admin", method: "GET", path: "admin/v2/defaultSupportedIdps" },
    admin("list", "GET", "defaultSupportedIdpConfigs"),
    admin("create", "POST", "defaultSupportedIdpConfigs", {
      query: { idpId: "facebook.com" },
      body: { enabled: false, clientId: "fireemu-client", clientSecret: "fireemu-secret" },
    }),
    admin("get", "GET", "defaultSupportedIdpConfigs/facebook.com"),
    admin("patch-enabled", "PATCH", "defaultSupportedIdpConfigs/facebook.com", {
      query: { updateMask: "enabled" },
      body: { enabled: true },
    }),
    admin("delete", "DELETE", "defaultSupportedIdpConfigs/facebook.com"),
    admin("get-deleted", "GET", "defaultSupportedIdpConfigs/facebook.com"),
  ],
};

/** A manual-credential signInWithIdp body; `form` becomes the URL-encoded `postBody`. */
export const idp = (form, extra = {}) => ({
  requestUri: "http://localhost",
  postBody: { $form: form },
  returnSecureToken: true,
  returnIdpCredential: true,
  ...extra,
});
export const from = (reference) => ({ $from: reference });
export const token = (name) => ({ $token: name });

const thirdPartyRefusals = {
  id: "auth-federation/third-party-refusals",
  providers: ["oidc.fireemu-RUN-off"],
  steps: [
    client(
      "google-garbage-id-token",
      "signInWithIdp",
      idp({ providerId: "google.com", id_token: "fireemu-garbage" }),
    ),
    client(
      "facebook-garbage-access-token",
      "signInWithIdp",
      idp({ providerId: "facebook.com", access_token: "fireemu-garbage" }),
    ),
    client(
      "unconfigured-oidc",
      "signInWithIdp",
      idp({ providerId: "oidc.fireemu-RUN-missing", id_token: "TOKEN(missing)" }),
    ),
    admin("create-disabled", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-off" },
      body: { clientId: "client-off", issuer: ISSUER, enabled: false },
    }),
    client(
      "disabled-oidc",
      "signInWithIdp",
      idp({ providerId: "oidc.fireemu-RUN-off", id_token: "TOKEN(off)" }),
    ),
    client("create-auth-uri-disabled", "createAuthUri", {
      providerId: "oidc.fireemu-RUN-off",
      continueUri: "https://{project}.firebaseapp.com/__/auth/handler",
    }),
    admin("delete-disabled", "DELETE", "oauthIdpConfigs/oidc.fireemu-RUN-off"),
  ],
};

// ---- the controlled OIDC IdP (O1) --------------------------------------------------------
//
// Each program creates its own enabled provider for the run's issuer (published on the
// sandbox's Hosting) and signs its ID tokens with the run's key. `tokens` describes them:
// `claims` merged over the default claims (iss, aud, sub, iat, exp), `$now: s` for a time
// relative to the run, `$sha256: raw` for a hashed nonce, `drop` for claims left out, a
// `header` override and `signWith: "other"` for a key the issuer does not publish.

export const oidcProvider = (letter) => `oidc.fireemu-RUN-${letter}`;
export const createOidc = (letter, extra = {}) =>
  admin(`create-provider`, "POST", "oauthIdpConfigs", {
    query: { oauthIdpConfigId: oidcProvider(letter) },
    body: {
      clientId: `client-${letter}`,
      issuer: ISSUER,
      enabled: true,
      responseType: { idToken: true },
      ...extra,
    },
  });
export const signIn = (id, letter, tokenName, extra = {}, form = {}) =>
  client(
    id,
    "signInWithIdp",
    idp({ providerId: oidcProvider(letter), id_token: token(tokenName), ...form }, extra),
  );
export const lookup = (id, reference) => ({
  id,
  auth: "admin",
  path: "v1/projects/{project}/accounts:lookup",
  body: { localId: [from(reference)] },
});

const oidcVerification = {
  id: "auth-federation/oidc/verification",
  providers: [oidcProvider("v"), oidcProvider("u")],
  client: "client-v",
  tokens: {
    valid: { claims: { email: "EMAIL(valid)", email_verified: true } },
    "other-key": { signWith: "other" },
    "unknown-kid": { header: { kid: "fireemu-unknown-kid" } },
    "wrong-issuer": { claims: { iss: "https://{project}.web.app/oidc/RUN-other" } },
    "wrong-audience": { claims: { aud: "client-other" } },
    "several-audiences": { claims: { aud: ["client-v", "client-other"] } },
    expired: { claims: { iat: { $now: -7200 }, exp: { $now: -3600 } } },
    "issued-in-future": { claims: { iat: { $now: 3600 }, exp: { $now: 7200 } } },
    "not-yet-valid": { claims: { nbf: { $now: 3600 } } },
    "without-subject": { drop: ["sub"] },
    "hs256-header": { header: { alg: "HS256" } },
    "unpublished-issuer": { claims: { iss: "https://ISSUERHOST/oidc/RUN-unpublished" } },
  },
  steps: [
    createOidc("v"),
    signIn("valid", "v", "valid"),
    ...[
      "other-key",
      "unknown-kid",
      "wrong-issuer",
      "wrong-audience",
      "several-audiences",
      "expired",
      "issued-in-future",
      "not-yet-valid",
      "without-subject",
      "hs256-header",
    ].map((name) => signIn(name, "v", name)),
    client(
      "garbage",
      "signInWithIdp",
      idp({ providerId: oidcProvider("v"), id_token: "fireemu-garbage" }),
    ),
    client("missing-token", "signInWithIdp", idp({ providerId: oidcProvider("v") })),
    // The run's provider named in another case: strict refuses it (O4), production unobserved.
    signIn("mixed-case-provider", "V", "valid"),
    // A provider whose issuer publishes no discovery document or keys.
    admin("create-unpublished", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: oidcProvider("u") },
      body: {
        clientId: "client-v",
        issuer: "https://ISSUERHOST/oidc/RUN-unpublished",
        enabled: true,
        responseType: { idToken: true },
      },
    }),
    signIn("unpublished-issuer", "u", "unpublished-issuer"),
  ],
};

const oidcNonce = {
  id: "auth-federation/oidc/nonce",
  providers: [oidcProvider("n")],
  client: "client-n",
  tokens: {
    hashed: { claims: { nonce: { $sha256: "fireemu-nonce-a" } } },
    plain: {},
  },
  steps: [
    createOidc("n"),
    signIn("matching-nonce", "n", "hashed", {}, { nonce: "fireemu-nonce-a" }),
    signIn("other-nonce", "n", "hashed", {}, { nonce: "fireemu-nonce-b" }),
    signIn("token-nonce-only", "n", "hashed"),
    signIn("request-nonce-only", "n", "plain", {}, { nonce: "fireemu-nonce-a" }),
  ],
};

const oidcReplay = {
  id: "auth-federation/oidc/replay",
  providers: [oidcProvider("r")],
  client: "client-r",
  tokens: { once: {} },
  steps: [createOidc("r"), signIn("first", "r", "once"), signIn("again", "r", "once")],
};

const accountsNew = {
  id: "auth-federation/accounts/new",
  providers: [oidcProvider("a")],
  client: "client-a",
  tokens: {
    profile: {
      claims: {
        sub: "sub-profile",
        email: "EMAIL(new)",
        email_verified: true,
        name: "Fed User",
        picture: "https://{project}.web.app/picture.png",
      },
    },
    "unverified-email": {
      claims: { sub: "sub-unverified", email: "EMAIL(unverified)", email_verified: false },
    },
    "without-email": { claims: { sub: "sub-no-email" } },
  },
  steps: [
    createOidc("a"),
    signIn("profile", "a", "profile"),
    lookup("lookup-profile", "profile:localId"),
    signIn("unverified-email", "a", "unverified-email"),
    signIn("without-email", "a", "without-email"),
  ],
};

const accountsReturning = {
  id: "auth-federation/accounts/returning",
  providers: [oidcProvider("b")],
  client: "client-b",
  tokens: {
    first: { claims: { sub: "sub-returning", email: "EMAIL(returning)", email_verified: true } },
    second: {
      claims: {
        sub: "sub-returning",
        email: "EMAIL(returning)",
        email_verified: true,
        name: "Renamed",
      },
    },
  },
  steps: [
    createOidc("b"),
    signIn("first", "b", "first"),
    signIn("second", "b", "second"),
    lookup("lookup-after-second", "second:localId"),
  ],
};

export const adminCreate = (id, body) => ({
  id,
  auth: "admin",
  path: "v1/projects/{project}/accounts",
  body,
});

const collisionVerified = {
  id: "auth-federation/collision/verified",
  providers: [oidcProvider("c")],
  client: "client-c",
  tokens: {
    verified: { claims: { sub: "sub-verified", email: "EMAIL(owner-v)", email_verified: true } },
  },
  steps: [
    createOidc("c"),
    adminCreate("create-owner", { email: "EMAIL(owner-v)", password: "fireemu-password-1" }),
    signIn("verified-email", "c", "verified"),
    lookup("lookup-owner", "create-owner:localId"),
  ],
};

const collisionUnverified = {
  id: "auth-federation/collision/unverified",
  providers: [oidcProvider("u")],
  client: "client-u",
  tokens: {
    unverified: {
      claims: { sub: "sub-unverified", email: "EMAIL(owner-u)", email_verified: false },
    },
  },
  steps: [
    createOidc("u"),
    adminCreate("create-owner", { email: "EMAIL(owner-u)", password: "fireemu-password-1" }),
    signIn("unverified-email", "u", "unverified"),
    lookup("lookup-owner", "create-owner:localId"),
  ],
};

const link = {
  id: "auth-federation/link",
  providers: [oidcProvider("l")],
  client: "client-l",
  tokens: {
    first: { claims: { sub: "sub-first", email: "EMAIL(first)", email_verified: true } },
    second: { claims: { sub: "sub-second" } },
    "second-again": { claims: { sub: "sub-second" } },
    "taken-email": { claims: { sub: "sub-taken", email: "EMAIL(taken)", email_verified: true } },
  },
  steps: [
    createOidc("l"),
    signIn("first", "l", "first"),
    adminCreate("create-other", { email: "EMAIL(other)", password: "fireemu-password-1" }),
    adminCreate("create-taken", { email: "EMAIL(taken)", password: "fireemu-password-1" }),
    signIn("link-second", "l", "second", { idToken: from("first:idToken") }),
    lookup("lookup-linked", "first:localId"),
    signIn("link-linked-elsewhere", "l", "second-again", { idToken: from("first:idToken") }),
    signIn("link-linked-elsewhere-without-credential", "l", "second-again", {
      idToken: from("first:idToken"),
      returnIdpCredential: false,
    }),
    signIn("link-taken-email", "l", "taken-email", { idToken: from("first:idToken") }),
  ],
};

const duplicateEmail = {
  id: "auth-federation/duplicate-email",
  providers: [oidcProvider("d")],
  client: "client-d",
  touches: ["signIn.allowDuplicateEmails"],
  tokens: {
    shared: { claims: { sub: "sub-shared", email: "EMAIL(shared)", email_verified: true } },
  },
  steps: [
    createOidc("d"),
    admin("allow-duplicates", "PATCH", "config", {
      query: { updateMask: "signIn.allowDuplicateEmails" },
      body: { signIn: { allowDuplicateEmails: true } },
      // The answer is the whole project config: only the member written is recorded.
      record: ["signIn.allowDuplicateEmails"],
    }),
    adminCreate("create-owner", { email: "EMAIL(shared)", password: "fireemu-password-1" }),
    signIn("sign-in-with-duplicates-allowed", "d", "shared"),
    lookup("lookup-owner", "create-owner:localId"),
  ],
};

const pendingToken = {
  id: "auth-federation/pending-token",
  providers: [oidcProvider("p")],
  client: "client-p",
  tokens: {
    first: { claims: { sub: "sub-pending", email: "EMAIL(pending)", email_verified: true } },
  },
  steps: [
    createOidc("p"),
    signIn("first", "p", "first"),
    client("pending-token", "signInWithIdp", {
      requestUri: "http://localhost",
      pendingToken: from("first:pendingToken"),
      returnSecureToken: true,
    }),
    client("pending-token-again", "signInWithIdp", {
      requestUri: "http://localhost",
      pendingToken: from("first:pendingToken"),
      returnSecureToken: true,
    }),
  ],
};

export const refresh = (id, reference) => ({
  id,
  auth: "key",
  path: "v1/token",
  body: { grant_type: "refresh_token", refresh_token: from(reference) },
});
const cookie = (id, reference) => ({
  id,
  auth: "admin",
  path: "v1/projects/{project}:createSessionCookie",
  body: { idToken: from(reference), validDuration: "3600" },
});

/** The IdP session claims (C7), each condition a program of its own sign-in. */
const claimsProgram = (suffix, letter, extra) => ({
  id: `auth-federation/claims/${suffix}`,
  providers: [oidcProvider(letter)],
  client: `client-${letter}`,
  tokens: {
    rich: {
      claims: {
        sub: `sub-claims-${suffix}`,
        email: `EMAIL(claims-${suffix})`,
        email_verified: true,
        name: "Claims User",
        department: "fireemu",
      },
    },
  },
  steps: [createOidc(letter), signIn("sign-in", letter, "rich"), ...extra],
});
const claimsSignIn = claimsProgram("sign-in", "s", []);
const claimsRefresh = claimsProgram("refresh", "t", [refresh("refresh", "sign-in:refreshToken")]);
const claimsCookie = claimsProgram("session-cookie", "k", [
  refresh("refresh", "sign-in:refreshToken"),
  cookie("cookie-from-sign-in", "sign-in:idToken"),
  cookie("cookie-from-refresh", "refresh:id_token"),
]);

const createAuthUri = {
  id: "auth-federation/create-auth-uri",
  providers: [oidcProvider("q")],
  steps: [
    createOidc("q"),
    client("create-auth-uri", "createAuthUri", {
      providerId: oidcProvider("q"),
      continueUri: "https://{project}.firebaseapp.com/__/auth/handler",
    }),
    client("create-auth-uri-without-continue", "createAuthUri", { providerId: oidcProvider("q") }),
  ],
};

const requestUri = {
  id: "auth-federation/request-uri",
  providers: [oidcProvider("w")],
  client: "client-w",
  tokens: { session: { claims: { sub: "sub-session" } } },
  steps: [
    createOidc("w"),
    client("create-auth-uri", "createAuthUri", {
      providerId: oidcProvider("w"),
      continueUri: "https://{project}.firebaseapp.com/__/auth/handler",
    }),
    signIn("with-session", "w", "session", {
      requestUri: "https://{project}.firebaseapp.com/__/auth/handler",
      sessionId: from("create-auth-uri:sessionId"),
    }),
    signIn("with-wrong-session", "w", "session", {
      requestUri: "https://{project}.firebaseapp.com/__/auth/handler",
      sessionId: "fireemu-wrong-session",
    }),
    signIn("with-other-request-uri", "w", "session", {
      requestUri: "https://{project}.web.app/__/auth/handler",
      sessionId: from("create-auth-uri:sessionId"),
    }),
    signIn("without-session", "w", "session", {
      requestUri: "https://{project}.firebaseapp.com/__/auth/handler",
    }),
  ],
};

const providerEnablement = {
  id: "auth-federation/provider-enablement",
  providers: [oidcProvider("e")],
  client: "client-e",
  tokens: { valid: { claims: { sub: "sub-enabled" } } },
  steps: [
    createOidc("e"),
    signIn("enabled", "e", "valid"),
    admin("disable", "PATCH", `oauthIdpConfigs/${oidcProvider("e")}`, {
      query: { updateMask: "enabled" },
      body: { enabled: false },
    }),
    signIn("disabled", "e", "valid"),
  ],
};

export const PROGRAMS = [
  oidcConfig,
  samlConfig,
  defaultSupported,
  thirdPartyRefusals,
  oidcVerification,
  oidcNonce,
  oidcReplay,
  accountsNew,
  accountsReturning,
  collisionVerified,
  collisionUnverified,
  link,
  duplicateEmail,
  pendingToken,
  claimsSignIn,
  claimsRefresh,
  claimsCookie,
  createAuthUri,
  requestUri,
  providerEnablement,
];

/**
 * The corpus with this run's values in place of its placeholders: `{project}`, `RUN` (the
 * run's tag), `ISSUERHOST` (the run's preview channel; required, never the live site),
 * `CERT(name)` and `TOKEN(name)` from the given maps.
 */
export function resolveCorpus(
  programs,
  { project, run, issuerHost, certificates = {}, tokens = {} },
) {
  if (!issuerChannelHost(project, run).test(issuerHost ?? "")) {
    throw new Error(`issuer host ${issuerHost} is not the run's preview channel of the sandbox`);
  }
  const text = (value) =>
    value
      .replaceAll("ISSUERHOST", issuerHost)
      .replaceAll("{project}", project)
      .replaceAll(/EMAIL\(([\w-]+)\)/g, (_, name) => `fireemu-fed-RUN-${name}@example.com`)
      .replaceAll("RUN", run)
      .replaceAll(/CERT\(([\w-]+)\)/g, (_, name) => certificates[name] ?? `fireemu-no-cert-${name}`)
      .replaceAll(/TOKEN\(([\w-]+)\)/g, (_, name) => tokens[name] ?? `fireemu-no-token-${name}`);
  const walk = (value) => {
    if (typeof value === "string") return text(value);
    if (Array.isArray(value)) return value.map(walk);
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, walk(v)]));
    }
    return value;
  };
  return walk(programs);
}
