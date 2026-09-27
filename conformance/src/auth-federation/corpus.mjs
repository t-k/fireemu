// AUTH-FEDERATION corpus, draft. Only the programs that do not depend on the open owner
// decisions (O1 to O6 of the closure draft): provider configuration and the refusals of
// providers this parent does not sign in with. The controlled-IdP programs (signed OIDC and
// SAML sign-in, linking, collision and the session claims) are added once the decisions and
// the frozen closure conditions exist. Nothing here has been sent.
//
// Placeholders the harness resolves per run: `{project}`; `RUN` (a short run tag, so provider
// IDs are `oidc.fireemu-RUN-…`); `CERT(name)`, a PEM certificate of a key made for this run;
// `TOKEN(name)`, an ID token signed with the run's key.

const admin = (id, method, path, extra = {}) => ({
  id,
  auth: "admin",
  method,
  path: `admin/v2/projects/{project}/${path}`,
  ...extra,
});
const client = (id, method, body) => ({ id, auth: "key", path: `v1/accounts:${method}`, body });

const ISSUER = "https://{project}.web.app/oidc/RUN";

const oidcConfig = {
  id: "auth-federation/provider-config/oidc",
  providers: ["oidc.fireemu-RUN-a", "oidc.fireemu-RUN-b"],
  steps: [
    admin("create", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-a" },
      body: { clientId: "client-a", issuer: ISSUER, enabled: true, responseType: { idToken: true } },
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
  providers: ["saml.fireemu-RUN-a"],
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

const idp = (postBody) => ({
  requestUri: "http://localhost",
  postBody,
  returnSecureToken: true,
  returnIdpCredential: true,
});

const thirdPartyRefusals = {
  id: "auth-federation/third-party-refusals",
  providers: ["oidc.fireemu-RUN-off"],
  steps: [
    client("google-garbage-id-token", "signInWithIdp", idp("providerId=google.com&id_token=fireemu-garbage")),
    client("facebook-garbage-access-token", "signInWithIdp", idp("providerId=facebook.com&access_token=fireemu-garbage")),
    client("unconfigured-oidc", "signInWithIdp", idp("providerId=oidc.fireemu-RUN-missing&id_token=TOKEN(missing)")),
    admin("create-disabled", "POST", "oauthIdpConfigs", {
      query: { oauthIdpConfigId: "oidc.fireemu-RUN-off" },
      body: { clientId: "client-off", issuer: ISSUER, enabled: false },
    }),
    client("disabled-oidc", "signInWithIdp", idp("providerId=oidc.fireemu-RUN-off&id_token=TOKEN(off)")),
    client("create-auth-uri-disabled", "createAuthUri", {
      providerId: "oidc.fireemu-RUN-off",
      continueUri: "https://{project}.firebaseapp.com/__/auth/handler",
    }),
    admin("delete-disabled", "DELETE", "oauthIdpConfigs/oidc.fireemu-RUN-off"),
  ],
};

export const PROGRAMS = [oidcConfig, samlConfig, defaultSupported, thirdPartyRefusals];

/**
 * The corpus with this run's values in place of its placeholders: `{project}`, `RUN` (a
 * lowercase tag), `CERT(name)` and `TOKEN(name)` from the given maps.
 */
export function resolveCorpus(programs, { project, run, certificates = {}, tokens = {} }) {
  const text = (value) =>
    value
      .replaceAll("{project}", project)
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
