// AUTH-FEDERATION record-saml corpus: what record-oidc left unobserved (closure materials N1 to
// N8). SAML sign-ins with the run's IdP (each SAMLResponse signed at its step, answering the
// AuthnRequest a createAuthUri step returned), the SAML conditions production may check (one
// condition changed per row), attributes, the ACS a createAuthUri names, an expired signing
// certificate, and the OIDC rows record-oidc could not tell apart. Placeholders as in
// corpus.mjs; `CERT(saml-expired)` is a certificate of the run whose validity has ended.

import {
  admin,
  adminCreate,
  client,
  createOidc,
  from,
  idp,
  lookup,
  oidcProvider,
  refresh,
  signIn,
} from "./corpus.mjs";

const SAML_IDP = "https://{project}.web.app/saml/RUN";
const SSO = "https://{project}.web.app/saml/RUN/sso";
const SP = "https://{project}.firebaseapp.com/saml/RUN";
const CALLBACK = "https://{project}.firebaseapp.com/__/auth/handler";

const samlProvider = (letters) => `saml.fireemu-RUN-${letters}`;
const createSaml = (letters, certificate = "saml-a") =>
  admin("create-provider", "POST", "inboundSamlConfigs", {
    query: { inboundSamlConfigId: samlProvider(letters) },
    body: {
      idpConfig: {
        idpEntityId: SAML_IDP,
        ssoUrl: SSO,
        idpCertificates: [{ x509Certificate: `CERT(${certificate})` }],
      },
      spConfig: { spEntityId: SP, callbackUri: CALLBACK },
      enabled: true,
    },
  });
const authUri = (id, letters, continueUri = CALLBACK) =>
  client(id, "createAuthUri", { providerId: samlProvider(letters), continueUri });
/**
 * A SAML sign-in answering the AuthnRequest of step `request`, with its session and relay
 * state. `spec` changes the response (see run.mjs `samlValue`).
 */
const samlSignIn = (id, letters, request, spec = {}) =>
  client(id, "signInWithIdp", {
    requestUri: CALLBACK,
    sessionId: from(`${request}:sessionId`),
    postBody: {
      $form: {
        providerId: samlProvider(letters),
        SAMLResponse: {
          $saml: { request, issuer: SAML_IDP, audience: SP, destination: CALLBACK, ...spec },
        },
        RelayState: { $relayState: request },
      },
    },
    returnSecureToken: true,
    returnIdpCredential: true,
  });

const samlSignInProgram = {
  id: "auth-federation/saml/sign-in",
  providers: [samlProvider("si")],
  steps: [
    createSaml("si"),
    authUri("auth-uri", "si"),
    samlSignIn("first", "si", "auth-uri", {
      nameId: "EMAIL(saml-first)",
      attributes: { department: "fireemu" },
    }),
    authUri("auth-uri-again", "si"),
    samlSignIn("returning", "si", "auth-uri-again", {
      nameId: "EMAIL(saml-first)",
      attributes: { department: "renamed" },
    }),
    lookup("lookup", "first:localId"),
    refresh("refresh", "first:refreshToken"),
  ],
};

/** One condition changed per row, the NameID shared: an accepted row signs one account in. */
const CONDITIONS = {
  valid: {},
  "audience-other": { audience: "https://{project}.firebaseapp.com/saml/RUN-other" },
  "destination-other": {
    destination: "https://{project}.firebaseapp.com/__/auth/other",
    recipient: CALLBACK,
  },
  "recipient-other": { recipient: "https://{project}.firebaseapp.com/__/auth/other" },
  "not-yet-valid": { conditions: { notBefore: 600 } },
  "expired-conditions": { conditions: { notBefore: -1200, notOnOrAfter: -600 } },
  "expired-confirmation": { confirmationNotOnOrAfter: -600 },
  "in-response-to-other": { inResponseTo: "_fireemu-other-request" },
  "in-response-to-absent": { inResponseTo: null },
  "issuer-other": { assertionIssuer: "https://{project}.web.app/saml/RUN-other" },
  "status-failure": { status: "urn:oasis:names:tc:SAML:2.0:status:Requester" },
};
const samlConditions = {
  id: "auth-federation/saml/conditions",
  providers: [samlProvider("co")],
  steps: [
    createSaml("co"),
    ...Object.entries(CONDITIONS).flatMap(([row, spec]) => [
      authUri(`${row}-auth-uri`, "co"),
      samlSignIn(row, "co", `${row}-auth-uri`, { nameId: "EMAIL(saml-conditions)", ...spec }),
    ]),
  ],
};

const samlAttributes = {
  id: "auth-federation/saml/attributes",
  providers: [samlProvider("at")],
  steps: [
    createSaml("at"),
    authUri("persistent-auth-uri", "at"),
    samlSignIn("persistent-name-id", "at", "persistent-auth-uri", {
      nameId: "fireemu-RUN-persistent-1",
      nameIdFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    }),
    lookup("lookup-persistent", "persistent-name-id:localId"),
    authUri("multi-auth-uri", "at"),
    samlSignIn("multi-valued", "at", "multi-auth-uri", {
      nameId: "EMAIL(saml-multi)",
      attributes: { groups: ["reader", "writer"], department: "fireemu" },
    }),
  ],
};

const samlAcs = {
  id: "auth-federation/saml/acs",
  providers: [samlProvider("ac")],
  steps: [
    createSaml("ac"),
    authUri("other-continue", "ac", "https://{project}.web.app/__/auth/handler"),
  ],
};

const samlCertificate = {
  id: "auth-federation/saml/certificate",
  providers: [samlProvider("ex")],
  steps: [
    createSaml("ex", "saml-expired"),
    authUri("auth-uri", "ex"),
    samlSignIn("expired-certificate", "ex", "auth-uri", {
      nameId: "EMAIL(saml-expired)",
      key: "expired",
    }),
  ],
};

const duplicateEmailLookup = {
  id: "auth-federation/duplicate-email-lookup",
  providers: [oidcProvider("dm")],
  client: "client-dm",
  touches: ["signIn.allowDuplicateEmails"],
  tokens: {
    shared: { claims: { sub: "sub-dm-shared", email: "EMAIL(dm-shared)", email_verified: true } },
  },
  steps: [
    createOidc("dm"),
    admin("allow-duplicates", "PATCH", "config", {
      query: { updateMask: "signIn.allowDuplicateEmails" },
      body: { signIn: { allowDuplicateEmails: true } },
      record: ["signIn.allowDuplicateEmails"],
    }),
    adminCreate("create-owner", { email: "EMAIL(dm-shared)", password: "fireemu-password-1" }),
    signIn("sign-in", "dm", "shared"),
    lookup("lookup-new", "sign-in:localId"),
    lookup("lookup-owner", "create-owner:localId"),
    client("identifier", "createAuthUri", { identifier: "EMAIL(dm-shared)", continueUri: CALLBACK }),
  ],
};

const oidcNonceMismatch = {
  id: "auth-federation/oidc/nonce-mismatch",
  providers: [oidcProvider("nm")],
  client: "client-nm",
  tokens: { fresh: { claims: { sub: "sub-nm", nonce: { $sha256: "fireemu-nonce-a" } } } },
  steps: [createOidc("nm"), signIn("mismatch", "nm", "fresh", {}, { nonce: "fireemu-nonce-b" })],
};

/** iat moved into the past with exp still ahead: where production calls a token stale. */
const STALE = [300, 1800, 3500, 3700, 7200];
const oidcStale = {
  id: "auth-federation/oidc/stale",
  providers: [oidcProvider("st")],
  client: "client-st",
  tokens: Object.fromEntries(
    STALE.map((age) => [
      `iat-minus-${age}`,
      { claims: { sub: "sub-st", iat: { $now: -age }, exp: { $now: 600 } } },
    ]),
  ),
  steps: [
    createOidc("st"),
    ...STALE.map((age) => signIn(`iat-minus-${age}`, "st", `iat-minus-${age}`)),
  ],
};

const oidcAzp = {
  id: "auth-federation/oidc/azp",
  providers: [oidcProvider("az")],
  client: "client-az",
  tokens: {
    "other-party": { claims: { sub: "sub-az", azp: "client-other" } },
    "own-party": { claims: { sub: "sub-az", azp: "client-az", aud: ["client-az", "client-x"] } },
  },
  steps: [
    createOidc("az"),
    signIn("azp-other", "az", "other-party"),
    signIn("azp-own", "az", "own-party"),
  ],
};

const thirdPartyConfigured = {
  id: "auth-federation/third-party-configured",
  defaultIdpWrites: ["google.com"],
  steps: [
    admin("create-google", "POST", "defaultSupportedIdpConfigs", {
      query: { idpId: "google.com" },
      body: { enabled: true, clientId: "fireemu-client", clientSecret: "fireemu-secret" },
    }),
    client(
      "google-garbage-id-token",
      "signInWithIdp",
      idp({ providerId: "google.com", id_token: "fireemu-garbage" }),
    ),
    admin("delete-google", "DELETE", "defaultSupportedIdpConfigs/google.com"),
  ],
};

export const SAML_PROGRAMS = [
  samlSignInProgram,
  samlConditions,
  samlAttributes,
  samlAcs,
  samlCertificate,
  duplicateEmailLookup,
  oidcNonceMismatch,
  oidcStale,
  oidcAzp,
  thirdPartyConfigured,
];
