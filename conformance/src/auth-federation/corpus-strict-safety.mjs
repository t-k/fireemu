// AUTH-FEDERATION record-strict-safety corpus (the coordinator's N10 packet, 2026-09-29). The
// strict profile has behaviours that production's recordings never observed; these programs
// observe them, so each can be kept, changed or documented on evidence:
// - a SAML response signed with SHA-1 (signature and digest);
// - a response without NotOnOrAfter on its Conditions, its SubjectConfirmationData or both;
// - the same response sent again, without a session and within one session;
// - createAuthUri with characters that need escaping in `continueUri` and in a provider's `clientId`;
// - a nonce-bearing sign-in, its continuation resumed twice, and the continuation a link
//   refusal answers with. record-oidc recorded a resume and a repeated one only for a credential
//   without a nonce.
// Program IDs sit under existing closure recipes, so no recipe changes. Placeholders as in
// corpus.mjs.

import { client, createOidc, from, oidcProvider, signIn } from "./corpus.mjs";
import { authUri, createSaml, samlProvider, samlSignIn } from "./corpus-saml.mjs";

const SAML_IDP = "https://{project}.web.app/saml/RUN";
const SP = "https://{project}.firebaseapp.com/saml/RUN";
const CALLBACK = "https://{project}.firebaseapp.com/__/auth/handler";

const samlSha1 = {
  id: "auth-federation/saml/signature/sha1",
  providers: [samlProvider("s1")],
  steps: [
    createSaml("s1"),
    authUri("auth-uri", "s1"),
    samlSignIn("sha1", "s1", "auth-uri", { nameId: "EMAIL(saml-sha1)", algorithm: "sha1" }),
  ],
};

const samlOpenEnded = {
  id: "auth-federation/saml/conditions/open-ended",
  providers: [samlProvider("oe")],
  steps: [
    createSaml("oe"),
    authUri("conditions-auth-uri", "oe"),
    samlSignIn("no-conditions-end", "oe", "conditions-auth-uri", {
      nameId: "EMAIL(saml-open)",
      conditions: { notOnOrAfter: null },
    }),
    authUri("confirmation-auth-uri", "oe"),
    samlSignIn("no-confirmation-end", "oe", "confirmation-auth-uri", {
      nameId: "EMAIL(saml-open)",
      confirmationNotOnOrAfter: null,
    }),
    authUri("both-auth-uri", "oe"),
    samlSignIn("no-end-at-all", "oe", "both-auth-uri", {
      nameId: "EMAIL(saml-open)",
      conditions: { notOnOrAfter: null },
      confirmationNotOnOrAfter: null,
    }),
  ],
};

/** A sign-in that names no session: what an IdP-initiated response looks like. */
const samlSignInWithoutSession = (id, letters, spec) =>
  client(id, "signInWithIdp", {
    requestUri: CALLBACK,
    postBody: {
      $form: {
        providerId: samlProvider(letters),
        SAMLResponse: {
          $saml: { issuer: SAML_IDP, audience: SP, destination: CALLBACK, ...spec },
        },
      },
    },
    returnSecureToken: true,
    returnIdpCredential: true,
  });

const samlReplay = {
  id: "auth-federation/saml/sign-in/replay",
  providers: [samlProvider("rp")],
  steps: [
    createSaml("rp"),
    samlSignInWithoutSession("unsolicited-first", "rp", {
      nameId: "EMAIL(saml-replay)",
      inResponseTo: null,
      remember: "unsolicited",
    }),
    samlSignInWithoutSession("unsolicited-again", "rp", { reuse: "unsolicited" }),
    authUri("auth-uri", "rp"),
    samlSignIn("session-first", "rp", "auth-uri", {
      nameId: "EMAIL(saml-replay)",
      remember: "session",
    }),
    samlSignIn("session-again", "rp", "auth-uri", { reuse: "session" }),
  ],
};

/** The continueUri variants: each puts one character that needs escaping into the URL. */
const CONTINUE_URIS = {
  ampersand: `${CALLBACK}?a=1&b=2`,
  fragment: `${CALLBACK}#fragment`,
  space: `${CALLBACK}?q=a b`,
  percent: `${CALLBACK}?q=%41`,
  plus: `${CALLBACK}?q=a+b`,
  "non-ascii": "https://{project}.firebaseapp.com/__/auth/hándler",
};

const createAuthUriEscaping = {
  id: "auth-federation/create-auth-uri/escaping",
  providers: [oidcProvider("es"), oidcProvider("ec")],
  steps: [
    createOidc("es"),
    ...Object.entries(CONTINUE_URIS).map(([row, continueUri]) =>
      client(`continue-${row}`, "createAuthUri", { providerId: oidcProvider("es"), continueUri }),
    ),
    { ...createOidc("ec", { clientId: "client&x=1 é" }), id: "create-provider-special-client" },
    client("special-client-id", "createAuthUri", {
      providerId: oidcProvider("ec"),
      continueUri: CALLBACK,
    }),
  ],
};

const resume = (id, reference) =>
  client(id, "signInWithIdp", {
    requestUri: "http://localhost",
    pendingToken: from(reference),
    returnSecureToken: true,
  });

const pendingTokenNonce = {
  id: "auth-federation/pending-token/nonce",
  providers: [oidcProvider("nr")],
  client: "client-nr",
  tokens: {
    first: {
      claims: {
        sub: "sub-nr-first-PASSTAG",
        email: "EMAIL(nr-first)",
        email_verified: true,
        nonce: { $sha256: "fireemu-nonce-a-PASSTAG" },
      },
    },
    second: { claims: { sub: "sub-nr-second-PASSTAG", nonce: { $sha256: "fireemu-nonce-b-PASSTAG" } } },
    "second-again": { claims: { sub: "sub-nr-second-PASSTAG", nonce: { $sha256: "fireemu-nonce-c-PASSTAG" } } },
  },
  steps: [
    createOidc("nr"),
    signIn("first", "nr", "first", {}, { nonce: "fireemu-nonce-a-PASSTAG" }),
    resume("resume", "first:pendingToken"),
    resume("resume-again", "first:pendingToken"),
    signIn("replay", "nr", "first", {}, { nonce: "fireemu-nonce-a-PASSTAG" }),
    signIn("link", "nr", "second", { idToken: from("first:idToken") }, { nonce: "fireemu-nonce-b-PASSTAG" }),
    signIn(
      "link-again",
      "nr",
      "second-again",
      { idToken: from("first:idToken") },
      { nonce: "fireemu-nonce-c-PASSTAG" },
    ),
    resume("resume-link-again", "link-again:pendingToken"),
  ],
};

export const STRICT_SAFETY_PROGRAMS = [
  samlSha1,
  samlOpenEnded,
  samlReplay,
  createAuthUriEscaping,
  pendingTokenNonce,
];
