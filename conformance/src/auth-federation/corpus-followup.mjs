// AUTH-FEDERATION record-followup corpus (the coordinator's T12 (c) and the signature rows,
// 2026-09-29). Two observations the closure left inferred or single:
// - which scopes production's createAuthUri asks an OIDC issuer for. The run's issuer lists
//   scopes_supported in an order Google's does not and with a scope Google's does not list, so
//   the answer tells a copied list from a fixed one (record-oidc's issuer listed none and got
//   openid; accounts.google.com lists openid, email and profile and got those three);
// - production's refusal of a tampered and of an unsigned SAMLResponse, recorded twice (the
//   closure had it from the single saml-smoke run efe0ef).
// Placeholders as in corpus.mjs.

import { client, createOidc, oidcProvider } from "./corpus.mjs";
import { authUri, createSaml, samlProvider, samlSignIn } from "./corpus-saml.mjs";

/** The scopes the run's issuer lists in its discovery document for this corpus. */
export const FOLLOWUP_DISCOVERY_SCOPES = ["profile", "openid", "email", "phone"];

const CALLBACK = "https://{project}.firebaseapp.com/__/auth/handler";

const oidcScopes = {
  id: "auth-federation/oidc/scopes",
  providers: [oidcProvider("sc")],
  steps: [
    createOidc("sc"),
    client("create-auth-uri", "createAuthUri", {
      providerId: oidcProvider("sc"),
      continueUri: CALLBACK,
    }),
  ],
};

const samlSignature = {
  id: "auth-federation/saml/signature",
  providers: [samlProvider("sg")],
  steps: [
    createSaml("sg"),
    authUri("tampered-auth-uri", "sg"),
    samlSignIn("tampered", "sg", "tampered-auth-uri", {
      nameId: "EMAIL(saml-signature)",
      tamper: true,
    }),
    authUri("unsigned-auth-uri", "sg"),
    samlSignIn("unsigned", "sg", "unsigned-auth-uri", {
      nameId: "EMAIL(saml-signature)",
      sign: "none",
    }),
  ],
};

export const FOLLOWUP_PROGRAMS = [oidcScopes, samlSignature];
