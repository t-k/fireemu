// FS-RULES/principals, FS-RULES/auth-token-fields and FS-RULES/tenant.
//
// Values inside request.auth are observed through rules: every case is a literal document path
// whose get is allowed exactly when its predicate holds, so a row answers 404 (allowed, the
// document does not exist) or 403 (denied). Predicates compare with patterns and relations, not
// with run-specific values, so the same ruleset serves both sides.

import { allow, create, EVERYONE, FRESH, get, runQuery, seedDocs, string } from "./common.mjs";

const T = "request.auth.token";
const PROJECT = "fireemu-oracle-idp";

/** Every top-level claim a production ID token of these providers may carry. */
const TOKEN_KEYS = [
  "iss",
  "aud",
  "auth_time",
  "user_id",
  "sub",
  "iat",
  "exp",
  "email",
  "email_verified",
  "phone_number",
  "name",
  "picture",
  "firebase",
  "role",
  "level",
  "ratio",
  "flags",
  "tags",
  "tier",
];
const FIREBASE_KEYS = ["identities", "sign_in_provider", "tenant"];

/** `[case, predicate, principals]`: principals default to everyone with a token. */
const CLAIM_CASES = [
  ["auth-null", "request.auth == null"],
  ["auth-present", "request.auth != null"],
  ["uid-is-sub", `request.auth.uid == ${T}.sub`],
  ["uid-is-user-id", `request.auth.uid == ${T}.user_id`],
  ["uid-string", "request.auth.uid is string"],
  ["uid-custom-shape", "request.auth.uid.matches('fsr-[0-9]+-custom')"],
  ["token-map", `${T} is map`],
  ["keys-known", `${T}.keys().hasOnly(${JSON.stringify(TOKEN_KEYS).replaceAll('"', "'")})`],
  [
    "firebase-keys-known",
    `${T}.firebase.keys().hasOnly(${JSON.stringify(FIREBASE_KEYS).replaceAll('"', "'")})`,
  ],
  ...TOKEN_KEYS.map((key) => [`has-${key.replaceAll("_", "-")}`, `'${key}' in ${T}`]),
  ...FIREBASE_KEYS.map((key) => [
    `firebase-has-${key.replaceAll("_", "-")}`,
    `'${key}' in ${T}.firebase`,
  ]),
  ["size-leq-8", `${T}.size() <= 8`],
  ["size-leq-9", `${T}.size() <= 9`],
  ["size-leq-10", `${T}.size() <= 10`],
  ["size-leq-11", `${T}.size() <= 11`],
  ["size-leq-12", `${T}.size() <= 12`],
  ["size-leq-13", `${T}.size() <= 13`],
  ["size-leq-14", `${T}.size() <= 14`],
  ["aud-project", `${T}.aud == '${PROJECT}'`],
  ["iss-project", `${T}.iss == 'https://securetoken.google.com/${PROJECT}'`],
  ["iat-int", `${T}.iat is int`],
  ["exp-int", `${T}.exp is int`],
  ["auth-time-int", `${T}.auth_time is int`],
  ["lifetime-3600", `${T}.exp - ${T}.iat == 3600`],
  ["auth-time-not-after-iat", `${T}.auth_time <= ${T}.iat`],
  ["iat-before-request", `timestamp.value(${T}.iat * 1000) <= request.time`],
  ["exp-after-request", `timestamp.value(${T}.exp * 1000) > request.time`],
  ["email-shape", `${T}.email.matches('fsr-[0-9]+-[a-z]+@example[.]com')`],
  ["email-verified-true", `${T}.email_verified == true`],
  ["email-verified-false", `${T}.email_verified == false`],
  ["email-verified-bool", `${T}.email_verified is bool`],
  ["phone-number", `${T}.phone_number == '+16505550105'`],
  ["name", `${T}.name == 'Fsr A'`],
  ["picture", `${T}.picture == 'https://example.com/fsr-a.png'`],
  ["provider-password", `${T}.firebase.sign_in_provider == 'password'`],
  ["provider-anonymous", `${T}.firebase.sign_in_provider == 'anonymous'`],
  ["provider-phone", `${T}.firebase.sign_in_provider == 'phone'`],
  ["provider-custom", `${T}.firebase.sign_in_provider == 'custom'`],
  ["identities-map", `${T}.firebase.identities is map`],
  ["identities-empty", `${T}.firebase.identities.size() == 0`],
  ["identities-email-only", `${T}.firebase.identities.keys().hasOnly(['email'])`],
  ["identities-phone-only", `${T}.firebase.identities.keys().hasOnly(['phone'])`],
  ["identities-email-is-token-email", `${T}.firebase.identities.email == [${T}.email]`],
  ["identities-phone-is-token-phone", `${T}.firebase.identities.phone == [${T}.phone_number]`],
  ["tenant-shape", `${T}.firebase.tenant.matches('fsr-tenant-[a-z0-9]+')`],
  ["tenant-absent", `!('tenant' in ${T}.firebase)`],
  ["claim-role-editor", `${T}.role == 'editor'`],
  ["claim-level-int", `${T}.level is int && ${T}.level == 3`],
  ["claim-ratio-float", `${T}.ratio is float && ${T}.ratio == 0.5`],
  ["claim-flags-map", `${T}.flags is map && ${T}.flags.beta == true`],
  ["claim-tags-list", `${T}.tags is list && ${T}.tags == ['x', 'y']`],
  ["claim-role-admin", `${T}.role == 'admin'`],
  ["claim-tier-int", `${T}.tier is int && ${T}.tier == 2`],
  ["claim-role-late", `${T}.role == 'late'`],
];

export const FRAGMENTS = [
  [
    allow(
      "/fsr-own/{uid}/items/{item}",
      "get, list",
      "request.auth != null && request.auth.uid == uid",
    ),
    allow(
      "/fsr-own/{uid}/items/{item}",
      "create",
      "request.auth != null && request.auth.uid == uid && request.resource.data.owner == request.auth.uid",
    ),
    allow("/fsr-null/{d}", "get", "request.auth == null"),
    allow("/fsr-any/{d}", "get", "request.auth != null"),
    allow("/fsr-open/{d}", "read", "true"),
    ...CLAIM_CASES.map(([name, predicate]) => allow(`/fsr-claim/${name}`, "get", predicate)),
    allow("/fsr-tenant/{d}", "get", `request.auth != null && ${T}.firebase.tenant is string`),
  ].join("\n"),
];

const OWN_SEED = seedDocs([
  ["fsr-own/UID(a)/items/x", { owner: string("UID(a)") }],
  ["fsr-own/UID(b)/items/x", { owner: string("UID(b)") }],
  ["fsr-null/d", { n: string("null") }],
  ["fsr-any/d", { n: string("any") }],
  ["fsr-open/d", { n: string("open") }],
  ["fsr-tenant/d", { n: string("tenant") }],
]);

export const PROGRAMS = [
  {
    id: "fs-rules/principals/separation",
    ruleset: "main",
    refresh: FRESH,
    seed: OWN_SEED,
    steps: EVERYONE.flatMap((as) => [
      get(`${as}-get-a-own`, as, "fsr-own/UID(a)/items/x"),
      get(`${as}-get-null-clause`, as, "fsr-null/d"),
      get(`${as}-get-any-clause`, as, "fsr-any/d"),
      get(`${as}-get-open`, as, "fsr-open/d"),
      runQuery(`${as}-list-a-own`, as, "items", { parent: "fsr-own/UID(a)" }),
      ...(as === "none"
        ? []
        : [
            create(`${as}-create-own`, as, `fsr-own/UID(${as})/items/new`, {
              owner: string(`UID(${as})`),
            }),
            create(`${as}-create-in-b`, as, "fsr-own/UID(b)/items/from-other", {
              owner: string(`UID(${as})`),
            }),
          ]),
    ]),
  },
  {
    id: "fs-rules/principals/grpc",
    ruleset: "main",
    refresh: FRESH,
    seed: OWN_SEED,
    steps: ["none", "anon", "a", "b", "custom", "tenant"].flatMap((as) => [
      get(`${as}-get-a-own`, as, "fsr-own/UID(a)/items/x", { transport: "grpc" }),
      get(`${as}-get-null-clause`, as, "fsr-null/d", { transport: "grpc" }),
      runQuery(`${as}-list-a-own`, as, "items", { parent: "fsr-own/UID(a)", transport: "grpc" }),
    ]),
  },
  {
    id: "fs-rules/auth-token/claims",
    ruleset: "main",
    refresh: FRESH,
    steps: EVERYONE.flatMap((as) =>
      CLAIM_CASES.map(([name]) => get(`${as}-${name}`, as, `fsr-claim/${name}`)),
    ),
  },
  {
    id: "fs-rules/auth-token/claims-need-refresh",
    ruleset: "main",
    refresh: FRESH,
    steps: [
      { action: "principal", principal: "late", spec: { provider: "password" } },
      { action: "snapshot", principal: "late", as: "before" },
      get("before-change", "late", "fsr-claim/claim-role-late"),
      { action: "claims", principal: "late", claims: { role: "late" } },
      { action: "sleep", ms: 1500 },
      get("old-token-after-change", "late@before", "fsr-claim/claim-role-late"),
      { action: "refresh", principal: "late" },
      get("refreshed-token", "late", "fsr-claim/claim-role-late"),
      get("refreshed-keys-known", "late", "fsr-claim/keys-known"),
      { action: "delete-account", principal: "late" },
    ],
  },
  {
    id: "fs-rules/tenant/separation",
    ruleset: "main",
    refresh: FRESH,
    seed: OWN_SEED,
    steps: ["tenant", "a", "anon", "custom", "none"].flatMap((as) => [
      get(`${as}-tenant-rule`, as, "fsr-tenant/d"),
      get(`${as}-tenant-rule-grpc`, as, "fsr-tenant/d", { transport: "grpc" }),
    ]),
  },
];
