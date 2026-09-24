// AUTH-CREDENTIAL corpus: one program per recipe of spec/compatibility/closure/AUTH-CREDENTIAL.json.
// Programs only record answers; they never assert. Each program runs on an empty project (the
// session wipes before and after) and uses run-unique EMAIL(...)/UID(...) values.
//
// Timing: a step that must fall in a later whole second than an earlier one waits 1.1 s
// (`delayMs`), on both sides. The one-hour expiry wait is the last program, because fireemu
// takes it on its virtual clock.

import { TEST_PHONE_CODE } from "../auth-account/harness.mjs";

// ---- step builders -------------------------------------------------------------------------

const from = (reference) => ({ $from: reference });
const token = (name, tamperHow) => ({ $token: name, ...(tamperHow ? { tamper: tamperHow } : {}) });
const client = (id, method, body, extra = {}) => ({
  id,
  path: `v1/accounts:${method}`,
  auth: "key",
  body,
  ...extra,
});
const adminCall = (id, method, body, extra = {}) => ({
  id,
  path: `v1/projects/{project}/accounts:${method}`,
  auth: "admin",
  body,
  ...extra,
});
const adminCreate = (id, body) => ({
  id,
  path: "v1/projects/{project}/accounts",
  auth: "admin",
  body,
});
const signUp = (id, name, extra = {}) =>
  client(
    id,
    "signUp",
    { email: `EMAIL(${name})`, password: "password123", returnSecureToken: true },
    extra,
  );
const signIn = (id, name, extra = {}) =>
  client(
    id,
    "signInWithPassword",
    { email: `EMAIL(${name})`, password: "password123", returnSecureToken: true },
    extra,
  );
const customSignIn = (id, tokenValue, extra = {}) =>
  client(id, "signInWithCustomToken", { token: tokenValue, returnSecureToken: true }, extra);
const lookupWith = (id, idToken, extra = {}) => client(id, "lookup", { idToken }, extra);
const refreshWith = (id, refreshToken, extra = {}) => ({
  id,
  api: "securetoken",
  path: "v1/token",
  auth: "key",
  form: { grant_type: "refresh_token", refresh_token: refreshToken },
  ...extra,
});
const cookie = (id, idToken, validDuration, extra = {}) => ({
  id,
  path: "v1/projects/{project}:createSessionCookie",
  auth: "admin",
  body: { idToken, ...(validDuration === undefined ? {} : { validDuration }) },
  ...extra,
});
const adminLookup = (id, localId) => adminCall(id, "lookup", { localId: [localId] });

/** Relations of an issued token to the session it came from. */
const sessionRelations = (field, origin) => ({
  authTimeVsOrigin: { kind: "time", left: `${field}.auth_time`, right: `${origin}.auth_time` },
  iatVsOrigin: { kind: "time", left: `${field}.iat`, right: `${origin}.iat` },
  userIdVsOrigin: { kind: "same", left: `${field}.user_id`, right: `${origin}.user_id` },
});

/** A fresh sign-in's own token: is the session's auth_time the token's issue time? */
const fresh = (field = "idToken") => ({
  relations: {
    authTimeVsIat: { kind: "time", left: `${field}.auth_time`, right: `${field}.iat` },
  },
});

/** A refresh answer also hands back a refresh token: the one it was given, or a new one? */
const rotation = (origin) => ({
  refreshTokenVsInput: { kind: "same", left: "refresh_token", right: `${origin}:refreshToken` },
});

const program = (id, steps, extra = {}) => ({ id, steps, ...extra });

// ---- ID token composition per sign-in method -------------------------------------------------

const idTokenMethods = program(
  "auth-credential/id-token/methods",
  [
    signUp("password-sign-up", "pw", fresh()),
    {
      ...signIn("password-sign-in", "pw"),
      delayMs: 1100,
      relations: sessionRelations("idToken", "password-sign-up:idToken"),
    },
    client("anonymous-sign-up", "signUp", { returnSecureToken: true }, fresh()),
    client("phone-send-code", "sendVerificationCode", { phoneNumber: "PHONE(0)" }),
    client(
      "phone-sign-in",
      "signInWithPhoneNumber",
      { sessionInfo: from("phone-send-code:sessionInfo"), code: TEST_PHONE_CODE },
      fresh(),
    ),
    customSignIn("custom-sign-in", token("plain"), fresh()),
    customSignIn("custom-sign-in-with-claims", token("claims")),
    adminCreate("admin-create-rich", {
      localId: "UID(rich)",
      email: "EMAIL(rich)",
      password: "password123",
      emailVerified: true,
      displayName: "Rich User",
      photoUrl: "https://example.com/rich.png",
      phoneNumber: "PHONE(1)",
    }),
    signIn("rich-sign-in", "rich", fresh()),
    customSignIn("custom-sign-in-existing-email-account", token("rich")),
    adminLookup("admin-lookup-after-custom-sign-in", "UID(rich)"),
    adminCall("set-account-claims", "update", {
      localId: "UID(rich)",
      customAttributes: '{"role":"account","level":3,"flags":{"beta":true}}',
    }),
    signIn("rich-sign-in-with-account-claims", "rich"),
  ],
  {
    tokens: {
      plain: { uid: "UID(custom)" },
      claims: {
        uid: "UID(custom-claims)",
        claims: { role: "developer", n: 1, list: ["a", 2], nested: { x: true }, empty: null },
      },
      rich: { uid: "UID(rich)" },
    },
  },
);

/** Every sign-in response without `returnSecureToken`: what production hands back instead. */
const idTokenLegacy = program(
  "auth-credential/id-token/without-return-secure-token",
  [
    client("password-sign-up", "signUp", { email: "EMAIL(legacy)", password: "password123" }),
    client("password-sign-in", "signInWithPassword", {
      email: "EMAIL(legacy)",
      password: "password123",
    }),
    lookupWith("lookup-with-legacy-password-token", from("password-sign-in:idToken")),
    client("anonymous-sign-up", "signUp", {}),
    client("custom-sign-in", "signInWithCustomToken", { token: token("plain") }),
    client("custom-sign-in-false", "signInWithCustomToken", {
      token: token("plain"),
      returnSecureToken: false,
    }),
    client("custom-sign-in-with-claims", "signInWithCustomToken", { token: token("claims") }),
    lookupWith("lookup-with-legacy-custom-token", from("custom-sign-in:idToken")),
    cookie("cookie-from-legacy-custom-token", from("custom-sign-in:idToken"), 3600),
    cookie("cookie-from-legacy-password-token", from("password-sign-in:idToken"), 3600),
    client("update-with-legacy-password-token", "update", {
      idToken: from("password-sign-in:idToken"),
      displayName: "Legacy Name",
    }),
    // Routes production has not yet been seen to honour the legacy token on.
    client("send-verification-with-legacy-token", "sendOobCode", {
      requestType: "VERIFY_EMAIL",
      idToken: from("password-sign-in:idToken"),
    }),
    {
      id: "mfa-start-with-legacy-token",
      path: "v2/accounts/mfaEnrollment:start",
      auth: "key",
      body: { idToken: from("password-sign-in:idToken"), totpEnrollmentInfo: {} },
    },
    {
      id: "mfa-withdraw-with-legacy-token",
      path: "v2/accounts/mfaEnrollment:withdraw",
      auth: "key",
      body: { idToken: from("password-sign-in:idToken"), mfaEnrollmentId: "unknown" },
    },
    client("phone-send-code-for-link", "sendVerificationCode", { phoneNumber: "PHONE(4)" }),
    client("phone-link-with-legacy-token", "signInWithPhoneNumber", {
      idToken: from("password-sign-in:idToken"),
      sessionInfo: from("phone-send-code-for-link:sessionInfo"),
      code: TEST_PHONE_CODE,
    }),
    // A second boundary after the legacy sign-in, so the password the upgrade sets revokes the
    // legacy token on both sides, however fast they answer.
    {
      ...client("sign-up-upgrade-with-legacy-token", "signUp", {
        idToken: from("custom-sign-in:idToken"),
        email: "EMAIL(legacy-upgrade)",
        password: "password123",
      }),
      delayMs: 1100,
    },
    client("delete-with-legacy-custom-token", "delete", {
      idToken: from("custom-sign-in:idToken"),
    }),
    adminLookup("admin-lookup-after-legacy-delete", "UID(legacy-custom)"),
  ],
  {
    tokens: {
      plain: { uid: "UID(legacy-custom)" },
      claims: { uid: "UID(legacy-claims)", claims: { role: "developer" } },
    },
  },
);

// ---- refresh exchange -------------------------------------------------------------------------

const refreshExchange = program(
  "auth-credential/refresh/exchange",
  [
    signUp("sign-up", "refresh"),
    {
      ...refreshWith("refresh-form", from("sign-up:refreshToken")),
      delayMs: 1100,
      relations: {
        ...sessionRelations("id_token", "sign-up:idToken"),
        refreshTokenVsInput: { kind: "same", left: "refresh_token", right: "sign-up:refreshToken" },
        accessTokenVsIdToken: { kind: "same", left: "access_token", right: "id_token" },
      },
    },
    {
      id: "refresh-json",
      api: "securetoken",
      path: "v1/token",
      auth: "key",
      body: { grant_type: "refresh_token", refresh_token: from("sign-up:refreshToken") },
      delayMs: 1100,
      relations: {
        ...sessionRelations("id_token", "sign-up:idToken"),
        iatVsFirstRefresh: {
          kind: "time",
          left: "id_token.iat",
          right: "refresh-form:id_token.iat",
        },
      },
    },
    {
      ...refreshWith("refresh-with-returned-token", from("refresh-form:refresh_token")),
      delayMs: 1100,
      relations: sessionRelations("id_token", "sign-up:idToken"),
    },
    lookupWith("lookup-with-refreshed-id-token", from("refresh-with-returned-token:id_token")),
    lookupWith("lookup-with-original-id-token", from("sign-up:idToken")),
    client("anonymous-sign-up", "signUp", { returnSecureToken: true }),
    {
      ...refreshWith("anonymous-refresh", from("anonymous-sign-up:refreshToken")),
      delayMs: 1100,
      relations: {
        ...sessionRelations("id_token", "anonymous-sign-up:idToken"),
        ...rotation("anonymous-sign-up"),
      },
    },
    customSignIn("custom-sign-in", token("claims")),
    {
      ...refreshWith("custom-refresh", from("custom-sign-in:refreshToken")),
      delayMs: 1100,
      relations: {
        ...sessionRelations("id_token", "custom-sign-in:idToken"),
        ...rotation("custom-sign-in"),
      },
    },
    client("phone-send-code", "sendVerificationCode", { phoneNumber: "PHONE(2)" }),
    client("phone-sign-in", "signInWithPhoneNumber", {
      sessionInfo: from("phone-send-code:sessionInfo"),
      code: TEST_PHONE_CODE,
    }),
    {
      ...refreshWith("phone-refresh", from("phone-sign-in:refreshToken")),
      delayMs: 1100,
      relations: {
        ...sessionRelations("id_token", "phone-sign-in:idToken"),
        ...rotation("phone-sign-in"),
      },
    },
    // A profile change after sign-in reaches the next refreshed token.
    client("set-display-name", "update", {
      idToken: from("sign-up:idToken"),
      displayName: "Refreshed Name",
      photoUrl: "https://example.com/refreshed.png",
    }),
    adminCall("admin-verify-email", "update", {
      localId: from("sign-up:localId"),
      emailVerified: true,
    }),
    refreshWith("refresh-after-profile-change", from("sign-up:refreshToken")),
  ],
  { tokens: { claims: { uid: "UID(refresh-custom)", claims: { role: "developer" } } } },
);

const refreshRefusals = program("auth-credential/refresh/refusals", [
  signUp("sign-up", "refusal"),
  {
    id: "no-refresh-token",
    api: "securetoken",
    path: "v1/token",
    auth: "key",
    form: { grant_type: "refresh_token" },
  },
  {
    id: "no-grant-type",
    api: "securetoken",
    path: "v1/token",
    auth: "key",
    form: { refresh_token: from("sign-up:refreshToken") },
  },
  {
    id: "password-grant-type",
    api: "securetoken",
    path: "v1/token",
    auth: "key",
    form: { grant_type: "password", refresh_token: from("sign-up:refreshToken") },
  },
  {
    id: "authorization-code-grant-type",
    api: "securetoken",
    path: "v1/token",
    auth: "key",
    form: { grant_type: "authorization_code", code: "not-a-code" },
  },
  refreshWith("malformed-refresh-token", "not-a-refresh-token"),
  refreshWith("empty-refresh-token", ""),
  refreshWith("id-token-as-refresh-token", from("sign-up:idToken")),
  refreshWith("truncated-refresh-token", { $chop: "sign-up:refreshToken", drop: 8 }),
  { id: "empty-body", api: "securetoken", path: "v1/token", auth: "key", form: {} },
  {
    ...refreshWith("no-api-key", from("sign-up:refreshToken")),
    auth: "none",
  },
  {
    ...refreshWith("invalid-api-key", from("sign-up:refreshToken")),
    auth: "none",
    query: { key: "fireemu-not-a-real-api-key" },
  },
  refreshWith("control-still-valid", from("sign-up:refreshToken")),
]);

// ---- ID token refusals ------------------------------------------------------------------------

const idTokenRefusals = program("auth-credential/id-token/refusals", [
  signUp("sign-up", "idrefusal"),
  lookupWith("garbage", "not-a-jwt"),
  lookupWith("empty", ""),
  client("missing", "lookup", {}),
  lookupWith("tampered-signature", { $tamperFrom: "sign-up:idToken", how: "signature" }),
  lookupWith("stripped-signature", { $tamperFrom: "sign-up:idToken", how: "strip-signature" }),
  lookupWith("alg-none", { $tamperFrom: "sign-up:idToken", how: "alg-none" }),
  lookupWith("tampered-payload", { $tamperFrom: "sign-up:idToken", how: "payload" }),
  lookupWith("refresh-token-as-id-token", from("sign-up:refreshToken")),
  client("update-with-tampered", "update", {
    idToken: { $tamperFrom: "sign-up:idToken", how: "signature" },
    displayName: "Nope",
  }),
  client("delete-with-tampered", "delete", {
    idToken: { $tamperFrom: "sign-up:idToken", how: "signature" },
  }),
  cookie("cookie-with-garbage", "not-a-jwt", 3600),
  cookie("cookie-with-tampered", { $tamperFrom: "sign-up:idToken", how: "signature" }, 3600),
  lookupWith("control-original", from("sign-up:idToken")),
]);

// ---- revocation through validSince -------------------------------------------------------------

const revocation = program(
  "auth-credential/revocation/valid-since",
  [
    signUp("sign-up", "revoke"),
    // validSince pinned to the token's own auth_time: the same-second boundary.
    adminCall("valid-since-equal", "update", {
      localId: from("sign-up:localId"),
      validSince: { $string: from("sign-up:idToken.auth_time") },
    }),
    {
      ...adminLookup("read-back-equal", from("sign-up:localId")),
      relations: {
        validSinceVsAuthTime: {
          kind: "time",
          left: "users.0.validSince",
          right: "sign-up:idToken.auth_time",
        },
      },
    },
    lookupWith("lookup-at-equal", from("sign-up:idToken")),
    refreshWith("refresh-at-equal", from("sign-up:refreshToken")),
    cookie("cookie-at-equal", from("sign-up:idToken"), 3600),
    // One second later than auth_time: the session predates validSince. The delay puts the value
    // in the past when it is written, on both sides.
    {
      ...adminCall("valid-since-after", "update", {
        localId: from("sign-up:localId"),
        validSince: { $string: { $sum: [from("sign-up:idToken.auth_time"), 1] } },
      }),
      delayMs: 1100,
    },
    lookupWith("lookup-after", from("sign-up:idToken")),
    refreshWith("refresh-after", from("sign-up:refreshToken")),
    cookie("cookie-after", from("sign-up:idToken"), 3600),
    client("update-after", "update", { idToken: from("sign-up:idToken"), displayName: "Nope" }),
    // A new session started after validSince is honoured.
    {
      ...signIn("new-sign-in", "revoke"),
      delayMs: 1100,
    },
    lookupWith("lookup-new-session", from("new-sign-in:idToken")),
    refreshWith("refresh-new-session", from("new-sign-in:refreshToken")),
    cookie("cookie-new-session", from("new-sign-in:idToken"), 3600),
    // validSince moved back before the old session's auth_time: does the old session return?
    adminCall("valid-since-before", "update", {
      localId: from("sign-up:localId"),
      validSince: { $string: { $sum: [from("sign-up:idToken.auth_time"), -1] } },
    }),
    lookupWith("lookup-old-after-moving-back", from("sign-up:idToken")),
    refreshWith("refresh-old-after-moving-back", from("sign-up:refreshToken")),
    // validSince in the future: a sign-in now issues a session that already predates it.
    adminCall("valid-since-future", "update", {
      localId: from("sign-up:localId"),
      validSince: { $string: { $sum: [from("new-sign-in:idToken.auth_time"), 600] } },
    }),
    signIn("sign-in-before-future-valid-since", "revoke"),
    lookupWith(
      "lookup-before-future-valid-since",
      from("sign-in-before-future-valid-since:idToken"),
    ),
    refreshWith(
      "refresh-before-future-valid-since",
      from("sign-in-before-future-valid-since:refreshToken"),
    ),
    // A custom-token session is revoked the same way.
    customSignIn("custom-sign-in", token("custom")),
    {
      ...adminCall("custom-valid-since-after", "update", {
        localId: "UID(revoke-custom)",
        validSince: { $string: { $sum: [from("custom-sign-in:idToken.auth_time"), 1] } },
      }),
      delayMs: 1100,
    },
    lookupWith("custom-lookup-after", from("custom-sign-in:idToken")),
    refreshWith("custom-refresh-after", from("custom-sign-in:refreshToken")),
    { ...customSignIn("custom-sign-in-again", token("custom")), delayMs: 1100 },
    // Admin password replacement revokes as well (AUTH-ACCOUNT covers the client path).
    adminCreate("admin-create", {
      localId: "UID(revoke-admin)",
      email: "EMAIL(revoke-admin)",
      password: "password123",
    }),
    signIn("admin-account-sign-in", "revoke-admin"),
    {
      ...adminCall("admin-password-change", "update", {
        localId: "UID(revoke-admin)",
        password: "password456",
      }),
      delayMs: 1100,
    },
    lookupWith("lookup-after-admin-password-change", from("admin-account-sign-in:idToken")),
    refreshWith("refresh-after-admin-password-change", from("admin-account-sign-in:refreshToken")),
  ],
  { tokens: { custom: { uid: "UID(revoke-custom)" } } },
);

// ---- custom tokens --------------------------------------------------------------------------------

const customSignInProgram = program(
  "auth-credential/custom-token/sign-in",
  [
    customSignIn("new-account", token("first")),
    {
      ...adminLookup("admin-lookup-new-account", "UID(custom-new)"),
    },
    { ...customSignIn("existing-account", token("first")), delayMs: 1100 },
    {
      ...refreshWith("refresh", from("new-account:refreshToken")),
      delayMs: 1100,
      relations: sessionRelations("id_token", "new-account:idToken"),
    },
    customSignIn("uid-128", token("uid128")),
    customSignIn("uid-129", token("uid129")),
    customSignIn("uid-with-symbols", token("uidSymbols")),
    adminCreate("admin-create-disabled", { localId: "UID(custom-disabled)", disabled: true }),
    customSignIn("disabled-account", token("disabled")),
    customSignIn("claims-at-limit", token("claimsAtLimit")),
    customSignIn("claims-over-limit", token("claimsOverLimit")),
    customSignIn("claims-empty-object", token("claimsEmpty")),
    customSignIn("iat-in-future", token("iatFuture")),
    customSignIn("lifetime-over-hour", token("longLived")),
    customSignIn("no-exp", token("noExp")),
    customSignIn("no-iat", token("noIat")),
    lookupWith("lookup-new-account-token", from("new-account:idToken")),
    cookie("cookie-from-custom-session", from("new-account:idToken"), 3600),
  ],
  {
    tokens: {
      first: { uid: "UID(custom-new)", claims: { role: "developer", premium: true } },
      uid128: { uid: "u".repeat(128) },
      uid129: { uid: "u".repeat(129) },
      uidSymbols: { uid: "UID(sym)/with.symbols+and space" },
      disabled: { uid: "UID(custom-disabled)" },
      claimsAtLimit: { uid: "UID(claims-limit)", claims: { k: "x".repeat(992) } },
      claimsOverLimit: { uid: "UID(claims-over)", claims: { k: "x".repeat(993) } },
      claimsEmpty: { uid: "UID(claims-empty)", claims: {} },
      iatFuture: { uid: "UID(iat-future)", iatOffset: 600 },
      longLived: { uid: "UID(long-lived)", lifetime: 7200 },
      noExp: { uid: "UID(no-exp)", omit: ["exp"] },
      noIat: { uid: "UID(no-iat)", omit: ["iat"] },
    },
  },
);

const RESERVED = [
  "acr",
  "amr",
  "at_hash",
  "aud",
  "auth_time",
  "azp",
  "cnf",
  "c_hash",
  "exp",
  "firebase",
  "iat",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "sub",
];

const customValidation = program(
  "auth-credential/custom-token/validation",
  [
    customSignIn("other-project-signer", token("other")),
    customSignIn("tampered-signature", token("valid", "signature")),
    customSignIn("stripped-signature", token("valid", "strip-signature")),
    customSignIn("alg-none", token("valid", "alg-none")),
    customSignIn("tampered-payload", token("valid", "payload")),
    customSignIn("garbage", "not-a-jwt"),
    customSignIn("empty", ""),
    client("missing-token", "signInWithCustomToken", { returnSecureToken: true }),
    customSignIn("json-object-token", '{"uid":"fake"}'),
    customSignIn("wrong-audience", token("wrongAud")),
    customSignIn("missing-uid", token("noUid")),
    customSignIn("empty-uid", token("emptyUid")),
    customSignIn("numeric-uid", token("numericUid")),
    customSignIn("iss-not-sub", token("issNotSub")),
    customSignIn("claims-not-object", token("claimsString")),
    customSignIn("claims-array", token("claimsArray")),
    ...RESERVED.map((name) => customSignIn(`reserved-${name}`, token(`reserved-${name}`))),
    customSignIn("user-id-developer-claim", token("userIdClaim")),
    {
      ...customSignIn("invalid-api-key", token("valid")),
      auth: "none",
      query: { key: "fireemu-not-a-real-api-key" },
    },
    customSignIn("control-valid", token("valid")),
  ],
  {
    tokens: {
      valid: { uid: "UID(valid)" },
      other: { uid: "UID(other)", signer: "other" },
      wrongAud: { uid: "UID(wrong-aud)", set: { aud: "https://example.com/not-identitytoolkit" } },
      noUid: {},
      emptyUid: { uid: "" },
      numericUid: { set: { uid: 12345 } },
      issNotSub: { uid: "UID(iss-not-sub)", set: { sub: "someone-else@example.com" } },
      claimsString: { uid: "UID(claims-string)", set: { claims: "role=admin" } },
      claimsArray: { uid: "UID(claims-array)", set: { claims: ["role"] } },
      userIdClaim: { uid: "UID(user-id-claim)", claims: { user_id: "someone-else" } },
      ...Object.fromEntries(
        RESERVED.map((name) => [
          `reserved-${name}`,
          { uid: `UID(reserved-${name.replaceAll("_", "-")})`, claims: { [name]: "value" } },
        ]),
      ),
    },
  },
);

// ---- claims from the account and from the session -----------------------------------------------

const claimPrecedence = program(
  "auth-credential/claims/precedence",
  [
    adminCreate("create", { localId: "UID(prec)", email: "EMAIL(prec)", password: "password123" }),
    adminCall("set-account-claims", "update", {
      localId: "UID(prec)",
      customAttributes: '{"role":"account","tier":"gold"}',
    }),
    signIn("password-session", "prec"),
    customSignIn("custom-session-same-name", token("session")),
    adminCall("change-account-claims", "update", {
      localId: "UID(prec)",
      customAttributes: '{"role":"changed","tier":"platinum","added":1}',
    }),
    {
      ...refreshWith("refresh-custom-session", from("custom-session-same-name:refreshToken")),
      delayMs: 1100,
    },
    refreshWith("refresh-password-session", from("password-session:refreshToken")),
    adminCall("clear-account-claims", "update", { localId: "UID(prec)", customAttributes: "{}" }),
    refreshWith("refresh-custom-after-clear", from("custom-session-same-name:refreshToken")),
    refreshWith("refresh-password-after-clear", from("password-session:refreshToken")),
    adminCall("reserved-account-claim", "update", {
      localId: "UID(prec)",
      customAttributes: '{"sub":"x"}',
    }),
    adminCall("firebase-account-claim", "update", {
      localId: "UID(prec)",
      customAttributes: '{"firebase":{"x":1}}',
    }),
    cookie("cookie-custom-session", from("refresh-custom-session:id_token"), 3600),
  ],
  { tokens: { session: { uid: "UID(prec)", claims: { role: "session", only_session: true } } } },
);

// ---- session cookies -------------------------------------------------------------------------------

const sessionCookieDurations = program("auth-credential/session-cookie/durations", [
  signUp("sign-up", "cookie"),
  cookie("default-duration", from("sign-up:idToken")),
  cookie("minimum", from("sign-up:idToken"), 300),
  cookie("below-minimum", from("sign-up:idToken"), 299),
  cookie("maximum", from("sign-up:idToken"), 1209600),
  cookie("above-maximum", from("sign-up:idToken"), 1209601),
  cookie("zero", from("sign-up:idToken"), 0),
  cookie("negative", from("sign-up:idToken"), -1),
  cookie("numeric-string", from("sign-up:idToken"), "3600"),
  cookie("fractional", from("sign-up:idToken"), 3600.5),
  cookie("not-a-number", from("sign-up:idToken"), "an hour"),
  {
    ...cookie("relations", from("sign-up:idToken"), 3600),
    delayMs: 1100,
    relations: sessionRelations("sessionCookie", "sign-up:idToken"),
  },
]);

const sessionCookieSessions = program("auth-credential/session-cookie/sessions", [
  signUp("sign-up", "cookie-session"),
  cookie("missing-id-token", undefined, 3600),
  client("client-api-key", "createSessionCookie", undefined, {
    path: "v1/projects/{project}:createSessionCookie",
    body: { idToken: from("sign-up:idToken"), validDuration: 3600 },
  }),
  client("anonymous-sign-up", "signUp", { returnSecureToken: true }),
  cookie("anonymous-session", from("anonymous-sign-up:idToken"), 3600),
  client("phone-send-code", "sendVerificationCode", { phoneNumber: "PHONE(3)" }),
  client("phone-sign-in", "signInWithPhoneNumber", {
    sessionInfo: from("phone-send-code:sessionInfo"),
    code: TEST_PHONE_CODE,
  }),
  cookie("phone-session", from("phone-sign-in:idToken"), 3600),
  adminCreate("create-with-claims", {
    localId: "UID(cookie-claims)",
    email: "EMAIL(cookie-claims)",
    password: "password123",
  }),
  adminCall("set-claims", "update", {
    localId: "UID(cookie-claims)",
    customAttributes: '{"role":"account"}',
  }),
  signIn("claims-sign-in", "cookie-claims"),
  cookie("account-claims-session", from("claims-sign-in:idToken"), 3600),
  // Claims changed after sign-in: the cookie carries what the ID token carried, or the account?
  adminCall("change-claims", "update", {
    localId: "UID(cookie-claims)",
    customAttributes: '{"role":"changed"}',
  }),
  cookie("after-claims-change", from("claims-sign-in:idToken"), 3600),
  adminCall("disable", "update", { localId: "UID(cookie-claims)", disableUser: true }),
  cookie("disabled-account", from("claims-sign-in:idToken"), 3600),
  adminCall("delete", "delete", { localId: "UID(cookie-claims)" }),
  cookie("deleted-account", from("claims-sign-in:idToken"), 3600),
  cookie("session-cookie-as-id-token", from("account-claims-session:sessionCookie"), 3600),
  lookupWith("session-cookie-on-lookup", from("account-claims-session:sessionCookie")),
]);

// ---- expiry (last: fireemu takes the wait on its virtual clock) -------------------------------

const expiry = program(
  "auth-credential/expiry/one-hour",
  [
    signUp("sign-up", "expiry"),
    cookie("cookie-before", from("sign-up:idToken"), 300),
    // Ten seconds past exp: any tolerance for clock skew shows here and not below.
    { ...lookupWith("lookup-expired", from("sign-up:idToken")), waitSeconds: 3610 },
    client("update-expired", "update", { idToken: from("sign-up:idToken"), displayName: "Late" }),
    cookie("cookie-from-expired", from("sign-up:idToken"), 3600),
    customSignIn("custom-token-expired", token("expiring")),
    {
      ...refreshWith("refresh-after-hour", from("sign-up:refreshToken")),
      relations: sessionRelations("id_token", "sign-up:idToken"),
    },
    lookupWith("lookup-refreshed", from("refresh-after-hour:id_token")),
    // The exact edge of the five-minute allowance, custom token first (it expires earlier).
    {
      ...customSignIn("custom-token-at-exp-plus-299", token("expiring")),
      waitUntil: { of: "token:expiring:exp", plus: 299 },
    },
    {
      ...customSignIn("custom-token-at-exp-plus-300", token("expiring")),
      waitUntil: { of: "token:expiring:exp", plus: 300 },
    },
    {
      ...lookupWith("lookup-at-exp-plus-299", from("sign-up:idToken")),
      waitUntil: { of: "sign-up:idToken.exp", plus: 299 },
    },
    {
      ...lookupWith("lookup-at-exp-plus-300", from("sign-up:idToken")),
      waitUntil: { of: "sign-up:idToken.exp", plus: 300 },
    },
    // Further on, well past the allowance.
    { ...lookupWith("lookup-expired-later", from("sign-up:idToken")), waitSeconds: 30 },
    cookie("cookie-from-expired-later", from("sign-up:idToken"), 3600),
    customSignIn("custom-token-expired-later", token("expiring")),
    // Deleting last keeps every earlier answer about a live account.
    client("delete-expired", "delete", { idToken: from("sign-up:idToken") }),
    adminLookup("admin-lookup-after-delete-attempt", from("sign-up:localId")),
  ],
  // Minted before the sign-up and five seconds shorter-lived, so its allowance ends first and
  // every wait above moves forward.
  { tokens: { expiring: { uid: "UID(expiring)", lifetime: 3595 } } },
);

export const PROGRAMS = [
  idTokenMethods,
  idTokenLegacy,
  refreshExchange,
  refreshRefusals,
  idTokenRefusals,
  revocation,
  customSignInProgram,
  customValidation,
  claimPrecedence,
  sessionCookieDurations,
  sessionCookieSessions,
  expiry,
];
