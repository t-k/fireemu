// AUTH-TENANT-BLOCKING corpus, blocking half: one program per blocking recipe of
// spec/compatibility/closure/AUTH-TENANT-BLOCKING.json. Every program runs while the fixture in
// ./function is deployed and registered for beforeCreate, beforeSignIn, beforeSendEmail and
// beforeSendSms (owner decision TB1; locally fireemu serves the same codebase). What the
// functions do is chosen by the words of each account's address (function/index.js):
// EMAIL(r1-cdenypd) is refused by beforeCreate with permission-denied. Without a refusing word,
// beforeCreate saves an echo of its event in customClaims.atbC and beforeSignIn puts one in
// sessionClaims.atbS, so a token shows which events ran and what they saw (TB5).
//
// Every phone is a sandbox test number (M3); the last one, PHONE(5), is refused by
// beforeSendSms with its echo. Every address is @example.com (null MX, E1), and every client
// action-code request names an address whose beforeSendEmail refuses or blocks it with its
// echo, so no mail should leave production even where the function runs.

import { TEST_PHONE_CODE } from "../auth-account/harness.mjs";
import { MFA_CONFIGS } from "../auth-mfa/guard.mjs";

const from = (reference) => ({ $from: reference });

const client = (id, method, body, extra = {}) => ({
  id,
  path: `v1/accounts:${method}`,
  auth: "key",
  body,
  ...extra,
});
const clientV2 = (id, method, body, extra = {}) => ({
  id,
  path: `v2/accounts/${method}`,
  auth: "key",
  body,
  ...extra,
});
const admin = (id, method, body, extra = {}) => ({
  id,
  path: `v1/projects/{project}/accounts${method ? `:${method}` : ""}`,
  auth: "admin",
  body,
  ...extra,
});
const tenantAdmin = (id, tenant, method, body) => ({
  id,
  path: `v1/projects/{project}/tenants/${tenant}/accounts${method ? `:${method}` : ""}`,
  auth: "admin",
  body,
});
const adminCreate = (id, name, extra = {}) =>
  admin(id, "", {
    localId: `UID(${name.split("-")[0]})`,
    email: `EMAIL(${name})`,
    password: "password123",
    emailVerified: true,
    ...extra,
  });
const lookupEmails = (id, names) => admin(id, "lookup", { email: names.map((n) => `EMAIL(${n})`) });
const signUp = (id, name, extra = {}) =>
  client(id, "signUp", {
    email: `EMAIL(${name})`,
    password: "password123",
    returnSecureToken: true,
    ...extra,
  });
const signIn = (id, name, extra = {}) =>
  client(id, "signInWithPassword", {
    email: `EMAIL(${name})`,
    password: "password123",
    returnSecureToken: true,
    ...extra,
  });
const refreshWith = (id, tokenStep) => ({
  id,
  api: "securetoken",
  path: "v1/token",
  auth: "key",
  form: { grant_type: "refresh_token", refresh_token: from(`${tokenStep}:refreshToken`) },
});
const phoneCode = (id, phone, extra = {}) =>
  client(id, "sendVerificationCode", { phoneNumber: `PHONE(${phone})`, ...extra });
const phoneSignIn = (id, codeStep, extra = {}) =>
  client(id, "signInWithPhoneNumber", {
    sessionInfo: from(`${codeStep}:sessionInfo`),
    code: TEST_PHONE_CODE,
    ...extra,
  });

const program = (id, steps, extra = {}) => ({ id, steps, functions: true, ...extra });
const openTenant = (displayName) => ({
  displayName,
  allowPasswordSignup: true,
  enableEmailLinkSignin: true,
  enableAnonymousUser: true,
});

// ---- B1 which events fire ----------------------------------------------------------------------

const events = program("atb/blocking/events", [
  signUp("sign-up-password", "e1"),
  signIn("sign-in-password", "e1"),
  refreshWith("refresh-password", "sign-in-password"),
  client("sign-up-anonymous", "signUp", { returnSecureToken: true }),
  adminCreate("admin-create", "e2"),
  lookupEmails("admin-lookup-created", ["e2"]),
  signIn("sign-in-admin-created", "e2"),
  admin("admin-import", "batchCreate", {
    users: [{ localId: "UID(e3)", email: "EMAIL(e3)" }],
  }),
  lookupEmails("admin-lookup-imported", ["e3"]),
  client("update-profile", "update", {
    idToken: from("sign-in-password:idToken"),
    displayName: "Updated",
    returnSecureToken: true,
  }),
  phoneCode("phone-code-new", 3),
  phoneSignIn("phone-sign-in-new", "phone-code-new"),
  phoneCode("phone-code-existing", 3),
  phoneSignIn("phone-sign-in-existing", "phone-code-existing"),
]);

// ---- B1 email-link sign-in (in a tenant, where email links are on without a project change) ---

const L = "TENANT(l)";
const emailLink = program(
  "atb/blocking/email-link",
  [
    tenantAdmin("link-code-new", L, "sendOobCode", {
      requestType: "EMAIL_SIGNIN",
      email: "EMAIL(k1)",
      returnOobLink: true,
    }),
    client("link-sign-in-new", "signInWithEmailLink", {
      email: "EMAIL(k1)",
      oobCode: from("link-code-new:oobCode"),
      tenantId: L,
    }),
    tenantAdmin("link-code-existing", L, "sendOobCode", {
      requestType: "EMAIL_SIGNIN",
      email: "EMAIL(k1)",
      returnOobLink: true,
    }),
    client("link-sign-in-existing", "signInWithEmailLink", {
      email: "EMAIL(k1)",
      oobCode: from("link-code-existing:oobCode"),
      tenantId: L,
    }),
  ],
  { tenants: { l: openTenant("atb-blk-link") } },
);

// ---- B1 custom-token sign-in (minted as AUTH-CREDENTIAL mints, TB7) --------------------------

const customToken = program(
  "atb/blocking/custom-token",
  [
    client("custom-new", "signInWithCustomToken", {
      token: { $token: "c1" },
      returnSecureToken: true,
    }),
    client("custom-existing", "signInWithCustomToken", {
      token: { $token: "c1" },
      returnSecureToken: true,
    }),
    admin("admin-lookup-custom", "lookup", { localId: ["UID(c1)"] }),
  ],
  { tokens: { c1: { uid: "UID(c1)" } } },
);

// ---- B1 and M6: a second factor ----------------------------------------------------------------

const mfa = program(
  "atb/blocking/mfa",
  [
    adminCreate("create-m1", "m1"),
    signIn("sign-in-m1", "m1"),
    clientV2("phone-start", "mfaEnrollment:start", {
      idToken: from("sign-in-m1:idToken"),
      phoneEnrollmentInfo: { phoneNumber: "PHONE(4)" },
    }),
    clientV2("phone-finalize", "mfaEnrollment:finalize", {
      idToken: from("sign-in-m1:idToken"),
      phoneVerificationInfo: {
        sessionInfo: from("phone-start:phoneSessionInfo.sessionInfo"),
        code: TEST_PHONE_CODE,
      },
      displayName: "Phone",
    }),
    signIn("first-factor", "m1"),
    clientV2("second-factor-start", "mfaSignIn:start", {
      mfaPendingCredential: from("first-factor:mfaPendingCredential"),
      mfaEnrollmentId: from("first-factor:mfaInfo.0.mfaEnrollmentId"),
      phoneSignInInfo: {},
    }),
    clientV2("second-factor-finalize", "mfaSignIn:finalize", {
      mfaPendingCredential: from("first-factor:mfaPendingCredential"),
      mfaEnrollmentId: from("first-factor:mfaInfo.0.mfaEnrollmentId"),
      phoneVerificationInfo: {
        sessionInfo: from("second-factor-start:phoneResponseInfo.sessionInfo"),
        code: TEST_PHONE_CODE,
      },
    }),
  ],
  { config: { mfa: MFA_CONFIGS.smsOnly } },
);

// ---- B2 ordering and what beforeSignIn sees ----------------------------------------------------

const ordering = program("atb/blocking/ordering", [
  signUp("sign-up-profile", "o1-cprofile"),
  lookupEmails("lookup-profile", ["o1-cprofile"]),
  signIn("sign-in-profile", "o1-cprofile"),
]);

// ---- B3 refusal -------------------------------------------------------------------------------

const refusal = program("atb/blocking/refusal", [
  signUp("create-permission-denied", "r1-cdenypd"),
  signUp("create-invalid-argument", "r2-cdenyia"),
  signUp("create-unavailable", "r3-cdenyun"),
  signUp("create-resource-exhausted", "r4-cdenyrx"),
  signUp("create-unhandled", "r5-cthrow"),
  lookupEmails("lookup-refused-creates", [
    "r1-cdenypd",
    "r2-cdenyia",
    "r3-cdenyun",
    "r4-cdenyrx",
    "r5-cthrow",
  ]),
  adminCreate("admin-create-refused", "r9-cdenypd"),
  adminCreate("admin-create-sign-in-refused", "r6-sdenypd"),
  signIn("sign-in-permission-denied", "r6-sdenypd"),
  adminCreate("admin-create-sign-in-internal", "r8-sdenyin"),
  signIn("sign-in-internal", "r8-sdenyin"),
  adminCreate("admin-create-sign-in-unhandled", "r7-sthrow"),
  signIn("sign-in-unhandled", "r7-sthrow"),
  lookupEmails("lookup-after-refused-sign-ins", ["r6-sdenypd", "r7-sthrow", "r8-sdenyin"]),
]);

// ---- B4 rollback and disabled ------------------------------------------------------------------

const rollback = program("atb/blocking/rollback", [
  signUp("sign-up-refused-at-sign-in", "k1-sdenypd"),
  lookupEmails("lookup-refused-at-sign-in", ["k1-sdenypd"]),
  signUp("sign-up-again", "k1-sdenypd"),
  signUp("sign-up-create-disabled", "k2-cdisable"),
  lookupEmails("lookup-create-disabled", ["k2-cdisable"]),
  signUp("sign-up-sign-in-disabled", "k3-sdisable"),
  lookupEmails("lookup-sign-in-disabled", ["k3-sdisable"]),
]);

// ---- B5 timeout --------------------------------------------------------------------------------

const timeout = program("atb/blocking/timeout", [
  signUp("sign-up-slow-create", "w1-cslow"),
  lookupEmails("lookup-slow-create", ["w1-cslow"]),
  adminCreate("admin-create-slow-sign-in", "w2-sslow"),
  signIn("sign-in-slow", "w2-sslow"),
  lookupEmails("lookup-slow-sign-in", ["w2-sslow"]),
]);

// ---- B6 claims --------------------------------------------------------------------------------

const claims = program("atb/blocking/claims", [
  signUp("create-big-claims", "l1-cbig"),
  signUp("create-reserved-claim", "l2-creserved"),
  adminCreate("admin-create-big-session", "l3-sbig"),
  signIn("sign-in-big-session", "l3-sbig"),
  adminCreate("admin-create-reserved-session", "l4-sreserved"),
  signIn("sign-in-reserved-session", "l4-sreserved"),
  signUp("sign-up-l5", "l5"),
  refreshWith("refresh-l5", "sign-up-l5"),
  admin("admin-claims-l5", "update", {
    localId: from("sign-up-l5:localId"),
    customAttributes: '{"atbS":"admin","atbAdmin":true}',
  }),
  signIn("sign-in-l5-with-claims", "l5"),
  lookupEmails("lookup-l5", ["l5"]),
]);

// ---- B7 answers Identity Platform does not accept ---------------------------------------------

const response = program("atb/blocking/response", [
  signUp("create-bad-type", "v1-cbadtype"),
  signUp("create-unknown-member", "v2-cunknown"),
  lookupEmails("lookup-bad-answers", ["v1-cbadtype", "v2-cunknown"]),
]);

// ---- B8 blocking configuration -----------------------------------------------------------------

const config = program(
  "atb/blocking/config",
  [
    {
      id: "config-blocking",
      path: "admin/v2/projects/{project}/config",
      method: "GET",
      auth: "admin",
      project: "blockingFunctions",
    },
    {
      id: "tenant-get",
      path: "v2/projects/{project}/tenants/TENANT(c)",
      method: "GET",
      auth: "admin",
    },
    {
      id: "tenant-patch-blocking",
      path: "v2/projects/{project}/tenants/TENANT(c)",
      method: "PATCH",
      auth: "admin",
      query: { updateMask: "blockingFunctions" },
      body: { blockingFunctions: { triggers: {} } },
    },
  ],
  { tenants: { c: openTenant("atb-blk-config") } },
);

// ---- B10 tenant accounts -----------------------------------------------------------------------

const T = "TENANT(t)";
const tenant = program(
  "atb/blocking/tenant",
  [
    signUp("tenant-sign-up", "t1", { tenantId: T }),
    signIn("tenant-sign-in", "t1", { tenantId: T }),
    tenantAdmin("tenant-lookup", T, "lookup", { email: ["EMAIL(t1)"] }),
  ],
  { tenants: { t: openTenant("atb-blk-tenant") } },
);

// ---- B11 beforeSendEmail and beforeSendSms -----------------------------------------------------

const Q = "TENANT(q)";
const send = program(
  "atb/blocking/send",
  [
    adminCreate("create-s1", "s1-eecho"),
    client("reset-mail-echo", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(s1-eecho)",
    }),
    adminCreate("create-s2", "s2-edenypd"),
    client("reset-mail-refused", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(s2-edenypd)",
    }),
    adminCreate("create-s3", "s3-eblock"),
    client("reset-mail-blocked", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(s3-eblock)",
    }),
    signIn("sign-in-s1", "s1-eecho"),
    client("verify-mail-echo", "sendOobCode", {
      requestType: "VERIFY_EMAIL",
      idToken: from("sign-in-s1:idToken"),
    }),
    admin("admin-reset-link-echo", "sendOobCode", {
      requestType: "PASSWORD_RESET",
      email: "EMAIL(s1-eecho)",
      returnOobLink: true,
    }),
    client("link-mail-echo-in-tenant", "sendOobCode", {
      requestType: "EMAIL_SIGNIN",
      email: "EMAIL(s4-eecho)",
      continueUrl: "https://{project}.firebaseapp.com/finish",
      canHandleCodeInApp: true,
      tenantId: Q,
    }),
    phoneCode("sms-echo", 5),
    phoneCode("sms-plain", 0),
  ],
  { tenants: { q: openTenant("atb-blk-send") } },
);

/** Every blocking program, in recording order (the custom-token program is recorded apart). */
export const BLOCKING_PROGRAMS = [
  events,
  emailLink,
  mfa,
  ordering,
  refusal,
  rollback,
  timeout,
  claims,
  response,
  config,
  tenant,
  send,
  customToken,
];
