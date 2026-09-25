// AUTH-MFA corpus: one program per recipe of spec/compatibility/closure/AUTH-MFA.json.
// Programs only record answers; they never assert. Each program runs on an empty project (the
// session wipes before and after) and uses run-unique EMAIL(...)/UID(...) values.
//
// Second factors are TOTP (codes computed by the session from the secret the enrollment start
// returned) and SMS to the sandbox's configured test numbers, whose code is fixed and which are
// never texted (owner decision M3). A program that needs MFA declares the project `mfa` value
// it runs under; the session applies it and restores the pre-run value afterwards (M1). Only the
// first program runs with MFA disabled. Email-link and custom-token first factors are in scope
// (M5): the email-link program also switches password sign-in off for its own duration, and the
// custom-token program mints its token as the AUTH-CREDENTIAL harness does.
//
// A TOTP code is named by its offset from the target's current step. Steps marked `align` first
// move to the middle of a step, so a few requests after it see the step they were computed for.
// Every accepted code is used once: a row that must not be refused for replay uses a step no
// earlier row of the program used, later than every step used before it.

import { TEST_PHONE_CODE } from "../auth-account/harness.mjs";
import { MFA_CONFIGS, MFA_CONFIG_PROBES } from "./guard.mjs";

// ---- step builders -------------------------------------------------------------------------

const from = (reference) => ({ $from: reference });
const totp = (startStep, offset = 0) => ({ $totp: startStep, offset });
const wrongTotp = (startStep) => ({ $totpWrong: startStep });
const sameCode = (step) => ({ $sameCode: step });

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
const adminCall = (id, method, body, extra = {}) => ({
  id,
  path: `v1/projects/{project}/accounts:${method}`,
  auth: "admin",
  body,
  ...extra,
});
/** An Admin-created password account; MFA enrollment needs a verified address. */
const adminCreate = (id, name, extra = {}) => ({
  id,
  path: "v1/projects/{project}/accounts",
  auth: "admin",
  body: {
    localId: `UID(${name})`,
    email: `EMAIL(${name})`,
    password: "password123",
    emailVerified: true,
    ...extra,
  },
});
const adminLookup = (id, name, extra = {}) =>
  adminCall(id, "lookup", { localId: [`UID(${name})`] }, extra);
const adminUpdate = (id, name, fields, extra = {}) =>
  adminCall(id, "update", { localId: `UID(${name})`, ...fields }, extra);
const adminDelete = (id, name) => adminCall(id, "delete", { localId: `UID(${name})` });

const signIn = (id, name, password = "password123", extra = {}) =>
  client(
    id,
    "signInWithPassword",
    { email: `EMAIL(${name})`, password, returnSecureToken: true },
    extra,
  );
const lookupWith = (id, tokenStep) =>
  client(id, "lookup", { idToken: from(`${tokenStep}:idToken`) });
const refreshWith = (id, tokenStep, extra = {}) => ({
  id,
  api: "securetoken",
  path: "v1/token",
  auth: "key",
  form: { grant_type: "refresh_token", refresh_token: from(`${tokenStep}:refreshToken`) },
  ...extra,
});
const cookie = (id, tokenStep, extra = {}) => ({
  id,
  path: "v1/projects/{project}:createSessionCookie",
  auth: "admin",
  body: { idToken: from(`${tokenStep}:idToken`), validDuration: 3600 },
  ...extra,
});

/** The factor an enrollment finalize (or an MFA sign-in) put in its token. */
const factorOf = (tokenStep) => from(`${tokenStep}:idToken.firebase.second_factor_identifier`);
/** The n-th factor a first-factor sign-in listed. */
const listed = (signInStep, n = 0) => from(`${signInStep}:mfaInfo.${n}.mfaEnrollmentId`);
const pendingOf = (signInStep) => from(`${signInStep}:mfaPendingCredential`);

const totpStart = (id, tokenStep, extra = {}) =>
  clientV2(
    id,
    "mfaEnrollment:start",
    { idToken: from(`${tokenStep}:idToken`), totpEnrollmentInfo: {} },
    { deadline: true, ...extra },
  );
const totpFinalize = (id, tokenStep, startStep, code, extra = {}) =>
  clientV2(id, "mfaEnrollment:finalize", {
    idToken: from(`${tokenStep}:idToken`),
    totpVerificationInfo: {
      sessionInfo: from(`${startStep}:totpSessionInfo.sessionInfo`),
      verificationCode: code,
    },
    displayName: "Authenticator",
    ...extra,
  });
const phoneStart = (id, tokenStep, phone, extra = {}) =>
  clientV2(id, "mfaEnrollment:start", {
    idToken: from(`${tokenStep}:idToken`),
    phoneEnrollmentInfo: { phoneNumber: `PHONE(${phone})` },
    ...extra,
  });
const phoneFinalize = (id, tokenStep, startStep, code = TEST_PHONE_CODE, extra = {}) =>
  clientV2(id, "mfaEnrollment:finalize", {
    idToken: from(`${tokenStep}:idToken`),
    phoneVerificationInfo: {
      sessionInfo: from(`${startStep}:phoneSessionInfo.sessionInfo`),
      code,
    },
    displayName: "Phone",
    ...extra,
  });
const withdraw = (id, tokenStep, enrollment) =>
  clientV2(id, "mfaEnrollment:withdraw", {
    idToken: from(`${tokenStep}:idToken`),
    mfaEnrollmentId: enrollment,
  });
const totpSignIn = (id, pendingStep, enrollment, code, extra = {}) =>
  clientV2(id, "mfaSignIn:finalize", {
    mfaPendingCredential: pendingOf(pendingStep),
    mfaEnrollmentId: enrollment,
    totpVerificationInfo: { verificationCode: code },
    ...extra,
  });
const smsStart = (id, pendingStep, enrollment, extra = {}) =>
  clientV2(id, "mfaSignIn:start", {
    mfaPendingCredential: pendingOf(pendingStep),
    mfaEnrollmentId: enrollment,
    phoneSignInInfo: {},
    ...extra,
  });
const smsSignIn = (id, pendingStep, enrollment, startStep, code = TEST_PHONE_CODE, extra = {}) =>
  clientV2(id, "mfaSignIn:finalize", {
    mfaPendingCredential: pendingOf(pendingStep),
    mfaEnrollmentId: enrollment,
    phoneVerificationInfo: {
      sessionInfo: from(`${startStep}:phoneResponseInfo.sessionInfo`),
      code,
    },
    ...extra,
  });

/** Admin factor list entries, by test phone. */
const phoneFactor = (phone, displayName = `Phone ${phone}`) => ({
  phoneInfo: `PHONE(${phone})`,
  displayName,
});

/** A fresh sign-in's own token: is the session's auth_time the token's issue time? */
const fresh = (field = "idToken") => ({
  relations: { authTimeVsIat: { kind: "time", left: `${field}.auth_time`, right: `${field}.iat` } },
});
/** A token issued later in the session: same account, same auth_time, later or equal iat. */
const sameSession = (field, origin) => ({
  relations: {
    authTimeVsOrigin: { kind: "time", left: `${field}.auth_time`, right: `${origin}.auth_time` },
    iatVsOrigin: { kind: "time", left: `${field}.iat`, right: `${origin}.iat` },
    userIdVsOrigin: { kind: "same", left: `${field}.user_id`, right: `${origin}.user_id` },
  },
});
/** Whether an Admin lookup's validSince moved past a token's issue time. */
const validSinceVs = (tokenReference) => ({
  relations: {
    validSinceVsToken: { kind: "time", left: "users.0.validSince", right: tokenReference },
  },
});

const program = (id, steps, extra = {}) => ({ id, steps, ...extra });
const ENABLED = { config: { mfa: MFA_CONFIGS.enabled } };

// ---- MFA disabled (the project's baseline) ---------------------------------------------------

const disabled = program("auth-mfa/disabled", [
  adminCreate("create-a", "a"),
  signIn("sign-in-a", "a"),
  totpStart("totp-start", "sign-in-a"),
  phoneStart("phone-start", "sign-in-a", 0),
  // A factor the Admin API writes while the project has MFA switched off.
  adminUpdate("admin-set-phone-factor", "a", { mfa: { enrollments: [phoneFactor(1)] } }),
  adminLookup("admin-lookup-a", "a"),
  signIn("sign-in-a-with-factor", "a", "password123", fresh()),
  smsStart("sms-start", "sign-in-a-with-factor", listed("sign-in-a-with-factor")),
  smsSignIn("sms-finalize", "sign-in-a-with-factor", listed("sign-in-a-with-factor"), "sms-start"),
]);

// ---- the project `mfa` config (Admin config API) ---------------------------------------------

const configWrite = (id, value) => ({
  id,
  path: "admin/v2/projects/{project}/config",
  method: "PATCH",
  auth: "admin",
  query: { updateMask: "mfa" },
  body: { mfa: value },
  project: "mfa",
});
const configRead = (id) => ({
  id,
  path: "admin/v2/projects/{project}/config",
  method: "GET",
  auth: "admin",
  project: "mfa",
});

const config = program(
  "auth-mfa/config",
  [
    configRead("read-enabled"),
    ...Object.entries(MFA_CONFIG_PROBES).map(([name, value]) =>
      configWrite(`write-${name.replaceAll(/([A-Z])/g, "-$1").toLowerCase()}`, value),
    ),
    configRead("read-after-writes"),
  ],
  ENABLED,
);

// ---- TOTP enrollment ---------------------------------------------------------------------------

const totpEnroll = program(
  "auth-mfa/totp/enroll",
  [
    adminCreate("create-a", "a"),
    signIn("sign-in-a", "a", "password123", fresh()),
    clientV2("start-without-info", "mfaEnrollment:start", {
      idToken: from("sign-in-a:idToken"),
    }),
    totpStart("start", "sign-in-a"),
    clientV2("finalize-missing-code", "mfaEnrollment:finalize", {
      idToken: from("sign-in-a:idToken"),
      totpVerificationInfo: { sessionInfo: from("start:totpSessionInfo.sessionInfo") },
    }),
    clientV2("finalize-missing-session", "mfaEnrollment:finalize", {
      idToken: from("sign-in-a:idToken"),
      totpVerificationInfo: { verificationCode: wrongTotp("start") },
    }),
    totpFinalize("finalize-unknown-session", "sign-in-a", "start", wrongTotp("start"), {
      totpVerificationInfo: { sessionInfo: "not-a-session", verificationCode: "123456" },
    }),
    {
      ...totpFinalize("finalize-wrong-code", "sign-in-a", "start", wrongTotp("start")),
      align: true,
    },
    totpFinalize("finalize-wrong-code-again", "sign-in-a", "start", wrongTotp("start")),
    {
      ...totpFinalize("finalize", "sign-in-a", "start", totp("start", 0)),
      delayMs: 1100,
      ...sameSession("idToken", "sign-in-a:idToken"),
    },
    totpFinalize("finalize-again", "finalize", "start", totp("start", 1)),
    lookupWith("lookup-new-token", "finalize"),
    lookupWith("lookup-old-token", "sign-in-a"),
    refreshWith("refresh-old-token", "sign-in-a", {
      delayMs: 1100,
      ...sameSession("id_token", "sign-in-a:idToken"),
    }),
    refreshWith("refresh-new-token", "finalize", {
      ...sameSession("id_token", "finalize:idToken"),
    }),
    { ...adminLookup("admin-lookup-a", "a"), ...validSinceVs("sign-in-a:idToken.iat") },
    totpStart("start-second-totp", "finalize"),
    // The window at enrollment: two accounts, one per side, each enrolling on a fresh secret.
    adminCreate("create-wa", "wa"),
    signIn("sign-in-wa", "wa"),
    totpStart("start-wa", "sign-in-wa"),
    adminCreate("create-wb", "wb"),
    signIn("sign-in-wb", "wb"),
    totpStart("start-wb", "sign-in-wb"),
    {
      ...totpFinalize("finalize-wa-minus-6", "sign-in-wa", "start-wa", totp("start-wa", -6)),
      align: true,
    },
    totpFinalize("finalize-wa-minus-5", "sign-in-wa", "start-wa", totp("start-wa", -5)),
    totpFinalize("finalize-wb-plus-6", "sign-in-wb", "start-wb", totp("start-wb", 6)),
    totpFinalize("finalize-wb-plus-5", "sign-in-wb", "start-wb", totp("start-wb", 5), {
      displayName: undefined,
    }),
    adminCall("admin-lookup-window", "lookup", { localId: ["UID(wa)", "UID(wb)"] }),
  ],
  ENABLED,
);

// ---- TOTP sign-in ------------------------------------------------------------------------------

const totpSignInProgram = program(
  "auth-mfa/totp/sign-in",
  [
    adminCreate("create-c", "c"),
    signIn("sign-in-c", "c"),
    totpStart("start-c", "sign-in-c"),
    { ...totpFinalize("finalize-c", "sign-in-c", "start-c", totp("start-c", 0)), align: true },
    signIn("pending-1", "c"),
    signIn("wrong-password", "c", "password999"),
    clientV2("start-totp", "mfaSignIn:start", {
      mfaPendingCredential: pendingOf("pending-1"),
      mfaEnrollmentId: listed("pending-1"),
    }),
    smsStart("start-totp-as-phone", "pending-1", listed("pending-1")),
    clientV2("finalize-missing-pending", "mfaSignIn:finalize", {
      mfaEnrollmentId: listed("pending-1"),
      totpVerificationInfo: { verificationCode: wrongTotp("start-c") },
    }),
    totpSignIn("finalize-unknown-pending", "pending-1", listed("pending-1"), wrongTotp("start-c"), {
      mfaPendingCredential: "not-a-pending-credential",
    }),
    totpSignIn("finalize-missing-code", "pending-1", listed("pending-1"), undefined, {
      totpVerificationInfo: {},
    }),
    totpSignIn(
      "finalize-unknown-enrollment",
      "pending-1",
      "not-an-enrollment",
      wrongTotp("start-c"),
    ),
    {
      ...totpSignIn("finalize-wrong-code", "pending-1", listed("pending-1"), wrongTotp("start-c")),
      align: true,
    },
    totpSignIn("finalize-minus-6", "pending-1", listed("pending-1"), totp("start-c", -6)),
    totpSignIn("finalize-plus-6", "pending-1", listed("pending-1"), totp("start-c", 6)),
    {
      ...totpSignIn("finalize-plus-4", "pending-1", listed("pending-1"), totp("start-c", 4)),
      ...fresh(),
    },
    // The pending credential again, with a code of a later step no row used.
    totpSignIn("pending-1-again", "pending-1", listed("pending-1"), totp("start-c", 5)),
    refreshWith("refresh-after-mfa", "finalize-plus-4", {
      delayMs: 1100,
      ...sameSession("id_token", "finalize-plus-4:idToken"),
    }),
    lookupWith("lookup-after-mfa", "finalize-plus-4"),
    cookie("cookie-after-mfa", "finalize-plus-4"),
    // Codes already used, on a new pending credential.
    signIn("pending-2", "c"),
    totpSignIn(
      "replayed-sign-in-code",
      "pending-2",
      listed("pending-2"),
      sameCode("finalize-plus-4"),
    ),
    totpSignIn(
      "replayed-enrollment-code",
      "pending-2",
      listed("pending-2"),
      sameCode("finalize-c"),
    ),
    // An unused code of an earlier step than the last accepted one.
    totpSignIn("older-unused-code", "pending-2", listed("pending-2"), totp("start-c", 2)),
    // A second account: the factor id left out, and phone verification offered for TOTP.
    adminCreate("create-d", "d"),
    signIn("sign-in-d", "d"),
    totpStart("start-d", "sign-in-d"),
    { ...totpFinalize("finalize-d", "sign-in-d", "start-d", totp("start-d", 0)), align: true },
    signIn("pending-d1", "d"),
    clientV2("finalize-without-enrollment-id", "mfaSignIn:finalize", {
      mfaPendingCredential: pendingOf("pending-d1"),
      totpVerificationInfo: { verificationCode: totp("start-d", 2) },
    }),
    signIn("pending-d2", "d"),
    clientV2("finalize-phone-info-for-totp", "mfaSignIn:finalize", {
      mfaPendingCredential: pendingOf("pending-d2"),
      mfaEnrollmentId: listed("pending-d2"),
      phoneVerificationInfo: { sessionInfo: "not-a-session", code: TEST_PHONE_CODE },
    }),
  ],
  ENABLED,
);

// ---- TOTP withdrawal and what it revokes ---------------------------------------------------------

const totpWithdraw = program(
  "auth-mfa/totp/withdraw",
  [
    adminCreate("create-e", "e"),
    signIn("sign-in-e", "e"),
    totpStart("start-e", "sign-in-e"),
    { ...totpFinalize("finalize-e", "sign-in-e", "start-e", totp("start-e", 0)), align: true },
    clientV2("withdraw-missing-id", "mfaEnrollment:withdraw", {
      idToken: from("finalize-e:idToken"),
    }),
    withdraw("withdraw-unknown-id", "finalize-e", "not-an-enrollment"),
    clientV2("withdraw-missing-token", "mfaEnrollment:withdraw", {
      mfaEnrollmentId: factorOf("finalize-e"),
    }),
    { ...withdraw("withdraw", "finalize-e", factorOf("finalize-e")), delayMs: 1100 },
    lookupWith("lookup-token-before-withdraw", "finalize-e"),
    refreshWith("refresh-token-before-withdraw", "finalize-e"),
    lookupWith("lookup-first-factor-token", "sign-in-e"),
    withdraw("withdraw-again", "finalize-e", factorOf("finalize-e")),
    { ...adminLookup("admin-lookup-e", "e"), ...validSinceVs("finalize-e:idToken.iat") },
    signIn("sign-in-after-withdraw", "e", "password123", fresh()),
    lookupWith("lookup-after-withdraw", "sign-in-after-withdraw"),
    // Withdrawing with the first-factor token of a session that predates the factor.
    adminCreate("create-f", "f"),
    signIn("sign-in-f", "f"),
    totpStart("start-f", "sign-in-f"),
    { ...totpFinalize("finalize-f", "sign-in-f", "start-f", totp("start-f", 0)), align: true },
    withdraw("withdraw-with-first-factor-token", "sign-in-f", factorOf("finalize-f")),
    adminLookup("admin-lookup-f", "f"),
  ],
  ENABLED,
);

// ---- SMS to a test number ------------------------------------------------------------------------

const sms = program(
  "auth-mfa/sms",
  [
    adminCreate("create-s", "s"),
    signIn("sign-in-s", "s"),
    clientV2("start-missing-number", "mfaEnrollment:start", {
      idToken: from("sign-in-s:idToken"),
      phoneEnrollmentInfo: {},
    }),
    clientV2("start-invalid-number", "mfaEnrollment:start", {
      idToken: from("sign-in-s:idToken"),
      phoneEnrollmentInfo: { phoneNumber: "not-a-number" },
    }),
    phoneStart("start", "sign-in-s", 1),
    phoneFinalize("finalize-missing-code", "sign-in-s", "start", undefined, {
      phoneVerificationInfo: { sessionInfo: from("start:phoneSessionInfo.sessionInfo") },
    }),
    phoneFinalize("finalize-wrong-code", "sign-in-s", "start", "654321"),
    {
      ...phoneFinalize("finalize", "sign-in-s", "start"),
      delayMs: 1100,
      ...sameSession("idToken", "sign-in-s:idToken"),
    },
    phoneFinalize("finalize-again", "finalize", "start"),
    lookupWith("lookup-new-token", "finalize"),
    { ...adminLookup("admin-lookup-s", "s"), ...validSinceVs("sign-in-s:idToken.iat") },
    signIn("pending-1", "s"),
    clientV2("sign-in-start-without-info", "mfaSignIn:start", {
      mfaPendingCredential: pendingOf("pending-1"),
      mfaEnrollmentId: listed("pending-1"),
    }),
    smsStart("sign-in-start-unknown-enrollment", "pending-1", "not-an-enrollment"),
    smsStart("sign-in-start", "pending-1", listed("pending-1")),
    smsSignIn("sign-in-wrong-code", "pending-1", listed("pending-1"), "sign-in-start", "654321"),
    {
      ...smsSignIn("sign-in-finalize", "pending-1", listed("pending-1"), "sign-in-start"),
      ...fresh(),
    },
    smsSignIn("sign-in-finalize-again", "pending-1", listed("pending-1"), "sign-in-start"),
    refreshWith("refresh-after-mfa", "sign-in-finalize", {
      delayMs: 1100,
      ...sameSession("id_token", "sign-in-finalize:idToken"),
    }),
    cookie("cookie-after-mfa", "sign-in-finalize"),
    // A second phone factor, and the same number twice.
    phoneStart("start-second-phone", "sign-in-finalize", 2),
    phoneFinalize("finalize-second-phone", "sign-in-finalize", "start-second-phone"),
    phoneStart("start-same-number", "finalize-second-phone", 1),
    signIn("pending-2", "s"),
    smsStart("sign-in-start-second-phone", "pending-2", listed("pending-2", 1)),
    smsSignIn(
      "sign-in-second-phone",
      "pending-2",
      listed("pending-2", 1),
      "sign-in-start-second-phone",
    ),
    {
      ...withdraw("withdraw-first-phone", "sign-in-second-phone", listed("pending-2", 0)),
      delayMs: 1100,
    },
    {
      ...adminLookup("admin-lookup-after-withdraw", "s"),
      ...validSinceVs("sign-in-second-phone:idToken.iat"),
    },
  ],
  ENABLED,
);

// ---- the used-code checks again, below the account's attempt quota (owner decision M10) --------

// In auth-mfa/totp/sign-in production answered QUOTA_EXCEEDED to #replayed-enrollment-code
// (recording 1) and #older-unused-code (both recordings), the fifth and sixth wrong codes on
// that account. Here each check is the only wrong code on a new account: a factor enrolled
// with its step-0 code, a sign-in with the code four steps after that sign-in's own send time
// (offsets are relative to each row's send time), then the check on a new pending credential.
const quotaFreeAccount = (n, check, code) => [
  adminCreate(`create-${n}`, n),
  signIn(`sign-in-${n}`, n),
  totpStart(`start-${n}`, `sign-in-${n}`),
  { ...totpFinalize(`finalize-${n}`, `sign-in-${n}`, `start-${n}`, totp(`start-${n}`, 0)), align: true },
  signIn(`pending-${n}`, n),
  {
    ...totpSignIn(`plus-4-${n}`, `pending-${n}`, listed(`pending-${n}`), totp(`start-${n}`, 4)),
    ...fresh(),
  },
  signIn(`pending-${n}-again`, n),
  totpSignIn(check, `pending-${n}-again`, listed(`pending-${n}-again`), code(n)),
];

const totpQuotaFree = program(
  "auth-mfa/totp/quota-free",
  [
    // The code the enrollment used (step 0), after the step-4 sign-in.
    ...quotaFreeAccount("qe", "replayed-enrollment-code", (n) => sameCode(`finalize-${n}`)),
    // An unused code of step 2, older than the accepted step 4.
    ...quotaFreeAccount("qo", "older-unused-code", (n) => totp(`start-${n}`, 2)),
  ],
  ENABLED,
);

// ---- who may enroll, and how many ----------------------------------------------------------------

const interactions = program(
  "auth-mfa/interactions",
  [
    // An unverified address.
    adminCreate("create-u", "u", { emailVerified: false }),
    signIn("sign-in-u", "u"),
    totpStart("unverified-totp-start", "sign-in-u"),
    phoneStart("unverified-phone-start", "sign-in-u", 0),
    // Anonymous and phone first factors.
    client("anonymous-sign-up", "signUp", { returnSecureToken: true }),
    totpStart("anonymous-totp-start", "anonymous-sign-up"),
    phoneStart("anonymous-phone-start", "anonymous-sign-up", 0),
    client("phone-send-code", "sendVerificationCode", { phoneNumber: "PHONE(3)" }),
    client("phone-sign-in", "signInWithPhoneNumber", {
      sessionInfo: from("phone-send-code:sessionInfo"),
      code: TEST_PHONE_CODE,
    }),
    totpStart("phone-account-totp-start", "phone-sign-in"),
    phoneStart("phone-account-phone-start", "phone-sign-in", 4),
    // No ID token, a garbage one, and both kinds of enrollment at once.
    clientV2("start-missing-token", "mfaEnrollment:start", { totpEnrollmentInfo: {} }),
    clientV2("start-garbage-token", "mfaEnrollment:start", {
      idToken: "not-a-token",
      totpEnrollmentInfo: {},
    }),
    adminCreate("create-b", "b"),
    signIn("sign-in-b", "b"),
    clientV2("start-both-kinds", "mfaEnrollment:start", {
      idToken: from("sign-in-b:idToken"),
      totpEnrollmentInfo: {},
      phoneEnrollmentInfo: { phoneNumber: "PHONE(0)" },
    }),
    // TOTP first, then a phone: both are listed, in enrollment order.
    totpStart("start-b-totp", "sign-in-b"),
    {
      ...totpFinalize("finalize-b-totp", "sign-in-b", "start-b-totp", totp("start-b-totp", 0)),
      align: true,
    },
    phoneStart("start-b-phone", "finalize-b-totp", 0),
    phoneFinalize("finalize-b-phone", "finalize-b-totp", "start-b-phone"),
    signIn("pending-b", "b"),
    // The factor limit, written by the Admin API.
    adminCreate("create-l", "l"),
    adminUpdate("admin-set-five-factors", "l", {
      mfa: { enrollments: [0, 1, 2, 3, 4].map((n) => phoneFactor(n)) },
    }),
    signIn("sign-in-l", "l"),
    smsStart("sign-in-l-start", "sign-in-l", listed("sign-in-l", 4)),
    smsSignIn("sign-in-l-finalize", "sign-in-l", listed("sign-in-l", 4), "sign-in-l-start"),
    totpStart("totp-start-at-limit", "sign-in-l-finalize"),
    phoneStart("phone-start-at-limit", "sign-in-l-finalize", 5),
    adminUpdate("admin-set-six-factors", "l", {
      mfa: { enrollments: [0, 1, 2, 3, 4, 5].map((n) => phoneFactor(n)) },
    }),
    adminLookup("admin-lookup-l", "l"),
    // The account changes between the first and the second factor.
    adminCreate("create-x", "x"),
    signIn("sign-in-x", "x"),
    totpStart("start-x", "sign-in-x"),
    { ...totpFinalize("finalize-x", "sign-in-x", "start-x", totp("start-x", 0)), align: true },
    signIn("pending-x-disabled", "x"),
    adminUpdate("admin-disable-x", "x", { disableUser: true }),
    totpSignIn(
      "finalize-x-disabled",
      "pending-x-disabled",
      listed("pending-x-disabled"),
      totp("start-x", 1),
    ),
    adminUpdate("admin-enable-x", "x", { disableUser: false }),
    totpSignIn(
      "finalize-x-enabled-again",
      "pending-x-disabled",
      listed("pending-x-disabled"),
      totp("start-x", 2),
    ),
    signIn("pending-x-password", "x"),
    { ...adminUpdate("admin-password-change-x", "x", { password: "password456" }), delayMs: 1100 },
    totpSignIn(
      "finalize-x-after-password-change",
      "pending-x-password",
      listed("pending-x-password"),
      totp("start-x", 3),
    ),
    signIn("pending-x-cleared", "x", "password456"),
    adminUpdate("admin-clear-factors-x", "x", { mfa: {} }),
    totpSignIn(
      "finalize-x-after-factors-cleared",
      "pending-x-cleared",
      listed("pending-x-cleared"),
      totp("start-x", 4),
    ),
    adminCreate("create-y", "y"),
    signIn("sign-in-y", "y"),
    totpStart("start-y", "sign-in-y"),
    { ...totpFinalize("finalize-y", "sign-in-y", "start-y", totp("start-y", 0)), align: true },
    signIn("pending-y", "y"),
    totpSignIn(
      "finalize-y-other-account-factor",
      "pending-y",
      listed("pending-b", 0),
      totp("start-y", 1),
    ),
    adminDelete("admin-delete-y", "y"),
    totpSignIn("finalize-y-deleted", "pending-y", listed("pending-y"), totp("start-y", 2)),
  ],
  ENABLED,
);

// ---- factors written by the Admin API (AUTH-ACCOUNT scope decision A10) ---------------------------

const IMPORTED_AT = "2020-01-02T03:04:05Z";

const adminFactors = program(
  "auth-mfa/admin-factors",
  [
    adminCall("batch-create", "batchCreate", {
      users: [
        {
          localId: "UID(ia)",
          email: "EMAIL(ia)",
          emailVerified: true,
          mfaInfo: [{ ...phoneFactor(0, "Imported"), enrolledAt: IMPORTED_AT }],
        },
        {
          localId: "UID(ib)",
          email: "EMAIL(ib)",
          emailVerified: true,
          mfaInfo: [
            { ...phoneFactor(1, "Imported with id"), mfaEnrollmentId: "imported-factor-1" },
          ],
        },
        {
          localId: "UID(it)",
          email: "EMAIL(it)",
          emailVerified: true,
          mfaInfo: [{ totpInfo: {}, displayName: "Imported TOTP" }],
        },
        {
          localId: "UID(ix)",
          email: "EMAIL(ix)",
          emailVerified: true,
          mfaInfo: [{ phoneInfo: "not-a-phone", displayName: "Invalid" }],
        },
      ],
    }),
    adminCall("admin-lookup-imported", "lookup", {
      localId: ["UID(ia)", "UID(ib)", "UID(it)", "UID(ix)"],
    }),
    adminUpdate("admin-set-password-ia", "ia", { password: "password123" }),
    signIn("sign-in-ia", "ia"),
    smsStart("sign-in-ia-start", "sign-in-ia", listed("sign-in-ia")),
    {
      ...smsSignIn("sign-in-ia-finalize", "sign-in-ia", listed("sign-in-ia"), "sign-in-ia-start"),
      ...fresh(),
    },
    adminUpdate("admin-replace-factors-ia", "ia", {
      mfa: { enrollments: [phoneFactor(2, "Replaced")] },
    }),
    adminLookup("admin-lookup-replaced", "ia"),
    adminUpdate("admin-set-totp-factor-ia", "ia", {
      mfa: { enrollments: [{ totpInfo: {}, displayName: "Admin TOTP" }] },
    }),
    adminUpdate("admin-set-invalid-phone-ia", "ia", {
      mfa: { enrollments: [{ phoneInfo: "not-a-phone" }] },
    }),
    adminUpdate("admin-clear-factors-ia", "ia", { mfa: {} }),
    adminLookup("admin-lookup-cleared", "ia"),
    signIn("sign-in-ia-after-clear", "ia", "password123", fresh()),
    // A client enrollment next to a factor the Admin API wrote.
    adminCreate("create-m", "m"),
    adminUpdate("admin-set-factor-m", "m", { mfa: { enrollments: [phoneFactor(3)] } }),
    signIn("sign-in-m", "m"),
    smsStart("sign-in-m-start", "sign-in-m", listed("sign-in-m")),
    smsSignIn("sign-in-m-finalize", "sign-in-m", listed("sign-in-m"), "sign-in-m-start"),
    totpStart("start-m-totp", "sign-in-m-finalize"),
    {
      ...totpFinalize(
        "finalize-m-totp",
        "sign-in-m-finalize",
        "start-m-totp",
        totp("start-m-totp", 0),
      ),
      align: true,
    },
    adminLookup("admin-lookup-m", "m"),
  ],
  ENABLED,
);

// ---- other first factors (owner decision M5) ---------------------------------------------------

/** An email-link sign-in code from the Admin route: returned, never mailed. */
const signInLink = (id, name) =>
  adminCall(id, "sendOobCode", {
    requestType: "EMAIL_SIGNIN",
    email: `EMAIL(${name})`,
    continueUrl: "https://{project}.firebaseapp.com/finish",
    canHandleCodeInApp: true,
    returnOobLink: true,
  });
const linkSignIn = (id, linkStep, name, extra = {}) =>
  client(id, "signInWithEmailLink", {
    oobCode: from(`${linkStep}:oobCode`),
    email: `EMAIL(${name})`,
    ...extra,
  });

const emailLinkFirstFactor = program(
  "auth-mfa/first-factor/email-link",
  [
    // A password account with a TOTP factor signs in by link.
    adminCreate("create-el", "el"),
    signIn("sign-in-el", "el"),
    totpStart("start-el", "sign-in-el"),
    { ...totpFinalize("finalize-el", "sign-in-el", "start-el", totp("start-el", 0)), align: true },
    signInLink("link-el", "el"),
    linkSignIn("sign-in-link-el", "link-el", "el"),
    {
      ...totpSignIn(
        "finalize-link-el",
        "sign-in-link-el",
        listed("sign-in-link-el"),
        totp("start-el", 1),
      ),
      ...fresh(),
    },
    // An account that only ever signed in by link enrolls, then signs in by link again.
    signInLink("link-eln", "eln"),
    linkSignIn("sign-in-link-eln", "link-eln", "eln", fresh()),
    totpStart("start-eln", "sign-in-link-eln"),
    {
      ...totpFinalize("finalize-eln", "sign-in-link-eln", "start-eln", totp("start-eln", 0)),
      align: true,
    },
    signInLink("link-eln-again", "eln"),
    linkSignIn("sign-in-link-eln-again", "link-eln-again", "eln"),
    totpSignIn(
      "finalize-link-eln-again",
      "sign-in-link-eln-again",
      listed("sign-in-link-eln-again"),
      totp("start-eln", 1),
    ),
  ],
  { config: { mfa: MFA_CONFIGS.enabled, "signIn.email.passwordRequired": false } },
);

const customTokenFirstFactor = program(
  "auth-mfa/first-factor/custom-token",
  [
    adminCreate("create-ct", "ct"),
    signIn("sign-in-ct", "ct"),
    totpStart("start-ct", "sign-in-ct"),
    { ...totpFinalize("finalize-ct", "sign-in-ct", "start-ct", totp("start-ct", 0)), align: true },
    client("custom-token-ct", "signInWithCustomToken", {
      token: { $token: "ct" },
      returnSecureToken: true,
    }),
    {
      ...totpSignIn(
        "finalize-custom-token-ct",
        "custom-token-ct",
        listed("custom-token-ct"),
        totp("start-ct", 1),
      ),
      ...fresh(),
    },
    refreshWith("refresh-custom-token-ct", "finalize-custom-token-ct", {
      delayMs: 1100,
      ...sameSession("id_token", "finalize-custom-token-ct:idToken"),
    }),
  ],
  { ...ENABLED, tokens: { ct: { uid: "UID(ct)" } } },
);

// ---- lifetimes (the last program: it waits half an hour) -----------------------------------------

// Owner decision M4: pending credentials are sampled at 300, 450 and 600 seconds, with 1800 as the
// refusal-side control. Each aged row is followed at once by a control on the same account with
// a resource acquired just then, so a refusal paired with an accepted control leaves age as the
// explanation. Enrollment sessions are sampled at the same ages; TOTP sessions also on either
// side of the 900 seconds their finalizeEnrollmentTime announced (exploration 2026-09-24). Every
// aged resource is acquired in one block before the first wait; each row waits until its own
// resource is old enough, so the ages elapse together and the program takes about 31 minutes.
const PENDING_AGES = [300, 450, 600, 1800];
const TOTP_SESSION_AGES = [300, 450, 600, 870, 930, 1800];
const PHONE_SESSION_AGES = [300, 450, 600, 1800];

const aged = (step, acquiredBy, seconds) => ({ ...step, age: { from: acquiredBy, seconds } });

function lifetimeSteps() {
  const setup = [];
  const acquire = [];
  const rows = [];
  PENDING_AGES.forEach((age) => {
    const n = `p${age}`;
    setup.push(
      adminCreate(`create-${n}`, n),
      signIn(`sign-in-${n}`, n),
      totpStart(`start-${n}`, `sign-in-${n}`),
      totpFinalize(`finalize-${n}`, `sign-in-${n}`, `start-${n}`, totp(`start-${n}`, 0)),
    );
    acquire.push(signIn(`pending-${n}`, n));
    rows.push({
      age,
      steps: [
        aged(
          totpSignIn(
            `aged-pending-${n}`,
            `pending-${n}`,
            listed(`pending-${n}`),
            totp(`start-${n}`, 0),
          ),
          `pending-${n}`,
          age,
        ),
        signIn(`control-pending-${n}`, n),
        totpSignIn(
          `control-finalize-${n}`,
          `control-pending-${n}`,
          listed(`control-pending-${n}`),
          totp(`start-${n}`, 1),
        ),
      ],
    });
  });
  // A session is finalized with a token of a sign-in made just before, so only the session is
  // old: a requirement of a recent sign-in would otherwise refuse the aged row and its control
  // alike (pre-send review MF-2). The wait is on that sign-in; the aged row follows it at once.
  TOTP_SESSION_AGES.forEach((age) => {
    const n = `t${age}`;
    setup.push(adminCreate(`create-${n}`, n), signIn(`sign-in-${n}`, n));
    acquire.push(totpStart(`start-${n}`, `sign-in-${n}`));
    rows.push({
      age,
      steps: [
        aged(signIn(`fresh-sign-in-${n}`, n), `start-${n}`, age),
        totpFinalize(
          `aged-session-${n}`,
          `fresh-sign-in-${n}`,
          `start-${n}`,
          totp(`start-${n}`, 0),
        ),
        totpStart(`control-start-${n}`, `fresh-sign-in-${n}`),
        totpFinalize(
          `control-session-${n}`,
          `fresh-sign-in-${n}`,
          `control-start-${n}`,
          totp(`control-start-${n}`, 0),
        ),
      ],
    });
  });
  PHONE_SESSION_AGES.forEach((age, index) => {
    const n = `s${age}`;
    setup.push(adminCreate(`create-${n}`, n), signIn(`sign-in-${n}`, n));
    acquire.push(phoneStart(`start-${n}`, `sign-in-${n}`, index));
    rows.push({
      age,
      steps: [
        aged(signIn(`fresh-sign-in-${n}`, n), `start-${n}`, age),
        phoneFinalize(`aged-session-${n}`, `fresh-sign-in-${n}`, `start-${n}`),
        phoneStart(`control-start-${n}`, `fresh-sign-in-${n}`, index),
        phoneFinalize(`control-session-${n}`, `fresh-sign-in-${n}`, `control-start-${n}`),
      ],
    });
  });
  // Whether enrollment needs a recent sign-in: a start with a token 1800 seconds old, and a
  // start with a new one at once.
  setup.push(adminCreate("create-o1800", "o1800"));
  acquire.push(signIn("sign-in-o1800", "o1800"));
  rows.push({
    age: 1800,
    steps: [
      aged(totpStart("aged-token-start-o1800", "sign-in-o1800"), "sign-in-o1800", 1800),
      signIn("control-sign-in-o1800", "o1800"),
      totpStart("control-start-o1800", "control-sign-in-o1800"),
    ],
  });
  // Longest-lived resources are acquired first, so the rows due soonest drift least.
  const order = (step) => -Number(/\d+$/.exec(step.id)?.[0] ?? 0);
  acquire.sort((a, b) => order(a) - order(b));
  rows.sort((a, b) => a.age - b.age);
  return [...setup, ...acquire, ...rows.flatMap((row) => row.steps)];
}

const lifetime = program("auth-mfa/lifetime", lifetimeSteps(), ENABLED);

// ---- short lifetimes (owner decision M8; waits about six minutes) ------------------------------

// The first recording (2026-09-24) found a TOTP pending credential refused as
// TOTP_CHALLENGE_TIMEOUT already at 300 seconds, and an enrollment start refused as
// CREDENTIAL_TOO_OLD_LOGIN_AGAIN with a token 1800 seconds old. This program brackets both: a
// TOTP pending credential at 60, 120, 180, 240 and 290 seconds, an SMS pending credential at 150
// and 300 seconds (its code is sent at that age and entered at once), and an enrollment start
// with a token 240 and 330 seconds old, each followed at once by a same-account control.
const SHORT_TOTP_PENDING_AGES = [60, 120, 180, 240, 290];
const SHORT_SMS_PENDING_AGES = [150, 300];
const SHORT_TOKEN_AGES = [240, 330];

function shortLifetimeSteps() {
  const setup = [];
  const acquire = [];
  const rows = [];
  SHORT_TOTP_PENDING_AGES.forEach((age) => {
    const n = `q${age}`;
    setup.push(
      adminCreate(`create-${n}`, n),
      signIn(`sign-in-${n}`, n),
      totpStart(`start-${n}`, `sign-in-${n}`),
      totpFinalize(`finalize-${n}`, `sign-in-${n}`, `start-${n}`, totp(`start-${n}`, 0)),
    );
    acquire.push(signIn(`pending-${n}`, n));
    rows.push({
      age,
      steps: [
        aged(
          totpSignIn(`aged-pending-${n}`, `pending-${n}`, listed(`pending-${n}`), totp(`start-${n}`, 0)),
          `pending-${n}`,
          age,
        ),
        signIn(`control-pending-${n}`, n),
        totpSignIn(
          `control-finalize-${n}`,
          `control-pending-${n}`,
          listed(`control-pending-${n}`),
          totp(`start-${n}`, 1),
        ),
      ],
    });
  });
  SHORT_SMS_PENDING_AGES.forEach((age, index) => {
    const n = `m${age}`;
    setup.push(
      adminCreate(`create-${n}`, n),
      signIn(`sign-in-${n}`, n),
      phoneStart(`start-${n}`, `sign-in-${n}`, index),
      phoneFinalize(`finalize-${n}`, `sign-in-${n}`, `start-${n}`),
    );
    acquire.push(signIn(`pending-${n}`, n));
    rows.push({
      age,
      steps: [
        aged(
          smsStart(`sms-start-aged-${n}`, `pending-${n}`, listed(`pending-${n}`)),
          `pending-${n}`,
          age,
        ),
        smsSignIn(`aged-pending-${n}`, `pending-${n}`, listed(`pending-${n}`), `sms-start-aged-${n}`),
        signIn(`control-pending-${n}`, n),
        smsStart(`control-start-${n}`, `control-pending-${n}`, listed(`control-pending-${n}`)),
        smsSignIn(
          `control-finalize-${n}`,
          `control-pending-${n}`,
          listed(`control-pending-${n}`),
          `control-start-${n}`,
        ),
      ],
    });
  });
  SHORT_TOKEN_AGES.forEach((age) => {
    const n = `r${age}`;
    setup.push(adminCreate(`create-${n}`, n));
    acquire.push(signIn(`sign-in-${n}`, n));
    rows.push({
      age,
      steps: [
        aged(totpStart(`aged-token-start-${n}`, `sign-in-${n}`), `sign-in-${n}`, age),
        signIn(`control-sign-in-${n}`, n),
        totpStart(`control-start-${n}`, `control-sign-in-${n}`),
      ],
    });
  });
  const order = (step) => -Number(/\d+$/.exec(step.id)?.[0] ?? 0);
  acquire.sort((a, b) => order(a) - order(b));
  rows.sort((a, b) => a.age - b.age);
  return [...setup, ...acquire, ...rows.flatMap((row) => row.steps)];
}

const lifetimeShort = program("auth-mfa/lifetime-short", shortLifetimeSteps(), ENABLED);

// ---- the SMS pending credential's lifetime (follow-up directive, Must 2; waits 30 minutes) -----

// Only TOTP pending credentials were sampled at 300, 450, 600 and 1800 seconds; an SMS one was
// sampled up to about 303 seconds (lifetime-short) and still accepted. An earlier production
// observation (GAP-AUTH-007) refused one from 600 seconds. This program samples an SMS pending
// credential at 450 and 600 seconds, with 1800 seconds as the refusal-side control (owner
// decisions M1 and M4, extended by the coordinator's delegation): its code is sent at that age
// and entered at once, and each row is followed at once by a same-account control.
const SMS_PENDING_AGES = [450, 600, 1800];

function smsLifetimeSteps() {
  const setup = [];
  const acquire = [];
  const rows = [];
  SMS_PENDING_AGES.forEach((age, index) => {
    const n = `m${age}`;
    setup.push(
      adminCreate(`create-${n}`, n),
      signIn(`sign-in-${n}`, n),
      phoneStart(`start-${n}`, `sign-in-${n}`, index),
      phoneFinalize(`finalize-${n}`, `sign-in-${n}`, `start-${n}`),
    );
    acquire.push(signIn(`pending-${n}`, n));
    rows.push({
      age,
      steps: [
        aged(
          smsStart(`sms-start-aged-${n}`, `pending-${n}`, listed(`pending-${n}`)),
          `pending-${n}`,
          age,
        ),
        smsSignIn(`aged-pending-${n}`, `pending-${n}`, listed(`pending-${n}`), `sms-start-aged-${n}`),
        signIn(`control-pending-${n}`, n),
        smsStart(`control-start-${n}`, `control-pending-${n}`, listed(`control-pending-${n}`)),
        smsSignIn(
          `control-finalize-${n}`,
          `control-pending-${n}`,
          listed(`control-pending-${n}`),
          `control-start-${n}`,
        ),
      ],
    });
  });
  const order = (step) => -Number(/\d+$/.exec(step.id)?.[0] ?? 0);
  acquire.sort((a, b) => order(a) - order(b));
  rows.sort((a, b) => a.age - b.age);
  return [...setup, ...acquire, ...rows.flatMap((row) => row.steps)];
}

const lifetimeSms = program("auth-mfa/lifetime-sms", smsLifetimeSteps(), ENABLED);

/** Every program, in recording order: MFA disabled first, the waiting programs last. */
export const PROGRAMS = [
  disabled,
  config,
  totpEnroll,
  totpSignInProgram,
  totpQuotaFree,
  totpWithdraw,
  sms,
  interactions,
  adminFactors,
  emailLinkFirstFactor,
  customTokenFirstFactor,
  lifetimeShort,
  lifetimeSms,
  lifetime,
];
