// AUTH-ACTION corpus: one program per recipe of spec/compatibility/closure/AUTH-ACTION.json.
// Programs only record answers; they never assert. Each program runs on an empty project (the
// session wipes before and after) and uses run-unique EMAIL(...)/UID(...) values.
//
// Codes come from the Admin sendOobCode with returnOobLink, which mails no code. Applying an
// email change may still send the old @example.com address a notice (example.com publishes a
// null MX, so nothing is delivered). A newer code
// of one type can retire an older one, so every program generates a code right before it uses
// it and names each code by the step that generated it. Only the email-link programs switch
// signIn.email.passwordRequired off, and the session switches it back afterwards.

import { TEST_PHONE_CODE } from "../auth-account/harness.mjs";

// ---- step builders -------------------------------------------------------------------------

const from = (reference) => ({ $from: reference });
const chop = (reference, drop) => ({ $chop: reference, drop });
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
const adminCreate = (id, name, extra = {}) => ({
  id,
  path: "v1/projects/{project}/accounts",
  auth: "admin",
  body: { localId: `UID(${name})`, email: `EMAIL(${name})`, password: "password123", ...extra },
});
const adminLookup = (id, name) => adminCall(id, "lookup", { localId: [`UID(${name})`] });
const adminUpdate = (id, name, fields) =>
  adminCall(id, "update", { localId: `UID(${name})`, ...fields });
const adminDelete = (id, name) => adminCall(id, "delete", { localId: `UID(${name})` });

/** An action code through the Admin route: the code and link come back and nothing is mailed. */
const oob = (id, requestType, fields = {}) =>
  adminCall(id, "sendOobCode", { requestType, ...fields, returnOobLink: true });
const resetLink = (id, name, fields = {}) =>
  oob(id, "PASSWORD_RESET", { email: `EMAIL(${name})`, ...fields });
const verifyLink = (id, name, fields = {}) =>
  oob(id, "VERIFY_EMAIL", { email: `EMAIL(${name})`, ...fields });
const changeLink = (id, name, newName, fields = {}) =>
  oob(id, "VERIFY_AND_CHANGE_EMAIL", {
    email: `EMAIL(${name})`,
    newEmail: `EMAIL(${newName})`,
    ...fields,
  });
const CONTINUE = "https://{project}.firebaseapp.com/finish";
const signInLink = (id, name, fields = {}) =>
  oob(id, "EMAIL_SIGNIN", {
    email: `EMAIL(${name})`,
    continueUrl: CONTINUE,
    canHandleCodeInApp: true,
    ...fields,
  });

/** `accounts:resetPassword` with only a code: inspects it without using it. */
const check = (id, codeStep) =>
  client(id, "resetPassword", { oobCode: from(`${codeStep}:oobCode`) });
const reset = (id, codeStep, newPassword = "password456", extra = {}) =>
  client(id, "resetPassword", { oobCode: from(`${codeStep}:oobCode`), newPassword, ...extra });
/** `accounts:update` with a code (applyActionCode). */
const apply = (id, codeStep, extra = {}) =>
  client(id, "update", { oobCode: from(`${codeStep}:oobCode`), ...extra });
const emailLinkSignIn = (id, codeStep, name, extra = {}) =>
  client(id, "signInWithEmailLink", {
    oobCode: from(`${codeStep}:oobCode`),
    email: `EMAIL(${name})`,
    ...extra,
  });
const signIn = (id, name, password = "password123", extra = {}) =>
  client(id, "signInWithPassword", {
    email: `EMAIL(${name})`,
    password,
    returnSecureToken: true,
    ...extra,
  });
/** A sign-in without returnSecureToken: production answers with a legacy token. */
const legacySignIn = (id, name) =>
  client(id, "signInWithPassword", { email: `EMAIL(${name})`, password: "password123" });
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
/** Whether an answer names the account an earlier step named. */
const sameAccount = (origin) => ({
  relations: { localIdVsOrigin: { kind: "same", left: "localId", right: `${origin}:localId` } },
});

const program = (id, steps, extra = {}) => ({ id, steps, ...extra });
const EMAIL_LINK_ON = { config: { "signIn.email.passwordRequired": false } };

// ---- generation through the Admin route ----------------------------------------------------

const generateAdmin = program("auth-action/generate/admin", [
  adminCreate("create-a", "a"),
  adminCreate("create-disabled", "d", { disabled: true }),
  {
    id: "create-phone",
    path: "v1/projects/{project}/accounts",
    auth: "admin",
    body: { localId: "UID(p)", phoneNumber: "PHONE(0)" },
  },
  resetLink("reset-link", "a"),
  check("reset-link-check", "reset-link"),
  resetLink("reset-link-mixed-case", "a", { email: "EMAILMIXED(a)" }),
  resetLink("reset-link-continue-firebaseapp", "a", {
    continueUrl: "https://{project}.firebaseapp.com/done?x=1",
  }),
  resetLink("reset-link-continue-web-app", "a", { continueUrl: "https://{project}.web.app/next" }),
  resetLink("reset-link-continue-localhost", "a", { continueUrl: "http://localhost:5000/done" }),
  resetLink("reset-link-continue-unauthorized", "a", {
    continueUrl: "https://unauthorized.example.com/done",
  }),
  resetLink("reset-link-continue-malformed", "a", { continueUrl: "not a url" }),
  resetLink("reset-link-continue-empty", "a", { continueUrl: "" }),
  resetLink("reset-link-in-app", "a", { continueUrl: CONTINUE, canHandleCodeInApp: true }),
  { ...resetLink("reset-link-unknown", "unknown-a"), noLinkExpected: true },
  resetLink("reset-link-disabled", "d"),
  oob("reset-link-missing-email", "PASSWORD_RESET"),
  {
    ...oob("reset-link-invalid-email", "PASSWORD_RESET", { email: "not-an-email" }),
    noLinkExpected: true,
  },
  oob("missing-request-type", undefined, { email: "EMAIL(a)" }),
  oob("unknown-request-type", "NOT_A_REQUEST_TYPE", { email: "EMAIL(a)" }),
  oob("unspecified-request-type", "OOB_REQ_TYPE_UNSPECIFIED", { email: "EMAIL(a)" }),
  adminCreate("create-gv", "gv"),
  verifyLink("verify-link", "gv"),
  check("verify-link-check", "verify-link"),
  { ...verifyLink("verify-link-unknown", "unknown-v"), noLinkExpected: true },
  verifyLink("verify-link-disabled", "d"),
  oob("verify-link-missing-email", "VERIFY_EMAIL"),
  changeLink("change-link", "a", "a-new"),
  check("change-link-check", "change-link"),
  oob("change-link-missing-new-email", "VERIFY_AND_CHANGE_EMAIL", { email: "EMAIL(a)" }),
  // Email privacy hides EMAIL_EXISTS: production answers 200 without a link.
  { ...changeLink("change-link-taken", "a", "d"), noLinkExpected: true },
  { ...changeLink("change-link-same", "a", "a"), noLinkExpected: true },
  changeLink("change-link-invalid-new", "a", "a", { newEmail: "not-an-email" }),
  { ...changeLink("change-link-unknown", "unknown-c", "c-new"), noLinkExpected: true },
  changeLink("change-link-disabled", "d", "d-new"),
  signInLink("sign-in-link-password-required", "a"),
  signIn("sign-in-a", "a"),
  adminCreate("create-gt", "gt"),
  signIn("sign-in-gt", "gt"),
  oob("verify-link-by-token", "VERIFY_EMAIL", { idToken: from("sign-in-gt:idToken") }),
  oob("change-link-by-token", "VERIFY_AND_CHANGE_EMAIL", {
    idToken: from("sign-in-a:idToken"),
    newEmail: "EMAIL(a-token)",
  }),
  check("change-link-by-token-check", "change-link-by-token"),
  oob("verify-link-garbage-token", "VERIFY_EMAIL", { idToken: "not-a-token" }),
  adminCreate("create-gu", "gu"),
  adminCreate("create-gw", "gw"),
  signIn("sign-in-gu", "gu"),
  oob("verify-link-token-and-email", "VERIFY_EMAIL", {
    idToken: from("sign-in-gu:idToken"),
    email: "EMAIL(gw)",
  }),
  client("phone-send-code", "sendVerificationCode", { phoneNumber: "PHONE(0)" }),
  client("phone-sign-in", "signInWithPhoneNumber", {
    sessionInfo: from("phone-send-code:sessionInfo"),
    code: TEST_PHONE_CODE,
  }),
  oob("verify-link-phone-account", "VERIFY_EMAIL", { idToken: from("phone-sign-in:idToken") }),
]);

// ---- the client route, only for addresses without an account --------------------------------

const clientReset = (id, fields = {}, extra = {}) =>
  client(
    id,
    "sendOobCode",
    { requestType: "PASSWORD_RESET", email: "EMAIL(unknown-1)", ...fields },
    extra,
  );

const generateClient = program("auth-action/generate/client", [
  clientReset("reset-unknown"),
  clientReset("reset-unknown-return-link", { returnOobLink: true }),
  clientReset("reset-unknown-continue-authorized", { continueUrl: CONTINUE }),
  clientReset("reset-unknown-continue-unauthorized", {
    continueUrl: "https://unauthorized.example.com/done",
  }),
  clientReset("reset-unknown-without-key", {}, { auth: "none" }),
]);

// ---- password reset --------------------------------------------------------------------------

const passwordReset = program("auth-action/password-reset", [
  adminCreate("create-a", "a"),
  signIn("sign-in-before", "a", "password123", fresh()),
  resetLink("reset-link-1", "a"),
  check("check-1", "reset-link-1"),
  resetLink("reset-link-2", "a"),
  check("check-1-after-second", "reset-link-1"),
  check("check-2", "reset-link-2"),
  reset("reset-weak-password", "reset-link-2", "12345"),
  check("check-2-after-weak", "reset-link-2"),
  client("reset-missing-code", "resetPassword", { newPassword: "password456" }),
  client("reset-unknown-code", "resetPassword", {
    oobCode: "not-a-real-code",
    newPassword: "password456",
  }),
  client("reset-truncated-code", "resetPassword", {
    oobCode: chop("reset-link-2:oobCode", 1),
    newPassword: "password456",
  }),
  reset("reset-empty-password", "reset-link-2", ""),
  // A second after the sign-in, so the revocation rows below do not depend on latency.
  { ...reset("reset-consume", "reset-link-2"), delayMs: 1100 },
  reset("reset-reuse", "reset-link-2", "password789"),
  check("check-2-after-consume", "reset-link-2"),
  signIn("sign-in-old-password", "a"),
  signIn("sign-in-new-password", "a", "password456", fresh()),
  lookupWith("lookup-token-before-reset", "sign-in-before"),
  refreshWith("refresh-token-before-reset", "sign-in-before"),
  adminLookup("admin-lookup-after-reset", "a"),
  // A code issued before an administrative password change.
  adminCreate("create-b", "b"),
  resetLink("reset-link-b", "b"),
  adminUpdate("admin-password-change-b", "b", { password: "password789" }),
  check("check-b-after-admin-password-change", "reset-link-b"),
  reset("reset-b-after-admin-password-change", "reset-link-b"),
  // A code issued before the account's own password change.
  adminCreate("create-c", "c"),
  signIn("sign-in-c", "c"),
  resetLink("reset-link-c", "c"),
  client("client-password-change-c", "update", {
    idToken: from("sign-in-c:idToken"),
    password: "password789",
    returnSecureToken: true,
  }),
  check("check-c-after-client-password-change", "reset-link-c"),
  reset("reset-c-after-client-password-change", "reset-link-c"),
  // A code issued before an administrative email change.
  adminCreate("create-e", "e"),
  resetLink("reset-link-e", "e"),
  adminUpdate("admin-email-change-e", "e", { email: "EMAIL(e-moved)" }),
  check("check-e-after-email-change", "reset-link-e"),
  reset("reset-e-after-email-change", "reset-link-e"),
  adminLookup("admin-lookup-e", "e"),
  // Disabled, then enabled again.
  adminCreate("create-f", "f"),
  resetLink("reset-link-f", "f"),
  adminUpdate("admin-disable-f", "f", { disableUser: true }),
  check("check-f-disabled", "reset-link-f"),
  reset("reset-f-disabled", "reset-link-f"),
  // Tells a refused use that spends the code apart from a re-enable that voids it.
  check("check-f-after-refused-reset", "reset-link-f"),
  adminUpdate("admin-enable-f", "f", { disableUser: false }),
  check("check-f-enabled", "reset-link-f"),
  reset("reset-f-enabled", "reset-link-f"),
  // Deleted.
  adminCreate("create-g", "g"),
  resetLink("reset-link-g", "g"),
  adminDelete("admin-delete-g", "g"),
  check("check-g-deleted", "reset-link-g"),
  reset("reset-g-deleted", "reset-link-g"),
  // A verification code offered as a reset code.
  adminCreate("create-rh", "rh"),
  verifyLink("verify-link-rh", "rh"),
  reset("reset-with-verify-code", "verify-link-rh"),
  check("check-verify-code-after-reset-attempt", "verify-link-rh"),
  signIn("sign-in-rh-original-password", "rh"),
]);

// ---- email verification ----------------------------------------------------------------------

// Production limits verification links per address (a second one within minutes answers
// TOO_MANY_ATTEMPTS_TRY_LATER, recording 2026-09-24), so each verification link of the corpus
// has an address of its own and a newer verification code cannot be observed (unobserved).
const verifyEmail = program("auth-action/verify-email", [
  adminCreate("create-va", "va"),
  signIn("sign-in-va", "va", "password123", fresh()),
  verifyLink("verify-link-va", "va"),
  check("check-va", "verify-link-va"),
  client("apply-truncated-code", "update", { oobCode: chop("verify-link-va:oobCode", 1) }),
  apply("apply-va", "verify-link-va"),
  apply("apply-va-again", "verify-link-va"),
  check("check-va-after-apply", "verify-link-va"),
  lookupWith("lookup-token-after-verify", "sign-in-va"),
  refreshWith("refresh-after-verify", "sign-in-va", {
    delayMs: 1100,
    ...sameSession("id_token", "sign-in-va:idToken"),
  }),
  signIn("sign-in-va-after-verify", "va"),
  client("apply-unknown-code", "update", { oobCode: "not-a-real-code" }),
  // Already verified.
  adminCreate("create-vv", "vv", { emailVerified: true }),
  verifyLink("verify-link-verified", "vv"),
  apply("apply-verified", "verify-link-verified"),
  // The address changed after the code was issued.
  adminCreate("create-vb", "vb"),
  verifyLink("verify-link-vb", "vb"),
  adminUpdate("admin-email-change-vb", "vb", { email: "EMAIL(vb-moved)" }),
  check("check-vb-after-email-change", "verify-link-vb"),
  apply("apply-vb-after-email-change", "verify-link-vb"),
  adminLookup("admin-lookup-vb", "vb"),
  // Disabled.
  adminCreate("create-vc", "vc"),
  verifyLink("verify-link-vc", "vc"),
  adminUpdate("admin-disable-vc", "vc", { disableUser: true }),
  apply("apply-vc-disabled", "verify-link-vc"),
  check("check-vc-after-refused-apply", "verify-link-vc"),
  adminUpdate("admin-enable-vc", "vc", { disableUser: false }),
  check("check-vc-enabled", "verify-link-vc"),
  apply("apply-vc-enabled", "verify-link-vc"),
  adminLookup("admin-lookup-vc", "vc"),
  // Deleted.
  adminCreate("create-ve", "ve"),
  verifyLink("verify-link-ve", "ve"),
  adminDelete("admin-delete-ve", "ve"),
  check("check-ve-deleted", "verify-link-ve"),
  apply("apply-ve-deleted", "verify-link-ve"),
  // A reset code applied as a verification.
  adminCreate("create-vf", "vf"),
  resetLink("reset-link-vf", "vf"),
  apply("apply-reset-code", "reset-link-vf"),
  check("check-reset-code-after-apply-attempt", "reset-link-vf"),
  adminLookup("admin-lookup-vf", "vf"),
]);

// ---- verify and change email -----------------------------------------------------------------

const changeEmail = program("auth-action/change-email", [
  adminCreate("create-a", "a"),
  signIn("sign-in-a", "a", "password123", fresh()),
  changeLink("change-link-1", "a", "a-first"),
  check("check-1", "change-link-1"),
  changeLink("change-link-2", "a", "a-second"),
  check("check-1-after-second", "change-link-1"),
  check("check-2", "change-link-2"),
  { ...apply("apply-2", "change-link-2"), delayMs: 1100 },
  apply("apply-2-again", "change-link-2"),
  apply("apply-1", "change-link-1"),
  signIn("sign-in-original-email", "a"),
  signIn("sign-in-second-email", "a-second", "password123", fresh()),
  signIn("sign-in-first-email", "a-first"),
  lookupWith("lookup-token-before-change", "sign-in-a"),
  refreshWith("refresh-token-before-change", "sign-in-a"),
  adminLookup("admin-lookup-a", "a"),
  // The new address is taken between issue and use.
  adminCreate("create-b", "b"),
  changeLink("change-link-b", "b", "late"),
  adminCreate("create-late", "late"),
  apply("apply-b-taken", "change-link-b"),
  adminLookup("admin-lookup-b-after-taken", "b"),
  // The account's address changed between issue and use.
  adminCreate("create-c", "c"),
  changeLink("change-link-c", "c", "c-new"),
  adminUpdate("admin-email-change-c", "c", { email: "EMAIL(c-admin)" }),
  check("check-c-after-admin-change", "change-link-c"),
  apply("apply-c-after-admin-change", "change-link-c"),
  adminLookup("admin-lookup-c", "c"),
  // Disabled and deleted.
  adminCreate("create-e", "e"),
  changeLink("change-link-e", "e", "e-new"),
  adminUpdate("admin-disable-e", "e", { disableUser: true }),
  apply("apply-e-disabled", "change-link-e"),
  adminLookup("admin-lookup-e", "e"),
  adminCreate("create-f", "f"),
  changeLink("change-link-f", "f", "f-new"),
  adminDelete("admin-delete-f", "f"),
  apply("apply-f-deleted", "change-link-f"),
  // A change code offered as a reset code.
  adminCreate("create-g", "g"),
  changeLink("change-link-g", "g", "g-new"),
  reset("reset-with-change-code", "change-link-g"),
  check("check-change-code-after-reset-attempt", "change-link-g"),
  // A verification code for the old address, applied after the change.
  adminCreate("create-ch", "ch"),
  verifyLink("verify-link-ch", "ch"),
  changeLink("change-link-ch", "ch", "ch-new"),
  apply("apply-change-ch", "change-link-ch"),
  apply("apply-old-verify-ch", "verify-link-ch"),
  adminLookup("admin-lookup-ch", "ch"),
]);

// ---- email link sign-in (email-link sign-in switched on for the program) --------------------

const emailLinkSignInProgram = program(
  "auth-action/email-link/sign-in",
  [
    signInLink("link-n", "n"),
    check("check-link-n", "link-n"),
    emailLinkSignIn("sign-in-mismatch", "link-n", "other"),
    client("sign-in-missing-email", "signInWithEmailLink", { oobCode: from("link-n:oobCode") }),
    client("sign-in-missing-code", "signInWithEmailLink", { email: "EMAIL(n)" }),
    client("sign-in-unknown-code", "signInWithEmailLink", {
      oobCode: "not-a-real-code",
      email: "EMAIL(n)",
    }),
    emailLinkSignIn("sign-in-new", "link-n", "n", fresh()),
    emailLinkSignIn("sign-in-reuse", "link-n", "n"),
    adminCall("admin-lookup-n", "lookup", { email: ["EMAIL(n)"] }),
    // Letter case of the address.
    signInLink("link-m", "m"),
    client("sign-in-mixed-case", "signInWithEmailLink", {
      oobCode: from("link-m:oobCode"),
      email: "EMAILMIXED(m)",
    }),
    // Link settings.
    signInLink("link-without-continue-url", "x", { continueUrl: undefined }),
    signInLink("link-without-in-app", "x", { canHandleCodeInApp: undefined }),
    signInLink("link-in-app-false", "x", { canHandleCodeInApp: false }),
    signInLink("link-unauthorized-continue-url", "x", {
      continueUrl: "https://unauthorized.example.com/finish",
    }),
    signInLink("link-localhost-continue-url", "x", { continueUrl: "http://localhost:5000/finish" }),
    // An existing password account.
    adminCreate("create-p", "p"),
    signInLink("link-p", "p"),
    emailLinkSignIn("sign-in-existing", "link-p", "p", fresh()),
    adminLookup("admin-lookup-p", "p"),
    signIn("sign-in-p-password", "p"),
    // A newer link for the same address.
    signInLink("link-q-1", "q"),
    signInLink("link-q-2", "q"),
    check("check-q-1-after-second", "link-q-1"),
    emailLinkSignIn("sign-in-q-1", "link-q-1", "q"),
    emailLinkSignIn("sign-in-q-2", "link-q-2", "q"),
    // Disabled and deleted accounts.
    adminCreate("create-disabled", "dl", { disabled: true }),
    signInLink("link-disabled", "dl"),
    emailLinkSignIn("sign-in-disabled", "link-disabled", "dl"),
    adminCreate("create-deleted", "del"),
    signInLink("link-deleted", "del"),
    adminDelete("admin-delete-del", "del"),
    emailLinkSignIn("sign-in-deleted", "link-deleted", "del"),
    adminCall("admin-lookup-del", "lookup", { email: ["EMAIL(del)"] }),
    // Linking the address to a signed-in session.
    client("anonymous-sign-up", "signUp", { returnSecureToken: true }),
    signInLink("link-anon", "anon"),
    {
      ...emailLinkSignIn("sign-in-link-to-anonymous", "link-anon", "anon", {
        idToken: from("anonymous-sign-up:idToken"),
      }),
      ...sameAccount("anonymous-sign-up"),
    },
    adminCall("admin-lookup-anon", "lookup", { email: ["EMAIL(anon)"] }),
    adminCreate("create-owner", "owned"),
    client("anonymous-sign-up-2", "signUp", { returnSecureToken: true }),
    signInLink("link-owned", "owned"),
    emailLinkSignIn("sign-in-link-owned-address", "link-owned", "owned", {
      idToken: from("anonymous-sign-up-2:idToken"),
    }),
    adminCreate("create-r", "r"),
    signIn("sign-in-r", "r"),
    signInLink("link-r-other-address", "r-other"),
    emailLinkSignIn("sign-in-link-other-address", "link-r-other-address", "r-other", {
      idToken: from("sign-in-r:idToken"),
    }),
    adminLookup("admin-lookup-r", "r"),
    // Codes of the other types.
    signInLink("link-z", "z"),
    reset("reset-with-sign-in-code", "link-z"),
    apply("apply-sign-in-code", "link-z"),
    check("check-z-after-misuse", "link-z"),
    resetLink("reset-link-p", "p"),
    emailLinkSignIn("sign-in-with-reset-code", "reset-link-p", "p"),
    check("check-reset-link-p-after-misuse", "reset-link-p"),
    // A password reset for an account that only ever signed in by link.
    resetLink("reset-link-n", "n"),
    reset("reset-n", "reset-link-n"),
    adminCall("admin-lookup-n-after-reset", "lookup", { email: ["EMAIL(n)"] }),
    signIn("sign-in-n-password", "n", "password456"),
  ],
  EMAIL_LINK_ON,
);

// ---- the session an email link opens (AUTH-CREDENTIAL scope decision C7) --------------------

const emailLinkSession = program(
  "auth-action/email-link/session",
  [
    signInLink("link-s", "s"),
    emailLinkSignIn("sign-in-s", "link-s", "s", fresh()),
    refreshWith("refresh-s", "sign-in-s", sameSession("id_token", "sign-in-s:idToken")),
    lookupWith("lookup-s", "sign-in-s"),
    cookie("cookie-s", "sign-in-s"),
    adminCreate("create-p", "p"),
    signInLink("link-p", "p"),
    emailLinkSignIn("sign-in-p", "link-p", "p", fresh()),
    refreshWith("refresh-p", "sign-in-p", sameSession("id_token", "sign-in-p:idToken")),
    cookie("cookie-p", "sign-in-p"),
    signIn("sign-in-p-password", "p", "password123", fresh()),
    client("anonymous-sign-up", "signUp", { returnSecureToken: true }),
    signInLink("link-anon", "anon"),
    {
      ...emailLinkSignIn("sign-in-anon-link", "link-anon", "anon", {
        idToken: from("anonymous-sign-up:idToken"),
      }),
      ...sameAccount("anonymous-sign-up"),
    },
    refreshWith(
      "refresh-anon-link",
      "sign-in-anon-link",
      sameSession("id_token", "sign-in-anon-link:idToken"),
    ),
    cookie("cookie-anon-link", "sign-in-anon-link"),
  ],
  EMAIL_LINK_ON,
);

// ---- legacy tokens (AUTH-CREDENTIAL left these inferred) --------------------------------------

const legacyToken = program(
  "auth-action/legacy-token",
  [
    adminCreate("create-la", "la"),
    // Only a password (or custom-token) sign-in without returnSecureToken issues a legacy token.
    legacySignIn("legacy-sign-in-la", "la"),
    oob("verify-link-by-legacy-token", "VERIFY_EMAIL", {
      idToken: from("legacy-sign-in-la:idToken"),
    }),
    check("verify-link-by-legacy-token-check", "verify-link-by-legacy-token"),
    oob("change-link-by-legacy-token", "VERIFY_AND_CHANGE_EMAIL", {
      idToken: from("legacy-sign-in-la:idToken"),
      newEmail: "EMAIL(la-legacy)",
    }),
    check("change-link-by-legacy-token-check", "change-link-by-legacy-token"),
    apply("apply-change-by-legacy-token", "change-link-by-legacy-token"),
    adminLookup("admin-lookup-la", "la"),
    // The client route reads the ID token (owner decision 2026-09-24): production mails a
    // confirmation to the unused @example.com address, which has a null MX.
    client("client-change-by-legacy-token", "sendOobCode", {
      requestType: "VERIFY_AND_CHANGE_EMAIL",
      idToken: from("legacy-sign-in-la:idToken"),
      newEmail: "EMAIL(lvc-legacy)",
    }),
    signIn("sign-in-la", "la"),
    client("client-change-by-secure-token", "sendOobCode", {
      requestType: "VERIFY_AND_CHANGE_EMAIL",
      idToken: from("sign-in-la:idToken"),
      newEmail: "EMAIL(lvc-secure)",
    }),
    adminCreate("create-lr", "lr"),
    legacySignIn("legacy-sign-in-lr", "lr"),
    signInLink("link-legacy", "lr-legacy"),
    emailLinkSignIn("sign-in-link-legacy-token", "link-legacy", "lr-legacy", {
      idToken: from("legacy-sign-in-lr:idToken"),
    }),
    adminLookup("admin-lookup-lr", "lr"),
    adminCall("admin-lookup-lr-legacy", "lookup", { email: ["EMAIL(lr-legacy)"] }),
  ],
  EMAIL_LINK_ON,
);

// ---- whose code it is --------------------------------------------------------------------------

const ownership = program("auth-action/ownership", [
  adminCreate("create-oa", "oa"),
  adminCreate("create-ob", "ob"),
  signIn("sign-in-ob", "ob"),
  verifyLink("verify-link-oa", "oa"),
  apply("apply-oa-code-with-ob-token", "verify-link-oa", { idToken: from("sign-in-ob:idToken") }),
  adminCall("admin-lookup-both-after-verify", "lookup", { localId: ["UID(oa)", "UID(ob)"] }),
  resetLink("reset-link-oa", "oa"),
  client("check-oa-code-naming-ob", "resetPassword", {
    oobCode: from("reset-link-oa:oobCode"),
    email: "EMAIL(ob)",
  }),
  reset("reset-oa-code-naming-ob", "reset-link-oa", "password456", { email: "EMAIL(ob)" }),
  signIn("sign-in-oa-new-password", "oa", "password456"),
  signIn("sign-in-ob-original-password", "ob"),
  changeLink("change-link-oa", "oa", "oa-new"),
  apply("apply-oa-change-with-ob-token", "change-link-oa", { idToken: from("sign-in-ob:idToken") }),
  adminCall("admin-lookup-both-after-change", "lookup", { localId: ["UID(oa)", "UID(ob)"] }),
  verifyLink("verify-link-ob", "ob"),
  apply("apply-ob-code-with-garbage-token", "verify-link-ob", { idToken: "not-a-token" }),
  adminLookup("admin-lookup-ob", "ob"),
]);

// ---- code lifetime (the last program: it waits an hour) ----------------------------------------

// Exploration (not evidence, 2026-09-24): a PASSWORD_RESET code answered at +3595 s after its
// generation and was EXPIRED_OOB_CODE at +3600 s; the other three types still answered at
// +3900 s. The checks straddle the reset code's hour by about ten seconds on either side, and
// record the other types' lower bound at the same time.
const WAIT_BEFORE = 3585;
const WAIT_ACROSS = 25;

const expiry = program(
  "auth-action/expiry",
  [
    adminCreate("create-a", "a"),
    adminCreate("create-b", "b"),
    verifyLink("verify-link-a", "a"),
    changeLink("change-link-b", "b", "b-new"),
    signInLink("link-n", "n"),
    resetLink("reset-link-b", "b"),
    // Generated last, so the wait starts right after it.
    resetLink("reset-link-a", "a"),
    { ...check("check-reset-before-hour", "reset-link-a"), waitSeconds: WAIT_BEFORE },
    { ...check("check-reset-across-hour", "reset-link-a"), waitSeconds: WAIT_ACROSS },
    reset("reset-after-hour", "reset-link-a"),
    reset("reset-b-after-hour", "reset-link-b"),
    check("check-verify-after-hour", "verify-link-a"),
    check("check-change-after-hour", "change-link-b"),
    check("check-sign-in-link-after-hour", "link-n"),
    apply("apply-verify-after-hour", "verify-link-a"),
    apply("apply-change-after-hour", "change-link-b"),
    emailLinkSignIn("sign-in-link-after-hour", "link-n", "n"),
    resetLink("reset-link-a-renewed", "a"),
    reset("reset-with-renewed-code", "reset-link-a-renewed"),
    adminCall("admin-lookup-after-hour", "lookup", { localId: ["UID(a)", "UID(b)"] }),
  ],
  EMAIL_LINK_ON,
);

/** Every program, in recording order. */
export const PROGRAMS = [
  generateAdmin,
  generateClient,
  passwordReset,
  verifyEmail,
  changeEmail,
  emailLinkSignInProgram,
  emailLinkSession,
  legacyToken,
  ownership,
  expiry,
];
