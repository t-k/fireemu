// Identity Toolkit REST programs that production, the official Auth emulator and fireemu can
// all answer: no emulator-only route, no out-of-band email that production would deliver, and
// every account a program creates is deleted by the program itself. `EMAIL(n)` becomes a
// unique address per run so a leftover account never turns a fresh run into EMAIL_EXISTS.

const step = (id, path, body, extra = {}) => ({ id, path, body, ...extra });

export const PROGRAMS = [
  {
    id: "password/sign-up-and-sign-in",
    area: "password",
    steps: [
      step("sign-up", "v1/accounts:signUp", {
        email: "EMAIL(primary)",
        password: "password123",
        returnSecureToken: true,
      }),
      step("duplicate-email", "v1/accounts:signUp", {
        email: "EMAIL(primary)",
        password: "password456",
        returnSecureToken: true,
      }),
      step("sign-in", "v1/accounts:signInWithPassword", {
        email: "EMAIL(primary)",
        password: "password123",
        returnSecureToken: true,
      }),
      step("wrong-password", "v1/accounts:signInWithPassword", {
        email: "EMAIL(primary)",
        password: "wrong-password",
        returnSecureToken: true,
      }),
      step("unknown-email", "v1/accounts:signInWithPassword", {
        email: "EMAIL(nobody)",
        password: "password123",
        returnSecureToken: true,
      }),
      step("lookup", "v1/accounts:lookup", { idToken: { $from: "sign-in", path: "idToken" } }),
      step("update-display-name", "v1/accounts:update", {
        idToken: { $from: "sign-in", path: "idToken" },
        displayName: "Probe User",
        returnSecureToken: true,
      }),
      step("delete", "v1/accounts:delete", { idToken: { $from: "sign-in", path: "idToken" } }),
      step("sign-in-after-delete", "v1/accounts:signInWithPassword", {
        email: "EMAIL(primary)",
        password: "password123",
        returnSecureToken: true,
      }),
    ],
  },
  {
    id: "password/validation",
    area: "password",
    steps: [
      step("invalid-email", "v1/accounts:signUp", {
        email: "not-an-email",
        password: "password123",
        returnSecureToken: true,
      }),
      step("weak-password", "v1/accounts:signUp", {
        email: "EMAIL(weak)",
        password: "123",
        returnSecureToken: true,
      }),
      step("missing-password", "v1/accounts:signUp", {
        email: "EMAIL(nopass)",
        returnSecureToken: true,
      }),
      step("missing-email", "v1/accounts:signInWithPassword", {
        password: "password123",
        returnSecureToken: true,
      }),
    ],
  },
  {
    id: "anonymous/lifecycle",
    area: "anonymous",
    steps: [
      step("anonymous-sign-up", "v1/accounts:signUp", { returnSecureToken: true }),
      step("lookup-anonymous", "v1/accounts:lookup", {
        idToken: { $from: "anonymous-sign-up", path: "idToken" },
      }),
      step("delete-anonymous", "v1/accounts:delete", {
        idToken: { $from: "anonymous-sign-up", path: "idToken" },
      }),
    ],
  },
  {
    id: "tokens/errors",
    area: "tokens",
    steps: [
      step("lookup-with-garbage-token", "v1/accounts:lookup", { idToken: "not-a-jwt" }),
      step("custom-token-garbage", "v1/accounts:signInWithCustomToken", {
        token: "not-a-custom-token",
        returnSecureToken: true,
      }),
      step("reset-password-bad-code", "v1/accounts:resetPassword", {
        oobCode: "definitely-not-a-code",
        newPassword: "password789",
      }),
      step("update-with-bad-oob-code", "v1/accounts:update", {
        oobCode: "definitely-not-a-code",
      }),
      step("unknown-method", "v1/accounts:definitelyNotAMethod", {}),
      step("password-reset-for-unknown-email", "v1/accounts:sendOobCode", {
        requestType: "PASSWORD_RESET",
        email: "EMAIL(nobody)",
      }),
      step("mfa-enrollment-start-without-token", "v2/accounts/mfaEnrollment:start", {
        phoneEnrollmentInfo: { phoneNumber: "+15555550100" },
      }),
    ],
  },
];
