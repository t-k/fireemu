// Authentication rows: the sign-up / sign-in error envelopes, the Identity Toolkit REST
// shapes underneath them, the MFA errors, and the shape of an out-of-band action code.

import { createUserWithEmailAndPassword, signInWithEmailAndPassword, signOut } from "firebase/auth";

import { VARIANTS } from "../config.mjs";
import { emailFor } from "./context.mjs";

const identityToolkit = (ctx, path, body, { version = "v1", query = "key=fake-api-key" } = {}) =>
  fetch(`http://${ctx.hosts.auth}/identitytoolkit.googleapis.com/${version}/${path}?${query}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

// Multi-factor enrolment and sign-in live on the v2 Identity Toolkit surface.
const identityToolkitV2 = (ctx, path, body) => identityToolkit(ctx, path, body, { version: "v2" });

const readJson = async (response) => {
  const text = await response.text();
  try {
    return { status: response.status, body: JSON.parse(text) };
  } catch {
    return { status: response.status, body: { nonJsonBodyLength: text.length } };
  }
};

const signUpAndSignIn = {
  id: "auth/sign-up-and-sign-in-errors",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["firebase/auth", "firebase-admin"],
  title: "Client sign-up and sign-in successes and every documented credential error",
  async run(ctx) {
    const auth = ctx.shared.webAuth();
    const email = emailFor("auth-signin", "primary");

    await ctx.step("sign-up", async () => {
      const cred = await createUserWithEmailAndPassword(auth, email, "password123");
      return {
        uidLength: cred.user.uid.length,
        email: cred.user.email,
        emailVerified: cred.user.emailVerified,
        isAnonymous: cred.user.isAnonymous,
        providerId: cred.user.providerData[0]?.providerId ?? null,
      };
    });

    await ctx.step("sign-up-with-an-email-already-in-use", async () => {
      await createUserWithEmailAndPassword(auth, email, "password123");
      return "created";
    });

    await ctx.step("sign-up-with-a-weak-password", async () => {
      await createUserWithEmailAndPassword(auth, emailFor("auth-signin", "weak"), "123");
      return "created";
    });

    await ctx.step("sign-up-with-a-malformed-email", async () => {
      await createUserWithEmailAndPassword(auth, "not-an-email", "password123");
      return "created";
    });

    await ctx.step("sign-in-with-the-wrong-password", async () => {
      await signInWithEmailAndPassword(auth, email, "wrong-password");
      return "signed in";
    });

    await ctx.step("sign-in-as-an-unknown-user", async () => {
      await signInWithEmailAndPassword(auth, emailFor("auth-signin", "ghost"), "password123");
      return "signed in";
    });

    await ctx.step("sign-in-succeeds-and-mints-an-id-token", async () => {
      const cred = await signInWithEmailAndPassword(auth, email, "password123");
      const token = await cred.user.getIdToken();
      const [header, payload] = token.split(".");
      const decode = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
      const claims = decode(payload);
      return {
        headerAlg: decode(header).alg,
        claimKeys: Object.keys(claims).toSorted(),
        aud: claims.aud,
        iss: claims.iss,
        firebaseSignInProvider: claims.firebase?.sign_in_provider ?? null,
      };
    });

    await ctx.step("sign-out", async () => {
      await signOut(auth);
      return { currentUser: auth.currentUser };
    });
  },
};

const identityToolkitShapes = {
  id: "auth/identity-toolkit-error-shapes",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "The raw Identity Toolkit REST envelopes the client SDK errors are built from",
  async run(ctx) {
    await ctx.step("signUp-without-a-password", () =>
      identityToolkit(ctx, "accounts:signUp", {
        email: emailFor("auth-itk", "nopass"),
        returnSecureToken: true,
      }).then(readJson),
    );

    await ctx.step("signInWithPassword-for-an-unknown-user", () =>
      identityToolkit(ctx, "accounts:signInWithPassword", {
        email: emailFor("auth-itk", "ghost"),
        password: "password123",
        returnSecureToken: true,
      }).then(readJson),
    );

    await ctx.step("signInWithPassword-with-a-missing-field", () =>
      identityToolkit(ctx, "accounts:signInWithPassword", { returnSecureToken: true }).then(
        readJson,
      ),
    );

    await ctx.step("lookup-with-an-invalid-id-token", () =>
      identityToolkit(ctx, "accounts:lookup", { idToken: "not-a-jwt" }).then(readJson),
    );

    await ctx.step("unknown-method", () =>
      identityToolkit(ctx, "accounts:definitelyNotAMethod", {}).then(readJson),
    );
  },
};

const oobCodeShapes = {
  id: "auth/oob-code-shapes",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["rest", "firebase-admin"],
  title: "The shape of a password-reset out-of-band code and its verification errors",
  async run(ctx) {
    const email = emailFor("auth-oob", "reset");
    await ctx.step("create-the-user", async () => {
      const response = await identityToolkit(ctx, "accounts:signUp", {
        email,
        password: "password123",
        returnSecureToken: true,
      });
      const { status, body } = await readJson(response);
      return { status, keys: Object.keys(body).toSorted() };
    });

    await ctx.step("request-a-password-reset", async () => {
      const response = await identityToolkit(ctx, "accounts:sendOobCode", {
        requestType: "PASSWORD_RESET",
        email,
      });
      const { status, body } = await readJson(response);
      return { status, keys: Object.keys(body).toSorted(), email: body.email ?? null };
    });

    // Both emulators expose generated codes on the same privileged inspection route.
    await ctx.step("inspect-the-generated-code", async () => {
      const response = await fetch(
        `http://${ctx.hosts.auth}/emulator/v1/projects/${ctx.project}/oobCodes`,
      );
      const { status, body } = await readJson(response);
      const codes = Array.isArray(body.oobCodes) ? body.oobCodes : [];
      const mine = codes.find((c) => c.email === email) ?? null;
      return {
        status,
        count: codes.length,
        keys: mine ? Object.keys(mine).toSorted() : null,
        requestType: mine?.requestType ?? null,
        hasOobLink: typeof mine?.oobLink === "string",
      };
    });

    await ctx.step("reset-with-an-unknown-code", () =>
      identityToolkit(ctx, "accounts:resetPassword", {
        oobCode: "definitely-not-a-code",
        newPassword: "password456",
      }).then(readJson),
    );

    await ctx.step("verify-an-unknown-code", () =>
      identityToolkit(ctx, "accounts:update", { oobCode: "definitely-not-a-code" }).then(readJson),
    );
  },
};

const mfaErrors = {
  id: "auth/mfa-error-shapes",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "Multi-factor enrolment and sign-in error envelopes",
  async run(ctx) {
    const email = emailFor("auth-mfa", "user");
    let idToken = null;

    await ctx.step("create-a-user-to-enrol", async () => {
      const { status, body } = await readJson(
        await identityToolkit(ctx, "accounts:signUp", {
          email,
          password: "password123",
          returnSecureToken: true,
        }),
      );
      idToken = body.idToken ?? null;
      return { status, hasIdToken: typeof body.idToken === "string" };
    });

    await ctx.step("start-enrolment-without-a-verified-email", () =>
      identityToolkitV2(ctx, "accounts/mfaEnrollment:start", {
        idToken,
        phoneEnrollmentInfo: { phoneNumber: "+15555550100" },
      }).then(readJson),
    );

    await ctx.step("start-enrolment-with-an-invalid-id-token", () =>
      identityToolkitV2(ctx, "accounts/mfaEnrollment:start", {
        idToken: "not-a-jwt",
        phoneEnrollmentInfo: { phoneNumber: "+15555550100" },
      }).then(readJson),
    );

    await ctx.step("finalize-enrolment-with-an-unknown-session", () =>
      identityToolkitV2(ctx, "accounts/mfaEnrollment:finalize", {
        idToken,
        phoneVerificationInfo: { sessionInfo: "unknown-session", code: "000000" },
      }).then(readJson),
    );

    await ctx.step("finalize-sign-in-with-an-unknown-pending-credential", () =>
      identityToolkitV2(ctx, "accounts/mfaSignIn:finalize", {
        mfaPendingCredential: "unknown-pending-credential",
        phoneVerificationInfo: { sessionInfo: "unknown-session", code: "000000" },
      }).then(readJson),
    );

    ctx.pending(
      "totp-enrolment-secret-shape",
      "needs a real project",
      "Identity Platform issues TOTP secrets only for a project with multi-factor authentication " +
        "enabled in the console; neither the official Auth emulator nor firebase-testd can produce " +
        "the production shape, so no local run may stand in for it.",
    );
  },
};

export const scenarios = [signUpAndSignIn, identityToolkitShapes, oobCodeShapes, mfaErrors];
