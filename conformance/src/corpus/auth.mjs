// Authentication rows: the sign-up / sign-in error envelopes, the Identity Toolkit REST
// shapes underneath them, the MFA errors, and the shape of an out-of-band action code.

import {
  EmailAuthProvider,
  createUserWithEmailAndPassword,
  deleteUser,
  fetchSignInMethodsForEmail,
  linkWithCredential,
  sendPasswordResetEmail,
  signInAnonymously,
  signInWithCustomToken,
  signInWithEmailAndPassword,
  signOut,
  updatePassword,
  updateProfile,
} from "firebase/auth";

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
        "enabled in the console; neither the official Auth emulator nor fireemu can produce " +
        "the production shape, so no local run may stand in for it.",
    );
  },
};

const emulatorRoute = (ctx, resource, init) =>
  fetch(`http://${ctx.hosts.auth}/emulator/v1/projects/${ctx.project}/${resource}`, init);

const lastVerificationCode = async (ctx) => {
  const { body } = await readJson(await emulatorRoute(ctx, "verificationCodes"));
  const codes = Array.isArray(body.verificationCodes) ? body.verificationCodes : [];
  return codes.at(-1) ?? null;
};

// Which first factors may carry a phone second factor, and the shapes of the enrolment and
// sign-in steps once one may. Generated ids and session handles are redacted by literal;
// the recorded rows are the statuses, error codes and key sets.
const mfaEligibility = {
  id: "auth/mfa-enrollment-eligibility",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["rest", "firebase-admin"],
  title:
    "Which first factors may enrol a phone second factor, and the enrolment and sign-in shapes",
  async run(ctx) {
    const admin = ctx.shared.adminAuth();
    const email = emailFor("auth-mfa-eligibility", "verified");
    const phone = "+15555550123";
    const start = (idToken, phoneNumber = phone) =>
      identityToolkitV2(ctx, "accounts/mfaEnrollment:start", {
        idToken,
        phoneEnrollmentInfo: { phoneNumber, recaptchaToken: "fake" },
      }).then(readJson);

    await ctx.step("an-anonymous-session-cannot-enrol", async () => {
      const { body } = await readJson(
        await identityToolkit(ctx, "accounts:signUp", { returnSecureToken: true }),
      );
      return start(body.idToken);
    });

    await ctx.step("a-phone-session-cannot-enrol", async () => {
      const sent = await readJson(
        await identityToolkit(ctx, "accounts:sendVerificationCode", {
          phoneNumber: "+15555550199",
          recaptchaToken: "fake",
        }),
      );
      const code = await lastVerificationCode(ctx);
      const signed = await readJson(
        await identityToolkit(ctx, "accounts:signInWithPhoneNumber", {
          sessionInfo: sent.body.sessionInfo,
          code: code?.code ?? "",
        }),
      );
      return start(signed.body.idToken);
    });

    let idToken = null;
    let localId = null;
    await ctx.step("a-verified-password-user-may-start", async () => {
      const { body } = await readJson(
        await identityToolkit(ctx, "accounts:signUp", {
          email,
          password: "password123",
          returnSecureToken: true,
        }),
      );
      localId = ctx.redact(body.localId, "<uid>");
      await admin.updateUser(localId, { emailVerified: true });
      // A fresh token carries the verified flag; the enrolment routes read the account.
      idToken = body.idToken;
      const started = await start(idToken);
      if (typeof started.body?.phoneSessionInfo?.sessionInfo === "string") {
        ctx.redact(started.body.phoneSessionInfo.sessionInfo, "<session>");
      }
      return { status: started.status, keys: Object.keys(started.body).toSorted() };
    });

    await ctx.step("finalize-with-the-wrong-code", async () => {
      const started = await start(idToken);
      ctx.redact(started.body.phoneSessionInfo.sessionInfo, "<session>");
      return identityToolkitV2(ctx, "accounts/mfaEnrollment:finalize", {
        idToken,
        phoneVerificationInfo: {
          sessionInfo: started.body.phoneSessionInfo.sessionInfo,
          code: "000000",
        },
      }).then(readJson);
    });

    await ctx.step("finalize-with-the-emulator-code", async () => {
      const started = await start(idToken);
      ctx.redact(started.body.phoneSessionInfo.sessionInfo, "<session>");
      const code = await lastVerificationCode(ctx);
      const { status, body } = await readJson(
        await identityToolkitV2(ctx, "accounts/mfaEnrollment:finalize", {
          idToken,
          displayName: "work phone",
          phoneVerificationInfo: {
            sessionInfo: started.body.phoneSessionInfo.sessionInfo,
            code: code?.code ?? "",
          },
        }),
      );
      return { status, keys: Object.keys(body).toSorted() };
    });

    await ctx.step("the-same-number-cannot-be-enrolled-twice", () => start(idToken));

    await ctx.step("the-account-record-carries-the-factor", async () => {
      const user = await admin.getUser(localId);
      const factors = user.multiFactor?.enrolledFactors ?? [];
      return factors.map((f) => ({
        factorId: f.factorId,
        displayName: f.displayName,
        phoneNumber: f.phoneNumber,
        hasEnrollmentTime: typeof f.enrollmentTime === "string",
        uidLength: f.uid.length,
      }));
    });

    let pending = null;
    await ctx.step("password-sign-in-stops-at-the-second-factor", async () => {
      const { status, body } = await readJson(
        await identityToolkit(ctx, "accounts:signInWithPassword", {
          email,
          password: "password123",
          returnSecureToken: true,
        }),
      );
      pending = body.mfaPendingCredential ?? null;
      if (typeof pending === "string") ctx.redact(pending, "<pending>");
      const hints = Array.isArray(body.mfaInfo) ? body.mfaInfo : [];
      for (const hint of hints) {
        if (typeof hint.mfaEnrollmentId === "string")
          ctx.redact(hint.mfaEnrollmentId, "<enrollment>");
      }
      return {
        status,
        keys: Object.keys(body).toSorted(),
        hints: hints.map((h) => ({
          keys: Object.keys(h).toSorted(),
          phoneInfo: h.phoneInfo,
          displayName: h.displayName,
        })),
      };
    });

    await ctx.step("second-factor-start-with-an-unknown-enrolment", () =>
      identityToolkitV2(ctx, "accounts/mfaSignIn:start", {
        mfaPendingCredential: pending,
        mfaEnrollmentId: "not-an-enrollment",
        phoneSignInInfo: { recaptchaToken: "fake" },
      }).then(readJson),
    );

    await ctx.step("second-factor-sign-in-completes", async () => {
      const user = await admin.getUser(localId);
      const enrollmentId = user.multiFactor.enrolledFactors[0].uid;
      const started = await readJson(
        await identityToolkitV2(ctx, "accounts/mfaSignIn:start", {
          mfaPendingCredential: pending,
          mfaEnrollmentId: enrollmentId,
          phoneSignInInfo: { recaptchaToken: "fake" },
        }),
      );
      const code = await lastVerificationCode(ctx);
      const { status, body } = await readJson(
        await identityToolkitV2(ctx, "accounts/mfaSignIn:finalize", {
          mfaPendingCredential: pending,
          phoneVerificationInfo: {
            sessionInfo: started.body.phoneResponseInfo?.sessionInfo,
            code: code?.code ?? "",
          },
        }),
      );
      const [, payload] = String(body.idToken ?? "..").split(".");
      const claims = payload ? JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) : {};
      return {
        status,
        keys: Object.keys(body).toSorted(),
        secondFactor: claims.firebase?.sign_in_second_factor ?? null,
      };
    });

    await ctx.step("withdraw-the-factor", async () => {
      const user = await admin.getUser(localId);
      const enrollmentId = user.multiFactor.enrolledFactors[0].uid;
      const { status, body } = await readJson(
        await identityToolkitV2(ctx, "accounts/mfaEnrollment:withdraw", {
          idToken,
          mfaEnrollmentId: enrollmentId,
        }),
      );
      const after = await admin.getUser(localId);
      return {
        status,
        keys: Object.keys(body).toSorted(),
        factorsLeft: after.multiFactor?.enrolledFactors?.length ?? 0,
      };
    });
  },
};

// The Admin SDK's account management, as real projects use it: create, read, update, custom
// claims, listing, import, deletion, session cookies and custom tokens.
const adminAccountLifecycle = {
  id: "auth/admin-account-lifecycle",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["firebase-admin", "firebase/auth"],
  title:
    "Admin SDK account management: create, read, update, claims, list, import, delete, cookies, custom tokens",
  async run(ctx) {
    const admin = ctx.shared.adminAuth();
    const auth = ctx.shared.webAuth();
    const uid = "conf-admin-alice";
    const email = emailFor("auth-admin", "alice");
    const record = (u) => ({
      uid: u.uid,
      email: u.email ?? null,
      emailVerified: u.emailVerified,
      displayName: u.displayName ?? null,
      photoURL: u.photoURL ?? null,
      phoneNumber: u.phoneNumber ?? null,
      disabled: u.disabled,
      providerIds: u.providerData.map((p) => p.providerId).toSorted(),
      customClaims: u.customClaims ?? null,
      hasCreationTime: typeof u.metadata.creationTime === "string",
    });

    await ctx.step("create-a-user-with-every-field", async () => {
      const u = await admin.createUser({
        uid,
        email,
        emailVerified: true,
        password: "password123",
        displayName: "Alice",
        photoURL: "https://example.com/alice.png",
        phoneNumber: "+15555550001",
        disabled: false,
      });
      return record(u);
    });

    await ctx.step("create-a-duplicate-uid", async () => {
      await admin.createUser({ uid, email: emailFor("auth-admin", "dup-uid") });
      return "created";
    });

    await ctx.step("create-a-duplicate-email", async () => {
      await admin.createUser({ email });
      return "created";
    });

    await ctx.step("create-a-duplicate-phone-number", async () => {
      await admin.createUser({ phoneNumber: "+15555550001" });
      return "created";
    });

    await ctx.step("look-up-by-email-and-phone", async () => {
      const byEmail = await admin.getUserByEmail(email);
      const byPhone = await admin.getUserByPhoneNumber("+15555550001");
      return { byEmail: byEmail.uid, byPhone: byPhone.uid };
    });

    await ctx.step("look-up-an-unknown-user", async () => {
      await admin.getUser("conf-admin-nobody");
      return "found";
    });

    await ctx.step("get-users-by-mixed-identifiers", async () => {
      const result = await admin.getUsers([
        { uid },
        { email: emailFor("auth-admin", "ghost") },
        { phoneNumber: "+15555550001" },
      ]);
      return {
        found: result.users.map((u) => u.uid),
        notFound: result.notFound.map((id) => Object.keys(id)[0]).toSorted(),
      };
    });

    await ctx.step("update-profile-and-disable", async () => {
      const u = await admin.updateUser(uid, {
        displayName: "Alice Updated",
        photoURL: null,
        disabled: true,
      });
      return record(u);
    });

    await ctx.step("a-disabled-user-cannot-sign-in", async () => {
      await signInWithEmailAndPassword(auth, email, "password123");
      return "signed in";
    });

    await ctx.step("set-and-read-custom-claims", async () => {
      await admin.updateUser(uid, { disabled: false });
      await admin.setCustomUserClaims(uid, { role: "admin", tier: 3 });
      const u = await admin.getUser(uid);
      const cred = await signInWithEmailAndPassword(auth, email, "password123");
      const result = await cred.user.getIdTokenResult();
      await signOut(auth);
      return {
        stored: u.customClaims,
        inToken: { role: result.claims.role, tier: result.claims.tier },
        signInProvider: result.signInProvider,
      };
    });

    await ctx.step("a-reserved-claim-is-refused", async () => {
      await admin.setCustomUserClaims(uid, { sub: "x" });
      return "set";
    });

    await ctx.step("list-users", async () => {
      const page = await admin.listUsers(1000);
      const mine = page.users.filter((u) => u.uid.startsWith("conf-admin-"));
      return {
        mine: mine.map((u) => u.uid).toSorted(),
        hasPageToken: page.pageToken !== undefined,
      };
    });

    await ctx.step("import-users", async () => {
      const result = await admin.importUsers([
        {
          uid: "conf-admin-import-1",
          email: emailFor("auth-admin", "import-1"),
          emailVerified: true,
          displayName: "Imported",
          customClaims: { tier: "gold" },
          providerData: [{ providerId: "google.com", uid: "google-import-1" }],
        },
        { uid, email: emailFor("auth-admin", "import-collides") },
      ]);
      const imported = await admin.getUser("conf-admin-import-1");
      return {
        successCount: result.successCount,
        failureCount: result.failureCount,
        errors: result.errors.map((e) => ({ index: e.index, code: e.error.code })),
        imported: record(imported),
      };
    });

    await ctx.step("import-a-user-with-a-phone-second-factor", async () => {
      const result = await admin.importUsers([
        {
          uid: "conf-admin-import-mfa",
          email: emailFor("auth-admin", "import-mfa"),
          emailVerified: true,
          multiFactor: {
            enrolledFactors: [
              {
                uid: "conf-admin-import-mfa-factor",
                phoneNumber: "+15555550077",
                factorId: "phone",
              },
            ],
          },
        },
      ]);
      const imported = await admin.getUser("conf-admin-import-mfa");
      return {
        successCount: result.successCount,
        failureCount: result.failureCount,
        factors: (imported.multiFactor?.enrolledFactors ?? []).map((f) => ({
          uid: f.uid,
          phoneNumber: f.phoneNumber,
          factorId: f.factorId,
        })),
      };
    });

    // The cookie is decoded here rather than through verifySessionCookie: the Admin SDK
    // checks its expiry against the wall clock, and the fireemu side of this suite runs on a
    // pinned virtual clock, so only the shape both sides mint can be compared.
    await ctx.step("session-cookie-shape", async () => {
      const cred = await signInWithEmailAndPassword(auth, email, "password123");
      const idToken = await cred.user.getIdToken();
      await signOut(auth);
      const cookie = await admin.createSessionCookie(idToken, { expiresIn: 60 * 60 * 1000 });
      const [header, payload] = cookie.split(".");
      const decode = (part) => JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
      const claims = decode(payload);
      return {
        alg: decode(header).alg,
        sub: claims.sub,
        iss: claims.iss,
        aud: claims.aud,
        lifetime: claims.exp - claims.iat,
        signInProvider: claims.firebase?.sign_in_provider ?? null,
      };
    });

    await ctx.step("a-session-cookie-lifetime-out-of-range-is-refused", async () => {
      const cred = await signInWithEmailAndPassword(auth, email, "password123");
      const idToken = await cred.user.getIdToken();
      await signOut(auth);
      await admin.createSessionCookie(idToken, { expiresIn: 60 * 1000 });
      return "created";
    });

    await ctx.step("custom-token-round-trip", async () => {
      const token = await admin.createCustomToken("conf-admin-custom", { plan: "pro" });
      const cred = await signInWithCustomToken(auth, token);
      const result = await cred.user.getIdTokenResult();
      const u = await admin.getUser("conf-admin-custom");
      await signOut(auth);
      return {
        uid: cred.user.uid,
        plan: result.claims.plan,
        signInProvider: result.signInProvider,
        providerIds: u.providerData.map((p) => p.providerId),
      };
    });

    // Only the account record is compared: the Admin SDK's checkRevoked verification also
    // checks token expiry against the wall clock, which the pinned fireemu side cannot pass.
    await ctx.step("revoke-refresh-tokens", async () => {
      const before = (await admin.getUser(uid)).tokensValidAfterTime;
      await admin.revokeRefreshTokens(uid);
      const after = (await admin.getUser(uid)).tokensValidAfterTime;
      return {
        recorded: typeof after === "string",
        movedOrSameSecond: before === undefined || Date.parse(after) >= Date.parse(before),
      };
    });

    await ctx.step("delete-a-user-and-look-it-up", async () => {
      await admin.deleteUser("conf-admin-import-1");
      await admin.getUser("conf-admin-import-1");
      return "found";
    });

    await ctx.step("delete-users-in-bulk", async () => {
      const result = await admin.deleteUsers([uid, "conf-admin-custom", "conf-admin-nobody"]);
      return {
        successCount: result.successCount,
        failureCount: result.failureCount,
        left: (await admin.listUsers(1000)).users
          .map((u) => u.uid)
          .filter((id) => id.startsWith("conf-admin-"))
          .toSorted(),
      };
    });
  },
};

// The client SDK flows a real app runs after sign-in: anonymous upgrade, profile and
// password changes (which re-issue tokens), account deletion, and the two behaviours the
// project's email privacy switch changes.
const clientAccountFlows = {
  id: "auth/client-account-flows",
  product: "auth",
  variant: VARIANTS.baseline,
  sdks: ["firebase/auth", "rest"],
  title:
    "Client SDK account flows: anonymous upgrade, profile and password updates, deletion, email privacy",
  async run(ctx) {
    const auth = ctx.shared.webAuth();
    const email = emailFor("auth-client", "upgrade");

    await ctx.step("anonymous-sign-in", async () => {
      const cred = await signInAnonymously(auth);
      ctx.redact(cred.user.uid, "<uid>");
      return {
        isAnonymous: cred.user.isAnonymous,
        providerIds: cred.user.providerData.map((p) => p.providerId),
        uidLength: cred.user.uid.length,
      };
    });

    await ctx.step("link-a-password-to-the-anonymous-user", async () => {
      const cred = await linkWithCredential(
        auth.currentUser,
        EmailAuthProvider.credential(email, "password123"),
      );
      const result = await cred.user.getIdTokenResult(true);
      return {
        isAnonymous: cred.user.isAnonymous,
        email: cred.user.email,
        emailVerified: cred.user.emailVerified,
        providerIds: cred.user.providerData.map((p) => p.providerId),
        signInProvider: result.signInProvider,
      };
    });

    await ctx.step("update-the-profile", async () => {
      await updateProfile(auth.currentUser, {
        displayName: "Upgraded",
        photoURL: "https://example.com/u.png",
      });
      await auth.currentUser.reload();
      return { displayName: auth.currentUser.displayName, photoURL: auth.currentUser.photoURL };
    });

    await ctx.step("change-the-password-and-keep-the-session", async () => {
      await updatePassword(auth.currentUser, "password456");
      // The response re-issues tokens, so the user is still signed in afterwards.
      await auth.currentUser.reload();
      const token = await auth.currentUser.getIdToken(true);
      return { stillSignedIn: auth.currentUser !== null, hasToken: typeof token === "string" };
    });

    await ctx.step("sign-in-with-the-new-password", async () => {
      await signOut(auth);
      const cred = await signInWithEmailAndPassword(auth, email, "password456");
      return { email: cred.user.email, displayName: cred.user.displayName };
    });

    await ctx.step("sign-in-methods-for-the-email", async () => {
      const methods = await fetchSignInMethodsForEmail(auth, email);
      return methods.toSorted();
    });

    await ctx.step("reset-for-an-unknown-email-reveals-it-by-default", async () => {
      await sendPasswordResetEmail(auth, emailFor("auth-client", "ghost"));
      return "sent";
    });

    await ctx.step("enable-improved-email-privacy", async () => {
      const { status, body } = await readJson(
        await emulatorRoute(ctx, "config", {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ emailPrivacyConfig: { enableImprovedEmailPrivacy: true } }),
        }),
      );
      return { status, body };
    });

    await ctx.step("with-privacy-a-reset-for-an-unknown-email-is-silent", async () => {
      await sendPasswordResetEmail(auth, emailFor("auth-client", "ghost"));
      const { body } = await readJson(await emulatorRoute(ctx, "oobCodes"));
      const codes = Array.isArray(body.oobCodes) ? body.oobCodes : [];
      return {
        sent: true,
        codesForGhost: codes.filter((c) => c.email === emailFor("auth-client", "ghost")).length,
      };
    });

    await ctx.step("with-privacy-a-wrong-password-is-undistinguished", async () => {
      await signOut(auth);
      await signInWithEmailAndPassword(auth, email, "wrong-password");
      return "signed in";
    });

    await ctx.step("with-privacy-an-unknown-user-is-undistinguished", async () => {
      await signInWithEmailAndPassword(auth, emailFor("auth-client", "ghost"), "password123");
      return "signed in";
    });

    await ctx.step("with-privacy-sign-in-methods-are-hidden", async () => {
      const methods = await fetchSignInMethodsForEmail(auth, email);
      return methods.toSorted();
    });

    await ctx.step("restore-the-default-privacy", async () => {
      const { status, body } = await readJson(
        await emulatorRoute(ctx, "config", {
          method: "PATCH",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ emailPrivacyConfig: { enableImprovedEmailPrivacy: false } }),
        }),
      );
      return { status, body };
    });

    await ctx.step("delete-the-account", async () => {
      const cred = await signInWithEmailAndPassword(auth, email, "password456");
      await deleteUser(cred.user);
      await signInWithEmailAndPassword(auth, email, "password456");
      return "signed in";
    });
  },
};

export const scenarios = [
  signUpAndSignIn,
  identityToolkitShapes,
  oobCodeShapes,
  mfaErrors,
  mfaEligibility,
  adminAccountLifecycle,
  clientAccountFlows,
];
