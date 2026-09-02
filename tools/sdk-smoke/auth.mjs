// Auth smoke: email actions, email link, phone, fixture identity providers and phone second
// factors through the real `firebase` client SDK and `firebase-admin`, with the codes read
// from the emulator inspection routes (what a test does instead of reading an inbox).
//
// Env: FIREBASE_AUTH_EMULATOR_HOST, GOOGLE_CLOUD_PROJECT (demo-app)
import { initializeApp } from "firebase/app";
import {
  getAuth,
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendPasswordResetEmail,
  verifyPasswordResetCode,
  confirmPasswordReset,
  sendEmailVerification,
  applyActionCode,
  sendSignInLinkToEmail,
  isSignInWithEmailLink,
  signInWithEmailLink,
  signInWithCredential,
  GoogleAuthProvider,
  OAuthProvider,
  fetchSignInMethodsForEmail,
  getMultiFactorResolver,
  updatePassword,
  signOut,
} from "firebase/auth";
import { initializeApp as initializeAdmin } from "firebase-admin/app";
import { getAuth as getAdminAuth } from "firebase-admin/auth";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";
const emulator = `http://${authHost}/emulator/v1/projects/${project}`;

const results = [];
async function check(name, fn) {
  try {
    const extra = await fn();
    results.push({ name, ok: true, extra });
  } catch (e) {
    results.push({ name, ok: false, error: String(e?.message ?? e), code: e?.code });
  }
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};
const lastOob = async () => (await (await fetch(`${emulator}/oobCodes`)).json()).oobCodes.at(-1);
const lastSms = async () =>
  (await (await fetch(`${emulator}/verificationCodes`)).json()).verificationCodes.at(-1);
// The Node build of `firebase/auth` has no phone support (it needs a browser reCAPTCHA
// verifier), so the phone steps go through the same REST calls the browser SDK makes.
const rest = async (path, body) => {
  const r = await fetch(`http://${authHost}/identitytoolkit.googleapis.com/${path}?key=fake-api-key`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await r.json();
  if (!r.ok) throw new Error(`${path}: ${json.error?.message}`);
  return json;
};

const app = initializeApp({ apiKey: "fake-api-key", projectId: project, appId: "1:1:web:1" });
const auth = getAuth(app);
connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
const adminAuth = getAdminAuth(initializeAdmin({ projectId: project }));

await check("password change invalidates an existing session cookie", async () => {
  const credential = await createUserWithEmailAndPassword(
    auth,
    "session-cookie@example.com",
    "password1",
  );
  const oldIdToken = await credential.user.getIdToken();
  const oldClaims = await adminAuth.verifyIdToken(oldIdToken);
  const oldCookie = await adminAuth.createSessionCookie(oldIdToken, { expiresIn: 60 * 60 * 1000 });
  while (Math.floor(Date.now() / 1000) <= oldClaims.auth_time) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }

  await updatePassword(credential.user, "password2");
  let oldCookieRejected = false;
  try {
    await adminAuth.verifySessionCookie(oldCookie, true);
  } catch (error) {
    oldCookieRejected = error?.code === "auth/session-cookie-revoked";
  }
  assert(oldCookieRejected, "the pre-change session cookie remained valid");

  const newIdToken = await credential.user.getIdToken(true);
  const newCookie = await adminAuth.createSessionCookie(newIdToken, { expiresIn: 60 * 60 * 1000 });
  const verified = await adminAuth.verifySessionCookie(newCookie, true);
  assert(verified.uid === credential.user.uid, "the replacement session cookie was rejected");
  await signOut(auth);
  return { uid: verified.uid };
});

await check("Admin password change lets the Web SDK finish same-second logout", async () => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    while (Date.now() % 1000 > 150) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    const email = `admin-password-${attempt}@example.com`;
    const created = await adminAuth.createUser({
      email,
      emailVerified: true,
      password: "password1",
    });
    const credential = await signInWithEmailAndPassword(auth, email, "password1");
    const claims = await adminAuth.verifyIdToken(await credential.user.getIdToken());
    const updated = await adminAuth.updateUser(created.uid, { password: "password2" });
    const validSince = Math.floor(new Date(updated.tokensValidAfterTime).getTime() / 1000);
    if (validSince !== claims.auth_time) {
      await signOut(auth);
      await adminAuth.deleteUser(created.uid);
      continue;
    }

    let flowError;
    try {
      await credential.user.reload();
      await credential.user.getIdToken(true);
      await signOut(auth);
    } catch (error) {
      flowError = error;
    }
    const userRemained = auth.currentUser !== null;
    if (userRemained) await signOut(auth);
    await adminAuth.deleteUser(created.uid);
    assert(!flowError, `same-second refresh failed: ${flowError?.code ?? flowError}`);
    assert(!userRemained, "the Web SDK user remained signed in");
    return { validSince, authTime: claims.auth_time };
  }
  throw new Error("could not obtain a same-second Admin password update");
});

await check("password reset through an oob code", async () => {
  await createUserWithEmailAndPassword(auth, "reset@example.com", "hunter22");
  await signOut(auth);
  await sendPasswordResetEmail(auth, "reset@example.com");
  const oob = await lastOob();
  assert(oob.requestType === "PASSWORD_RESET", `unexpected ${oob.requestType}`);
  const email = await verifyPasswordResetCode(auth, oob.oobCode);
  assert(email === "reset@example.com", email);
  await confirmPasswordReset(auth, oob.oobCode, "newpassword1");
  const cred = await signInWithEmailAndPassword(auth, "reset@example.com", "newpassword1");
  await signOut(auth);
  return { uid: cred.user.uid };
});

await check("email verification with applyActionCode", async () => {
  const cred = await createUserWithEmailAndPassword(auth, "verify@example.com", "hunter22");
  assert(!cred.user.emailVerified, "fresh user is unverified");
  await sendEmailVerification(cred.user);
  const oob = await lastOob();
  assert(oob.requestType === "VERIFY_EMAIL", oob.requestType);
  await applyActionCode(auth, oob.oobCode);
  await cred.user.reload();
  assert(cred.user.emailVerified, "verified after applyActionCode");
  await signOut(auth);
  return { link: oob.oobLink };
});

await check("email link sign-in", async () => {
  await sendSignInLinkToEmail(auth, "link@example.com", {
    url: "http://localhost:5173/finish",
    handleCodeInApp: true,
  });
  const oob = await lastOob();
  assert(oob.requestType === "EMAIL_SIGNIN", oob.requestType);
  assert(isSignInWithEmailLink(auth, oob.oobLink), "link recognised");
  const cred = await signInWithEmailLink(auth, "link@example.com", oob.oobLink);
  assert(cred.user.emailVerified, "email link users are verified");
  const methods = await fetchSignInMethodsForEmail(auth, "link@example.com");
  await signOut(auth);
  return { methods };
});

await check("phone sign-in with the emulator's code", async () => {
  const { sessionInfo } = await rest("v1/accounts:sendVerificationCode", {
    phoneNumber: "+15551230000",
    recaptchaToken: "fake-token",
  });
  const sms = await lastSms();
  assert(sms.phoneNumber === "+15551230000" && sms.sessionInfo === sessionInfo, "code listed");
  const signed = await rest("v1/accounts:signInWithPhoneNumber", { sessionInfo, code: sms.code });
  assert(signed.isNewUser === true && signed.phoneNumber === "+15551230000", "new phone user");
  const decoded = await adminAuth.verifyIdToken(signed.idToken);
  assert(decoded.phone_number === "+15551230000", "admin sees the phone claim");
  const user = await adminAuth.getUserByPhoneNumber("+15551230000");
  assert(user.uid === signed.localId, "getUserByPhoneNumber");
  return { uid: signed.localId, provider: decoded.firebase.sign_in_provider };
});

await check("fixture identity provider sign-in and admin lookup", async () => {
  const assertion = JSON.stringify({ sub: "google-1", email: "g@example.com", name: "G User" });
  const cred = await signInWithCredential(auth, GoogleAuthProvider.credential(assertion));
  assert(cred.user.providerData.some((p) => p.providerId === "google.com"), "provider data");
  const byProvider = await adminAuth.getUserByProviderUid("google.com", "google-1");
  assert(byProvider.uid === cred.user.uid, "getUserByProviderUid");
  await adminAuth.updateUser(cred.user.uid, { providerToLink: { providerId: "github.com", uid: "gh-1" } });
  const linked = await adminAuth.getUser(cred.user.uid);
  await signOut(auth);
  return { providers: linked.providerData.map((p) => p.providerId) };
});

await check("OIDC provider sign-in through OAuthProvider.credential", async () => {
  const provider = new OAuthProvider("oidc.corp");
  const cred = await signInWithCredential(
    auth,
    provider.credential({
      idToken: JSON.stringify({ sub: "oidc-7", email: "oidc@example.com", email_verified: true, name: "O" }),
    }),
  );
  assert(cred.user.providerData.some((p) => p.providerId === "oidc.corp"), "oidc provider data");
  const info = cred.user.providerData.find((p) => p.providerId === "oidc.corp");
  assert(info.uid === "oidc-7", "oidc raw id");
  await signOut(auth);
  return { uid: cred.user.uid, email: cred.user.email };
});

await check("SAML sign-in carries the assertion attributes (raw signInWithIdp)", async () => {
  const saml = {
    assertion: {
      subject: { nameId: "saml-person@example.com" },
      attributeStatements: { department: ["eng"] },
    },
  };
  const postBody =
    `providerId=saml.myidp` +
    `&id_token=${encodeURIComponent(JSON.stringify({ sub: "saml-1" }))}` +
    `&SAMLResponse=${encodeURIComponent(JSON.stringify(saml))}`;
  const res = await rest("v1/accounts:signInWithIdp", { postBody, requestUri: "http://localhost" });
  assert(res.providerId === "saml.myidp", "saml providerId");
  assert(res.email === "saml-person@example.com", "email from nameId");
  assert(res.emailVerified === true, "saml email verified");
  assert(JSON.parse(res.rawUserInfo).department[0] === "eng", "attributeStatements as rawUserInfo");
  assert(typeof res.idToken === "string" && res.idToken.length > 0, "id token issued");
  return { localId: res.localId, federatedId: res.federatedId };
});

await check("access_token credential and createAuthUri(providerId) are NotImplemented (501)", async () => {
  const notImpl = async (path, body) => {
    const r = await fetch(`http://${authHost}/identitytoolkit.googleapis.com/${path}?key=fake-api-key`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return r.status;
  };
  const access = await notImpl("v1/accounts:signInWithIdp", {
    postBody: "providerId=google.com&access_token=opaque",
    requestUri: "http://localhost",
  });
  assert(access === 501, `access_token status ${access}`);
  const authUri = await notImpl("v1/accounts:createAuthUri", {
    providerId: "google.com",
    identifier: "a@b.com",
    continueUri: "http://localhost",
  });
  assert(authUri === 501, `createAuthUri(providerId) status ${authUri}`);
  return { access, authUri };
});

await check("identity-provider widget pages are served as HTML", async () => {
  const handler = await fetch(
    `http://${authHost}/emulator/auth/handler?apiKey=fake-api-key&providerId=oidc.corp`,
  );
  const handlerBody = await handler.text();
  assert(handler.headers.get("content-type").startsWith("text/html"), "handler content-type");
  assert(handlerBody.includes("Sign-in with"), "handler page title");
  const iframe = await fetch(`http://${authHost}/emulator/auth/iframe?apiKey=fake-api-key&appName=x`);
  const iframeBody = await iframe.text();
  assert(iframeBody.includes("Auth Emulator Helper Iframe"), "iframe page");
  const bad = await fetch(`http://${authHost}/emulator/auth/handler?providerId=oidc.corp`);
  assert(bad.status === 400, "missing apiKey is 400");
  return { handlerStatus: handler.status, iframeStatus: iframe.status };
});

await check("phone second factor: enrol, then sign in through the resolver", async () => {
  const cred = await createUserWithEmailAndPassword(auth, "mfa@example.com", "hunter22");
  // The Auth emulator refuses second-factor enrolment for an unverified password user
  // (UNVERIFIED_EMAIL); real apps verify the address first, a test does it as an admin.
  let refused = null;
  try {
    await rest("v2/accounts/mfaEnrollment:start", {
      idToken: await cred.user.getIdToken(),
      phoneEnrollmentInfo: { phoneNumber: "+15559990000", recaptchaToken: "fake-token" },
    });
  } catch (e) {
    refused = String(e.message);
  }
  assert(refused?.includes("UNVERIFIED_EMAIL"), `unverified enrolment was not refused: ${refused}`);
  await adminAuth.updateUser(cred.user.uid, { emailVerified: true });
  const idToken = await cred.user.getIdToken(true);
  const start = await rest("v2/accounts/mfaEnrollment:start", {
    idToken,
    phoneEnrollmentInfo: { phoneNumber: "+15559990000", recaptchaToken: "fake-token" },
  });
  const sms = await lastSms();
  const done = await rest("v2/accounts/mfaEnrollment:finalize", {
    idToken,
    displayName: "my phone",
    phoneVerificationInfo: { sessionInfo: start.phoneSessionInfo.sessionInfo, code: sms.code },
  });
  assert(done.idToken && done.refreshToken, "enrolled (the finalize response carries only the tokens)");
  await signOut(auth);
  let resolver;
  try {
    await signInWithEmailAndPassword(auth, "mfa@example.com", "hunter22");
    throw new Error("second factor was not required");
  } catch (e) {
    assert(e.code === "auth/multi-factor-auth-required", `got ${e.code}`);
    resolver = getMultiFactorResolver(auth, e);
  }
  const hint = resolver.hints[0];
  assert(hint.factorId === "phone" && hint.displayName === "my phone", `${hint.factorId} ${hint.displayName}`);
  const pending = resolver.session.credential;
  assert(typeof pending === "string", "resolver carries the pending credential");
  const started = await rest("v2/accounts/mfaSignIn:start", {
    mfaPendingCredential: pending,
    mfaEnrollmentId: hint.uid,
    phoneSignInInfo: { recaptchaToken: "fake-token" },
  });
  const sms2 = await lastSms();
  const signed = await rest("v2/accounts/mfaSignIn:finalize", {
    mfaPendingCredential: pending,
    phoneVerificationInfo: { sessionInfo: started.phoneResponseInfo.sessionInfo, code: sms2.code },
  });
  const decoded = await adminAuth.verifyIdToken(signed.idToken);
  assert(decoded.firebase.sign_in_second_factor === "phone", "second factor claim");
  return { hint: hint.displayName };
});

await check("admin link generators and phone-factor users", async () => {
  const link = await adminAuth.generatePasswordResetLink("reset@example.com");
  assert(link.includes("mode=resetPassword"), link);
  const verify = await adminAuth.generateEmailVerificationLink("reset@example.com");
  assert(verify.includes("mode=verifyEmail"), verify);
  const user = await adminAuth.createUser({
    email: "admin-mfa@example.com",
    password: "hunter22",
    multiFactor: { enrolledFactors: [{ phoneNumber: "+15550001111", displayName: "work", factorId: "phone" }] },
  });
  const fetched = await adminAuth.getUser(user.uid);
  assert(fetched.multiFactor?.enrolledFactors?.[0]?.phoneNumber === "+15550001111", "factor round trip");
  return { factors: fetched.multiFactor.enrolledFactors.length };
});

console.log(JSON.stringify(results, null, 1));
const failed = results.filter((r) => !r.ok);
process.exit(failed.length === 0 ? 0 : 1);
