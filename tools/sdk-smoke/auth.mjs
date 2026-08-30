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
  fetchSignInMethodsForEmail,
  getMultiFactorResolver,
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
