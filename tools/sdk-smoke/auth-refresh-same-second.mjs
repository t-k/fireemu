// Minimal Admin password-update/Web SDK refresh repro.
// Run against an unpinned fireemu daemon with the strict profile.
import { getAuth, connectAuthEmulator, signInWithEmailAndPassword, signOut } from "firebase/auth";
import { deleteApp as deleteClientApp, initializeApp as initializeClient } from "firebase/app";
import { deleteApp as deleteAdminApp, initializeApp as initializeAdmin } from "firebase-admin/app";
import { getAuth as getAdminAuth } from "firebase-admin/auth";

const project = process.env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? "127.0.0.1:9099";
const clientApp = initializeClient({ apiKey: "fake-api-key", projectId: project, appId: "1:1:web:1" });
const auth = getAuth(clientApp);
connectAuthEmulator(auth, `http://${authHost}`, { disableWarnings: true });
const adminApp = initializeAdmin({ projectId: project });
const adminAuth = getAdminAuth(adminApp);

const refreshEndpoint = `http://${authHost}/securetoken.googleapis.com/v1/token?key=fake-api-key`;
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const postRefresh = async (refreshToken) => {
  const response = await fetch(refreshEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "refresh_token", refresh_token: refreshToken }),
  });
  return { status: response.status, body: await response.json() };
};

let result;
try {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    while (Date.now() % 1000 > 150) await wait(20);
    const email = `same-second-repro-${process.pid}-${attempt}@example.com`;
    const created = await adminAuth.createUser({ email, password: "password1" });
    try {
      const credential = await signInWithEmailAndPassword(auth, email, "password1");
      const idToken = await credential.user.getIdToken();
      const before = await adminAuth.verifyIdToken(idToken);
      const refreshToken = credential.user.refreshToken;
      const updated = await adminAuth.updateUser(created.uid, { password: "password2" });
      const validSince = Math.floor(new Date(updated.tokensValidAfterTime).getTime() / 1000);
      if (validSince !== before.auth_time) continue;

      const endpoint = await postRefresh(refreshToken);
      await credential.user.reload();
      let sdkError;
      try {
        await credential.user.getIdToken(true);
      } catch (error) {
        sdkError = { code: error?.code, message: error?.message };
      }
      result = {
        attempt,
        authTime: before.auth_time,
        validSince,
        endpoint: {
          status: endpoint.status,
          error: endpoint.body.error?.message ?? null,
          idTokenPresent: typeof endpoint.body.id_token === "string",
          refreshTokenPresent: typeof endpoint.body.refresh_token === "string",
        },
        sdkError,
      };
      if (endpoint.status !== 200 || sdkError) process.exitCode = 1;
      break;
    } finally {
      await signOut(auth).catch(() => {});
      await adminAuth.deleteUser(created.uid).catch(() => {});
    }
  }
  if (!result) throw new Error("could not obtain a same-second password update");
  console.log(JSON.stringify(result, null, 2));
} finally {
  await deleteClientApp(clientApp);
  await deleteAdminApp(adminApp);
}
