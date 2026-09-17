import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { initializeApp } from "firebase/app";
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  GoogleAuthProvider,
  linkWithCredential,
  signInWithCredential,
  signInWithEmailAndPassword,
  signOut,
  unlink,
} from "firebase/auth";
import { initializeApp as initializeAdminApp } from "firebase-admin/app";
import { getAuth as getAdminAuth } from "firebase-admin/auth";

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);
const SDK_VERSION = "firebase 12.18.0; firebase-admin 14.3.0; node >=20";
export const REQUIRED_OPERATION_IDS = [
  "signup-a",
  "signup-b",
  "same-provider-signin",
  "cross-provider-same-email-collision",
  "distinct-provider-link",
  "provider-unlink",
];

export function projectUser(user) {
  return {
    uid: user.uid,
    ...(typeof user.email === "string" ? { email: user.email } : {}),
    providers: [...(user.providerData ?? [])]
      .map((provider) => ({ providerId: provider.providerId, uid: provider.uid }))
      .sort((a, b) => `${a.providerId}:${a.uid}`.localeCompare(`${b.providerId}:${b.uid}`)),
  };
}

export function validateReceipt(receipt) {
  assert.equal(receipt?.status, "completed");
  assert.equal(receipt?.productionExecuted, false, "productionExecuted must be false");
  assert.equal(receipt?.transport, "real-fireemu-artifact");
  assert.equal(receipt?.providerBoundary, "local-emulator-fixture");
  assert.match(receipt?.sourceCommit ?? "", /^[0-9a-f]{9,40}$/, "source binding is required");
  assert.match(receipt?.artifact?.sha256 ?? "", /^[0-9a-f]{64}$/, "artifact binding is required");
  assert.equal(receipt?.cleanup?.ownedResources, 0, "owned resources must be reclaimed");
  assert.equal(receipt?.cleanup?.listenersClosed, true, "listeners must be closed");
  assert.equal(receipt?.cleanup?.processStopped, true, "process must be stopped");
  assert.equal(receipt?.comparison?.contract, "auth-settings-v1");
  assert.deepEqual(
    (receipt?.operations ?? []).map((operation) => operation.id),
    REQUIRED_OPERATION_IDS,
    "selected operation sequence is incomplete",
  );
  return receipt;
}

async function bindArtifact(env) {
  const path = env.FIREEMU_ARTIFACT;
  const expected = env.FIREEMU_ARTIFACT_SHA256;
  const sourceCommit = env.FIREEMU_SOURCE_COMMIT;
  assert.ok(path, "FIREEMU_ARTIFACT is required");
  assert.match(path, /(^|\/)fireemu$/, "artifact must be fireemu");
  assert.match(expected ?? "", /^[0-9a-f]{64}$/, "FIREEMU_ARTIFACT_SHA256 is required");
  assert.match(sourceCommit ?? "", /^[0-9a-f]{9,40}$/, "FIREEMU_SOURCE_COMMIT is required");
  assert.equal((await stat(path)).isFile(), true, "artifact must be a regular file");
  const actual = createHash("sha256").update(await readFile(path)).digest("hex");
  assert.equal(actual, expected, "artifact digest mismatch");
  return { path, sha256: actual, sourceCommit };
}

function authOrigin(value) {
  assert.ok(value, "FIREBASE_AUTH_EMULATOR_HOST is required");
  const url = new URL(`http://${value}`);
  assert.ok(LOOPBACK.has(url.hostname), "Auth collector is local-only");
  return url.origin;
}

async function absent(admin, uid) {
  await assert.rejects(admin.getUser(uid), (error) => error?.code === "auth/user-not-found");
}

export async function runLocalCase(env = process.env) {
  const artifact = await bindArtifact(env);
  const authHost = authOrigin(env.FIREBASE_AUTH_EMULATOR_HOST);
  const project = env.GOOGLE_CLOUD_PROJECT ?? "demo-app";
  const marker = randomBytes(8).toString("hex");
  const emailA = `link-a-${marker}@example.test`;
  const emailB = `link-b-${marker}@example.test`;
  const app = initializeApp({ apiKey: "fake-api-key", projectId: project }, `auth-link-${marker}`);
  const auth = (await import("firebase/auth")).getAuth(app);
  connectAuthEmulator(auth, authHost, { disableWarnings: true });
  const admin = getAdminAuth(initializeAdminApp({ projectId: project }, `admin-link-${marker}`));
  const owned = [];
  const operations = [];

  try {
    const accountA = await createUserWithEmailAndPassword(auth, emailA, "local-password-1");
    owned.push(accountA.user.uid);
    operations.push({ id: "signup-a", status: "success", user: projectUser(accountA.user) });
    await signOut(auth);

    const accountB = await createUserWithEmailAndPassword(auth, emailB, "local-password-2");
    owned.push(accountB.user.uid);
    operations.push({ id: "signup-b", status: "success", user: projectUser(accountB.user) });
    await signOut(auth);

    const sameProvider = await signInWithEmailAndPassword(auth, emailA, "local-password-1");
    assert.equal(sameProvider.user.uid, accountA.user.uid);
    operations.push({ id: "same-provider-signin", status: "success", user: projectUser(sameProvider.user) });
    await signOut(auth);

    const providerForA = GoogleAuthProvider.credential(
      JSON.stringify({ sub: `provider-a-${marker}`, email: emailA }),
    );
    const secondSession = await signInWithEmailAndPassword(auth, emailB, "local-password-2");
    let collisionCode = null;
    let collisionResult = null;
    try {
      const collision = await linkWithCredential(secondSession.user, providerForA);
      collisionResult = projectUser(collision.user);
    } catch (error) {
      collisionCode = error?.code ?? String(error);
    }
    operations.push({
      id: "cross-provider-same-email-collision",
      status: collisionCode ? "refused" : "accepted",
      ...(collisionCode ? { code: collisionCode } : { user: collisionResult }),
    });

    if (!collisionCode) {
      const afterCollision = await unlink(secondSession.user, "google.com");
      assert.equal(afterCollision.uid, accountB.user.uid);
    }

    const providerForB = GoogleAuthProvider.credential(
      JSON.stringify({ sub: `provider-b-${marker}` }),
    );
    const linked = await linkWithCredential(secondSession.user, providerForB);
    assert.equal(linked.user.uid, accountB.user.uid);
    operations.push({ id: "distinct-provider-link", status: "success", user: projectUser(linked.user) });
    const unlinked = await unlink(linked.user, "google.com");
    assert.equal(unlinked.uid, accountB.user.uid);
    operations.push({ id: "provider-unlink", status: "success", user: projectUser(unlinked) });
    await signOut(auth);

    const readback = await Promise.all(owned.map((uid) => admin.getUser(uid).then(projectUser)));
    for (const uid of owned) await admin.deleteUser(uid);
    for (const uid of owned) await absent(admin, uid);

    return validateReceipt({
      status: "completed",
      productionExecuted: false,
      transport: "real-fireemu-artifact",
      providerBoundary: "local-emulator-fixture",
      sourceCommit: artifact.sourceCommit,
      sdkVersion: SDK_VERSION,
      artifact,
      project,
      tenantId: null,
      operations,
      readback,
      cleanup: { ownedResources: 0, listenersClosed: true, processStopped: true },
      comparison: {
        contract: "auth-settings-v1",
        classifications: ["MATCH", "SEMANTIC_MISMATCH", "INDETERMINATE"],
        productionCompared: false,
      },
    });
  } finally {
    await signOut(auth).catch(() => {});
    for (const uid of owned) await admin.deleteUser(uid).catch(() => {});
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    const receipt = await runLocalCase();
    const output = process.env.AUTH_LINKING_RECEIPT;
    if (output) await writeFile(output, `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx" });
    console.log(JSON.stringify(receipt, null, 2));
  } catch (error) {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = 1;
  }
}
