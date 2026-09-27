import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";

const require = createRequire(import.meta.url);
const { assertLocalEnvironment } = require("../../functions-events/fixtures/local-host.js");

const documentData = (value) => ({ fixtureKind: "ordinary", value, count: 1 });

function firestoreFramePath(frame) {
  const event = frame.event ?? {};
  return (
    event.data?.path ??
    event.data?.after?.path ??
    event.data?.before?.path ??
    event.subject?.replace(/^documents\//, "") ??
    null
  );
}

async function waitForSeed(capture, cursor, handlers, path) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    await capture.barrier();
    const mine = capture
      .since(cursor)
      .filter(
        ({ frame }) => handlers.includes(frame.handler) && firestoreFramePath(frame) === path,
      );
    if (handlers.every((handler) => mine.some(({ frame }) => frame.handler === handler))) return;
    await delay(25);
  }
  throw new Error("seed event did not drain before source mutation");
}

async function authRest(host, method, body) {
  const response = await fetch(
    `http://${host}/identitytoolkit.googleapis.com/v1/accounts:${method}?key=fake-api-key`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (!response.ok) throw new Error(`local Auth ${method} failed (HTTP ${response.status})`);
  return response.json();
}

async function clientFirestoreCreate(host, projectId, path, data, idToken) {
  const fields = Object.fromEntries(
    Object.entries(data).map(([name, value]) => [
      name,
      typeof value === "number" ? { integerValue: String(value) } : { stringValue: value },
    ]),
  );
  const response = await fetch(
    `http://${host}/v1/projects/${projectId}/databases/(default)/documents/${path}`,
    {
      method: "PATCH",
      headers: { "content-type": "application/json", authorization: `Bearer ${idToken}` },
      body: JSON.stringify({ fields }),
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (!response.ok)
    throw new Error(`local client Firestore create failed (HTTP ${response.status})`);
}

async function runFirestoreScenario({ scenario, program, capture, firestore, auth, projectId }) {
  const id = `e${randomUUID().replaceAll("-", "")}`;
  const collection =
    scenario.resource === "collection-control" ? "fe_events_control" : "fe_events_primary";
  const reference = firestore.doc(`${collection}/${id}`);
  const host = process.env.FIRESTORE_EMULATOR_HOST;
  const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  let ownedUser = null;
  const cleanup = async () => {
    await reference.delete();
    const absent = !(await reference.get()).exists;
    if (ownedUser) await auth.deleteUser(ownedUser);
    if (scenario.id === "fs-retry") {
      const markers = await firestore
        .collection("fe_events_retry_markers")
        .where("documentPath", "==", reference.path)
        .get();
      for (const marker of markers.docs) await marker.ref.delete();
    }
    return { checked: absent, documentAbsent: absent, userDeleted: ownedUser !== null };
  };
  try {
    const needsSeed = ["fs-update", "fs-delete", "fs-noop"].includes(scenario.id);
    if (needsSeed) {
      const seedCursor = (await capture.barrier()).cursor;
      await reference.create(documentData("before"));
      const seedHitsProgram = [
        "functions-events/firestore/write",
        "functions-events/firestore/noop",
      ].includes(program.recipeId);
      if (seedHitsProgram) {
        await waitForSeed(
          capture,
          seedCursor,
          Object.values(program.handlerExports),
          reference.path,
        );
      }
    }
    let idToken = null;
    if (scenario.id === "fs-auth-client") {
      const email = `${id}@example.test`;
      const created = await authRest(authHost, "signUp", {
        email,
        password: "local-only-password-123",
        returnSecureToken: true,
      });
      assert.ok(typeof created.localId === "string" && typeof created.idToken === "string");
      ownedUser = created.localId;
      idToken = created.idToken;
    }
    const cursor = (await capture.barrier()).cursor;
    switch (scenario.id) {
      case "fs-create":
      case "fs-other-path":
      case "fs-auth-admin":
        await reference.create(documentData("created"));
        break;
      case "fs-auth-client":
        await clientFirestoreCreate(
          host,
          projectId,
          reference.path,
          documentData("client"),
          idToken,
        );
        break;
      case "fs-update":
        await reference.update({ value: "updated", count: 2 });
        break;
      case "fs-delete":
        await reference.delete();
        break;
      case "fs-noop":
        await reference.set(documentData("before"));
        break;
      case "fs-retry":
        await reference.create({ ...documentData("retry"), fixtureKind: "retry" });
        break;
      default:
        throw new Error(`unknown Firestore scenario: ${scenario.id}`);
    }
    const snapshot = await reference.get();
    return {
      cursor,
      matchKey: { kind: "firestore", value: reference.path },
      sourceResult: "typed-success",
      readback: {
        exists: snapshot.exists,
        data: snapshot.exists ? snapshot.data() : null,
        path: reference.path,
      },
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => {});
    throw error;
  }
}

/** Construct local-only mutation drivers after checking every SDK endpoint. */
export async function createLiveDriver({ projectId }) {
  assertLocalEnvironment();
  assert.match(projectId, /^demo-[a-z0-9-]+$/, "local project ID required");
  const [{ initializeApp, deleteApp }, { getFirestore }, { getAuth }] = await Promise.all([
    import("firebase-admin/app"),
    import("firebase-admin/firestore"),
    import("firebase-admin/auth"),
  ]);
  const app = initializeApp({ projectId }, `functions-events-${randomUUID()}`);
  const firestore = getFirestore(app);
  const auth = getAuth(app);
  return {
    async runScenario({ scenario, program, capture }) {
      assertLocalEnvironment();
      if (scenario.source === "firestore") {
        return runFirestoreScenario({ scenario, program, capture, firestore, auth, projectId });
      }
      throw new Error(`local driver for ${scenario.source} is not yet implemented`);
    },
    async close() {
      await deleteApp(app);
    },
  };
}
