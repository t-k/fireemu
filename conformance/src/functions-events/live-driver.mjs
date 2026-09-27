import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
import { runStorageScenario } from "./storage-driver.mjs";

const require = createRequire(import.meta.url);
const { assertLocalEnvironment } = require("../../functions-events/fixtures/local-host.js");

const documentData = (value) => ({ fixtureKind: "ordinary", value, count: 1 });

/** Advance only this local fireemu session's virtual clock. */
export async function advanceLocalClock({ controlUrl, token, seconds, request = fetch }) {
  let endpoint;
  try {
    endpoint = new URL(controlUrl);
  } catch {
    throw new Error("retry requires a loopback control URL");
  }
  if (
    endpoint.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname) ||
    !endpoint.port ||
    endpoint.username ||
    endpoint.password ||
    !Number.isSafeInteger(seconds) ||
    seconds < 1 ||
    seconds > 60 ||
    !token
  ) {
    throw new Error("retry requires a loopback control URL and bounded clock step");
  }
  const response = await request(`${endpoint.origin}/v1/sessions/default/clock:advance`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ seconds }),
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`local retry clock advance failed (HTTP ${response.status})`);
}

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

async function waitForRetryAttempt(capture, cursor, path, attempt, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  do {
    await capture.barrier();
    const found = capture
      .since(cursor)
      .some(
        ({ frame }) =>
          frame.handler === "fsRetryV2" &&
          firestoreFramePath(frame) === path &&
          frame.event?.data?.fixtureAttempt === attempt,
      );
    if (found) return true;
    if (Date.now() >= deadline) return false;
    await delay(25);
  } while (Date.now() <= deadline);
  return false;
}

async function driveLocalRetry(capture, cursor, path) {
  if (!(await waitForRetryAttempt(capture, cursor, path, "failed", 5000))) return false;
  for (const seconds of [2, 5, 20]) {
    await delay(100);
    await advanceLocalClock({
      controlUrl: process.env.FIREEMU_CONTROL_URL,
      token: process.env.FIREEMU_CONTROL_TOKEN,
      seconds,
    });
    if (await waitForRetryAttempt(capture, cursor, path, "succeeded", 750)) return true;
  }
  return false;
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

async function authUserOrNull(auth, uid) {
  try {
    return await auth.getUser(uid);
  } catch (error) {
    if (error.code === "auth/user-not-found") return null;
    throw error;
  }
}

async function waitForAuthCreate(capture, cursor, uid) {
  const deadline = Date.now() + 5000;
  while (Date.now() <= deadline) {
    await capture.barrier();
    if (
      capture
        .since(cursor)
        .some(({ frame }) => frame.handler === "authCreatedV1" && frame.event?.data?.uid === uid)
    )
      return;
    await delay(25);
  }
  throw new Error("Auth seed create event did not drain");
}

async function runAuthScenario({ scenario, capture, auth }) {
  const id = `e${randomUUID().replaceAll("-", "")}`;
  const email = `${id}@example.test`;
  const password = "local-only-password-123";
  const owned = new Set();
  const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  const cleanup = async () => {
    for (const uid of owned) {
      if (await authUserOrNull(auth, uid)) await auth.deleteUser(uid);
    }
    const absent = (await Promise.all([...owned].map((uid) => authUserOrNull(auth, uid)))).every(
      (user) => user === null,
    );
    return { checked: absent, usersAbsent: absent, count: owned.size };
  };
  try {
    let uid = id;
    if (["auth-repeat-signin", "auth-delete", "auth-bulk-delete"].includes(scenario.id)) {
      const seedCursor = (await capture.barrier()).cursor;
      await auth.createUser({ uid, email, password });
      owned.add(uid);
      await waitForAuthCreate(capture, seedCursor, uid);
      if (scenario.id === "auth-bulk-delete") {
        const second = `${id}b`;
        const secondCursor = (await capture.barrier()).cursor;
        await auth.createUser({ uid: second, email: `${second}@example.test`, password });
        owned.add(second);
        await waitForAuthCreate(capture, secondCursor, second);
      }
    }
    const cursor = (await capture.barrier()).cursor;
    switch (scenario.id) {
      case "auth-admin-create":
        await auth.createUser({ uid, email, password });
        owned.add(uid);
        break;
      case "auth-signup": {
        const created = await authRest(authHost, "signUp", {
          email,
          password,
          returnSecureToken: true,
        });
        assert.ok(typeof created.localId === "string");
        uid = created.localId;
        owned.add(uid);
        break;
      }
      case "auth-repeat-signin": {
        const signedIn = await authRest(authHost, "signInWithPassword", {
          email,
          password,
          returnSecureToken: true,
        });
        assert.equal(signedIn.localId, uid);
        break;
      }
      case "auth-delete":
        await auth.deleteUser(uid);
        break;
      case "auth-bulk-delete": {
        const deleted = await auth.deleteUsers([...owned]);
        assert.equal(deleted.failureCount, 0);
        break;
      }
      default:
        throw new Error(`unknown Auth scenario: ${scenario.id}`);
    }
    const users = await Promise.all([...owned].map((key) => authUserOrNull(auth, key)));
    return {
      cursor,
      matchKey:
        scenario.id === "auth-bulk-delete"
          ? { kind: "auth", values: [...owned] }
          : { kind: "auth", value: uid },
      sourceResult: "typed-success",
      readback: {
        users: users.map((user) => (user ? { uid: user.uid, email: user.email } : null)),
      },
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => {});
    throw error;
  }
}

export async function ensureLocalTopic(topic) {
  const [existed] = await topic.exists();
  if (!existed) await topic.create();
  return { created: !existed, existed };
}

async function runPubsubScenario({ scenario, capture, pubsub }) {
  const topicName =
    scenario.resource === "topic-control" ? "fe-events-control" : "fe-events-primary";
  const topic = pubsub.topic(topicName, { messageOrdering: scenario.id === "pubsub-ordering" });
  let created = false;
  let existed = false;
  const cleanup = async () => {
    if (created) await topic.delete();
    const [existsAfter] = await topic.exists();
    return {
      checked: created ? !existsAfter : existed && existsAfter,
      topicAbsent: !existsAfter,
      sharedTriggerTopicRetained: existed && existsAfter,
      subscriptionsAbsent: true,
    };
  };
  try {
    ({ created, existed } = await ensureLocalTopic(topic));
    const [before] = await topic.exists();
    assert.equal(before, true);
    const cursor = (await capture.barrier()).cursor;
    const message = scenario.message;
    const messageId = await topic.publishMessage({
      data: Buffer.from(message.dataUtf8, "utf8"),
      attributes: message.attributes,
      ...(scenario.id === "pubsub-ordering"
        ? { orderingKey: `e${randomUUID().replaceAll("-", "")}` }
        : {}),
    });
    const [after] = await topic.exists();
    return {
      cursor,
      matchKey: { kind: "pubsub", value: messageId },
      sourceResult: "typed-success",
      readback: { topicExists: after, messageIdPresent: Boolean(messageId), topicName },
      cleanup,
    };
  } catch (error) {
    await cleanup().catch(() => {});
    throw error;
  }
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
    const retrySucceeded =
      scenario.id === "fs-retry" ? await driveLocalRetry(capture, cursor, reference.path) : null;
    return {
      cursor,
      matchKey: { kind: "firestore", value: reference.path },
      sourceResult: "typed-success",
      readback: {
        exists: snapshot.exists,
        data: snapshot.exists ? snapshot.data() : null,
        path: reference.path,
        retrySucceeded,
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
  const [{ initializeApp, deleteApp }, { getFirestore }, { getAuth }, { getStorage }, { PubSub }] =
    await Promise.all([
      import("firebase-admin/app"),
      import("firebase-admin/firestore"),
      import("firebase-admin/auth"),
      import("firebase-admin/storage"),
      import("@google-cloud/pubsub"),
    ]);
  const app = initializeApp({ projectId }, `functions-events-${randomUUID()}`);
  const firestore = getFirestore(app);
  const auth = getAuth(app);
  const storage = getStorage(app);
  const pubsub = new PubSub({ projectId });
  return {
    async runScenario({ scenario, program, capture }) {
      assertLocalEnvironment();
      if (scenario.source === "firestore") {
        return runFirestoreScenario({ scenario, program, capture, firestore, auth, projectId });
      }
      if (scenario.source === "auth") {
        return runAuthScenario({ scenario, capture, auth });
      }
      if (scenario.source === "pubsub") {
        return runPubsubScenario({ scenario, capture, pubsub });
      }
      if (scenario.source === "storage") {
        return runStorageScenario({ scenario, capture, storage });
      }
      throw new Error(`local driver for ${scenario.source} is not yet implemented`);
    },
    async close() {
      await pubsub.close();
      await deleteApp(app);
    },
  };
}
