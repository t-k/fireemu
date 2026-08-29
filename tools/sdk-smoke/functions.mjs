// Functions smoke: firebase-admin writes and uploads trigger the functions in
// functions-project/ through firebase-testd; the control API's awaitIdle waits for them.
//
//   FIRESTORE_EMULATOR_HOST=... FIREBASE_AUTH_EMULATOR_HOST=... FIREBASE_STORAGE_EMULATOR_HOST=...
//   FTD_FUNCTIONS_HOST=127.0.0.1:5001 node functions.mjs
import { initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { getStorage } from "firebase-admin/storage";

const project = process.env.GOOGLE_CLOUD_PROJECT || "demo-app";
const control = `http://${process.env.FIREBASE_AUTH_EMULATOR_HOST}`;
const functionsHost = process.env.FTD_FUNCTIONS_HOST || "127.0.0.1:5001";
const app = initializeApp({ projectId: project, storageBucket: `${project}.appspot.com` });
const db = getFirestore(app);
const results = [];
function check(name, ok, extra) {
  results.push({ name, ok, extra });
}

async function awaitIdle() {
  const r = await fetch(`${control}/v1/sessions/default:awaitIdle`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ timeoutSeconds: 60 }),
  });
  const body = await r.json();
  if (r.status !== 200) throw new Error(`awaitIdle: ${r.status} ${JSON.stringify(body)}`);
  return body;
}

async function advanceClock(seconds) {
  const r = await fetch(`${control}/v1/sessions/default/clock:advance`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ seconds }),
  });
  if (r.status !== 200) throw new Error(`clock:advance ${r.status}`);
}

try {
  // Firestore created trigger with params and snapshot data.
  await db.doc("todos/t1").set({ title: "write the smoke" });
  await awaitIdle();
  const mirror = (await db.doc("mirror/t1").get()).data();
  check("onDocumentCreated mirrored the todo", mirror?.title === "write the smoke", mirror);
  check(
    "event attributes reach the handler",
    mirror?.eventType === "google.cloud.firestore.document.v1.created" && mirror?.document === "todos/t1" && mirror?.database === "(default)",
    { eventType: mirror?.eventType, document: mirror?.document },
  );

  // written trigger sees before / after.
  await db.doc("audit/a").set({ v: 1 });
  await db.doc("audit/a").update({ v: 2 });
  await db.doc("audit/a").delete();
  await awaitIdle();
  const audit = (await db.doc("stats/audit").get()).data();
  check("onDocumentWritten counted create, update and delete", audit?.writes === 3, audit);
  check("delete event carries before and no after", audit?.last?.before?.v === 2 && audit?.last?.after === null, audit?.last);

  // deleted trigger.
  await db.doc("todos/t1").delete();
  await awaitIdle();
  check("onDocumentDeleted removed the mirror", !(await db.doc("mirror/t1").get()).exists);

  // Storage finalized trigger.
  const bucket = getStorage(app).bucket();
  await bucket.file("images/logo.png").save(Buffer.from("png-bytes"), { contentType: "image/png" });
  await awaitIdle();
  const upload = (await db.doc("uploads/images_logo.png").get()).data();
  check("onObjectFinalized indexed the upload", upload?.size === 9 && upload?.contentType === "image/png", upload);

  // Schedule: advancing the virtual clock by 12 minutes runs "every 5 minutes" twice.
  await advanceClock(12 * 60);
  await awaitIdle();
  const ticks = (await db.doc("stats/ticks").get()).data();
  check("onSchedule ran twice after a 12 minute advance", ticks?.count === 2, ticks);
  const manual = await fetch(`${control}/v1/sessions/default/functions/tick:run`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  await awaitIdle();
  const ticks2 = (await db.doc("stats/ticks").get()).data();
  check("manual schedule run", manual.status === 200 && ticks2?.count === 3, ticks2);

  // Retry: the flaky function fails twice; retries are released by advancing the clock.
  await db.doc("flaky/f1").set({});
  let idle = await fetch(`${control}/v1/sessions/default:awaitIdle`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ timeoutSeconds: 3 }) });
  check("a retry-waiting event keeps the session busy", idle.status === 504, idle.status);
  // Each retry waits for virtual time to pass; a retry-waiting event is still active work,
  // so advance until the session drains (at most a handful of rounds).
  let drained = false;
  for (let round = 0; round < 6 && !drained; round++) {
    await advanceClock(60);
    const r = await fetch(`${control}/v1/sessions/default:awaitIdle`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ timeoutSeconds: 5 }) });
    drained = r.status === 200;
  }
  check("retries drained after advancing the clock", drained);
  const attempts = (await db.doc("flakyAttempts/f1").get()).data();
  check("retry succeeded on the third attempt", attempts?.attempts === 3, attempts);

  // HTTP and callable.
  const echo = await fetch(`http://${functionsHost}/${project}/us-central1/echo/some/path?x=1`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-smoke": "yes" },
    body: JSON.stringify({ hello: "world" }),
  });
  const echoBody = await echo.json();
  check("onRequest echoes method, path, query, body and headers", echo.status === 200 && echoBody.method === "POST" && echoBody.path === "/some/path" && echoBody.query?.x === "1" && echoBody.body?.hello === "world" && echoBody.header === "yes", echoBody);
  const call = await fetch(`http://${functionsHost}/${project}/us-central1/add`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ data: { a: 2, b: 3 } }),
  });
  const callBody = await call.json();
  check("onCall returns its result envelope", call.status === 200 && callBody.result?.sum === 5, callBody);
  const bad = await fetch(`http://${functionsHost}/${project}/us-central1/add`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ data: { a: "x" } }),
  });
  const badBody = await bad.json();
  check("onCall maps HttpsError to the callable error envelope", bad.status === 400 && badBody.error?.status === "INVALID_ARGUMENT", badBody);
  const status = await (await fetch(`${control}/v1/sessions/default/functions`)).json();
  check("functions status lists the codebase", Array.isArray(status.functions) && status.functions.includes("mirrorTodo"), status);
} catch (e) {
  check("smoke aborted", false, String(e?.stack || e));
}
console.log(JSON.stringify(results, null, 1));
process.exit(results.every((r) => r.ok) ? 0 : 1);
