// Runs inside `fireemu exec`: performs the check's source operations against the local emulators, with the
// production URLs of record/script.mjs mapped to the emulator hosts, then waits for the deliveries. The frames
// themselves reach the parent (dry-run.mjs) through fireemu's own output, as Cloud Logging carries them in production.
import { operations, undoOperations } from "../record/script.mjs";
import { PROJECT, REGION, TOPIC, ALL_FUNCTIONS, isSelected } from "../record/plan.mjs";

const [runId, localProject, settleSeconds = "25"] = process.argv.slice(2);
const host = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(name + " is not set");
  return value.replace(/^https?:\/\//, "");
};
const control = `http://${host("FIREBASE_AUTH_EMULATOR_HOST")}/v1/sessions/default`;
const bucket = `${localProject}.appspot.com`;
const OWNER = { authorization: "Bearer owner", "content-type": "application/json" };
// The Pub/Sub emulator refuses a bearer it did not issue; the others take the emulators' owner credential.
const headersFor = (url) =>
  url.includes(String(process.env.PUBSUB_EMULATOR_HOST))
    ? { "content-type": "application/json" }
    : OWNER;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Maps a production URL of the script to the emulator that stands in for it. */
export function localUrl(url) {
  const u = new URL(url);
  const path = u.pathname.replaceAll(PROJECT, localProject) + u.search;
  switch (u.hostname) {
    case "firestore.googleapis.com":
      return `http://${host("FIRESTORE_EMULATOR_HOST")}${path}`;
    case "storage.googleapis.com":
      return `http://${host("FIREBASE_STORAGE_EMULATOR_HOST")}${path}`;
    case "pubsub.googleapis.com":
      return `http://${host("PUBSUB_EMULATOR_HOST")}${path}`;
    case "eventarcpublishing.googleapis.com":
      return `http://${host("CLOUD_EVENTARC_EMULATOR_HOST")}${path.replace(/^\/v1/, "")}`;
    case "cloudtasks.googleapis.com":
      return `http://${host("CLOUD_TASKS_EMULATOR_HOST")}${path.replace(/^\/v2/, "")}`;
    default:
      throw new Error("no local stand-in for " + u.hostname);
  }
}

async function send(label, method, url, json) {
  const response = await fetch(url, {
    method,
    headers: headersFor(url),
    ...(json === undefined ? {} : { body: JSON.stringify(json) }),
  });
  const text = await response.text();
  console.log(`DRIVE ${label} ${response.status} ${text.slice(0, 160).replaceAll("\n", " ")}`);
  return response.status;
}

const all = operations({
  runId,
  bucket,
  targets: Object.fromEntries(
    ALL_FUNCTIONS.map((fn) => [fn, { uri: "", serviceAccountEmail: "local@example.invalid" }]),
  ),
});
// The topic must exist before the first publish (the recorder creates it the same way).
if (isSelected("pubsub")) {
  await send(
    "topic",
    "PUT",
    localUrl(`https://pubsub.googleapis.com/v1/projects/${PROJECT}/topics/${TOPIC}`),
    {},
  );
  await sleep(1000);
}
for (const op of all) {
  const { method, url, json } = op.request;
  if (url.startsWith("https://cloudscheduler.googleapis.com/")) {
    const fn = op.reaches[0];
    await send(op.key, "POST", `${control}/functions/${fn}:run`, {});
  } else if (url.startsWith("https://cloudtasks.googleapis.com/")) {
    // The emulator substitutes the function's own URL for an empty one, as it does for the Admin SDK's tasks.
    const task = structuredClone(json);
    task.task.httpRequest.url = "";
    delete task.task.httpRequest.oidcToken;
    await send(op.key, method, localUrl(url), task);
  } else {
    await send(op.key, method, localUrl(url), json);
  }
  await sleep(2000);
}
await sleep(Number(settleSeconds) * 1000);
for (const op of undoOperations({ runId, bucket }))
  await send(op.key, op.request.method, localUrl(op.request.url));
console.log("DRIVE done " + REGION);
