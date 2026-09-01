// Pub/Sub smoke: the real @google-cloud/pubsub client drives the fireemu Pub/Sub emulator
// over gRPC (PUBSUB_EMULATOR_HOST), and a message published through the wire protocol reaches
// a subscribed Cloud Function (EVTINFRA-01 / EVTINFRA-02).
//
// Start the daemon so it serves Firestore, Functions and Pub/Sub, e.g.:
//   fireemu exec --config tools/sdk-smoke/fireemu.pubsub.json \
//     --only firestore,functions,pubsub \
//     --functions tools/sdk-smoke/functions-project --functions-port 5001 \
//     --pubsub-port 8085 -- node tools/sdk-smoke/pubsub.mjs
//
// exec exports PUBSUB_EMULATOR_HOST, FIRESTORE_EMULATOR_HOST, FIREEMU_CONTROL_URL and
// FIREEMU_CONTROL_TOKEN; the client libraries read them.
import { PubSub } from "@google-cloud/pubsub";
import { initializeApp } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";

const project = process.env.GOOGLE_CLOUD_PROJECT || "demo-app";
const controlBase = (process.env.FIREEMU_CONTROL_URL || "").replace(/\/v1\/?$/, "");
const controlToken = process.env.FIREEMU_CONTROL_TOKEN || "";

const pubsub = new PubSub({ projectId: project });
const app = initializeApp({ projectId: project });
const db = getFirestore(app);

const results = [];
function check(name, ok, extra) {
  results.push({ name, ok, extra });
  if (!ok) console.error(`FAIL ${name}`, extra ?? "");
}

async function awaitIdle() {
  const r = await fetch(`${controlBase}/v1/sessions/default:awaitIdle`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${controlToken}` },
    body: JSON.stringify({ timeoutSeconds: 60 }),
  });
  if (r.status !== 200) throw new Error(`awaitIdle: ${r.status} ${await r.text()}`);
  return r.json();
}

async function getOrCreateTopic(name) {
  const topic = pubsub.topic(name);
  const [exists] = await topic.exists();
  if (!exists) await topic.create();
  return topic;
}

// Collects up to `n` messages from a subscription within `ms`, acking each.
function receive(sub, n, ms) {
  return new Promise((resolve) => {
    const got = [];
    const done = () => {
      sub.removeAllListeners("message");
      sub.close().catch(() => {});
      resolve(got);
    };
    const timer = setTimeout(done, ms);
    sub.on("error", () => {});
    sub.on("message", (m) => {
      got.push(m);
      m.ack();
      if (got.length >= n) {
        clearTimeout(timer);
        done();
      }
    });
  });
}

try {
  // --- T1: publish / receive / ack with attributes ---------------------------------------
  const orders = await getOrCreateTopic("smoke-orders");
  const [ordersSub] = await orders.createSubscription("smoke-orders-sub", { ackDeadlineSeconds: 10 });
  await orders.publishMessage({ data: Buffer.from("first"), attributes: { seq: "1" } });
  await orders.publishMessage({ data: Buffer.from("second"), attributes: { seq: "2" } });
  const received = await receive(ordersSub, 2, 8000);
  check("publish and pull deliver both messages", received.length === 2, received.length);
  check(
    "message data and attributes survive the round trip",
    received.some((m) => m.data.toString() === "first" && m.attributes.seq === "1") &&
      received.some((m) => m.data.toString() === "second" && m.attributes.seq === "2"),
    received.map((m) => [m.data.toString(), m.attributes]),
  );

  // --- T2: subscription filter -----------------------------------------------------------
  const events = await getOrCreateTopic("smoke-events");
  const [filtered] = await events.createSubscription("smoke-orders-only", {
    filter: 'attributes.type = "order"',
  });
  await events.publishMessage({ data: Buffer.from("o"), attributes: { type: "order" } });
  await events.publishMessage({ data: Buffer.from("r"), attributes: { type: "refund" } });
  const onlyOrders = await receive(filtered, 2, 4000);
  check(
    "the subscription filter drops non-matching messages",
    onlyOrders.length === 1 && onlyOrders[0].data.toString() === "o",
    onlyOrders.map((m) => m.data.toString()),
  );

  // --- T3: ordering keys -----------------------------------------------------------------
  const ordered = await getOrCreateTopic("smoke-ordered");
  const [orderedSub] = await ordered.createSubscription("smoke-ordered-sub", {
    enableMessageOrdering: true,
  });
  const orderedPub = pubsub.topic("smoke-ordered", { messageOrdering: true });
  for (const n of ["a", "b", "c"]) {
    await orderedPub.publishMessage({ data: Buffer.from(n), orderingKey: "k" });
  }
  const inOrder = await receive(orderedSub, 3, 8000);
  check(
    "ordering keys preserve delivery order",
    inOrder.map((m) => m.data.toString()).join("") === "abc",
    inOrder.map((m) => m.data.toString()),
  );

  // --- T4: a published message reaches a subscribed Cloud Function (EVTINFRA-02) ----------
  const jobs = pubsub.topic("jobs");
  const [jobsExists] = await jobs.exists();
  check("the Functions manifest provisions its Pub/Sub topic before exec", jobsExists);
  const [jobSubscriptionExists] = await pubsub.subscription("emulator-sub-jobs").exists();
  check(
    "the Functions manifest provisions its emulator subscription before exec",
    jobSubscriptionExists,
  );
  const [scheduleTopicExists] = await pubsub.topic("firebase-schedule-tick").exists();
  const [scheduleSubscriptionExists] = await pubsub
    .subscription("emulator-sub-firebase-schedule-tick")
    .exists();
  check(
    "scheduled Functions provision Firebase-compatible Pub/Sub resources",
    scheduleTopicExists && scheduleSubscriptionExists,
  );
  await jobs.publishMessage({
    data: Buffer.from(JSON.stringify({ task: "reindex" })),
    attributes: { priority: "high" },
  });
  await awaitIdle();
  const jobDocs = await db.collection("jobs").get();
  const jobDoc = jobDocs.docs.map((d) => d.data())[0];
  check(
    "onMessagePublished fired for a message published through the wire protocol",
    !!jobDoc && jobDoc.json?.task === "reindex" && jobDoc.attributes?.priority === "high",
    jobDoc,
  );
  const v1Docs = await db.collection("v1jobs").get();
  check(
    "the v1 topic().onPublish handler fired for the same message",
    v1Docs.size >= 1,
    v1Docs.size,
  );
} catch (err) {
  check("no exception", false, String(err?.stack || err));
}

const failed = results.filter((r) => !r.ok);
for (const r of results) console.log(`${r.ok ? "ok" : "FAIL"}  ${r.name}`);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
