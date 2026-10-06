const { createHash, randomUUID } = require("node:crypto");
const { onCustomEventPublished } = require("firebase-functions/v2/eventarc");
const { getApps, initializeApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const run = process.env.EVENTARC_H_RUN_ID;
if (!/^[a-f0-9]{12}$/.test(run || "")) throw new Error("EVENTARC_H_RUN_ID must be 12 hex digits");
const type = `fireemu.h.${run}`;
const source = `//fireemu/handler/${run}`;
const observe = `fe${run}HObserve`;
const filtered = `fe${run}HFiltered`;
const options = { eventType: type, region: "us-central1", minInstances: 0, maxInstances: 2 };

// Unlike FE's general reporter, keep the complete small event and its original member order.
function report(handler, event, attempt, invocationId) {
  const caseId = /^fe[a-f0-9]{12}-h-(.+)-\d+$/.exec(event.id)?.[1] ?? event.data?.case;
  console.log(
    `FE_EVENTS_FRAME ${JSON.stringify({ handler, generation: 2, run, recording: "h1", case: caseId, correlation: { id: event.id, source: event.source }, invocationId, attempt, eventKeys: Object.keys(event), event })}`,
  );
}

exports[observe] = onCustomEventPublished({ ...options, retry: true }, async (event) => {
  const invocationId = randomUUID();
  const retry =
    event.source === source &&
    event.type === type &&
    new RegExp(`^fe${run}-h-retry-\\d+$`).test(event.id) &&
    event.data?.fixtureKind === "retry" &&
    event.data?.run === run &&
    event.data?.recording === "h1" &&
    event.data?.case === "retry";
  if (!retry) return report(observe, event, "succeeded", invocationId);
  const app = getApps()[0] ?? initializeApp();
  const db = getFirestore(app);
  const digest = createHash("sha256")
    .update(JSON.stringify([event.source, event.id]))
    .digest("hex");
  const marker = db.doc(`fe_h_${run}/${digest}`);
  // The create-only transaction is the FE fsRetryV2 pattern, with bounded SDK attempts.
  const first = await db.runTransaction(
    async (transaction) => {
      const previous = await transaction.get(marker);
      if (previous.exists) return false;
      transaction.create(marker, { eventId: event.id, source: event.source, run });
      return true;
    },
    { maxAttempts: 3 },
  );
  report(observe, event, first ? "failed" : "succeeded", invocationId);
  if (first) throw new Error("intentional first delivery failure");
});

exports[filtered] = onCustomEventPublished(
  { ...options, eventType: `${type}.filtered`, retry: false },
  (event) => report(filtered, event, "succeeded", randomUUID()),
);
