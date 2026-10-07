const { createHash, randomUUID } = require("node:crypto");
const { onCustomEventPublished } = require("firebase-functions/v2/eventarc");
const { getApps, initializeApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const run = process.env.EVENTARC_H_RUN_ID;
if (!/^[a-f0-9]{12}$/.test(run || "")) throw new Error("EVENTARC_H_RUN_ID must be 12 hex digits");
const recording = process.env.EVENTARC_H_RECORDING || "h1";
const segment = process.env.EVENTARC_H_SEGMENT || "core";
if (
  !["h1", "h2-a", "h2-b"].includes(recording) ||
  !["core", "extension", "multi", "source"].includes(segment) ||
  (recording === "h2-b" && segment === "source")
)
  throw new Error("invalid H recording or segment");
const type = `fireemu.h.${run}`;
const source = `//fireemu/handler/${run}`;
const observe = `fe${run}HObserve`;
const filtered = `fe${run}HFiltered`;
const options = { eventType: type, region: "us-central1", minInstances: 0, maxInstances: 2 };

// Unlike FE's general reporter, keep the complete small event and its original member order.
function report(handler, event, attempt, invocationId) {
  const caseId = /^fe[a-f0-9]{12}-h-(.+)-\d+$/.exec(event.id)?.[1] ?? event.data?.case;
  console.log(
    `FE_EVENTS_FRAME ${JSON.stringify({ handler, generation: 2, run, recording, case: caseId, correlation: { id: event.id, source: event.source }, invocationId, attempt, eventKeys: Object.keys(event), event })}`,
  );
}

if (segment === "core") {
  exports[observe] = onCustomEventPublished({ ...options, retry: true }, async (event) => {
    const invocationId = randomUUID();
    const retry =
      event.source === source &&
      event.type === type &&
      new RegExp(`^fe${run}-h-retry-\\d+$`).test(event.id) &&
      event.data?.fixtureKind === "retry" &&
      event.data?.run === run &&
      event.data?.recording === recording &&
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
}

if (recording !== "h1") {
  if (!process.env.GCLOUD_PROJECT) throw new Error("H2 requires the owned project");
  const project = process.env.GCLOUD_PROJECT;
  const selected =
    segment === "core"
      ? [
          [`fe${run}HFanout`, {}],
          [
            `fe${run}HNamed`,
            { channel: `projects/${project}/locations/us-central1/channels/fe${run}-h-named` },
          ],
        ]
      : segment === "extension"
        ? [
            [
              `fe${run}HExtension`,
              { eventType: `${type}.extension`, filters: { tenant: `h${run}` } },
            ],
          ]
        : segment === "multi"
          ? [
              [
                `fe${run}HMulti`,
                {
                  eventType: `${type}.multi`,
                  filters: { tenant: `h${run}`, subject: `h${run}-subject` },
                },
              ],
            ]
          : [
              // Exactly repeat v4's complete native source-plus-tenant filter construction.
              [`fe${run}HSource`, { filters: { source, tenant: `h${run}` } }],
            ];
  for (const [name, extra] of selected)
    exports[name] = onCustomEventPublished({ ...options, ...extra, retry: false }, (event) =>
      report(name, event, "succeeded", randomUUID()),
    );
}
