const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall, onRequest } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { defineInt, defineSecret } = require("firebase-functions/params");

const apiKey = defineSecret("API_KEY");
const concurrency = defineInt("GLOBAL_CONCURRENCY");

setGlobalOptions({
  region: "asia-northeast1",
  timeoutSeconds: 17,
  concurrency,
  enforceAppCheck: true,
  memory: "512MiB",
  cpu: 1,
  minInstances: 1,
  maxInstances: 4,
  labels: { fixture: "options" },
  ingressSettings: "ALLOW_INTERNAL_ONLY",
  invoker: ["public"],
  serviceAccount: "runner@example.iam.gserviceaccount.com",
  vpcConnector: "projects/demo-options/locations/us-central1/connectors/default",
  vpcEgress: "PRIVATE_RANGES_ONLY",
  secrets: [apiKey],
  preserveExternalChanges: true,
});

exports.fxCallable = onCall(() => ({ ok: true }));
exports.fxHttp = onRequest((_request, response) => response.send("ok"));
exports.fxSchedule = onSchedule(
  {
    schedule: "30 2 * * *",
    timeZone: "America/New_York",
    retryCount: 4,
    maxRetrySeconds: 90,
    minBackoffSeconds: 3,
    maxBackoffSeconds: 30,
    maxDoublings: 2,
    region: "europe-west1",
    timeoutSeconds: 23,
    concurrency: 2,
  },
  () => {},
);
exports.fxOmitted = onCall({ omit: true }, () => ({ shouldNotRun: true }));
