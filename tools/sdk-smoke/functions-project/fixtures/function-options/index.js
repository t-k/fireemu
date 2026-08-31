const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");

setGlobalOptions({
  region: "asia-northeast1",
  timeoutSeconds: 17,
  concurrency: 3,
  enforceAppCheck: true,
  memory: "512MiB",
  cpu: 1,
  minInstances: 1,
  maxInstances: 4,
  labels: { fixture: "options" },
});

exports.fxCallable = onCall(() => ({ ok: true }));
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
