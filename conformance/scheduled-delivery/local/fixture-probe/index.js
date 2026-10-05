// Local-only probes for the retry and timeout behaviours the delivery recording observed (run 156715222b86ea44). Each
// handler prints one line, `PROBE {json}`, and fails, so that a retry chain can be counted and timed against
// the virtual clock. The retry declarations are the ones the recording used: `schedRetryV2`'s, the REST jobs
// `zero`, `duration` and `retry5`, and defaults. Never deployed.
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { setGlobalOptions } = require("firebase-functions/v2");

setGlobalOptions({ region: "us-central1" });

const mark = (handler, event) =>
  console.log("PROBE " + JSON.stringify({ handler, scheduleTime: event.scheduleTime }));
const failing = (name) => async (event) => {
  mark(name, event);
  throw new Error("deliberate failure of " + name);
};

exports.retryFour = onSchedule(
  { schedule: "every 5 minutes", timeZone: "Asia/Tokyo", retryCount: 4, minBackoffSeconds: 4, maxBackoffSeconds: 50, maxDoublings: 2 },
  failing("retryFour"),
);
exports.retryZero = onSchedule({ schedule: "every 5 minutes", retryCount: 0 }, failing("retryZero"));
exports.retryFive = onSchedule({ schedule: "every 5 minutes", retryCount: 5 }, failing("retryFive"));
exports.retryDuration = onSchedule(
  { schedule: "every 5 minutes", maxRetrySeconds: 30, minBackoffSeconds: 4, maxBackoffSeconds: 10 },
  failing("retryDuration"),
);
exports.retryDefault = onSchedule("every 5 minutes", failing("retryDefault"));
