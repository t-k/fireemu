const { onSchedule } = require("firebase-functions/v2/scheduler");
const logger = require("firebase-functions/logger");

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

exports.alpha = onSchedule("every 5 minutes", async () => {
  console.log("alpha start");
  logger.warn("alpha structured", {
    trace: "projects/demo/traces/abc",
    labels: { payment: "delayed", attempts: [1, 2] },
    metadata: { spoofed: true },
  });
  await delay(40);
  console.error("alpha done");
});

exports.beta = onSchedule("every 5 minutes", async () => {
  console.log("beta start");
  await delay(5);
  console.log("beta done");
});

exports.invalidUnicode = onSchedule("every 5 minutes", async () => {
  logger.info("invalid unicode", { invalid: "\ud800" });
  console.log("unicode survived");
});

exports.oversized = onSchedule("every 5 minutes", async () => {
  console.log("界".repeat(400_000));
});
