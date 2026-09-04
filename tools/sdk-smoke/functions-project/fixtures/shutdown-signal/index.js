const { spawn } = require("node:child_process");
const { writeFileSync } = require("node:fs");
const { onRequest } = require("firebase-functions/v2/https");

let exitMarker;

process.on("exit", () => {
  if (exitMarker) {
    writeFileSync(exitMarker, "graceful\n", { flag: "wx" });
  }
});

exports.arm = onRequest((request, response) => {
  if (typeof request.body?.marker !== "string" || request.body.marker.length === 0) {
    response.status(400).json({ error: "marker is required" });
    return;
  }

  exitMarker = request.body.marker;
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1_000)"], {
    stdio: "ignore",
  });
  child.unref();
  response.status(200).json({ runnerPid: process.pid, childPid: child.pid });
});
