// The second codebase. It declares a different region, so the two are also a routing test:
// the same functions port has to reach the right runner for /{project}/{region}/{function}.
const { onRequest } = require("firebase-functions/v2/https");

exports.fxBeta = onRequest({ region: "europe-west1" }, (_req, res) =>
  res.status(200).json({ codebase: "beta", pid: process.pid }),
);
