// The first of two codebases a multi-codebase project declares. Its functions run in their
// own runner process, and its region is the default one.
const { onRequest } = require("firebase-functions/v2/https");

exports.fxAlpha = onRequest((_req, res) =>
  res.status(200).json({ codebase: "alpha", pid: process.pid }),
);
