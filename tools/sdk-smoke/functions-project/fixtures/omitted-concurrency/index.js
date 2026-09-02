const { onRequest } = require("firebase-functions/v2/https");

exports.omittedConcurrency = onRequest(
  { memory: "2GiB" },
  (_request, response) => response.status(204).end(),
);
