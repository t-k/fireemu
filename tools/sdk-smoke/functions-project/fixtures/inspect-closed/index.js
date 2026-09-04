const inspector = require("node:inspector");
const { onRequest } = require("firebase-functions/v2/https");

inspector.close();

exports.http = onRequest((_request, response) => response.status(200).send("ok"));
