const { beforeUserCreated } = require("firebase-functions/v2/identity");
const { onRequest } = require("firebase-functions/v2/https");

exports.fxNeverSettles = beforeUserCreated(() => new Promise(() => {}));
exports.fxPid = onRequest((_request, response) => response.status(200).send(String(process.pid)));
