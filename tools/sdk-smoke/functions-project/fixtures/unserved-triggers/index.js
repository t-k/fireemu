// Exports whose trigger families belong to products fireemu does not serve, next to one
// that works. Discovery must name each unserved one instead of dropping it: the official
// emulator prints `functions[<id>]: function ignored because the <service> emulator does not
// exist or is not running.` and carries on, which is the shape fireemu reports and, by
// default, refuses.
const { onRequest } = require("firebase-functions/v2/https");
const { onValueWritten } = require("firebase-functions/v2/database");
const { onConfigUpdated } = require("firebase-functions/v2/remoteConfig");
const v1 = require("firebase-functions/v1");

// Served, and expected to survive a `report` run.
exports.fxHealth = onRequest((_req, res) => res.status(200).send("ok"));

// Realtime Database: deferred, no such service in the daemon.
exports.fxOnValueWritten = onValueWritten("/rooms/{roomId}", () => {});

// The v1 spelling of the same product.
exports.fxV1DatabaseWrite = v1.database.ref("/rooms/{roomId}").onWrite(() => {});

// Remote Config: deferred, no such service in the daemon.
exports.fxOnConfigUpdated = onConfigUpdated(() => {});
