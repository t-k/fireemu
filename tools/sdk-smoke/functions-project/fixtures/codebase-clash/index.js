// A codebase that exports a name `codebase-a` already exports. Loading both must be refused:
// a function name is unique across the project, because the emulator serves one URL per
// region and name.
const { onRequest } = require("firebase-functions/v2/https");

exports.fxAlpha = onRequest((_req, res) => res.status(200).send("the wrong handler"));
