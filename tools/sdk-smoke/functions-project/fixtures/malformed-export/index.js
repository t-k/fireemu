// One export that looks like a Cloud Function and cannot describe itself, and one that can.
//
// The v1 SDK computes `__endpoint` in a getter, so a misconfigured provider throws while
// discovery is reading it. Discovery has to record the export and carry on: a codebase must
// not lose its working functions because one of them cannot say what it is.
const { onRequest } = require("firebase-functions/v2/https");

exports.fxWorks = onRequest((_req, res) => res.status(200).send("ok"));

exports.fxThrows = Object.defineProperty(
  () => {},
  "__endpoint",
  {
    get() {
      throw new Error("this endpoint cannot describe itself");
    },
  },
);
