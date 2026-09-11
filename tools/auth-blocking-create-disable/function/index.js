// A beforeSignIn blocking function for the created-then-disabled observation: it disables
// the account when, and only when, the signing-in user carries the dedicated selector
// photo URL, which the recorder sets at sign-up so the very request that creates the
// account also disables it. Every other sign-in passes through unchanged. First-generation
// API for the reason recorded in ../../auth-blocking-disable/function/index.js.
const functions = require("firebase-functions/v1");

const SELECTOR = "https://example.test/fireemu-disable-on-create";

exports.fireemuDisableOnCreate = functions
  .region("us-central1")
  .auth.user()
  .beforeSignIn((user) => {
    if (user.photoURL === SELECTOR) {
      return { disabled: true };
    }
    return {};
  });
