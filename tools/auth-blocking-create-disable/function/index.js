// A beforeSignIn blocking function for the created-then-disabled observation: it disables
// the account when, and only when, the signing-in user's email local part starts with the
// dedicated selector prefix, which the recorder uses only for its owned target so the very
// request that creates the account also disables it. Every other sign-in passes through
// unchanged. First-generation API for the reason recorded in
// ../../auth-blocking-disable/function/index.js.
const functions = require("firebase-functions/v1");

const SELECTOR = "fireemu-basic-d15ab1e";

exports.fireemuDisableOnCreate = functions
  .region("us-central1")
  .auth.user()
  .beforeSignIn((user) => {
    if (typeof user.email === "string" && user.email.startsWith(SELECTOR)) {
      return { disabled: true };
    }
    return {};
  });
