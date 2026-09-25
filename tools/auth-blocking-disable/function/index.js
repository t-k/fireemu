// A beforeSignIn blocking function for the pending-disable observation: it disables the
// account when, and only when, the signing-in user carries the dedicated custom claim.
// Every other sign-in in the project passes through unchanged. Deployed and removed by
// the recorder; never left in place.
//
// The first-generation API is used on purpose: Identity Platform registers the
// cloudfunctions.net URI as the trigger and signs the blocking token for that audience,
// which the second-generation identity handler rejects (it expects a run.app audience).
const functions = require("firebase-functions/v1");

exports.fireemuDisableOnSignIn = functions
  .region("us-central1")
  .auth.user()
  .beforeSignIn((user) => {
    const claims = user.customClaims || {};
    if (claims.fireemuDisableOnSignIn === true) {
      return { disabled: true };
    }
    return {};
  });
