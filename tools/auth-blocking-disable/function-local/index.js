// Local twin of ../function/index.js for the owned fireemu run: the same decision (disable
// only accounts carrying the dedicated custom claim), written against the second-generation
// identity API that fireemu's Functions runtime serves. Never deployed anywhere.
const { beforeUserSignedIn } = require("firebase-functions/v2/identity");

exports.fireemuDisableOnSignIn = beforeUserSignedIn((event) => {
  const claims = (event.data && event.data.customClaims) || {};
  if (claims.fireemuDisableOnSignIn === true) {
    return { disabled: true };
  }
  return {};
});
