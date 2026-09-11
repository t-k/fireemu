// Local twin of ../function/index.js for the owned fireemu run (second-generation API at
// the SDK version fireemu's runner supports). Never deployed anywhere.
const { beforeUserSignedIn } = require("firebase-functions/v2/identity");

const SELECTOR = "fireemu-basic-d15ab1e";

exports.fireemuDisableOnCreate = beforeUserSignedIn((event) => {
  const email = event.data && event.data.email;
  if (typeof email === "string" && email.startsWith(SELECTOR)) {
    return { disabled: true };
  }
  return {};
});
