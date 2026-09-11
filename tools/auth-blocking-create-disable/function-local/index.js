// Local twin of ../function/index.js for the owned fireemu run (second-generation API at
// the SDK version fireemu's runner supports). Never deployed anywhere.
const { beforeUserSignedIn } = require("firebase-functions/v2/identity");

const SELECTOR = "https://example.test/fireemu-disable-on-create";

exports.fireemuDisableOnCreate = beforeUserSignedIn((event) => {
  if (event.data && event.data.photoURL === SELECTOR) {
    return { disabled: true };
  }
  return {};
});
