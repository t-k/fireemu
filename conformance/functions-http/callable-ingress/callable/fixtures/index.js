// Production fixture for the callable-ingress observation, variant "callable": the same callable code as
// the "wrapper" variant, deployed as a real callable (callable trigger and label), for the same requests.
// The function keeps the name of the stage 3 HTTP fixture so that the recorder's reviewed target, service
// and image names stay unchanged.
const { onCall } = require("firebase-functions/v2/https");

const region = "us-central1";

exports.fireemuHttpProbe = onCall(
  { region, timeoutSeconds: 10, minInstances: 0, maxInstances: 1, heartbeatSeconds: null },
  async (request) => {
    const data = request.data ?? {};
    if (data.op === "auth") {
      return request.auth
        ? {
            uid: request.auth.uid,
            email: request.auth.token.email ?? null,
            emailVerified: request.auth.token.email_verified ?? false,
            signInProvider: request.auth.token.firebase?.sign_in_provider ?? null,
          }
        : { auth: null };
    }
    return data.value ?? null;
  },
);
