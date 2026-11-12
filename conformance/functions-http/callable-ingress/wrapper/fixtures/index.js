// Production fixture for the callable-ingress observation, variant "wrapper": a callable's code deployed
// as a plain onRequest function. `onCall` builds the callable wrapper (the SDK's own Authorization,
// App Check and body checks); `onRequest` then serves that wrapper as an ordinary HTTPS function, so the
// deployed function carries no callable trigger or label. The callable itself is not exported.
const { onCall, onRequest } = require("firebase-functions/v2/https");

const region = "us-central1";

const callable = onCall(
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

// The function keeps the name of the stage 3 HTTP fixture so that the recorder's reviewed target, service
// and image names stay unchanged.
exports.fireemuHttpProbe = onRequest(
  { region, timeoutSeconds: 10, minInstances: 0, maxInstances: 1 },
  callable,
);
