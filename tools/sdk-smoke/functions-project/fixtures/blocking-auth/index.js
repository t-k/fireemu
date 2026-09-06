const {
  beforeUserCreated,
  beforeUserSignedIn,
  HttpsError,
} = require("firebase-functions/v2/identity");
const functionsV1 = require("firebase-functions/v1");

function validatedMutation(user) {
  if (
    user.displayName !== "Input name" ||
    user.emailVerified !== true ||
    user.photoURL !== "https://example.test/input.png" ||
    user.phoneNumber !== "+15555550123" ||
    user.customClaims?.role !== "tester" ||
    user.metadata?.creationTime !== "2026-08-29T12:01:00Z" ||
    user.metadata?.lastSignInTime !== "2026-08-30T12:01:00Z" ||
    user.providerData?.[0]?.providerId !== "example.com"
  ) {
    throw new Error("blocking user record did not use the Firebase Functions SDK shape");
  }
  return { displayName: `observed:${user.displayName}` };
}

exports.fxBeforeCreate = beforeUserCreated((event) => validatedMutation(event.data));
exports.fxBeforeSignIn = beforeUserSignedIn(() => ({ sessionClaims: { source: "blocking" } }));
exports.fxBeforeSignInContext = beforeUserSignedIn((event) => {
  if (
    event.eventType !==
    "providers/cloud.auth/eventTypes/user.beforeSignIn:oidc.corp"
  ) {
    throw new Error("blocking context used the wrong event type");
  }
  return { sessionClaims: { contextObserved: true } };
});
exports.fxBeforeSignInMethod = beforeUserSignedIn((event) => ({
  sessionClaims: { observedEventType: event.eventType },
}));
exports.fxSessionClaimsAtLimit = beforeUserSignedIn(() => ({
  sessionClaims: { value: "a".repeat(988) },
}));
exports.fxSessionClaimsOverLimit = beforeUserSignedIn(() => ({
  sessionClaims: { value: "😀".repeat(495) },
}));
exports.fxCombinedClaimsOverLimit = beforeUserSignedIn(() => ({
  customClaims: { custom: "a".repeat(600) },
  sessionClaims: { session: "b".repeat(600) },
}));
exports.fxLegacyBeforeCreate = functionsV1.auth.user().beforeCreate(validatedMutation);
for (let bits = 0; bits < 8; bits += 1) {
  exports[`fxTokenPolicy${bits}`] = beforeUserSignedIn(
    {
      accessToken: (bits & 1) !== 0,
      idToken: (bits & 2) !== 0,
      refreshToken: (bits & 4) !== 0,
    },
    (event) => ({
      sessionClaims: {
        credentialKeys: Object.keys(event.credential || {}).sort().join(","),
      },
    }),
  );
}
exports.fxBeforeCreateAllTokens = beforeUserCreated(
  { accessToken: true, idToken: true, refreshToken: true },
  (event) => ({
    customClaims: {
      credentialKeys: Object.keys(event.credential || {}).sort().join(","),
    },
  }),
);
exports.fxLegacyBeforeSignInTokens = functionsV1
  .auth.user({
    blockingOptions: { accessToken: true, idToken: false, refreshToken: true },
  })
  .beforeSignIn((_user, context) => ({
    sessionClaims: {
      credentialKeys: Object.keys(context.credential || {}).sort().join(","),
    },
  }));
exports.fxPermissionDenied = beforeUserCreated(() => {
  throw new HttpsError("permission-denied", "fixture rejected");
});
exports.fxExplicitDeadline = beforeUserCreated(() => {
  throw new HttpsError("deadline-exceeded", "fixture deadline");
});
exports.fxEsmPermissionDenied = beforeUserCreated(async () => {
  const { HttpsError: EsmHttpsError } = await import("firebase-functions/https");
  throw new EsmHttpsError("permission-denied", "ESM fixture rejected");
});
exports.fxUnhandled = beforeUserCreated(() => {
  throw new Error("private fixture marker");
});
