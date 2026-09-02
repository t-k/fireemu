const { beforeUserCreated, beforeUserSignedIn } = require("firebase-functions/v2/identity");
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
exports.fxLegacyBeforeCreate = functionsV1.auth.user().beforeCreate(validatedMutation);
