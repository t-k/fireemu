const { beforeUserCreated, beforeUserSignedIn } = require("firebase-functions/v2/identity");

exports.fxBeforeCreate = beforeUserCreated(() => ({ displayName: "created" }));
exports.fxBeforeSignIn = beforeUserSignedIn(() => ({ sessionClaims: { source: "blocking" } }));
