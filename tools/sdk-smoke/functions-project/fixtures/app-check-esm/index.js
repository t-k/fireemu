import { onCall } from "firebase-functions/v2/https";

export const guarded = onCall({ enforceAppCheck: true }, () => ({ ok: true }));
export const replayProtected = onCall(
  { enforceAppCheck: true, consumeAppCheckToken: true },
  () => ({ ok: true }),
);
