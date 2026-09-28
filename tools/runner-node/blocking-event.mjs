// The event a blocking function receives, built as Identity Platform's delivery builds it: the
// request carries an unsigned blocking token (`{"data":{"jwt":…}}`, the official Auth
// emulator's form), and the codebase's own firebase-functions parsers turn it into the user
// record and the event context, exactly as the SDK's wrapped handler does before it calls the
// handler (firebase-functions `common/providers/identity` `wrapHandler`). The runner keeps its
// own response and error handling (blocking-response.mjs, blocking-error.mjs).
import { dirname, join } from "node:path";
import { existsSync, readFileSync } from "node:fs";

/** A blocking token's payload, decoded without verification as the SDK does under the emulator. */
export function decodeBlockingToken(jwt) {
  if (typeof jwt !== "string") throw new TypeError("the blocking token is not a string");
  const parts = jwt.split(".");
  if (parts.length !== 3) throw new TypeError("the blocking token is not a JWT");
  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new TypeError("the blocking token's payload is not JSON");
  }
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TypeError("the blocking token's payload is not an object");
  }
  // The SDK's unsafeDecodeAuthBlockingToken names the subject as the uid.
  payload.uid = payload.sub;
  return payload;
}

/**
 * The handler's `{user, context}` for a request that carries a blocking token, or undefined
 * for one that does not. `parsers` are the SDK's `parseAuthUserRecord` and
 * `parseAuthEventContext`; the user record is parsed for the user events only.
 */
export function blockingEvent(body, parsers, projectId) {
  const jwt = body?.data?.jwt;
  if (jwt === undefined) return undefined;
  const decoded = decodeBlockingToken(jwt);
  const user =
    decoded.event_type === "beforeCreate" || decoded.event_type === "beforeSignIn"
      ? parsers.parseAuthUserRecord(decoded.user_record)
      : undefined;
  return { user, context: parsers.parseAuthEventContext(decoded, projectId) };
}

function packageRoot(require) {
  let root = dirname(require.resolve("firebase-functions"));
  for (;;) {
    const candidate = join(root, "package.json");
    if (existsSync(candidate) && JSON.parse(readFileSync(candidate, "utf8")).name === "firebase-functions")
      return root;
    const parent = dirname(root);
    if (parent === root) throw new Error("cannot locate the firebase-functions package root");
    root = parent;
  }
}

/**
 * The SDK's parsers from the codebase's firebase-functions (`lib/common/providers/identity.js`,
 * not in its public exports), or null when that SDK does not have both: a token is then not
 * parsed at all rather than parsed differently.
 */
export function loadIdentityParsers(require) {
  try {
    const identity = require(join(packageRoot(require), "lib", "common", "providers", "identity.js"));
    const { parseAuthUserRecord, parseAuthEventContext } = identity;
    if (typeof parseAuthUserRecord !== "function" || typeof parseAuthEventContext !== "function")
      return null;
    return { parseAuthUserRecord, parseAuthEventContext };
  } catch {
    return null;
  }
}
