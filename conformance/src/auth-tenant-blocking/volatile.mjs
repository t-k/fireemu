// Values production draws anew on every answer: createAuthUri's session handle, and the state
// and nonce inside the authUri it returns. The recording of 2026-09-27 showed four rows that
// differed only in these. They are masked where a fixture is written from the private
// recordings and where fireemu's rows are compared with it, so the rows compare on what they
// mean. The harness (whose digest the recordings are bound to) records them as they came.

const VOLATILE_QUERY = ["state", "nonce"];

function maskAuthUri(uri) {
  let out = uri;
  for (const name of VOLATILE_QUERY)
    out = out.replace(new RegExp(`([?&]${name}=)[^&#]*`), `$1<${name}>`);
  return out;
}

/** A copy of `value` with every volatile member masked. */
export function maskVolatile(value, key = "") {
  if (typeof value === "string" && key === "sessionId") return "<sessionId>";
  if (typeof value === "string" && key === "authUri") return maskAuthUri(value);
  if (Array.isArray(value)) return value.map((item) => maskVolatile(item, key));
  if (value && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskVolatile(v, k)]));
  return value;
}

/** Refuses a fixture text that still carries a volatile value. */
export function assertNoVolatileValue(text) {
  for (const [, value] of text.matchAll(/"sessionId":\s*"([^"]*)"/g))
    if (value !== "<sessionId>") throw new Error("fixture holds a value of sessionId");
  for (const [, uri] of text.matchAll(/"authUri":\s*"([^"]*)"/g))
    if (maskAuthUri(uri) !== uri) throw new Error("fixture holds a volatile value in authUri");
}
