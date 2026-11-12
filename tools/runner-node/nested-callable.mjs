// A callable's wrapper that runs inside an endpoint the daemon serves as something else.
//
// `onRequest(opts, onCall(opts, handler))` deploys the callable's code as a plain HTTPS function:
// discovery sees an `onRequest` endpoint (`httpsTrigger`, no `callableTrigger`), so the daemon does
// not treat it as a callable and forwards `Authorization` untouched, as it must for application
// code that verifies credentials itself. The wrapper inside then runs under `skipTokenVerification`
// (the trusted callable protocol) and decodes any Bearer without checking it, so an unsigned or
// malformed token became an identity (`uid: "x"`), where production's wrapper verifies the token and
// refuses it (FUNCTIONS-HTTP-CALLABLE-INGRESS, run 1: 401 for every unverified shape).
//
// In the strict profile the daemon therefore tells the runner whether the one `Authorization` field
// of a request to a non-callable HTTP endpoint is a Bearer of a user of the project it verified
// (`x-fireemu-credential-verified: 1`; the daemon removes every caller-supplied copy first). The
// runner marks such a request, and the callable wrapper, the one place that decodes credentials,
// receives a credential it cannot read as a Bearer when the daemon did not verify it. The wrapper
// then refuses it itself, with its own envelope and in its own order of checks, exactly as it does
// for any value that is not `Bearer <token>`. Nothing else changes: a plain `onRequest` function
// sees the request it always saw (the marker field is removed), and a real callable never carries
// the mark, because the daemon has already refused or verified its credential.

/// The field the daemon sets on a request to a non-callable HTTP endpoint in the strict profile.
export const VERIFIED_CREDENTIAL_HEADER = "x-fireemu-credential-verified";
export const VERIFIED_APP_CHECK_HEADER = "x-fireemu-appcheck-verified";

const CONTEXT = Symbol.for("fireemu.endpointContext");

/// What a callable wrapper receives instead of an unverified credential: not `Bearer <token>`, so
/// the SDK reads it as an invalid credential without decoding it.
export const UNVERIFIED_CREDENTIAL = "fireemu-unverified-credential";

/// Reads and removes the daemon's marker, then marks the request when it is served by a
/// non-callable HTTP endpoint in the strict profile. Returns whether the request was marked.
export function markNonCallableRequest(req, { strict, nonCallableHttp }) {
  const marker = req.headers?.[VERIFIED_CREDENTIAL_HEADER];
  const appCheckMarker = req.headers?.[VERIFIED_APP_CHECK_HEADER];
  if (req.headers) {
    for (const name of Object.keys(req.headers)) {
      if ([VERIFIED_CREDENTIAL_HEADER, VERIFIED_APP_CHECK_HEADER].includes(name.toLowerCase())) delete req.headers[name];
    }
  }
  if (Array.isArray(req.rawHeaders)) {
    const kept = [];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      if (![VERIFIED_CREDENTIAL_HEADER, VERIFIED_APP_CHECK_HEADER].includes(String(req.rawHeaders[i]).toLowerCase())) {
        kept.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
      }
    }
    req.rawHeaders = kept;
  }
  if (!nonCallableHttp || (!strict && appCheckMarker === undefined)) return false;
  Object.defineProperty(req, CONTEXT, {
    value: Object.freeze({ credentialVerified: !strict || marker === "1", appCheckVerified: appCheckMarker === undefined || appCheckMarker === "1" }),
    configurable: true,
  });
  return true;
}

/// The request a callable wrapper should see: the request itself, or, when it was served by a
/// non-callable endpoint and carries a credential the daemon did not verify, a view of it whose
/// `Authorization` is [`UNVERIFIED_CREDENTIAL`]. The view leaves the caller's own request untouched.
export function requestForCallableWrapper(req) {
  const context = req?.[CONTEXT];
  if (!context) return req;
  const headers = { ...req.headers };
  let changed = false;
  if (!context.credentialVerified && typeof headers.authorization === "string" && headers.authorization !== "") {
    headers.authorization = UNVERIFIED_CREDENTIAL;
    changed = true;
  }
  if (!context.appCheckVerified && headers["x-firebase-appcheck"] !== undefined) {
    delete headers["x-firebase-appcheck"];
    changed = true;
  }
  if (!changed) return req;
  return Object.create(req, { headers: { value: headers, enumerable: true } });
}

/// A callable wrapper that reads its request through [`requestForCallableWrapper`]. The result keeps
/// the wrapper's own properties, which the SDK reads and extends after the wrapper is built.
export function guardCallableWrapper(wrapper) {
  if (typeof wrapper !== "function") return wrapper;
  const guarded = function (req, ...rest) {
    return wrapper.call(this, requestForCallableWrapper(req), ...rest);
  };
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(wrapper))) {
    Reflect.defineProperty(guarded, key, descriptor);
  }
  for (const symbol of Object.getOwnPropertySymbols(wrapper)) {
    Reflect.defineProperty(guarded, symbol, Object.getOwnPropertyDescriptor(wrapper, symbol));
  }
  return guarded;
}
