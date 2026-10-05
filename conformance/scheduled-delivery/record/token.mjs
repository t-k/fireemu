// The OAuth access token of the owner's application-default credential, taken from
// `gcloud auth application-default print-access-token`. The recorder never reads the credential file, the refresh
// token or the client secret; it asks the same command again when the token in use is old enough to be near its
// end (about 60 minutes), at most `maxRefreshes` times (so at most three invocations in all). `printToken()` runs the
// command and returns its output; a string that does not look like a token is refused.

export const TOKEN_LIFETIME_MS = 40 * 60 * 1000;
export const MAX_REFRESHES = 2;
const SHAPE = /^[A-Za-z0-9._~+/=-]{8,4096}$/;

export function createTokenSource({
  printToken,
  now = () => Date.now(),
  lifetimeMs = TOKEN_LIFETIME_MS,
  maxRefreshes = MAX_REFRESHES,
}) {
  let token = null;
  let issuedAt = 0;
  let refreshes = 0;
  return async () => {
    if (token !== null) {
      if (now() - issuedAt < lifetimeMs || refreshes >= maxRefreshes) return token;
      refreshes++;
    }
    const printed = String(await printToken()).trim();
    if (!SHAPE.test(printed))
      throw new Error("the credential command did not print an access token");
    token = printed;
    issuedAt = now();
    return token;
  };
}
