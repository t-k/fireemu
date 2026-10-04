// The OAuth access token of the owner's application-default credential, taken from
// `gcloud auth application-default print-access-token` (ledger 809(1), sandbox-oracles.md). The
// recorder never reads the credential file, the refresh token or the client secret; it asks the same
// command again when the token is nearly out of date. `printToken()` runs the command and returns
// its output; a token that does not look like one is refused.

export const TOKEN_LIFETIME_MS = 45 * 60 * 1000;
const SHAPE = /^[A-Za-z0-9._~+/=-]{20,4096}$/;

export function createTokenSource({ printToken, now = () => Date.now() }) {
  let token;
  let issuedAt = -Infinity;
  return async () => {
    if (token && now() - issuedAt < TOKEN_LIFETIME_MS) return token;
    const printed = String(await printToken()).trim();
    if (!SHAPE.test(printed))
      throw new Error("the credential command did not print an access token");
    token = printed;
    issuedAt = now();
    return token;
  };
}
