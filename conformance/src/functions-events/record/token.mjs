// The OAuth access token of the owner's authorized-user credential, refreshed through the same
// guarded transport as every other request (so the refresh is counted, journaled and never stored).

import { TOKEN_LIFETIME_MS } from "./rest.mjs";

export function createTokenSource({ adc, request, now = () => Date.now() }) {
  for (const key of ["client_id", "client_secret", "refresh_token"]) {
    if (typeof adc?.[key] !== "string" || !adc[key]) throw new Error("the owner's authorized-user credential is incomplete");
  }
  if (adc.type !== "authorized_user") throw new Error("the credential is not an authorized-user credential");
  let token;
  let issuedAt = -Infinity;
  let counter = 0;
  return async () => {
    if (token && now() - issuedAt < TOKEN_LIFETIME_MS) return token;
    counter += 1;
    const body = new URLSearchParams({ client_id: adc.client_id, client_secret: adc.client_secret, refresh_token: adc.refresh_token, grant_type: "refresh_token" }).toString();
    const answer = await request({
      id: `oauth.${counter}`,
      role: "token",
      method: "POST",
      url: "https://oauth2.googleapis.com/token",
      auth: "none",
      mutation: false,
      expect: [200],
      contentType: "application/x-www-form-urlencoded",
      body,
    });
    if (answer.kind !== "success" || typeof answer.json?.access_token !== "string") throw new Error("the token refresh did not return an access token");
    token = answer.json.access_token;
    issuedAt = now();
    return token;
  };
}
