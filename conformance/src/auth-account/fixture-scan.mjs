// The last check before the committed AUTH-ACCOUNT fixture is written. It lives outside the
// harness digest on purpose: fixing a false refusal here must not make saved recordings
// stale, because rebuilding the fixture from them is exactly how such a fix is applied.

import { REDACTED_HASH } from "./harness.mjs";

/**
 * Refuses a fixture that carries a secret, a sandbox identifier, a token, password-hash
 * material or an email address outside example.com. Unlike the request guard, an address
 * needs a local part here, so JSON keys such as the proto Any "@type" are not addresses.
 */
export function scanFixture(text, secrets) {
  for (const secret of secrets.filter(Boolean)) {
    if (text.includes(secret)) throw new Error("fixture contains a secret or a sandbox identifier");
  }
  if ([/ya29\./, /eyJ[A-Za-z0-9_-]{5,}/, /AMf-/].some((pattern) => pattern.test(text))) {
    throw new Error("fixture contains a token");
  }
  for (const [, value] of text.matchAll(/"sharedSecretKey":\s*"([^"]*)"/g)) {
    if (value !== "<sharedSecretKey>") throw new Error("fixture contains a TOTP secret");
  }
  for (const [, key, value] of text.matchAll(/"(passwordHash|salt)":\s*"([^"]*)"/g)) {
    if (value !== "<bytes>" && !(key === "passwordHash" && value === REDACTED_HASH)) {
      throw new Error("fixture contains password hash material");
    }
  }
  for (const [, domain] of text.matchAll(/[^\s"'<>@(),;:]+@([^\s@"'<>/?#&]+)/g)) {
    if (domain.toLowerCase() !== "example.com") {
      throw new Error(`fixture: email outside example.com (${domain})`);
    }
  }
}
