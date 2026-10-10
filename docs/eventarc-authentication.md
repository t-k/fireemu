# Local OAuth credentials for strict Eventarc

The optional `eventarc.oauthCredentials` setting declares credentials recognized by the local simulation and their granted OAuth scopes. Keys are lowercase SHA-256 digests of the exact synthetic bearer bytes; values contain a unique array of nonempty scope strings. Use synthetic credentials rather than real Google access tokens.

```json
{
  "eventarc": {
    "oauthCredentials": {
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
        "scopes": ["https://www.googleapis.com/auth/cloud-platform"]
      }
    }
  }
}
```

Replace the example digest with the SHA-256 of your synthetic bearer. The existing canonical configuration fields are omitted from this fragment. Digest keys must contain exactly 64 lowercase hexadecimal characters. Unknown keys, null values, duplicate scopes and malformed entries are rejected.

With the catalog configured, an OAuth-shaped bearer absent from it receives 401 `ACCESS_TOKEN_TYPE_UNSUPPORTED`. A recognized bearer without the `https://www.googleapis.com/auth/cloud-platform` scope receives 403 `ACCESS_TOKEN_SCOPE_INSUFFICIENT`. Both decisions precede project, channel and publication checks. A sufficient grant continues through ordinary resource validation and delivery. An empty catalog recognizes no OAuth-shaped bearer; an empty scope array recognizes a credential without the required grant.

Without `oauthCredentials`, strict Eventarc preserves its existing shape-only admission of `ya29.` bearers. This is an authentication parity gap: arbitrary opaque credentials cannot be verified offline. Existing missing, malformed and JWT-shaped bearer refusals remain unchanged. The Emulator profile ignores this local catalog and retains its existing behavior.

The catalog supplies local issuer facts, not Google token validation. It does not verify Google issuance, expiry, revocation, principals, IAM permissions or project enablement. A sufficient OAuth scope is not a claim of complete IAM authorization or production parity.
