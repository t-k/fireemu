# Eventarc authentication

## Development default: any credential

Production Eventarc requires a Google OAuth access token on every request, and the Admin SDK always sends one: `getEventarc().channel(...).publish()` asks the app's credential for a token and sends `Authorization: Bearer <token>`, also to `CLOUD_EVENTARC_EMULATOR_HOST`. In CI there is no Google credential. The official emulator does not check the credential, so by default the strict Eventarc listener does not check it either (`eventarc.authentication: "permissive"`, in both profiles). A request with any bearer value, or with none, gets the same answer that production gives an accepted token: the validation order, the body shapes and the channel and project checks are unchanged. The listener never inspects the credential (no shape check and no catalog lookup), and its value never appears in an answer or a log.

Without application default credentials, the Admin SDK fails before it sends anything (`app/invalid-credential`, "Could not load the default credentials"). Give the app a fake credential instead of a real Google token:

```js
import { initializeApp } from "firebase-admin/app";
import { getEventarc } from "firebase-admin/eventarc";

const app = initializeApp({
  projectId: "demo-app",
  credential: { getAccessToken: async () => ({ access_token: "owner", expires_in: 3600 }) },
});
await getEventarc(app).channel("locations/us-central1/channels/firebase").publish({
  type: "com.example.thing.done",
  source: "https://example.com/things",
  data: { id: "e1" },
});
```

## Production: `eventarc.authentication: "production"`

Under `"production"` (strict profile only), the listener refuses a missing bearer, a value of no known shape and a JWT-shaped value with production's recorded 401 answers, before any other check. `productionExact: true` selects it, and so does a configured `eventarc.oauthCredentials` when `eventarc.authentication` is not given. An explicit `eventarc.authentication` wins over `productionExact`; `"permissive"` together with `oauthCredentials` under the strict profile is a configuration error, because the catalog would be ignored.

```json
{
  "schemaVersion": 1,
  "profile": "strict",
  "productionExact": true
}
```

Strict comparisons against production recordings whose rows depend on these refusals run with `"production"`.

## Local OAuth credentials

The optional `eventarc.oauthCredentials` setting declares credentials recognized by the local simulation and their granted OAuth scopes. It applies under `"production"`. Keys are lowercase SHA-256 digests of the exact synthetic bearer bytes; values contain a unique array of nonempty scope strings. Use synthetic credentials rather than real Google access tokens.

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

Under `"production"` without `oauthCredentials`, strict Eventarc keeps its shape-only admission of `ya29.` bearers. This is an authentication parity gap: arbitrary opaque credentials cannot be verified offline. Missing, malformed and JWT-shaped bearers are refused as described above. The Emulator profile ignores this local catalog and checks no credential, as the official emulator does.

The catalog supplies local issuer facts, not Google token validation. It does not verify Google issuance, expiry, revocation, principals, IAM permissions or project enablement. A sufficient OAuth scope is not a claim of complete IAM authorization or production parity.
