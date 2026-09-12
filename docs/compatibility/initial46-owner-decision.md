# Initial46 owner decision draft

Current status: API Keys API has now been enabled with owner authorization and its ENABLED state verified. The immediate key-ownership lookup still returned 403, so ownership remains unconfirmed. Successful Database/Auth acquisitions remain recorded and production execution remains unapproved.

The [single decision draft](../../spec/compatibility/broad-runs/a32fa8a7-owner-decision.json) references the immutable a32fa8a7 execution-input package and records the partial authorized metadata acquisition. It is not a production execution permission. Execution source remains a32fa8a7; b76b96b9 remains its original report publication, and subsequent input records do not replace either.

On 2026-09-12 at 13:57:52–13:57:54 UTC, one ADC acquisition and four HTTP requests were performed: tokeninfo 200, project 200, Database 200, Auth configuration 403. No automatic retry followed. API-key ownership was not requested because the Auth read failed and no approved key was available in the environment. No data or configuration mutation occurred. The acquisition stopped in 5.18 seconds, below the authorized 180-second bound.

Database identity was confirmed as project fireemu-35fe6/number 592603257417, database (default), us-central1, Standard Native. The draft contains its UID, full settings projection, acquisition timestamp, exact response-byte SHA256 and canonical parsed-response digest. The unchanged database-settings-v1 contract produced projection digest `1a067449eec406349580f171ae760ac33f5bc6ff0e0a53e00d26096da75e8fe8`. Auth's 403 response digest is refusal evidence, never an Auth configuration digest. Raw responses, especially tokeninfo, remain private.

## Pricing conditions

For the observed Iowa location, published Standard rates are USD 0.03/0.09/0.01 per 100,000 document reads/writes/deletes. Storage is USD 0.000205479/GiB-hour; the calculation conservatively budgets 744 hours. Two index-read batches and 3200 reads, 1600 writes, 200 deletes, 0.062622GiB-month storage and 0.146484GiB egress remain the manifest's limits. Using the maximum published destination egress rateUSD 0.23/GiB avoids assuming a free allowance or a particular destination. These rates are below the manifest's planning ceilings. [Firestore pricing](https://cloud.google.com/firestore/pricing)

Email/password Tier1's highest published paid rate is USD 0.0055/MAU; three users contribute at most USD 0.0165 at that rate, without free quota. [Identity Platform pricing](https://cloud.google.com/identity-platform/pricing)

The conditional total is approximately USD 0.06219 using those rates. The original planning estimate USD 0.30513 and proposed USD 1 cap remain unchanged. Overall tariff approval stays unset: the owner still needs to confirm applicable billing terms, the retrieved Auth configuration and absence of external integrations, and recovery of any retained resources within the stated horizon. The estimate does not cover indefinite unrecovered retention.

## First-window blocker and proposed follow-up

Auth returned a quota-project-required error for the current user ADC. Frozen a32fa8a7's direct REST transport does not supply `x-goog-user-project`. Google documents that this header explicitly selects the quota/billing project for APIs requiring it. [REST authentication](https://docs.cloud.google.com/docs/authentication/rest#user-credentials)

No other project's quota configuration was used, and neither ADC configuration nor IAM was changed. No frozen observer source or comparison contract was changed. A proposal for the two remaining metadata reads explicitly designates fireemu-35fe6 as quota project, retains the 180-second bound and no-retry policy, and remains unapproved. Successful reads alone would not authorize the 46-row production batch. If the frozen production transport needs a header change for these credentials, that small source delta requires its own review and explicit resolution of the frozen execution binding before use.

The production proposal remains 46 rows, three account attempts, eight documents, two queries over at most one owned document each, at most 2400 total requests, 1200 seconds including 300 recovery seconds/requests, and USD 1. Owner identity/reference, dates, unused nonce and production permission remain unset.

## Independent local progress

During the preceding permission wait, four existing gRPC Listen resume tests passed under nextest; 16 other stream tests were filter-skipped. They cover replay since a token, reset/target token rejection, retained versus compacted tokens and version-cap reset. These are local runtime assertions, not production or official-emulator comparisons. The test processes exited. Existing 193 historical matches, 26 local checks, 23 indeterminate comparisons, 46 mapping checks and earlier SDK/Rules/Listen observations retain their separate meanings.

No production-batch recording, cleanup or compatibility verdict exists for this draft. The partial metadata collection is incomplete; it must not be treated as a successful 46-row run.

## Additional authorized read window and current status

A separate 180-second window was explicitly authorized with `x-goog-user-project: fireemu-35fe6` on management requests. At 2026-09-12T14:07:48 UTC, one existing-ADC command and two direct HTTP requests ran: tokeninfo 200 and Auth configuration 200. The collector exited after 2.37 seconds. Project and Database were not reread. ADC's internal network traffic was not separately instrumented; the report distinguishes command invocations from directly issued HTTP requests. No persistent ADC/gcloud settings, IAM or oracle data were changed.

The helper incorrectly required `projects/fireemu-35fe6/config`; the valid response used `projects/592603257417/config`. This is a collection-side validation defect, not an Auth refusal or runtime compatibility gap. Execution stopped before the API-key lookup. No automatic retry or additional oracle request followed. Offline examination matched the response number to the already verified project and confirmed the successful response's canonical Auth digest as `7878eb2600c66f48c82ef55fb8c2443ab15689ea7542a77fbda206da06f817c2`. Its raw-byte digest is `b6e081a061371ee0b1bf4068f417a4274fce7650e768ae36dabf169acb3cae27`. This digest is from HTTP 200, not the earlier 403 response.

The retrieved configuration enables email/password and anonymous sign-in and lists no blocking triggers. Its existing API key is available in the private response, but independent key ownership is still unconfirmed. No token, key value, full Auth configuration or other private response was added to public evidence. The original acquisition report remains unchanged; a separate offline-validation record explains why the Auth body is valid despite the helper's stopped status.

The single decision JSON now combines the successful project/Database and Auth observations, price calculations, immutable source bindings and remaining gaps. It still has no production permission. The remaining metadata operation is one API-key ownership lookup, with fresh credential/expiry verification if separately authorized, without repeating successful project/Database/Auth reads. The prior window is closed rather than extended.

The successful quota-header request does not change frozen a32fa8a7's transport: it still lacks that header. Any necessary production-source delta must be narrowly reviewed and its execution binding explicitly resolved; a32fa8a7 must not be silently substituted. The 46-row batch, resource mutations, revision 3 and other production observations remain unexecuted.

## Final key-only read window: blocked by API availability

A new 180-second key-only window was explicitly authorized after the stopped helper run. At 2026-09-12T14:13:23–14:13:25 UTC, one existing-ADC command and two direct HTTP requests ran: tokeninfo 200 and API-key lookup 403. The management request specified `x-goog-user-project: fireemu-35fe6`. It used the existing key from the private successful Auth response and did not reread project, Database or Auth configuration. The run stopped after 2.7576 seconds.

The lookup returned `PERMISSION_DENIED`, stating that API Keys API had not been used in this project or was disabled. Its raw response hash `39519b2a17edecab25820250ab64c3139ebb0180ecabd66c0fd86fafd0637fcf` is refusal evidence, not ownership confirmation or a settings digest. No retries, API enablement, IAM changes, principal switch, persistent quota configuration or oracle data mutation followed. API-key ownership remains unconfirmed.

The [single decision draft](../../spec/compatibility/broad-runs/a32fa8a7-owner-decision.json) retains all three distinct read windows, successful Database/Auth baselines and hashes, pricing conditions, and this final blocker. All granted read windows have ended. API enablement is explicitly outside the granted scope and requires a separate owner decision; it is not implied by the API's error message. The unchanged frozen production adapter also still needs its quota-header execution binding resolved. Therefore the initial 46-row production batch is not ready for execution permission, and no production-batch recording/cleanup/compatibility result is claimed.


## Owner-authorized API enablement

The owner subsequently asked the assistant to enable the required API. Using the same ADC principal and request-level quota project fireemu-35fe6, one `services.enable` request enabled only `projects/592603257417/services/apikeys.googleapis.com`. One operation poll reported completion and an exact-service readback confirmed `ENABLED`. The operation followed the documented [Service Usage enable method](https://docs.cloud.google.com/service-usage/docs/reference/rest/v1/services/enable); no IAM grants or global credential/quota changes were made.

The action ran at 2026-09-12T14:20:41–14:20:47 UTC and stopped after 8.4051 seconds: one ADC command and five directly issued HTTP requests (tokeninfo, enable, operation poll, service-state readback, key lookup). The private response hashes and per-request quota project are in the single decision draft. Persistent ADC/gcloud configuration hashes were unchanged and the ADC principal matched the prior authorized reads. A narrow independent security review of this enablement scope had no Must Fix or Should Fix findings; it was not a repeated 46-row technical review.

The immediate API-key lookup still returned 403 with the prior API-not-used-or-disabled message. Propagation delay after enablement is possible but has not been established. No failed-request retry occurred, and ownership is not marked confirmed. Service enablement itself succeeded and was left enabled as requested; it was not rolled back because a later lookup remained unconfirmed. No account/document mutation, key creation/regeneration or 46-row production execution occurred. Frozen a32fa8a7 and its execution bindings remain unchanged.
