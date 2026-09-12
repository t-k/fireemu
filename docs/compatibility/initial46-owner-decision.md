# Initial46 owner decision draft

The [single decision draft](../../spec/compatibility/broad-runs/a32fa8a7-owner-decision.json) references the immutable a32fa8a7 execution-input package and records the partial authorized metadata acquisition. It is not a production execution permission. Execution source remains a32fa8a7; b76b96b9 remains its original report publication, and subsequent input records do not replace either.

On 2026-09-12 at 13:57:52–13:57:54 UTC, one ADC acquisition and four HTTP requests were performed: tokeninfo 200, project 200, Database 200, Auth configuration 403. No automatic retry followed. API-key ownership was not requested because the Auth read failed and no approved key was available in the environment. No data or configuration mutation occurred. The acquisition stopped in 5.18 seconds, below the authorized 180-second bound.

Database identity was confirmed as project fireemu-35fe6/number 592603257417, database (default), us-central1, Standard Native. The draft contains its UID, full settings projection, acquisition timestamp, exact response-byte SHA256 and canonical parsed-response digest. The unchanged database-settings-v1 contract produced projection digest `1a067449eec406349580f171ae760ac33f5bc6ff0e0a53e00d26096da75e8fe8`. Auth's 403 response digest is refusal evidence, never an Auth configuration digest. Raw responses, especially tokeninfo, remain private.

## Pricing conditions

For the observed Iowa location, published Standard rates are USD 0.03/0.09/0.01 per 100,000 document reads/writes/deletes. Storage is USD 0.000205479/GiB-hour; the calculation conservatively budgets 744 hours. Two index-read batches and 3200 reads, 1600 writes, 200 deletes, 0.062622GiB-month storage and 0.146484GiB egress remain the manifest's limits. Using the maximum published destination egress rateUSD 0.23/GiB avoids assuming a free allowance or a particular destination. These rates are below the manifest's planning ceilings. [Firestore pricing](https://cloud.google.com/firestore/pricing)

Email/password Tier1's highest published paid rate is USD 0.0055/MAU; three users contribute at most USD 0.0165 at that rate, without free quota. [Identity Platform pricing](https://cloud.google.com/identity-platform/pricing)

The conditional total is approximately USD 0.06219 using those rates. The original planning estimate USD 0.30513 and proposed USD 1 cap remain unchanged. Overall tariff approval stays unset: the owner still needs to confirm applicable billing terms, the unavailable Auth configuration and absence of external integrations, and recovery of any retained resources within the stated horizon. The estimate does not cover indefinite unrecovered retention.

## Current blocker and next decision

Auth returned a quota-project-required error for the current user ADC. Frozen a32fa8a7's direct REST transport does not supply `x-goog-user-project`. Google documents that this header explicitly selects the quota/billing project for APIs requiring it. [REST authentication](https://docs.cloud.google.com/docs/authentication/rest#user-credentials)

No other project's quota configuration was used, and neither ADC configuration nor IAM was changed. No frozen observer source or comparison contract was changed. A proposal for the two remaining metadata reads explicitly designates fireemu-35fe6 as quota project, retains the 180-second bound and no-retry policy, and remains unapproved. Successful reads alone would not authorize the 46-row production batch. If the frozen production transport needs a header change for these credentials, that small source delta requires its own review and explicit resolution of the frozen execution binding before use.

The production proposal remains 46 rows, three account attempts, eight documents, two queries over at most one owned document each, at most 2400 total requests, 1200 seconds including 300 recovery seconds/requests, and USD 1. Owner identity/reference, dates, unused nonce and production permission remain unset.

## Independent local progress

During the preceding permission wait, four existing gRPC Listen resume tests passed under nextest; 16 other stream tests were filter-skipped. They cover replay since a token, reset/target token rejection, retained versus compacted tokens and version-cap reset. These are local runtime assertions, not production or official-emulator comparisons. The test processes exited. Existing 193 historical matches, 26 local checks, 23 indeterminate comparisons, 46 mapping checks and earlier SDK/Rules/Listen observations retain their separate meanings.

No production-batch recording, cleanup or compatibility verdict exists for this draft. The partial metadata collection is incomplete; it must not be treated as a successful 46-row run.
