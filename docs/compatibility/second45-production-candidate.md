# Second45 production candidate

The one authorized production execution used frozen commit `774e9d8bf4ec56db47c8f1f4bdabd71ed8bc3ceb`, with the execution inputs published at `4777557d850a54b8c9b2550a43b12a648e6e445a`. The owner delegated identity and window selection; the recorded owner and manual recovery assignee are `t-k`, and the permission window was 2026-09-13T02:23:33.539062Z through 03:23:33.539062Z. A newly generated nonce was consumed once. Result approval remains separate and pending.

The observation completed in 139.54 seconds with recording, state validation, cleanup and unchanged configuration confirmed. There are no unrecovered accounts or documents. The observer process exited0 and stopped. Counts are Auth302, Firestore28 and metadata10, totaling340 budgeted operations. Recovery21 is included in those service counters, not added again. The total includes one credential acquisition command and339 HTTP requests. No follow-up production calls or automatic retries of the batch were made.

The fixed production comparison CLI returned32 matches and13 mismatches, with zero indeterminate rows. Auth has19 matches and13 mismatches; all13 Firestore steps match. These are candidate observations under the fixed manifest and environment, not a general compatibility claim.

The [candidate JSON](../../spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json) preserves the original comparison, source digests, fixed local runtime identity and normalized response/state pairs. Raw credentials, concrete account bindings, full HTTP headers and the original transport/journal receipts remain private. Published semantic rows are derivatives and do not replace or mutate those receipts.

## Initial cause classification

| Candidate | Rows | First divergence | Follow-up |
| --- | --- | --- | --- |
| Update input decoding | Auth06,07,10,11,12,13,18,22 | Object/array/type errors differ; numeric displayName0 is accepted as string0 in production | Scoped runtime decoder and response-shape regression |
| Restricted attribute presence and permission response | Auth19,20,21 | Strings reject with INSUFFICIENT_PERMISSION; null permits ordinary profile update | Preserve atomicity and token-derived ownership while repairing observed behavior |
| Absent/null token request classification | Auth23,24 | Production returns INVALID_REQ_TYPE for the observed localId/displayName input | Narrow endpoint regression; do not generalize other methods |

Later displayName state differences follow the first diagnostic divergence and are not counted as independent bugs. No runtime fix is claimed by this publication. The original13 mismatches remain immutable even if later runtime revisions agree.

## Reproduction and preservation

The actual comparison command was `uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production_pair.py --production <private-production-result.json> --local <fixed774-local-mapped-result.json> --output <private-comparison.json>`, executed from the clean fixed774 checkout. It exited0 because observation and cleanup were complete; semantic mismatch is preserved. The `--check` mode separately requires equality.

The local artifact SHA256 is `e6a5a347cf7eea5afa879f60c5f3b47dc4c02b1fc8797060fccf683de5e93843`. Its record and all prior first46, historical193, local safety, direct/mapped, Rules/SDK/Listen and lifetime results remain unchanged. This publication does not rerun those tests or claim new coverage for them.

The accepted conditional planning amount was USD0.084 with a USD1 owner budget and24-hour manual cleanup condition, not a billing hard cap. Actual charges were not queried. No manual cleanup is required for this completed run.
