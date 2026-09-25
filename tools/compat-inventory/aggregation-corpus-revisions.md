# Bounded aggregation corpus revisions

## Revision 2: ordering before limit (2026-09-10)

This is an explicit correction of a predefined expectation, not an expectation learned automatically from a probe. The four fixture documents and the Standard/Native, REST, strict, Admin-bypass scope are unchanged. The corpus now has twelve query cases and two refusal/state controls. Corpus schema version 2 permits a query case to specify either typed aggregate values or an explicit bounded error expectation; revision 2 identifies this fixed case set.

Revision 1 expected count 2 / integer sum 10 for `missing-before-limit`. That expectation assumed the ordinary document-name selection survived aggregation ordering. Controlled measurements and the runtime regression investigation contradicted that assumption: omitted-order aggregation selects A and D, giving count 2 / double sum 30.5. Ordinary omitted-order document queries still select A and B. The implementation was corrected in `fe37fe0`; reverting it to match the old expectation would restore the observed divergence.

The [previous artifact-bound bundle](../../spec/compatibility/evidence/history/aggregation-677e406a/) preserves the old expectation and independently recorded local and production values of 30.5. Its subject is `677e406a7f741649f56c68e53536808b2793f8ba90d856ced05b85170e7f7465`. The [earlier bundle](../../spec/compatibility/evidence/history/aggregation-376db0d9/) preserves the pre-fix runtime observation. Neither bundle is rewritten or approved by this revision.

The [ordering investigation](../aggregation-limit/README.md) describes the additional private diagnostic controls and their limitations. Revision 2 brings four discriminating controls into the public artifact-bound corpus so their new measurements can be independently checked:

| Case | Fixed expectation | Distinction |
| --- | --- | --- |
| `missing-before-limit` | count 2 / double sum 30.5 | Omitted aggregation order, limit 2 |
| `explicit-x-asc` | count 2 / double sum 30.5 | Explicit field order agrees with omission |
| `explicit-x-desc` | count 2 / double sum 20.5 | The string-valued document remains selected and counted |
| `explicit-x-offset` | count 1 / integer sum 0 | Offset 2, limit 1 selects the nonnumeric value; sum ignores it |
| `explicit-name-rejected` | HTTP 400 / `INVALID_ARGUMENT` | Name-only order cannot silently be rewritten to field order |

The rejection comparison checks the HTTP status and error status, not identical wording or wire envelopes. The bounded interpreter accepts only one error object, either directly or in a one-element array, with integer `code` matching HTTP 400 and nonempty string `message` and `status`. Extra elements, nulls, mixed results, missing fields and unsupported fields fail closed. A valid but wrong error status or an unexpected valid successful result remains a mismatch, never an approval candidate. Other HTTP statuses are outside this bounded interpreter and block evidence acceptance.

The intentional-mismatch regression now uses 31.5, not the corrected 30.5, and still proves that recorded verdicts cannot contradict raw responses or make mismatches eligible for approval. Source-derived obligations remain separate from measured ordering and harness state controls. Neither the selected source sections nor these finite cases prove all aggregation, numeric precision, SDK, gRPC, Rules, transaction or index behavior.

New captures must bind this corpus hash and the frozen probe sources. Publication starts with empty approvals. Only a named review of the newly generated subject and specified case IDs can authorize an approved bounded claim; agreeing to implement this revision does not approve that future subject.
