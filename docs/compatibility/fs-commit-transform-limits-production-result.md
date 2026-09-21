# Firestore Commit field-transform limit: production result

This artifact records one bounded production campaign against the owner's oracle project and its
comparison with fireemu. It closes a single declared condition of `FS-DATA-WRITE`. It does not
promote `FS-DATA-WRITE`, and it establishes nothing about the official emulator.

## The condition this closed

| | |
| --- | --- |
| Campaign | `FS-DATA-WRITE-COMMIT-TRANSFORMS-03` |
| Condition | `FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT` |
| Boundary | the split-write per-document field-transform 500/501 boundary |
| Source commit | `031c74bfe372e5a1f7e667397c84a063503a53d6` |

The per-write form of this boundary was already production-observed in the 2026-09-07 corpus. What
was missing was the split-write form: whether the limit is charged per write or per document when
one Commit carries several writes against the same document. Nothing in the reference
documentation settles it, and the two readings differ exactly at 500.

## What production does

Production charges the limit per document, summing every write in one Commit that targets that
document.

- Two writes on one document carrying 250 and 250 `fieldTransforms`, 500 in total, are accepted
  with `200`. All 500 `transformResults` are returned.
- Two writes on one document carrying 250 and 251 `fieldTransforms`, 501 in total, are refused with
  `400 INVALID_ARGUMENT` and the message
  `cannot have more than 500 field transforms on a single document`.

The refusal is whole-request. The post-state readback of the refused document returns the document
unchanged, so no part of the 501-transform Commit was applied.

fireemu reproduces both outcomes, matching on status, canonical error code and the error message
string byte for byte.

## Receipts

The production receipt, its release record, the request and response journals and the local
reference run are retained privately and are not published. They contain the campaign nonce, the
owned resource names and, in the coordinator journal, secret configuration values. The published
records carry their digests instead.

| Record | Path |
| --- | --- |
| Production result, immutable | [`spec/compatibility/broad-runs/fs-commit-transform-limits-031c74bfe-production-result.json`](../../spec/compatibility/broad-runs/fs-commit-transform-limits-031c74bfe-production-result.json) |
| Saved-reference result, repaired | [`spec/compatibility/broad-runs/fs-commit-transform-limits-aa39de4b6-saved-result.json`](../../spec/compatibility/broad-runs/fs-commit-transform-limits-aa39de4b6-saved-result.json) |

Both records are bound to the same anchors: production receipt
`6b196cda5324342c6d3ee1a4d799b3661ca87c330417b3f185cc43fdae0359da`, frozen inputs
`9604ea6e8e8749d6292d467955979b17fa4851d1e04ad402f88c240befec5cde`, permission
`4591e54be787edb17f8feefb147d3295882a70494bbc302803abcf2d28fa1c06`, manifest
`721def298e8dec75ed00c136e9b077d33f13b784da08c2f552768c439a17db58`, campaign nonce digest
`10be7f76188bb9fa788516f5ee332a8e94dab697617530e5159f2da6548a93fe`, and retained local artifact
`e792e0bc1947bbd227b3ee9778eca093cda94fbde767911dd6139a6cbfd90be4` under the reviewed
`repaired-567565bdd` profile.

## Counts, and why there are two of them

The comparison covers 17 rows: 11 observation rows and six recovery rows.

| Record | MATCH | SEMANTIC_MISMATCH |
| --- | ---: | ---: |
| Production result, as the frozen comparator produced it | 13 | 4 |
| Saved-reference result, repaired comparator | 17 | 0 |

The original classification is immutable. A production comparison is published as the comparator
frozen with the run produced it, and a later repair never rewrites it, because the alternative is a
record whose counts depend on when it was last read.

The four original mismatches are the typed-absence rows: the two preflight reads that prove the
documents do not yet exist, and the two cleanup reads that prove they are gone again. Both sides
returned `404` with error code `404` and status `NOT_FOUND`. The only difference was the resource
name embedded in the message, which necessarily differs because production runs under the oracle
project and its campaign nonce while the local reference runs under its own project and its own
nonce. The comparator normalized the `name` field of a document but not the resource name inside a
message, so those four rows were a `SEMANTIC_MISMATCH` by construction on every possible run, and
the whole-comparison classification was too. That hid any real difference behind a permanent one.

The repair replaces only the resource-name substring of a typed-absence message, with the same
identity label the `name` slot uses. The rest of the message is still compared literally: different
wording, or a message naming a resource the plan does not declare, remains a mismatch. Regression
tests cover both directions. The saved-reference recompare then re-runs the repaired comparator
against the same saved production receipt and the same retained local receipt, with no new
production request, and reports 17 of 17 rows in agreement.

The recompare replays the frozen comparison first, so the immutable 13/4 classification has to
reproduce from the saved records before the repaired comparator is allowed to run. The published
saved result carries both comparator digests, frozen
`07fbc3c4329e9daf486d24207043325cdfb3c284d2789309a8508505df763f53` and repaired
`9ade4a79b2fd86db24016603ae1698628a2e96eb8716a3f96cacd6453f768a49`.

Because the comparator is listed in the v11 frozen source map and bound by the permission as
`comparatorSha256`, the repair means those frozen inputs no longer describe the current tree. A
future freeze rebuilds them. The copy of the comparator inside the retained run output is
unchanged, so the immutable result remains reproducible from its own evidence.

## Cost and footprint

| | |
| --- | ---: |
| Charged requests | 27 |
| Data requests | 17 |
| Documents created | 2 |
| Accounting cost | US$0.132370 |

The cost is conservative budget accounting against the campaign's own planning model, not a
measured invoice. The reservation was released, both owned documents were deleted and their absence
proved, and the project configuration was not modified.

## What this does not establish

Seventeen rows cover one finite case group. `FS-DATA-WRITE` is not promoted, and the following
remain open: BatchWrite continuation past a malformed or undecodable item; the catalog limits
`FS-LIMIT-COLLECTION-ID`, `FS-LIMIT-SUBCOLLECTION-DEPTH`, `FS-LIMIT-DOCUMENT-NAME-BYTES`,
`FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT`, `FS-LIMIT-INDEX-ENTRY-BYTES` and
`FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT`, the last three of which additionally need an
index-configuration decision; the four write-path limits the catalog declares `unsupported`; and
final-artifact regression plus independent closure review. The local side of this comparison is the
retained `repaired-567565bdd` artifact, not the current build.

## Addendum (2026-09-21)

The limitation above that names "the four write-path limits the catalog declares `unsupported`" reflects the catalog at the time of the 2026-09-18 observation. Since `6cb5c3d29` the catalog declares those four limits `implemented`; the observation receipt is immutable and its wording is left as recorded. The limits themselves remain production-unobserved except for the scalar `FIELD-VALUE-BYTES` refusal, and are covered by the limits-03 and request-byte campaigns.
