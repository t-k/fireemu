# FS-TRANSACTION recorder cancellation guard provenance

The recorder checks raw cancellation before filtering approval topics or Markdown columns. Ledger text and comparison constants use NFKC followed by casefold. A matching packet SHA, envelope identifier, source commit or runner SHA stops admission. A bounded `sourceCommit=` hexadecimal prefix of at least eight characters also identifies the current source. Malformed cancellation scopes fail closed; recognized case-varied scope keys and valid scopes naming only another packet or envelope remain unrelated. Unicode punctuation and full-width or mixed-case `REVOKED` are recognized. The same guard runs in legacy transaction admission and the P09/P10-A/P10-B authority entrypoints. Exact source, runner, packet, envelope and approval checks remain required.

This is a recorder admission correction. It changes neither the P09/P10-A observation graphs, collectors, session timing, native workers nor Fireemu's provisional strict 70-second idle policy, emulator 60-second idle policy or total 270-second policy. Synthetic decision fixtures verified the affected entrypoints and semantic mutations included deleting each authority hook. No new production acquisition was performed.

## Changed and retained bindings

The transitive P09/P10-A runner manifests include their authority file and shared admission helper. The first guard correction recorded these bindings:

| Recorder | Before guard | After guard |
| --- | --- | --- |
| P09 | `0111f03df5a20fdc60311cff7736ab49ab5886447df38ed907cb2691c0f9287c` | `ba6cc760f9e55c1bc3a262f730b8e366c3f261b62d12219e878fda02717464c6` |
| P10-A | `3f595fd3683458afaac04fe62abb6f1b1da17c7acc248afa652701a13319192a` | `21f089e516cb3c52589ab23542be45e65ba41b8159fd131bd82994c00c2e207c` |

These bindings belong to the first guard correction. Future production packets must pin the new exact source and runner, pass review, and receive their own envelope, version approval and GO. An earlier packet, approval or GO grants no authority to execute changed recorder bytes.

## Normalized cancellation and both delegation foundations

The subsequent P10-B pre-send review found cancellation forms missed by the first guard. Raw cancellation now scans the entire normalized line, including malformed column counts and references outside the topic column. A delegation-prefix cancellation invalidates delegated authority even when another packet scope is present. Every delegated version actor, including the existing within-envelope actor, depends on both sending and envelope-approval owner foundations. Their raw UTF-8 decision-field checksums remain `d57a2ebb9efdcb798ff64afca7ed2bc15e28556822336342505e41fb822cad46` and `9027f967c3479e7c43f2390ccc0bcddf3a7dccaa2b6164e2f5025a4f3c6516a5`. Normalization applies to comparison views while the checksum retains the original permission bytes.

The existing two-argument actor helper retains its complete raw ledger snapshot. Missing snapshots, mismatched snapshots and mutated parsed entries refuse delegation. The within-envelope actor remains confined to version approval; the recovery actor set remains unchanged. This API compatibility correction leaves the recovery recorder bytes intact. The recovery packet's separate filtered packet-revocation loop has not been expanded to certify raw packet/source/runner cancellation coverage.

| Recorder | Before normalized guard | After normalized guard | Transitive files |
| --- | --- | --- | ---: |
| P09 | `ba6cc760f9e55c1bc3a262f730b8e366c3f261b62d12219e878fda02717464c6` | `2c378a990938fb84d3ac5add192b6022ca528f861cb69eef4e3bfbefbf86c97f` | 65 |
| P10-A | `21f089e516cb3c52589ab23542be45e65ba41b8159fd131bd82994c00c2e207c` | `cc89fe6f5ff429120e161d47d165804483f778adeda0712199dde0634d270b1a` | 65 |
| P10-B | `6abf53f2b861cc4201e365e7770485543c26a45b59c02e2ca9843b4e8726fb24` | `39e712b7347645a5e9f371fc66983ec566a5b2566dc793beb021722b7cb0426e` | 78 |

The shared permission fixture now includes both exact owner foundations, adding one imported fixture file to each closure. Authority and fixture changes are included in the new runner digests. P09/P10-A changes are limited to delegated actor helper calls and their fixtures. P10-B additionally normalizes its authority comparisons and rejects normalized duplicate keys. All observation graphs, collectors, runners and workers remain byte-identical to source `8cceb10625af364103464707dcbca8699e0ca58e`.

Regression tests reproduce the coordinator's cancellation table and preserve its other-packet and valid-delegation controls. Twenty-one selected semantic mutants are killed, including removal of input or constant normalization, the delegation prefix, the second foundation, raw permission checksums, source-prefix matching and punctuation boundaries, snapshot consistency and each current authority's delegation or cancellation helper. Mutation runs restore the original source bytes and make zero production requests.

The historical REST source closure remains eight inputs with digest `87e8ecd63c57c215104cbffd2e91379c8362d669e919c4630ec756d6e1dc7ed4`; the top-level observer remains 93 inputs with digest `aa3a818c07b3ab89325c92029c177aec6e0b2c584adaa3e081d6a34b043a7986`; runtime remains 444 inputs with digest `6af57d5c36b371fc6332137f82f1d70a9675b2fb710654e11e88d770e02a21de`. Fixed Quint bound inputs and saved public comparison bytes remain unchanged. These retained bindings preserve historical attribution; future production acquisition still requires the new exact runner/source, review, approval and GO.

The changes and regression test are nested under `tools/compat-broad/fs-write-txn`. They change neither the top-level compat-broad execution-input manifest nor the eight explicit inputs of the historical REST corpus source digest. The Python authority files are outside the fixed registered Quint evidence inputs and the Cargo/config/Rust runtime-input closure. No Quint regeneration or runtime rebuild is required solely for this correction; unchanged runtime hashes do not imply unchanged recorder authority hashes.

The saved [native idle comparison](../../spec/compatibility/broad-runs/fs-transaction-p10-idle-candidate-comparison-v1.json) retains its named source `ff4024b8f066e18277834fa82a58059b01f9bc4d`, artifact `1e45a2c3ddcaf2157bb1d03ada21a0eceb8c89c56bfdf7141054db7938ad47bf`, original production bindings and P09 freeze references. The [REST comparison](../../spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json) likewise retains its original source and recording hashes. Those acquisitions and their recorder provenance predate this guard; they are historical partial evidence, not acquisitions performed by the corrected guard. Their bytes are retained without rebinding observations to later recorder code.

The parent remains IMPLEMENTING with eighteen frozen conditions and closure review PENDING. This admission correction grants no production permission and promotes no compatibility condition.
