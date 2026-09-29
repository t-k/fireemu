# FS-TRANSACTION recorder cancellation guard provenance

The recorder now checks cancellation before filtering approval topics or Markdown columns. A matching packet SHA or envelope identifier stops admission; malformed cancellation scopes, including missing or incorrect assignments and case-varied scope keys, fail closed, and a valid cancellation scoped only to another packet or envelope remains unrelated. Unicode punctuation after `REVOKED` is recognized. The same guard runs in legacy transaction admission and the P09/P10-A authority entrypoints. Exact source, runner, packet, envelope and approval checks remain required.

This is a recorder admission correction. It changes neither the P09/P10-A observation graphs, collectors, session timing, native workers nor Fireemu's provisional strict 70-second idle policy, emulator 60-second idle policy or total 270-second policy. Synthetic decision fixtures verified the affected entrypoints and semantic mutations included deleting each authority hook. No new production acquisition was performed.

## Changed and retained bindings

The transitive P09/P10-A runner manifests include their authority file and shared admission helper. Their current runner digests change as follows:

| Recorder | Before guard | After guard |
| --- | --- | --- |
| P09 | `0111f03df5a20fdc60311cff7736ab49ab5886447df38ed907cb2691c0f9287c` | `ba6cc760f9e55c1bc3a262f730b8e366c3f261b62d12219e878fda02717464c6` |
| P10-A | `3f595fd3683458afaac04fe62abb6f1b1da17c7acc248afa652701a13319192a` | `21f089e516cb3c52589ab23542be45e65ba41b8159fd131bd82994c00c2e207c` |

These are current recorder bindings for the guard correction. Future production packets must pin the new exact source and runner, pass review, and receive their own envelope, version approval and GO. An earlier packet, approval or GO grants no authority to execute changed recorder bytes.

The changes and regression test are nested under `tools/compat-broad/fs-write-txn`. They change neither the top-level compat-broad execution-input manifest nor the eight explicit inputs of the historical REST corpus source digest. The Python authority files are outside the fixed registered Quint evidence inputs and the Cargo/config/Rust runtime-input closure. No Quint regeneration or runtime rebuild is required solely for this correction; unchanged runtime hashes do not imply unchanged recorder authority hashes.

The saved [native idle comparison](../../spec/compatibility/broad-runs/fs-transaction-p10-idle-candidate-comparison-v1.json) retains its named source `ff4024b8f066e18277834fa82a58059b01f9bc4d`, artifact `1e45a2c3ddcaf2157bb1d03ada21a0eceb8c89c56bfdf7141054db7938ad47bf`, original production bindings and P09 freeze references. The [REST comparison](../../spec/compatibility/broad-runs/fs-transaction-expiry-retry-04-recorded-comparison-v1.json) likewise retains its original source and recording hashes. Those acquisitions and their recorder provenance predate this guard; they are historical partial evidence, not acquisitions performed by the corrected guard. Their bytes are retained without rebinding observations to later recorder code.

The parent remains IMPLEMENTING with eighteen frozen conditions and closure review PENDING. This admission correction grants no production permission and promotes no compatibility condition.
