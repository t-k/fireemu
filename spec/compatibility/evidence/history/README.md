# Historical evidence

These bundles preserve previously published inputs and observations byte-for-byte. They are historical records, not evidence for the current runtime or probe source. Current-source integrity gates validate the active `../aggregation/` bundle, not these snapshots.

`aggregation-376db0d9/` preserves subject `b2039b9b60eaf511700b3af52534f8c79f767bbf7a30939e9f8f624ea04d489c` before the aggregation-order normalization fix. Its local receipt matched the old corpus in ten cases, while production matched nine. Neither the original expectations nor the receipts were rewritten, and no approvals were added.

`aggregation-677e406a/` preserves subject `7287f67ddd3203f63d2209f028557f883f8e5dc6bfc19159d8f9befa47429d80` after the runtime fix but before the explicit corpus revision. Local and production both matched nine of ten old expectations and both returned double sum 30.5 for the disputed limit case. All six files retain their exact bytes from commit `536889a`; no approvals were added. The current revision and its reasons are documented in [the corpus revision record](../../../../tools/compat-inventory/aggregation-corpus-revisions.md).
