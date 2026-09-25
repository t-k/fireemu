# Historical evidence

These bundles preserve previously published inputs and observations byte-for-byte. They are historical records, not evidence for the current runtime or probe source. Current-source integrity gates validate the active `../aggregation/` bundle, not these snapshots.

`aggregation-376db0d9/` preserves subject `376db0d96ca2ee4e449c523297d51b511fb3d6fc8f314690a08bea07842218b9` before the aggregation-order normalization fix. Its local receipt matched the old corpus in ten cases, while production matched nine. Neither the original expectations nor the receipts were rewritten, and no approvals were added.

`aggregation-677e406a/` preserves subject `677e406a7f741649f56c68e53536808b2793f8ba90d856ced05b85170e7f7465` after the runtime fix but before the explicit corpus revision. Local and production both matched nine of ten old expectations and both returned double sum 30.5 for the disputed limit case. All six files retain their exact bytes from commit `536889a`; no approvals were added. The current revision and its reasons are documented in [the corpus revision record](../../../../tools/compat-inventory/aggregation-corpus-revisions.md).
