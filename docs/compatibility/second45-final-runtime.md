# Second45 final runtime re-evaluation

The current frozen local artifact at evaluator commit `e4ae2b60f619248669fac41c31335969feb0b039` completed the original closed 45-row mapped operations and was compared with the saved production candidate `774e9d8b-second45-production-candidate.json`. All 45 rows matched. Recording, cleanup, state validation and owned-process shutdown completed successfully.

The run artifact SHA256 is `4c1ca3b8253bc3cd32ae421e39fc188af03b7ad8407f0891cb03ff0fe862f06d`. The configuration digest is `9073c3ba6719e7973e473f4757f884a1cab7537328089bfe87932c4767716561`. The comparison contract digest is `0625bd76c028de64ff0ae9ae595b1c5f44bd48cc5475c63e806a8060cbf742cb`; the current observer digest is `8500b0979493c65dbe4b5e5139201da7e2febd4e7eb4133bb626a861de68498b`, and the saved observer digest is `2bbf234fd2b1543902b9d3c66720b5fb0d9b86d7a83f5675ae5e544b57f0b313`.

The parent runner manifest independently recorded mapped receipt bytes with SHA256 `4518fcefcfcc61f4cfb66da52a17411d3793e93b688f522a97c594d7dcbe94e2` and sealed its own contents with SHA256 `0167ef1c1d5a866cda0ca1eccd4ed1dd0f3c99d1b9f44d1d0ef3d3714b1215e4`. Saved mode verified both hashes, the parent-owned artifact/commit/configuration identity, the immutable source anchor, the exact `second45-local-run-v1` receipt kind, and both local admission manifest declarations. The evaluator source commit is recorded separately in the machine-readable result and must reproduce the saved comparison source tree.

The adapter recorded 302 Auth requests and 28 Firestore requests, for 330 total service requests. Of those 330 requests, 17 occurred during recovery; recovery is an overlapping phase count, not an additional 17 requests. The runtime exited with code 0, its owned process stopped, and all listeners closed. The machine-readable result is [af1d2bc3-second45-runtime-recomparison.json](../../spec/compatibility/broad-runs/af1d2bc3-second45-runtime-recomparison.json).

The saved candidate file was verified by bytes with SHA256 `8938a0c31909a85753916dfeed095d102dfaa9cc4b1f6ebd6b93060b1c9d4d73`. Raw historical production receipts are unavailable; therefore this is a saved normalized candidate comparison, not a new production observation. No Cloud request or production operation was performed, and collection/state/cleanup evidence remains separate from compatibility classification.

The exact commands were:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad/test_second_production_pair.py -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_mapped.py --output <private-run-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production_pair.py --mode saved --saved-production-candidate spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json --local <private-run-directory>/pair/mapped/result.json --parent-manifest <private-run-directory>/manifest.json --output <private-comparison.json>
```
