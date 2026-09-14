# Second45 final runtime re-evaluation

The current frozen local artifact at commit `6274aef67fad145f430f6cdd2e22fc31ee2b0298` completed the original closed 45-row mapped operations and was compared with the saved production candidate `774e9d8b-second45-production-candidate.json`. All 45 rows matched. Recording, cleanup, state validation and owned-process shutdown completed successfully.

The run artifact SHA256 is `133abaa3f5d4ddb6f9739c27b4e177e958bee568b4528546749ee906262a2921`. The configuration digest is `929cd4c7c1ecb760a5703158657d07e10065353fba22153737ccbc9975a7204f`. The comparison contract digest is `0625bd76c028de64ff0ae9ae595b1c5f44bd48cc5475c63e806a8060cbf742cb`; the current observer digest is `dfe07b7973e3b2324865524b7e4373ab689afce72735981771c607a98e89af4a`, and the saved observer digest is `2bbf234fd2b1543902b9d3c66720b5fb0d9b86d7a83f5675ae5e544b57f0b313`.

The parent runner manifest independently recorded mapped receipt bytes with SHA256 `7f6975425ccd4603ae9472f704fe1cbedb332213a86061b65fbab11fd11842b1` and sealed its own contents with SHA256 `e8cefc59ee4d7b7a4857aef796902fabe99d0c88e4ed92b3dada73a05524f3d9`. Saved mode verified both hashes, the parent-owned artifact/commit/configuration identity, the exact `second45-local-run-v1` receipt kind, and both local admission manifest declarations.

The adapter recorded 302 Auth requests and 28 Firestore requests, for 330 total service requests. Of those 330 requests, 17 occurred during recovery; recovery is an overlapping phase count, not an additional 17 requests. The runtime exited with code 0, its owned process stopped, and all listeners closed. The machine-readable result is [af1d2bc3-second45-runtime-recomparison.json](../../spec/compatibility/broad-runs/af1d2bc3-second45-runtime-recomparison.json).

The saved candidate file was verified by bytes with SHA256 `8938a0c31909a85753916dfeed095d102dfaa9cc4b1f6ebd6b93060b1c9d4d73`. Raw historical production receipts are unavailable; therefore this is a saved normalized candidate comparison, not a new production observation. No Cloud request or production operation was performed, and collection/state/cleanup evidence remains separate from compatibility classification.

The exact commands were:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad/test_second_production_pair.py -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_mapped.py --output <private-run-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production_pair.py --mode saved --saved-production-candidate spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json --local <private-run-directory>/pair/mapped/result.json --parent-manifest <private-run-directory>/manifest.json --output <private-comparison.json>
```
