# Second45 final runtime re-evaluation

The current frozen local artifact at commit `a3b7e0c7863fab667dc46aa7a71a8702e4b66548` completed the original closed 45-row mapped operations and was compared with the saved production candidate `774e9d8b-second45-production-candidate.json`. All 45 rows matched. Recording, cleanup, state validation and owned-process shutdown completed successfully.

The run artifact SHA256 is `4231f871295ba9e762951ebaa271b2693159f96ea23e45f1873abb0e16920f8c`. The configuration digest is `09ef1a2ab60d8255757f8c32d23e67ea55792936ec8b3656a4e3337ae99895f1`. The comparison contract digest is `0625bd76c028de64ff0ae9ae595b1c5f44bd48cc5475c63e806a8060cbf742cb`; the current observer digest is `92b91cbeed6158e355fc50908d545aa15b49cb067ead791ec1e904e93f609a22`, and the saved observer digest is `2bbf234fd2b1543902b9d3c66720b5fb0d9b86d7a83f5675ae5e544b57f0b313`.

The parent runner manifest independently recorded mapped receipt bytes with SHA256 `25116a5073364244a654aef6768864c756565ee680d85b43032530ed273ca147` and sealed its own contents with SHA256 `2619fa0005100c156d0fc2d8a4e86df6fcf7900f1a75e0cf664ec3bd4626d499`. Saved mode verified both hashes, the parent-owned artifact/commit/configuration identity, the exact `second45-local-run-v1` receipt kind, and both local admission manifest declarations.

The adapter recorded 302 Auth requests and 28 Firestore requests, for 330 total service requests. Of those 330 requests, 17 occurred during recovery; recovery is an overlapping phase count, not an additional 17 requests. The runtime exited with code 0, its owned process stopped, and all listeners closed. The machine-readable result is [af1d2bc3-second45-runtime-recomparison.json](../../spec/compatibility/broad-runs/af1d2bc3-second45-runtime-recomparison.json).

The saved candidate file was verified by bytes with SHA256 `8938a0c31909a85753916dfeed095d102dfaa9cc4b1f6ebd6b93060b1c9d4d73`. Raw historical production receipts are unavailable; therefore this is a saved normalized candidate comparison, not a new production observation. No Cloud request or production operation was performed, and collection/state/cleanup evidence remains separate from compatibility classification.

The exact commands were:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad/test_second_production_pair.py -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_mapped.py --output <private-run-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production_pair.py --mode saved --saved-production-candidate spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json --local <private-run-directory>/pair/mapped/result.json --parent-manifest <private-run-directory>/manifest.json --output <private-comparison.json>
```
