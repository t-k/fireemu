# Second45 final runtime re-evaluation

The current frozen local artifact at commit `af1d2bc37f392e6d0d36a8cf02cbdf35778dc115` completed the original closed 45-row mapped operations and was compared with the saved production candidate `774e9d8b-second45-production-candidate.json`. All 45 rows matched. Recording, cleanup, state validation and owned-process shutdown completed successfully.

The run artifact SHA256 is `e97945ea75809cdab2cc9778dd40790312a22f308667a079060d4e52d4acce39`. The configuration digest is `2e6dec8a80a5fcf4493c291e41bcd5e0b11d67d84714f6586d35831903092001`. The comparison contract digest is `0625bd76c028de64ff0ae9ae595b1c5f44bd48cc5475c63e806a8060cbf742cb`; the current observer digest is `3f653d556139c45377d0579957277520dfc963f4dd8a92a9296b288ed24a4453`, and the saved observer digest is `2bbf234fd2b1543902b9d3c66720b5fb0d9b86d7a83f5675ae5e544b57f0b313`.

The adapter recorded 302 Auth requests, 28 Firestore requests and 17 recovery requests, for 330 total requests. The runtime exited with code 0, its owned process stopped, and all listeners closed. The machine-readable result is [af1d2bc3-second45-runtime-recomparison.json](../../spec/compatibility/broad-runs/af1d2bc3-second45-runtime-recomparison.json).

The saved candidate file was verified by bytes with SHA256 `8938a0c31909a85753916dfeed095d102dfaa9cc4b1f6ebd6b93060b1c9d4d73`. Raw historical production receipts are unavailable; therefore this is a saved normalized candidate comparison, not a new production observation. No Cloud request or production operation was performed, and collection/state/cleanup evidence remains separate from compatibility classification.

The exact commands were:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad/test_second_production_pair.py -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_mapped.py --output <private-run-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production_pair.py --mode saved --saved-production-candidate spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json --local <private-run-directory>/pair/mapped/result.json --parent-manifest <private-run-directory>/parent-manifest.json --output <private-comparison.json>
```
