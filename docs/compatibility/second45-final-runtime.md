# Second45 final runtime re-evaluation

The current frozen local artifact was executed from runtime source commit `22320fc0a0fc99bff2109f5bdc236bde29de5497` and evaluated by clean evaluator commit `ec4e1fa155016c89dcdf0700077c219ae9c80885`. This evidence is published in a later commit; the publication commit is not the evaluator identity. It completed the original closed 45-row mapped operations and was compared with the saved production candidate `774e9d8b-second45-production-candidate.json`. All 45 rows matched. Recording, cleanup, state validation and owned-process shutdown completed successfully.

The run artifact SHA256 is `4fa9bce06cc47e148a6eaed936703ad13c2be3d2ed5aa76586fd1632fc0b3a35`. The configuration digest is `e19ec6872c0e06835c92df832a42c2d2e02ffeabdab71d0470aeedf5d68660fd`. The comparison contract digest is `0625bd76c028de64ff0ae9ae595b1c5f44bd48cc5475c63e806a8060cbf742cb`; the current observer digest is `d24e3c0f67b15e5bbb62f8a1c7e26d6f505a75dd7085e24ed37e0df88559fc69d`, and the saved observer digest is `2bbf234fd2b1543902b9d3c66720b5fb0d9b86d7a83f5675ae5e544b57f0b313`.

The parent runner manifest independently recorded mapped receipt bytes with SHA256 `b96f63483e8215cd65804ed9d100ff177f60e85153e1e6b50895bde865b265df` and sealed its own contents with SHA256 `1e62da98ded06ca800c5fb60ff2be7b784c595ad30c94d4cde31ebc475648d73`. The evaluator emitted its actual HEAD commit `ec4e1fa155016c89dcdf0700077c219ae9c80885` and anchor SHA256 `71e6948274cc6e33e20ffb9f5bec356e672fd9129be50d86c8623caf9ed2f35b`, together with the parent and receipt hashes. The exact emitted comparison JSON has SHA256 `725b5a386cdb16fd1e4bb5aeeea2ad4722b658a4a5d2e441af4978ea4ace6e40`. Saved mode verified these bindings, the parent-owned artifact/commit/configuration identity, the immutable source anchor, the exact `second45-local-run-v1` receipt kind, and both local admission manifest declarations.

The adapter recorded 302 Auth requests and 28 Firestore requests, for 330 total service requests. Of those 330 requests, 17 occurred during recovery; recovery is an overlapping phase count, not an additional 17 requests. The runtime exited with code 0, its owned process stopped, and all listeners closed. The machine-readable result is [af1d2bc3-second45-runtime-recomparison.json](../../spec/compatibility/broad-runs/af1d2bc3-second45-runtime-recomparison.json).

The saved candidate file was verified by bytes with SHA256 `8938a0c31909a85753916dfeed095d102dfaa9cc4b1f6ebd6b93060b1c9d4d73`. Raw historical production receipts are unavailable; therefore this is a saved normalized candidate comparison, not a new production observation. No Cloud request or production operation was performed, and collection/state/cleanup evidence remains separate from compatibility classification.

The exact commands were:

```sh
uv run --project tools/compat-inventory --locked --python 3.12 -m pytest tools/compat-broad/test_second_production_pair.py -q
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_mapped.py --output <private-run-directory>
uv run --project tools/compat-inventory --locked --python 3.12 tools/compat-broad/second_production_pair.py --mode saved --saved-production-candidate spec/compatibility/broad-runs/774e9d8b-second45-production-candidate.json --local <private-run-directory>/pair/mapped/result.json --parent-manifest <private-run-directory>/manifest.json --output <private-comparison.json>
```

The positive clean-checkout reproduction detached evaluator commit `ec4e1fa155016c89dcdf0700077c219ae9c80885` and ran the same saved command against the frozen private receipt. It returned `match` for 45 rows with no errors and reproduced the emitted evaluator identity; running from a later publication checkout is a separate verification execution.
