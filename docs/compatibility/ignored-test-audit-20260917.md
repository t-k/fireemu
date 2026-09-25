# Explicitly ignored workspace tests

This audit applies to source `ca78c80b2d069e203d1594895d1bca40356a8ce2` on macOS. The normal PR-profile run completed with 2,621 passes and 81 skips. An independent `cargo nextest list --locked --workspace --message-format json` enumeration identifies exactly 81 ignored tests in the compiled test binaries. Source-only annotation counts are different because some tests are conditional or outside this workspace build.

| Group | Ignored tests | Required treatment |
| --- | ---: | --- |
| Quint CLI / Java verification and Connect | 48 | Execute the applicable pinned-tool verification lane; normal Rust tests do not substitute for it. |
| Functions real SDK discovery and runtime | 24 | Install the pinned SDK dependencies and explicitly execute the ignored integration tests with process cleanup. |
| Release performance / resource qualification | 7 | Use the declared release-mode qualification; debug test timing is not equivalent evidence. |
| Intentional process-leak fixtures | 2 | Run through their nested nextest/census drivers, not as ordinary standalone successful tests. |

None of these 81 annotations identifies a production-credential dependency. The earlier broad description of these skips as credential-dependent was inaccurate for this compiled test set. An ignored test is neither a failure nor an executed pass. A parent requiring its evidence must retain that condition until a suitable separate run is bound to the relevant source/artifact.

## Auth follow-up execution

The six ignored tests in `auth_totp_connect` and `compatibility_selection_connect` were explicitly executed at the source above and all passed:

```sh
QUINT_REAL_BIN="$PWD/verification/quint/node_modules/.bin/quint" \
PATH="$PWD/verification/quint/bin:$PATH" \
cargo nextest run --locked -p fireemu-verification-quint \
  --test auth_totp_connect --test compatibility_selection_connect \
  --profile pr --run-ignored only
```

Each binary exercised deterministic scenarios, projection-fault detection, and generated traces against its existing driver. The command reported `6 passed, 9 skipped`; those nine are the ordinary tests excluded by `--run-ignored only`, not nine failures or new ignored cases. The full workspace run already covered those ordinary tests.

This is local model/implementation evidence for the existing models. It does not establish production parity or prove the new reservation protocol as a dedicated formal model. Historical evidence and prior runs remain unchanged.

## Blocking Functions SDK follow-up

After `npm ci --prefix tools/sdk-smoke --ignore-scripts --no-audit --no-fund`, the two existing `blocking_identity_exports` tests were explicitly executed through the port-registry process wrapper:

```sh
cargo nextest run --locked -p fireemu --test functions_discovery \
  --profile pr --run-ignored only -E 'test(blocking_identity_exports)'
```

Both passed: discovery classified the real `firebase-functions` 7.3.2 exports as served triggers, and the runner exposed their synchronous blocking endpoint. The selected run's 19 skips are excluded tests from that binary. These two checks establish SDK-local discovery/runner behavior, not end-to-end Auth mutation or production hook parity. Together with the six Connect checks, eight of the 81 baseline ignored tests were explicitly executed in this follow-up; the other 73 were not executed here. The normal workspace run retains its original 81-skip result.

## Complete Functions SDK follow-up at 06ab2a6ad

The 24 ignored Functions discovery/runtime checks were explicitly executed at `06ab2a6adae0ace3d49617acbdfd514caf896c76` after the locked `tools/sdk-smoke` dependency installation. All 24 selected tests passed; the one additional test excluded by `--run-ignored only` is not a failed or newly ignored case. Pins were `firebase-functions` 7.3.2, `firebase-admin` 14.3.0 and `firebase` 12.18.0, with Node 24.14.0.

```sh
cargo nextest run --locked -p fireemu --test functions_codebases --test functions_discovery --profile pr --run-ignored only
```

The command ran through the owned port-registry wrapper. Its reservation, Functions runners and child processes were closed afterward. Rust and SDK inputs matched the fixed source; unrelated pending Commit-observation Python edits did not change those inputs. The private record preserves tool-returned stdout, dependency installation, input binding and cleanup results, explicitly identifying the later transcription of the original tool output.

This execution covers the 24-case SDK-local group, including the two discovery checks previously run at the older source. It does not change the original normal-workspace result of 81 skips, does not execute the remaining 57 ignored cases in this follow-up, and is not production hook-parity evidence. Formal/Java, release qualification and intentional leak-driver obligations remain separately tracked.

## Current-head formal and Functions follow-up at 80840b4db

At source `80840b4db7bb7ca0206fbce3f1af1c6fee7daa63`, the same explicit Functions command selected 24 tests and passed all 24; one ordinary test was filtered by `--run-ignored only`. The complete pinned Quint authority pass also exited successfully with `VERIFICATION_PASSES=1`. It ran model, Connect, mutation and evidence gates for all 14 registered models, followed by traceability verification. The authority log contained 58 gate entries and ended with `traceability: ok (3 pending artifact(s))`; the three pending Kani/limit artifacts are not thereby completed.

The two intentional leak fixtures were also exercised through the normal nested `leak_fixture` driver at this source. The driver ran two tests and both passed; the two fixture entries stayed ignored in the outer run and were cleaned by the nested driver. The command was `cargo nextest run --locked -p fireemu --test leak_fixture --profile pr`.

These runs give current-source local evidence for the 24 Functions and 48 Quint groups, plus the leak-detection driver, that the normal PR profile intentionally ignores. They do not turn the original 81 skipped tests into executed passes, establish production parity, or discharge the seven release/resource qualifications. The full authority log is retained in the private work log with SHA-256 `c22a0f95769b8f0edde409683e39e7cb462aae6c26d6f9f2e31a2dccc7d05917`; no production credential was used.

## Release/resource qualification at 49e445e05

All seven release/resource checks were explicitly run with `cargo nextest run --locked --release --run-ignored only` against source `49e445e05`; each selected test passed. The two Firestore query checks were selected together and the other five were selected individually, so these results cover seven distinct ignored tests. The target selectors were `fireemu-core-types --test hash`, `fireemu --bin fireemu` for both RSA cache and Functions source scan, `fireemu-core-firestore --test query_execution` for both large query checks, `fireemu-adapter-grpc --lib`, and `fireemu-core-storage --test snapshot`.

The first one-million-document run exposed a test-fixture error: the helper created 1,000,010 versions under the default 1,000,000-version history cap, so it failed before measuring query behavior. The fixture now supplies an explicit capacity sufficient for its million unrelated documents and ten target documents; the 200,000-document control also passed after this test-only change. No production runtime limit was raised. These release-mode checks establish their stated local performance and resource assertions at this source. They do not convert the historical PR-profile 81 skips into passes, establish production compatibility, or replace final-artifact qualification if later relevant source changes invalidate this binding.
