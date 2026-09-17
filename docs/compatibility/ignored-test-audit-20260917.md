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
