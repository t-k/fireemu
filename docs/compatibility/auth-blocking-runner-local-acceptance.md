# AUTH-TENANT-BLOCKING: callback response serialization

This is local JavaScript runtime evidence, not production parity, an SDK run, or
completion of the AUTH-TENANT-BLOCKING parent. The Rust adapter and its downstream
validation are unchanged. No production transport, owner permission, or historical
receipt is added or modified.

## Finite invariants addressed

The Node runner invokes both generations' Blocking Functions through `fn.run` and
converts callback results in `tools/runner-node/blocking-response.mjs`.

1. An own property whose value is `undefined` must not appear in the generated
   update mask. Explicit `null`, `false`, and empty strings remain explicit
   updates. The existing public-name to wire-name mapping is unchanged.
2. Claim name and serialized-size validation must examine the JSON representation
   that is subsequently sent, not a mutable callback object. The runner builds a
   candidate wire envelope, materializes JSON once, validates that snapshot, and
   returns an immutable, unaliased JSON value. Stateful getters and `toJSON` are
   not executed again by HTTP serialization. Wire-envelope extensions survive,
   but the serialized `userRecord` must still be an object.
3. Non-null custom/session claims that are validated by this runner must be JSON
   objects, not arrays or scalar values. A serialization or property-access error
   produces a fixed invalid-argument diagnostic without including the original
   thrown value or an object path. Existing beforeCreate session-claim handling
   is not expanded by this change.
4. The public Blocking Function error message is the same immutable string that
   passed validation. Error properties are read once, and unreadable accessors,
   revoked proxies, and throwing `instanceof` hooks fall back to the existing
   UNAVAILABLE envelope. Failure to render a diagnostic must not suppress this
   safe HTTP response.

## Reference and compatibility boundary

The pinned fixture dependency is `firebase-functions@7.3.2` in
`tools/sdk-smoke/package-lock.json`. Its `getUpdateMask` omits undefined own
properties, and its claim validators use `JSON.stringify(...).length` (JavaScript
UTF-16 code units), including the custom/session merged limit. This patch retains
that 1,000-code-unit rule and the runner's existing reserved-name list and
session-overrides-custom merge rule.

Primary source:
https://github.com/firebase/firebase-functions/blob/v7.3.2/src/common/providers/identity.ts
(`getUpdateMask`, `validateAuthResponse`, `generateResponsePayload`).

The serialize-once guard is an explicit local defensive policy; it is not a claim
that the upstream SDK performs the same materialization. Null claims retain the
runner's prior pass-through behaviour; this is not a claim that the Rust backend
accepts null claim maps. Invalid shapes may now fail earlier at the runner.
Arbitrary non-object returns preserve the runner's old no-result behaviour.

The runner and the Rust Auth adapter already have separate claim validation.
The reproduced flaw is a bypass of the Node-side validation/serialization
invariant, not proof of a deployed account takeover or a bypass of the Rust
adapter. No production service was contacted.

## Executable local tests

```sh
node --test tools/runner-node/*.test.mjs
```

`blocking-boundary.test.mjs` calls the real helpers and exercises an actual
loopback HTTP serialization. `blocking-runner.test.mjs` starts the actual
`index.mjs` child process, parses its hello frame, and calls both v1 and v2
Blocking Function HTTP routes. Its temporary Express and HttpsError packages are
test doubles, not installed copies of Firebase Functions or Express. It tests
proxy-secret refusal, undefined masks, post-toJSON validation, safe errors,
throwing error diagnostics, and the next successful request after failure.

## Remaining acceptance work

Run the locked Functions SDK and real Express, the native daemon/Auth adapter,
existing Blocking Functions SDK tests, concurrency/tenant/callback rollback
checks, and workspace/static gates against the final artifact. Preserve historic
receipts: source changes require fresh artifact-bound evidence rather than
replacement of historic hashes. Independent correctness/security review remains
outstanding.

The snapshot is not a JavaScript sandbox. A malicious callback in the same Node
process can run arbitrary code, change global prototypes, or hang a getter or
`toJSON`; this patch does not preempt that code or attest the producer. Large
serialization/allocation, process termination, and all tenant/runtime isolation
requirements remain subject to the existing runner/daemon limits and separate
verification. Local test success does not set `COMPAT_VERIFIED`.
