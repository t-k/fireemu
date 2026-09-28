# Functions endpoint option resolution (local Node runner)

The runner resolves the runtime values of the supported `__endpoint` options
before announcing a manifest. Firebase Functions 7.3.2 leaves `Expression`
objects in endpoint metadata: their `.value()` returns a runtime value, whereas
`.toJSON()` represents a deployment expression. The runner must not substitute
object truthiness or that deployment string for the runtime setting.

## Supported boundary in this change

| Option | Announced value |
|---|---|
| `omit` | A strict boolean; true suppresses the function before other option getters are evaluated. |
| `region` | A non-empty string; an array is validated and the existing first-region selection is retained. |
| `timeoutSeconds` | A non-negative safe integer. Zero is omitted, preserving the existing unset/default behavior. |
| `eventTrigger.retry` | A strict boolean for Gen1/Gen2 endpoint event triggers; absent/reset defaults to false. |
| `availableMemoryMb`, `minInstances`, `maxInstances`, Gen2 `concurrency` | The existing non-negative-safe-integer contract with the same single-read resolver. |

A value is read directly or by calling its synchronous `.value()` method with
its original receiver. The method property is obtained once per option
resolution; getters must not be read a second time to perform the invocation.
No string, numeric or boolean coercion and no `toJSON`/`toString` evaluation is
used for these options. Null/undefined and the existing SDK ResetValue symbol
retain default/unset semantics. An expression returning null/undefined is an
unresolved value, not evidence for silently choosing a default.

Invalid types, non-finite/fractional numeric results, unresolved values and
throwing evaluators isolate the export as a named `ignored` entry. Healthy
siblings can still be announced and invoked. Async values and nested expression
results are unsupported. This is not a CEL interpreter, parameter prompting or a
network/configuration lookup. Parameter environments must already be supplied
by the normal launch path. Executing arbitrary user evaluators is not a sandbox
or an externally enforced time limit.

## Deliberately unchanged or unverified

This is not complete parameterized configuration support. The follow-up
[trigger option boundary](functions-trigger-option-resolution.md) covers selected
event resource/filter strings, runtime schedule expressions and Task Queue
retry/rate values. Pre-rendered CEL is not evaluated. Multi-region expansion is
NOT implemented here: the current first-region policy remains. Deployed range
constraints and the native manifest validator remain separate. Secret values are
not resolved by this helper.

The regression uses the real Node runner, subprocesses and framed IPC, with
Functions-shaped metadata and `.value()` test expressions. It does not execute
the installed Firebase SDK, Rust/native task or event dispatch, deployment,
production observation, or saved-production replay. Old receipts are unchanged.

## Primary sources (pinned)

- `firebase/firebase-functions`, tag `v7.3.2`, `src/v2/options.ts`: endpoint
  conversion retains `omit`, `region`, `timeoutSeconds` and numeric options;
  literal zero timeout denotes unset/default.
- The same tag, `src/common/encoding.ts`: `copyIfPresent` copies option objects.
- The same tag, `src/params/types.ts`: `Expression.value()` returns runtime values,
  `Expression.toJSON()` returns the expression representation.

## Local regression

```sh
node --test --test-concurrency=1 tools/runner-node/endpoint-options-runner.test.mjs
```
