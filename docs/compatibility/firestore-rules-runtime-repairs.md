# Firestore and Storage Rules runtime repairs

The Rules evaluator now resolves user-defined function calls in the lexical scope where each function is declared. A function called from a nested `match` therefore does not accidentally bind to a same-named function declared at the call site. Firestore and Storage evaluations share this resolver and have dedicated regressions in `crates/fireemu-core-rules/tests/eval.rs`.

Rules activation also rejects every static linter diagnostic whose level is `Error`. The previous active generation remains published when a parseable candidate exceeds a source or structural limit. The activation regression is in `crates/fireemu-core-rules/tests/activation.rs`.

Rules activation now validates the declared version and recursive-wildcard structure before publication. Unknown versions, more than one recursive wildcard in a match, and non-terminal recursive wildcards under rules_version 1 are rejected without replacing the active generation.

The file supervisor reconciles the disk contents observed at startup with the active generation and checks a content signature in addition to file metadata. This catches a change that occurs before the supervisor starts and replacements that preserve size and modification time while retaining the last-known-good behavior for invalid candidates.

These are local runtime repairs. They do not claim production Rules parity or production compiler/watch behavior.

User-defined functions now restore the binding values captured at their declaration match as well as the declaration's function namespace. A caller's parameter or nested match capture cannot shadow a callee's lexical capture. The evaluator also visits recursive-wildcard path splits incrementally and charges a separate bounded matcher-work budget; it fails closed with an explicit evaluator budget reason instead of allocating every split up front. These local safety boundaries are not production limit claims.

Function declarations in one lexical scope now share one immutable function environment. A function call switches to that shared declaration environment and returns to the caller without cloning the declaration list, removing the per-request quadratic reference table while preserving lexical name resolution. The local regression asserts pointer sharing across a generated declaration set; production memory and performance parity remain unobserved.

Once an applicable allow has succeeded, later match-path exploration cannot turn that decision into a denial solely because the independent `FIREEMU-RULES-MATCH-WORK` budget is exhausted. The evaluator still propagates expression, call-depth, unsupported-operation and other budget failures, and it remains fail-closed when no allow has succeeded. Firestore and Storage regressions cover a successful allow followed by hundreds of non-matching recursive-wildcard matches; this is local evaluator evidence and does not claim a production compiler limit.
