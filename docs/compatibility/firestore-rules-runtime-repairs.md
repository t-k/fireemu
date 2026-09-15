# Firestore and Storage Rules runtime repairs

The Rules evaluator now resolves user-defined function calls in the lexical scope where each function is declared. A function called from a nested `match` therefore does not accidentally bind to a same-named function declared at the call site. Firestore and Storage evaluations share this resolver and have dedicated regressions in `crates/fireemu-core-rules/tests/eval.rs`.

Rules activation also rejects every static linter diagnostic whose level is `Error`. The previous active generation remains published when a parseable candidate exceeds a source or structural limit. The activation regression is in `crates/fireemu-core-rules/tests/activation.rs`.

Rules activation now validates the declared version and recursive-wildcard structure before publication. Unknown versions, more than one recursive wildcard in a match, and non-terminal recursive wildcards under rules_version 1 are rejected without replacing the active generation.

The file supervisor reconciles the disk contents observed at startup with the active generation and checks a content signature in addition to file metadata. This catches a change that occurs before the supervisor starts and replacements that preserve size and modification time while retaining the last-known-good behavior for invalid candidates.

These are local runtime repairs. They do not claim production Rules parity or production compiler/watch behavior.
