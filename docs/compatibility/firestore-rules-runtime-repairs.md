# Firestore and Storage Rules runtime repairs

The Rules evaluator now resolves user-defined function calls in the lexical scope where each function is declared. A function called from a nested `match` therefore does not accidentally bind to a same-named function declared at the call site. Firestore and Storage evaluations share this resolver and have dedicated regressions in `crates/fireemu-core-rules/tests/eval.rs`.

Rules activation also rejects every static linter diagnostic whose level is `Error`. The previous active generation remains published when a parseable candidate exceeds a source or structural limit. The activation regression is in `crates/fireemu-core-rules/tests/activation.rs`.

These are local runtime repairs. They do not claim production Rules parity. Recursive wildcard validation, explicit version validation, file replacement races and production-specific limits remain separate inventory work.
