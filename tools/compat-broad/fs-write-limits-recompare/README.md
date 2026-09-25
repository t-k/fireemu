# FS write limits v2 recompare

This directory contains a credential-free derived analysis for the frozen
`fs-write-limits` comparison. The entry point writes the original v1 result to
an exclusive output directory first. Only an acquisition-validated v1 result
is passed to the v2 kernel; the v2 result remains `promotionReady: false`.

The v2 kernel preserves the v1 normalization and additionally recognizes two
complete error-message grammars. It normalizes only the exact resource from the
current request. The quoted resource is represented as a structured segment,
so resource-like text elsewhere in an error or in a different message remains
literal and causes a mismatch.

The v1 `production.py` and `comparator.py` files are imported unchanged and
their source hashes are not replaced by this derived output.
