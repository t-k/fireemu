# O5 Rules publication transition preparation

This directory contains a credential-free, finite contract for
`FS-RULES-PUBLICATION-USER-TOKEN-01`. It prepares one nonce-scoped transition
from Ruleset A to Ruleset B for an Auth user token and records the bounded
Firestore user SDK reads: three successful reads under A, an owned-document
permission denial under B, a public control success under B, and a second-user
denial under B.

The compiler never obtains an Auth token, publishes Rules, starts a local
server, or sends a Firestore request. The local shadow is only a collector and
comparator sanity check. It cannot establish production Rules parity. Admin
REST, Admin credentials, local evaluator results, and local or unsigned tokens
are explicitly excluded from user-token authorization evidence.

The plan owns exactly two nonce-scoped documents and at most two short-lived
users. Its six observation reads and three recovery slots are immutable and
bounded. Recovery requires readback-bound ownership before deleting either
document or user; a final fixed deny-all Rules publication is represented as a
recovery slot. A future production runner must bind a fresh nonce, shared lock,
owners, SDK/package digests, Rules source/artifact digests, execution window,
and cost/retention ceiling before any data operation.

Run focused checks with:

```text
PYTHONPATH=tools/compat-broad/fs-rules-publication uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-rules-publication
```

