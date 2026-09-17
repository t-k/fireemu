# O5 Rules publication observation case

This directory contains an offline, non-executable observation case for `FS-RULES-PUBLICATION-USER-TOKEN-01`. Its only status is `PREPARATION_ONLY`; `productionExecuted` and `productionReady` are false. No production comparison result exists. The comparator always returns `INDETERMINATE` until a separately reviewed typed collector and provenance validator exist. The template digest checks only the consistency of this design artifact, not evidence authenticity.

The logical A→B sequence keeps six intended user SDK observations: three owned-document successes under A, then an owned-document denial, public-document success, and second-user owned-document denial under B. Rules source and resource paths illustrate the case; they are not a publication plan. The project, database, nonce, user identities, source bytes, SDK build, and execution window have not been verified or reserved. A syntactically valid nonce does not prove freshness. No wire request, cost, retention, or time bound is enforced.

Publishing Rules changes the entire database's Rules state. Safe restoration of preexisting Rules needs an approved owner, captured version and bytes, conditional publication, readback, and a shared lock. A fixed deny-all Ruleset cannot serve as automatic recovery. Document and user deletion likewise need owner- and version-bound readback and final absence evidence. None of these operations is implemented here. Local shadow output describes expected statuses only; it does not claim SDK traffic, credentials, cleanup, or production observations.

Run the offline checks with:

```text
PYTHONPATH=tools/compat-broad/fs-rules-publication uv run --project tools/compat-inventory --locked pytest tools/compat-broad/fs-rules-publication
```
