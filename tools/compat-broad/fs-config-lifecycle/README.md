# FS-CONFIG-LIFECYCLE oracle preparation

This directory classifies the Firestore Admin API v1 management surface and prepares one bounded observation of it. Nothing here contacts Google, starts fireemu, reads a credential, or records a result. There is no collector, and the comparator cannot report a match.

`surface_matrix.py` is the classification. Its denominator is the Discovery document already pinned at `spec/compatibility/upstream/2026-09-09-retry/discovery.json`, so the enumeration is reproducible without a fetch. Each of the forty-two management methods is placed in exactly one of three classes with a rationale, the data-plane consequence that survives the classification, and the `file:line` where the behavior lives in this checkout or a declaration that it does not exist. The eighteen document methods are listed as an explicit exclusion so the management denominator is the complement of a published set. The module also classifies every field of the Database resource and carries five open repair tickets. `--write` publishes the machine-readable form to `spec/compatibility/fs-config-lifecycle-surfaces.json`; a test fails if the checked-in file drifts, and another test fails if any cited line no longer exists.

`cases.py` compiles twenty-two abstract observation cases from one 32-character hexadecimal nonce: inventory controls, one create and delete lifecycle for a throwaway named database, the time-to-live and single-field-exemption patches with their baselines and reverts, five identity refusals, a project-boundary refusal and one bounded operation poll. Every mutating case names the case that reverts it, every negative case creates nothing, and no case touches a document. `manifest.py` freezes the inputs, the budget, the permission envelope, the owner preconditions, the abort rules, the owned-resource ledger and a resumable operation poll. `rehearsal.py` replays the cleanup path offline under six injected failures so an unrecovered resource is visible as an outcome rather than as a silent success.

`comparator.py` always returns `PREPARATION_ONLY` with no rows and states the normalization rules a future measurement version must apply. `shadow.py` restates the expected local result per case from the classification matrix; it opens no socket and proves no local behavior. `doc_render.py` renders `docs/compatibility/fs-config-lifecycle-classification.md` from the same compiled matrix, so a row cannot appear in the document and not in the specification.

A future measurement version must bind path-specific digests for the source, collector and comparator, a resolved runtime identity, per-case request and response records, the final ledger with every entry recovered, the operation checkpoint, and a separately supplied owner permission bound to this manifest and an unused nonce. None of that exists yet.

```sh
uv run --python 3.12 --with pytest pytest -q tools/compat-broad/fs-config-lifecycle
uv run --python 3.12 -m ruff check tools/compat-broad/fs-config-lifecycle
```
