# Text search replay fixtures

The scripts that build the committed production text-search fixtures of `crates/fireemu-core-firestore/tests/fixtures/` from the private production recordings:

```sh
python3 extract.py inv.json <run dir> [<run dir> ...]
python3 order_fixture.py inv.json production_text_order.json
python3 membership_fixture.py inv.json production_text_membership.json
```

Pass every recorded text run directory, not only those that hold searches: index creates and deletes live in other runs, and a search without a reconstructed text index stops the builders with a message. `extract.py` replays the directories in the order of their first sent request, so the order of the arguments does not matter. The committed fixtures were built from these 32 run directories (recorder outputs with `journal.jsonl` and the request and response bodies; private, not committed):

- 2026-10-23: `text01-v4`, `text02-v1`, `text-calibration01-v2`, `text-continuation01-v2`, `text-continuation02-v1`, `text-lexical01-v1`, `text-reconcile01-v3`.
- 2026-10-24 and 2026-10-25: `text-boolean-composition01-v1`, `text-boolean-recovery01-v6`, `text-boolean-recovery01-v8`, `text-boundary-final-verify01-v1`, `text-boundary-recovery01-v1`, `text-boundary-v3-20261025-02`, `text-boundary-v5-20261025-03`, `text-boundary01-v1`, `text-discriminator01-v1`, `text-enhancement-matched01-v1`, `text-language-controlled01-v1`, `text-language-held02-v1`, `text-language-held03-v1`, `text-or-composition01-v1`, `text-proof01-v1`, `text-repair-held03-v1`, `text-repair-held04-v1`, `text-repair-inplace01-v1`, `text-repair-probe01-v1`, `text-repair-probe02-v1`, `text-score-fresh-db-continuation01-v1`, `text-score-fresh-db-retirement01-v1`, `text-score-fresh-db-retirement03-v1`, `text-score-fresh-db01-v1`, `text-score-twins01-v1`.

Both fixture builders stop when two recordings of the same case disagree. On these recordings (531 search responses) none disagree, and both committed fixtures are reproduced byte for byte.
