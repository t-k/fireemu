# Text search replay fixtures

The scripts that build the committed production text-search fixtures of `crates/fireemu-core-firestore/tests/fixtures/` from the private production recordings:

```sh
python3 extract.py inv.json <run dir> [<run dir> ...]
python3 order_fixture.py inv.json production_text_order.json
python3 membership_fixture.py inv.json production_text_membership.json
```

Run directories are recorder outputs (`journal.jsonl` and the request and response bodies); they are private and are not committed. Both fixture builders stop when two recordings of the same case disagree. On the recordings of 2026-10-23 to 2026-10-25 (531 search responses) none disagree, and both committed fixtures are reproduced byte for byte.
