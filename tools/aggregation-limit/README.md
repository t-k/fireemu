# Aggregation ordering diagnostics

This is a bounded diagnostic, not a compatibility approval or a source of automatically learned golden expectations. It preserves the original omitted-order, limit-two request from the aggregation corpus and compares it with explicit ordering and ordinary document queries.

## Scope and execution

The diagnostic crosses count-plus-sum, sum alone, and ordinary document queries with five controls: omitted order, `__name__ ASC`, `x ASC`, `x ASC` with offset two and limit one, and `x DESC`. The other controls use limit two. All use the four unchanged fixtures from `tools/compat-inventory/aggregation_corpus.py`.

```sh
uv run --project tools/compat-inventory --locked -m pytest tools/aggregation-limit -q
uv run --project tools/compat-inventory --locked tools/aggregation-limit/probe_limit.py --target production --output /absolute/path/to/new-production-record.json
```

Production execution writes four exclusively created documents in one random collection in the fixed authorized project `fireemu-35fe6`, project number `592603257417`, Native/Standard `(default)` database. It validates project and database identity before writing, journals every attempted creation, and performs ownership-checked cleanup followed by absence verification. It does not create indexes or change settings. Application Default Credentials must already have the required access. Never run it against another project by modifying the constants.

For local execution, run the same Python command with `--target local` as the direct child of `fireemu exec`, using a strict config and ephemeral ports. The script obtains the endpoint and control token from that owned invocation and checks the profile and control authentication. It does not independently attest a binary hash or build provenance; use `owned_runner.py` for formal artifact-bound observations.

The output path must not exist. Full requests and responses are retained. Non-200 responses are recorded, not counted as successes. An invalid successful-response stream stops collection and still triggers cleanup. A complete run containing a rejection remains `inconclusive` and exits nonzero; inspect `cases`, `failure`, `before`, `after`, and `cleanup` rather than interpreting the exit code as a compatibility verdict.

## Observation on 2026-09-10

The final 15-case production run and local baseline run used the same diagnostic script and case definitions. Local runtime baseline: branch commit `8a9671f04ce4e69244ae1f9698cf857c1399d44e`; this diagnostic is not an artifact attestation. Each final run created four documents, observed unchanged before/after document states, and confirmed all four absent after cleanup.

| Control | Production count / sum | Local count / sum | Ordinary document IDs, both targets |
| --- | --- | --- | --- |
| Omitted order, limit 2 | 2 / 30.5 | 2 / 10 | A, B |
| `__name__ ASC`, limit 2 | HTTP 400 `INVALID_ARGUMENT` | 2 / 10 | A, B |
| `x ASC`, limit 2 | 2 / 30.5 | 2 / 30.5 | A, D |
| `x ASC`, offset 2, limit 1 | 1 / 0 | 1 / 0 | C |
| `x DESC`, limit 2 | 2 / 20.5 | 2 / 20.5 | C, D |

Sum-only requests produced the corresponding sum values and the same name-order rejection. Fixture B lacks `x`; C has a string value. The offset and descending controls show that strings remain in the selected set and contribute to count, while sum ignores their values. This rules out filtering nonnumeric documents before limit as the explanation for the original divergence. The omitted aggregation agrees with explicit `x ASC`, unlike the ordinary omitted-order query.

The name-order error states that an index would need `x` after `__name__`, which Firestore does not support. The local aggregation index requirement currently inserts missing aggregation fields before `__name__`, even when that name order was explicit. Execution independently retains the ordinary query's ordering. These are distinct validation and execution defects, not an arithmetic defect.

[The official aggregation documentation](https://firebase.google.com/docs/firestore/query-data/aggregation-queries#limitations) describes nonnumeric handling and field-presence restrictions; the specific implicit-order and rejection observations above come from the live controls, not an extrapolated documentation guarantee.

## Remaining implementation gate

No runtime behavior, historical corpus expectation, execution receipt, or approval was changed by this diagnostic. In particular, the published `missing-before-limit` mismatch remains visible.

Before changing aggregation-specific query normalization, measure cursor arity/value interpretation, multiple aggregation fields, equality-constrained fields, and direction inheritance. A shared normalizer must serve validation, ordinary aggregation execution, transaction execution, and the query stored for transaction conflict rechecking. Do not change ordinary query ordering globally or silently rewrite explicit name order. Add failing domain tests from those observations before implementing the fix, then rerun artifact-bound evidence acquisition without rewriting historical receipts or fabricating approval.
