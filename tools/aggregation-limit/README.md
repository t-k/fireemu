# Aggregation ordering diagnostics

This is a bounded diagnostic, not a compatibility approval or a source of automatically learned golden expectations. It preserves the original omitted-order, limit-two request from the aggregation corpus and compares it with explicit ordering and ordinary document queries.

## Scope and execution

The diagnostic crosses count-plus-sum, sum alone, and ordinary document queries with five controls: omitted order, `__name__ ASC`, `x ASC`, `x ASC` with offset two and limit one, and `x DESC`. The other controls use limit two. All use the four unchanged fixtures from `tools/compat-inventory/aggregation_corpus.py`.

```sh
uv run --project tools/compat-inventory --locked -m pytest tools/aggregation-limit -q
uv run --project tools/compat-inventory --locked tools/aggregation-limit/probe_limit.py --target production --output /absolute/path/to/new-production-record.json
```

Production execution writes four exclusively created documents in one random collection in the fixed authorized project `fireemu-35fe6`, project number `592603257417`, Native/Standard `(default)` database. It validates project and database identity before writing, journals every attempted creation, and performs ownership-checked cleanup followed by absence verification. The default run does not create indexes or change settings. Application Default Credentials must already have the required access. Never run it against another project by modifying the constants.

`--extended` adds twelve cursor, equality, multi-field, and ordering controls. In production it also creates one narrowly owned `x ASC, y ASC` composite index, waits for readiness, and deletes it with absence verification. `--details` adds eight cursor, inequality, and array-membership controls without creating an index. Both flags together select 35 distinct cases. Compare runs with equivalent index configurations: an index-dependent rejection is not comparable with a successful run that has the required index. For local runs only, `--collection` accepts a private UUID namespace so an index file can be configured before the owned runtime starts; production namespace overrides are rejected.

For local execution, run the same Python command with `--target local` as the direct child of `fireemu exec`, using a strict config and ephemeral ports. The script obtains the endpoint and control token from that owned invocation and checks the profile and control authentication. It does not independently attest a binary hash or build provenance; use `owned_runner.py` for formal artifact-bound observations.

The output path must not exist. Full requests and responses are retained. Non-200 responses are recorded, not counted as successes. An invalid successful-response stream stops collection and still triggers cleanup. A complete run containing a rejection remains `inconclusive` and exits nonzero; inspect `cases`, `failure`, `before`, `after`, and `cleanup` rather than interpreting the exit code as a compatibility verdict.

## Baseline observation on 2026-09-10

The final 15-case production run and local baseline run used the same diagnostic script and case definitions. Local runtime baseline: branch commit `8a9671f04ce4e69244ae1f9698cf857c1399d44e`; this diagnostic is not an artifact attestation. Each final run created four documents, observed unchanged before/after document states, and confirmed all four absent after cleanup.

| Control | Production count / sum | Local count / sum | Ordinary document IDs, both targets |
| --- | --- | --- | --- |
| Omitted order, limit 2 | 2 / 30.5 | 2 / 10 | A, B |
| `__name__ ASC`, limit 2 | HTTP 400 `INVALID_ARGUMENT` | 2 / 10 | A, B |
| `x ASC`, limit 2 | 2 / 30.5 | 2 / 30.5 | A, D |
| `x ASC`, offset 2, limit 1 | 1 / 0 | 1 / 0 | C |
| `x DESC`, limit 2 | 2 / 20.5 | 2 / 20.5 | C, D |

Sum-only requests produced the corresponding sum values and the same name-order rejection. Fixture B lacks `x`; C has a string value. The offset and descending controls show that strings remain in the selected set and contribute to count, while sum ignores their values. This rules out filtering nonnumeric documents before limit as the explanation for the original divergence. The omitted aggregation agrees with explicit `x ASC`, unlike the ordinary omitted-order query.

The name-order error states that an index would need `x` after `__name__`, which Firestore does not support. The baseline local aggregation index requirement inserted missing aggregation fields before `__name__`, even when that name order was explicit. Execution independently retained the ordinary query's ordering. These were distinct validation and execution defects, not an arithmetic defect.

[The official aggregation documentation](https://firebase.google.com/docs/firestore/query-data/aggregation-queries#limitations) describes nonnumeric handling and field-presence restrictions; the specific implicit-order and rejection observations above come from the live controls, not an extrapolated documentation guarantee.

## Implemented normalization and bounded recheck

Runtime commit `fe37fe0` introduces shared aggregation-specific ordering normalization for index validation, execution, and transactional observation/rechecking. It appends missing inequality fields before canonically ordered aggregation fields, inherits the last explicit direction, rejects unsupported fields after an explicit document-name order, and validates cursor arity against caller-supplied order fields. Ordinary document queries retain their behavior. Security Rules continue to see the caller's original query metadata, not the implicit execution order.

With equivalent index configurations, the refreshed local run matched the production extended run on 27 controls and the production details run on 23 controls, covering 35 distinct case IDs. This comparison covers HTTP status, aggregate fields, document IDs, and error status; it does not assert identical error messages, error envelopes, timestamps, or complete wire compatibility. The extended comparison had the `x ASC, y ASC` index on both targets; the details comparison had no composite index. Each local run observed unchanged document state and confirmed all four created documents absent after cleanup. Production runs likewise confirmed document cleanup and, for the extended run, owned-index absence. Diagnostic raw records remain private working logs and are not approved execution evidence.

The [post-fix, pre-revision artifact-bound evidence](../../spec/compatibility/evidence/history/aggregation-677e406a/) was reacquired separately using the unchanged ten-case corpus. Both production and the rebuilt owned strict runtime return count 2 / sum 30.5 for `missing-before-limit`; the historical expected sum remains 10, so both receipts truthfully record 9/10 matches. Its approvals remain empty. This bundle and the [earlier evidence bundle](../../spec/compatibility/evidence/history/aggregation-376db0d9/) are preserved byte-for-byte, rather than rewritten to fit the new implementation.

The [explicit corpus revision](../compat-inventory/aggregation-corpus-revisions.md) corrects the mistaken expectation and brings the ASC, DESC, offset and name-order rejection controls into a fourteen-case artifact-bound corpus. The [current evidence page](../../docs/compatibility/aggregation-evidence.md) reports the new captures and exact approval subject separately. A new subject still requires explicit approval of only its supported scope. These bounded observations do not establish general aggregation compatibility or authorize automatic promotion of candidate evidence.
