# SDK111 reconnect callback observations

SDK111 has two independent comparison axes. The existing aggregate or wire verdict retains its original status. The callback verdict compares the collector's ordered `rawEvents.slice(baselineAt)` window, before cached-prefix removal, metadata-only collapsing, or change aggregation. `baselineAt` is the number of events already present when the collector executes its baseline step. Warm-up events before that index are excluded; the callback window can validly be empty.

The callback projection retains listener identity, snapshot kind, ordered document names, complete ordered changes including oldIndex/newIndex, existence, error, fromCache, and hasPendingWrites. Error callbacks remain in the same event sequence as snapshots. Generated clock fields are excluded. The projection follows the current collector's retained data: query changes use the existing default `docChanges()` semantics, and document field values or per-document metadata that were never recorded are not inferred.

Missing rawEvents, a missing or invalid baseline, inconsistent recorded event count, or incomplete callback records yield UNOBSERVED. An unfinished row with available callback evidence yields INDETERMINATE. Two valid empty windows yield MATCH; absence is never converted to an empty window. Different production callback repeats yield NONDETERMINISTIC independently of aggregate agreement. A callback mismatch yields MISMATCH even when final documents and aggregate changes match.

Reports retain each original aggregate row status and add callbackStatus for `sdk/111` and its browser transport variants. aggregateOk and callbackOk remain separate; combined ok requires both. The browser JSON and Markdown reports and the native CLI expose the callback axis. Closure evidence retains aggregateStatus and callbackStatus, maps missing/unfinished/nondeterministic callbacks to NOT_COMPARABLE, and maps callback differences to DIVERGES. An aggregate MATCH alone cannot establish callback compatibility.

The saved production SDK111 recordings do not contain rawEvents/baselineAt. Their historical aggregate MATCH remains evidence for the aggregate only; SDK111 callback compatibility is UNOBSERVED. The recording relays now preserve future collector evidence, but no new production recording was performed for this change. Existing SDK203/203C callback findings remain separate from SDK111's changed-document reconnect case.

## Historical source binding

The saved closure comparison binds its own conformance runner tree digest and release binary. It has not been regenerated with this comparator. The closure producer's sourceBound check covers binary build inputs; it does not prove that an old comparison used the current JavaScript comparator. Historical COMPAT_VERIFIED decisions and generated comparison summaries must not be presented as fresh callback verification. Running the current offline consumer preserves the runner digest and rejects unobserved callbacks. This source-only change requires no Quint evidence regeneration because no Quint-bound input changed.

## Coverage obligations

| Obligation | Verification |
| --- | --- |
| Compare the post-baseline window, without warm-up events or generated clocks | Callback baseline positive and recorder-to-comparator regression. |
| Distinguish a valid empty window from absent/malformed observations | Separate empty, legacy missing, invalid baseline, count, and record-shape negatives. |
| Preserve grouping, metadata-only callbacks, error order, document/change order and indexes | Equal-aggregate negative regressions plus an index property over 32 values. |
| Keep aggregate and callback verdicts independent | Both mismatch directions and production-callback nondeterminism regressions. |
| Make callback absence/difference visible to consumers | Browser CLI JSON/Markdown and closure consumer regressions. |
| Preserve actual producer-to-adapter evidence | SDK producer and adapter relay regressions; no production parity claim from synthetic inputs. |
| Detect defects in callback and consumer guards | Scoped hand mutations with a passing baseline and unchanged control. |
