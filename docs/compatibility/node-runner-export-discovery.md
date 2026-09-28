# Node runner export discovery

This is a local Functions runtime improvement supporting Auth/Functions and
Functions event delivery. It does not close any parent compatibility domain and
does not authorize production observation.

## Normalization and traversal

The runner preserves CommonJS root insertion order and precedence, fills missing
named ES exports, and omits the same `default` / `module.exports` interop aliases
as before. Root properties are resolved lazily with their original receiver.
A throwing root getter is diagnosed by name, not eagerly evaluated by a bulk
`Object.assign` that prevents all discovery. The temporary namespace has a null
prototype and uses own-property membership, so prototype-shaped export names do
not disappear or mutate the merger's prototype. Inherited, nonenumerable, symbol,
array and unmarked utility-function exports remain excluded as before.

Traversal uses an explicit stack. Cycle detection tracks ancestors on the
current path, including the original normalized root, not a global visited set.
Shared acyclic groups therefore remain available at each distinct alias; a root
self-reference does not create additional copies of the root functions.
Cycles, failed property reads and nested enumeration errors are included in the
existing `ignored` inventory as unsupported/malformed names. Describing an
endpoint can also throw an arbitrary value; the existing bounded safe error
formatter handles it without running arbitrary string conversion a second time.
An inability to enumerate the root aborts discovery because a complete root
inventory is not known.

## Ambiguous flattened names

If two distinct export paths resolve to one flattened name, neither function is
served at that name. The callable map and manifest cannot have different winners.
A broken export colliding with a valid one also blocks that name. Multiple aliases
to the same function object are not an exception if their *flattened names*
collide. Other healthy names remain callable. Ignored entries carry the original
paths to explain the ambiguity. This is a deliberate local defensive policy;
it has not been compared against a production deployment or official emulator.

## Local resource limits

The maximum is 128 nested groups, 10,000 visited enumerable export slots across
all traversed paths, and 1,024 UTF-8 bytes per flattened name. These are local
inspection bounds, **not Google quotas or a new native function-name contract**.
Crossing a limit terminates discovery with exit 1 before a hello/manifest is
published. A truncated graph is never presented as a complete inventory. A large
shared DAG consumes a slot at every visited path, preventing unbounded alias
expansion. `Object.keys` still allocates the key array of one object; these bounds
are not a proof of total process memory or time consumption.

Ordinary cyclic edges are diagnosed and do not abort healthy siblings. In contrast,
an exceeded global traversal limit makes it impossible to rule out later name
collisions, so the entire discovery is rejected rather than partially served.

## Packaging and verification

`discovery.mjs` is included in the platform package's explicit runner file list.
The package test copies and boots the real runner outside the checkout with a
cyclic/ambiguous codebase. Its placeholder native file is never executed. Unit
and real-runner tests cover CJS/ESM names, order, aliases, collisions in both
orders, throwing getters/proxies, recoverable ignored branches and finite bounds.
The real runner tests invoke healthy functions after discovery and verify that
ambiguous/ignored names never enter a callback.

## Remaining boundaries

This code inspects trusted local user JavaScript; it is not an arbitrary-code
sandbox. A getter that never returns, global prototype/intrinsic modification,
process-wide stdout backpressure, unbounded callback concurrency, and complete
metadata validation are outside this change. The existing endpoint-to-manifest
logic remains responsible for individual platform options. Exceptions and caps
are not evidence of rollback of user code executed during import/discovery.

Rust/native Functions integration, actual Firebase SDK/Express, configured Node 24,
full workspace testing, new source/binary-bound local evidence, saved-reference
comparisons, and independent review remain unexecuted here. Past observation
receipts and approval bindings are unchanged.
