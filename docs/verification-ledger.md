# The requirement ledger and how its artifacts are resolved

`verification/requirements/requirements.json` is the traceability ledger: it lists the
requirements the project claims to hold and, for each one, the artifacts that prove it.
`tools/traceability-check` is the gate. It reads the ledger together with
`verification/mutants/catalog.json` and `verification/loom/scenarios.json` (ADR-033) and fails
CI when the ledger and the repository disagree.

The rule the gate enforces is simple: **a requirement that claims to be built names artifacts
that exist**. A name that resolves to nothing is a false green, not evidence (ADR-010).

## Requirement fields

| Field | Meaning |
| --- | --- |
| `id` | Upper-case, digits and `-` only; unique. |
| `statement` | What the requirement claims. Never empty. |
| `criticality` | `critical`, `important` or `normal`. |
| `status` | `planned`, `partial` or `implemented`. |
| `owner` | The crate or team that answers for it. Never empty. |
| `note` | Optional prose; the place to explain what is still missing. |
| `artifacts` | The evidence, per category (below). |

## Artifact categories and how each one resolves

| Category | Shape | Resolves against |
| --- | --- | --- |
| `tla` | `Module.tla::Property` | `verification/tla/<Module>.tla` must contain `<Property> ==`. |
| `loom` | list of snake_case names | Defined in `verification/loom/scenarios.json` **and** present as `fn <name>(` under `verification/loom/src`. |
| `kani` | snake_case function name | A `#[kani::proof]` function of that name under `verification/kani`. An attribute such as `#[kani::unwind(4)]` may sit between the proof attribute and the function; a name that appears only in a comment does not resolve. |
| `property` | snake_case function name | A function of that name defined in a Rust file under a `tests/` directory anywhere in the workspace (`proptest!` bodies count: they expand to `fn <name>(...)`). Property artifacts for the core invariants live in `verification/property/tests`. |
| `fuzz` | snake_case target name | A file `fuzz/fuzz_targets/<name>.rs` under the repository root or under any crate. |
| `mutation` | list of mutant IDs | `verification/mutants/catalog.json`. |
| `conformance` | repository-relative path | The file or directory must exist. |
| `integration` | list of repository-relative paths | Each must be an existing file. |

## Status decides how strictly artifacts are resolved

- `implemented` and `partial`: every artifact must resolve, or be explicitly marked pending.
- `planned`: the requirement describes work that does not exist yet, so its artifacts are not
  resolved. `integration` paths are the exception; they are always checked, because a stale test
  path is a mistake at any status.

## Pending artifacts

An artifact that is decided but not written yet is marked with the `pending:` prefix, keeping
the intended name visible:

```json
"kani": "pending:conservative_index_never_false_accepts"
```

A pending artifact:

- is never resolved against the repository;
- is **never evidence**: it cannot satisfy the gate below, whatever the requirement's status;
- is printed by `traceability-check` on every run (`pending: <requirement>: <category> <name>`),
  so that it stays visible instead of quietly ageing;
- must still carry a name; `"pending:"` on its own is a malformed reference.

Use it on `partial` requirements to say precisely which half is missing, and record the reason
in `note`.

## The gate for critical requirements

A requirement with `criticality: critical` and `status: implemented` must have all three of:

1. a **dynamic** test: a resolved `integration` file or a resolved `property` test;
2. a **formal or systematic** artifact: a resolved `tla`, `kani`, `loom`, `property` or `fuzz`
   artifact;
3. a **mutation or negative** test: a `mutation` ID or a resolved `conformance` artifact.

Only resolved artifacts count. Every critical mutant in the catalog must also be referenced by
at least one requirement.

## Running it

```sh
cargo run -p traceability-check              # the gate; exits non-zero on any problem
cargo test -p traceability-check             # the checker's own fixtures
cargo test -p ftd-verification-property      # the property artifacts
cargo kani -p ftd-verification-kani          # the Kani harnesses
```

`tools/traceability-check/tests/artifact_references.rs` holds table-driven fixtures: for every
category, a missing reference must fail with the requirement ID and the artifact name, and a real
one must pass. The last fixture runs the checker over this repository, so `cargo nextest run`
fails as soon as the ledger and the repository drift apart.
