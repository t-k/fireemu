# FS-DATA-WRITE local boundary corpus

This directory compiles **inputs**, not observations. It cannot issue requests,
load credentials, authorize production, or release a production reservation.
`nativeExecuted: false` remains false even after input compilation succeeds.
Expectations are local hypotheses to test against the implementation, not an
oracle inferred from synthetic responses.

## Finite coverage

The compiler has 14 closed families and three points (maximum - 1, maximum,
maximum + 1), for **42 inputs** covering 11 distinct catalog limits:

- Collection ID, document ID, collection depth, full document resource name.
- Field name and canonical field path.
- Field-value bytes as scalar string, scalar bytes, aggregate map and array.
- Indexed value bytes, composite-entry count, individual composite-entry bytes,
  and total composite-entry bytes.

The indexed-value over-limit input is expected to be **accepted**. Index charging
is capped, but stored field data must not be truncated. A simple field-name
boundary also overlaps the canonical field-path limit; the input records that
fact rather than asserting an unestablished diagnostic precedence.

The three index limits use explicitly configured composites with automatic
single-field indexes disabled for the target collection. This isolates the
count, entry-size and total-size limits from each other. It does not change the
existing automatic-index counting model. Integer array members are distinct;
the total-size remainder uses a bytes value of a different type. Every case
needs a **fresh, empty, independently owned local backend**; the configurations
must never be applied to a shared or production database.

Document bytes, map/array depth, request bytes and transforms per document remain
in their existing collectors/native tests. `separateExistingCoverage` links those
four additional limits without pretending this compiler re-executed them.

## What the tests establish

`test_boundaries.py` independently checks byte arithmetic, explicit composite
entry expansion, isolation from unrelated size limits, catalog drift, immutable
output publication, and closed input selection. These are Python tests of the
**test inputs**. They do not establish native behavior or production parity.

`crates/fireemu-adapter-grpc/tests/write_boundary_corpus.rs` passes these inputs to
real `RestState`/`LocalBackend` handlers. It declares 42 Rust tests (14 families
across PATCH, Commit and BatchWrite); each tests all three points, giving **126
intended handler scenarios**. The native test checks exact field readback,
Commit sibling atomicity and version stability after rejection, and BatchWrite
sibling independence. Invalid resource names must yield typed rejection on GET;
that rejection is not used as a 404 absence proof. A separate in-memory backend
is destroyed after each point. This is not HTTP-wire, gRPC or SDK testing.

**The newly added Rust target has not been compiled or executed in the authoring
environment.** The counts above describe prepared cases, not successful native
runs. A machine with the repository's pinned toolchain is required to accept it.

## Reproduction (local only)

```sh
python3 tools/compat-broad/fs-data-write-local/boundaries.py \
  --nonce aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --family index-entry --position over --output /path/to/new-input.json

python3 -m pytest -q tools/compat-broad/fs-data-write-local/test_boundaries.py

cargo test --locked -p fireemu-adapter-grpc --test write_boundary_corpus
cargo test --locked -p fireemu-core-firestore --test reference_size_namespaces
cargo test --locked -p fireemu-adapter-grpc --test request_bytes
```

The first command is safe input compilation with a fixed demonstration nonce;
it does not consume an observation nonce or approval. Output must not exist.
The Rust target invokes `python3 -I -S -B` with a selected single case; a missing
Python/compiler dependency fails the test instead of skipping it. Existing
wire, streaming, core write/mask/transform and SDK lanes remain separate duties.
See `docs/compatibility/fs-data-write-local-acceptance.md` for the remaining work.
