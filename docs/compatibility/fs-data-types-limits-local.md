# Firestore Standard data types and limits: local coverage

This artifact records the finite local coverage added for `FS-DATA-WRITE` at the REST and gRPC adapter boundaries. It is local verification evidence and does not establish a production comparison.

The REST tests round trip null, boolean, integer, double, NaN, timestamp, bytes, document reference, geo point, array and map values. They also distinguish an absent field from an explicit null through a response mask, verify that a failed existence precondition leaves the document unchanged, and check the accepted and refused document nesting and size boundaries without publishing refused documents. Oversized payloads include the field name in the refusal message, matching the saved production response (`The value of property "blob" is longer than 1048487 bytes.`).

The gRPC test checks the same missing versus null distinction for `GetDocument`, `BatchGetDocuments` and `ListDocuments` response masks. BatchGet returns both a found and missing item, and the listing contains only the stored document with the requested projection.

Evidence is provided by:

- `crates/fireemu-adapter-grpc/tests/rest.rs`: `rest_round_trips_all_standard_value_types_and_preserves_refused_writes` and `rest_document_size_and_nesting_boundaries_refuse_without_publishing`.
- `crates/fireemu-adapter-grpc/tests/local.rs`: `grpc_batch_get_and_list_apply_masks_without_confusing_missing_and_null`.
- `conformance/firestore-production-matrix.json`: the saved production reference for the existing REST listing and BatchGet wire assertions. The new value and limit cases are local-only; production observation remains coverage debt.

The focused adapter run passed 113 tests with `cargo nextest run -p fireemu-adapter-grpc --test rest --test local --profile pr`. The test target was isolated with `CARGO_TARGET_DIR=target-fs-data`.
