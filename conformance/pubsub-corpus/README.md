# Pub/Sub unary corpus substrate

These modules record bounded REST and native unary exchanges from the same canonical JSON operation. They are library components, not a production executor. The guarded executor must supply exact owned resources, authoritative admission, durable receipt storage, a pinned protobuf descriptor, bounded credentials and a controlled transport. Production requests remain coordinator-only.

`wire-methods.mjs` names each selected RPC input/output and REST binding explicitly. `native-codec.mjs` checks representability before protobuf coercion, preserves duration/timestamp precision and field masks, and does not replace service-invalid but wire-representable values with defaults. Canonical JSON byte fields use base64 strings. An invalid base64 value cannot become a native bytes-field service rejection; record its client nonrepresentability and the corresponding valid native bytes control separately.

`unary-session.mjs` freezes operation identity, request and routing before asynchronous admission. It durably reserves each attempt, rechecks live admission for that same input before dispatch, permits one active attempt, and halts after uncertainty or persistence failure. Each actual response buffer is stored with its base64 representation, length and SHA-256. An unavailable native response is explicitly marked unavailable; it is distinct from a received zero-byte protobuf Empty message. Credentials and arbitrary exception messages are excluded from receipts. REST redirects are returned without following them.

`grpc-transport.mjs` binds a caller-owned grpc-js client and closes only that client and its pending calls. The caller must disable retries and synthetic interceptors, invocation transformers and channel overrides. The adapter retains duplicate/binary public terminal metadata. grpc-js public status combines peer and locally synthesized errors, so every non-OK terminal has unverified origin and remains a raw uncertain observation. Code0 is successful only with a successful callback, defined response bytes and an unexpired budget. A future transport that records peer HTTP/2 trailers is required for confirmed native refusal observations; a status code or initial-metadata event alone cannot prove peer origin.

Source-only verification:

```sh
node --test conformance/src/pubsub-wire-methods.test.mjs conformance/src/pubsub-unary-session.test.mjs conformance/src/pubsub-grpc-transport.test.mjs conformance/src/pubsub-native-codec.test.mjs
```
