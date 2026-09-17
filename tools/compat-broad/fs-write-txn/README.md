# Finite local Write-stream transaction collector

`stream_collector.mjs` runs one bounded, loopback-only observation of the Standard/Native gRPC Write stream while a read-write transaction holds a document read lock. It records transport completion separately from semantic observations, including the actual contention status and readback state. A local API error is retained in the receipt; it is not converted into a manufactured expected result.

The collector creates only documents below its nonce-specific prefix with an owner marker. Cleanup reads each created document, deletes it only when the marker is still owned, and uses the observed update time as a conditional precondition before checking typed absence. It never restores or deletes a document without an ownership proof.

The existing owned Firestore fixture can invoke it with OS-assigned service ports:

```sh
target/debug/fireemu exec --config tools/sdk-smoke/fireemu.smoke.json \
  --project fireemu-test --only firestore --firestore-port 0 --http-port 0 \
  --hub-port 0 --ui-port 0 --logging-port 0 --log-verbosity silent -- \
  node tools/compat-broad/fs-write-txn/stream_collector.mjs
```

The collector consumes `FIRESTORE_EMULATOR_HOST` and `GOOGLE_CLOUD_PROJECT` from the owned child environment. It does not contact Firebase production or use ADC credentials.
