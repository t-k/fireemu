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

## Reviewed production preparation

`stream_shadow.py` runs an owned local rehearsal using a retained, validated artifact. `stream_production.py prepare` binds that receipt, collector sources, SDK evidence, and artifact into a proposal. Without a campaign-specific permission, the proposal remains `BLOCKED_OWNER`. `execute` accepts only a frozen prepared input and a private credential file descriptor; production remains subject to O7 review and a new explicit permission. The earlier document-size/depth permission does not authorize this campaign.

The reviewed `c5cfc7e50` preparation was integrated at `c53f92510`. Its latest local rehearsal completed 31 requests, typed cleanup for three resources, reservation release, and process/listener shutdown. The plan reserves at most 33 requests, three resources, zero accounts, 1100 seconds, concurrency one, and USD1.3033. The cost is a conservative planning ceiling, not an observed bill: it includes 5483 MiB of bounded encoded responses and allowances at USD0.23/GiB, rounded into a USD1.30 fixed reserve plus request charges. Installed Firestore SDK 8.7.1 source and lockfile evidence bind the encoded receive cap; the smaller decoded-message cap does not reduce that network allowance.

Terminal events settle outstanding response waits, prevent further sends, and release the client in `finally`. Oversized status/error events become bounded incomplete receipts. A successful terminal status without a required acknowledgement does not establish successful acquisition.
