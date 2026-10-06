# Offline STREAM-DLQ comparison

Build the comparison binary with `RUSTC_WRAPPER= cargo build -p fireemu --bin fireemu --release`. Keep a private build-pin JSON containing `path` (the release executable), its `sha256`, the 40-character source `head`, `profile: "release"`, `rustcWrapper: ""` and the exact Cargo `command` array. The pin describes build provenance; retain the corresponding build receipt alongside the report.

Run the CLI with a closed capture and its two journals:

```sh
node conformance/src/pubsub-production/stream-dlq-compare.mjs \
  --capture capture.jsonl --capture-sha256 CAPTURE_SHA256 \
  --issued issued.jsonl --issued-sha256 ISSUED_SHA256 \
  --iam iam.jsonl --iam-sha256 IAM_SHA256 \
  --build-pin build-pin.json --out new-comparison-directory
```

Every input is hashed before JSON parsing. The run markers must enclose the recording, timestamps must be finite and ordered, and request durations must be nonnegative integers whose derived starts remain within their case and after the previous response. Invalid chronology is refused before server launch. Raw native frame blobs must remain beside the capture at its recorded relative paths; missing, changed or inconsistent frames remain NOT_COMPARABLE. The CLI starts its own pinned binary in strict mode through `fireemu exec`, uses OS-assigned loopback ports and advances to each uniquely paired request-dispatch timestamp without repairing regressions. The report retains every clock advance. The replay child checks its actual pinned exec parent and strict configuration. Direct worker invocation is refused. This launch verification currently requires macOS or Linux `ps`. Launcher SIGINT/SIGTERM is forwarded to its owned exec, whose existing supervisor stops its worker tree; `runtime-start.json` identifies those owned PIDs.

The clock replays recorded dispatch instants, not intra-RPC wall latency or service delivery timing. The transport measures duration before capture.record takes its timestamp, so subtracting duration is not an exact dispatch clock; no fixed tolerance is assumed for synchronous persistence. Time-sensitive response gaps require review against the source recording; this tool does not establish their cause from a single replay.

`comparison.json` always contains the eight case IDs, each with MATCH, DIVERGES or NOT_COMPARABLE, and source sequence references. A known comparable gap takes precedence over incomplete observations, whose reasons remain attached. Aborted cases, missing dispatch/journal provenance, unknown statuses, missing bindings and absent case requests cannot become MATCH. Publication IDs, received ACKs and cursors are mapped causally; user data and maps stay intact. StreamingPull remains a native bidirectional RPC and sends dependent followups only after the actual local causal receive.

IAM requests are never sent. Policy/journal checks report structural needs-review; successful structure is not IAM parity or propagation completion. REST layout compares recorded wire lengths against measured local lengths. Equal lengths alone do not establish byte-exact layout, headers or raw JSON whitespace. Synthetic inputs are labeled fixture evidence and never promote production compatibility. The current recorder packet remains independently frozen.

The optional integration test uses `FIREEMU_PUBSUB_COMPARE_BUILD_PIN` and `FIREEMU_PUBSUB_COMPARE_FIXTURE`. The latter names a synthetic eight-case fixture directory containing the three journals, relative frame blobs and `pins.json`; the test refuses an input labeled production. Without these explicit inputs, portable selftests skip the release-process integration test.
