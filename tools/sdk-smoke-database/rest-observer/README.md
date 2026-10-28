# RTDB REST observation runner

This packet-bound runner is designed for reviewed, bounded observations against an isolated RTDB instance. A packet supplies the target, source digests, runtime pins, request limits and expected anchors; the packet and authorization remain external to this directory. An exclusive claim prevents repeating ADC acquisition. The provider passes the credential over a pipe to the launcher, and service requests are counted and recorded with durable response capture.

`adc-preflight.mjs` is an unchanged copy of `tools/sdk-smoke-database/adc-preflight.mjs`. The packet fixture in this directory uses synthetic identifiers and responses solely for offline tests. It does not authorize access to any project.

Run the offline tests with `node --test tools/sdk-smoke-database/rest-observer/*.test.mjs`.
