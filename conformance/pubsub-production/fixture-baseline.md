# Read-only fixture baseline collector

`fixture-baseline.mjs` captures exactly three resource calls: project identity GET, the read-only Cloud Resource Manager v1 `getIamPolicy` POST with `requestedPolicyVersion:3`, and IAM v1 GET of the explicitly derived Pub/Sub service account. It never generates a service identity, changes IAM, enables an API or deploys a fixture. There is no executable entry point or credential discovery. Production execution remains coordinator-only and requires a separately reviewed packet, exact owner authority and a future guarded runner.

The caller supplies credentials, a live admission guard and a durable receipt sink. Both callbacks receive `{signal}` and must honor cancellation. A reservation consumes its slot before awaiting persistence because a lost acknowledgement may conceal a durable write. Headers are persisted before bounded raw body bytes. Recorded HTTP failures are capture evidence; a captured result does not establish baseline usability or compatibility.

`baseline-authority.mjs` is a separate fixed read-only authority checker. Its exact subject/envelope, three-call scope, credential/time bounds, closed version pins and unique E/V/grant parsing cannot admit an owned-resource writing envelope. It reuses the revocation scanner, whose universal global stops are independent of old-version references or delegation wording. This checker is not a production executor; a future runner must bind its actual request plan and current private ledger to these predicates before credentials and every send.

The collector checks elapsed time after asynchronous work and before declaring capture, bounds all callback, transport and body waits by its overall ten-minute abort, bounds each resource transport by at most thirty seconds, and aborts the owned request on exit. An unlocked response body is cancelled with a one-second cleanup cap. An interrupted operation that has not demonstrably settled sets `terminationRequired:true` and stops the collector. The runner must treat this flag as a required process-termination condition, never as cleanup success. It must prohibit resume, retry and additional sends, terminate and reap the collector process and its relevant descendants, and verify they have exited before releasing the run's lock. Admission, persistence, transport and response operations must execute in that owned process; callbacks delegated to a surviving parent do not meet this contract. The future runner must enforce a hard overall process deadline independently, including during a blocked event loop, and preserve uncertain reservations and receipts on failure.

Source-only tests use injected responses and callbacks without a server or credentials:

```sh
node --test conformance/src/pubsub-fixture-baseline.test.mjs
```
