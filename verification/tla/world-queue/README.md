# World operation queue model

`WorldQueue.tla` models the admission rules of the test-world operation queue in `npm/fireemu/testing-queue.mjs`. Operations are admitted in call order and have one of three kinds:

- `M` (ordered): clock helpers and ordinary control calls. They run one at a time, in order.
- `W` (waiting): `awaitIdle`. It starts after every earlier ordered operation and never delays a later ordered operation. A wait with `needs = TRUE` only completes once a later ordered operation has completed (an `awaitIdle` that needs a clock move).
- `E` (exclusive): `reset` and `dispose`. It starts after every earlier operation and delays every later one. Admitting it cancels the unfinished waits admitted before it.

## Configurations

| Config | `Mode` | Expected TLC result |
| --- | --- | --- |
| `lanes.cfg` | `lanes`, the shipped rules | no error: safety invariants hold and every operation completes |
| `lanes-nocancel.cfg` | `lanes-nocancel`, the rules without cancellation | no error, but an exclusive operation waits for a pending wait |
| `serial.cfg` | `serial`, the old single FIFO queue | `Deadlock reached`: a wait that needs a later clock move blocks it |

`N = 4` operations are checked in every kind and order combination.

## Running

TLC needs Java 17 or newer and `tla2tools.jar` from the TLA+ tools release.

```sh
cd verification/tla/world-queue
java -jar tla2tools.jar -config lanes.cfg WorldQueue.tla
java -jar tla2tools.jar -config lanes-nocancel.cfg WorldQueue.tla
java -jar tla2tools.jar -config serial.cfg WorldQueue.tla   # expected to report a deadlock
```

The queue is checked in code by `npm/scripts/testing-queue.test.mjs`, which compares 400 seeded random interleavings with the same predecessor rules.
