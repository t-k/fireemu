# Waiting for runnable work

`POST /v1/sessions/default:awaitIdle` accepts `{"scope":"runnable","timeoutSeconds":20}`. The default scope, `all`, still waits for every outstanding task. The opt-in `runnable` scope excludes future task schedules and future retry backoff. It continues waiting for background events, active HTTP requests, due tasks blocked by rate or concurrency limits, and due retries.

The response identifies the scope and includes bounded task diagnostics. `future` counts future schedules and retry backoff; `excluded` counts the work left behind by the selected scope (zero for `all`); `runnable` counts work that still prevents scoped idle. Neither a successful scoped wait nor an empty ready queue means all tasks succeeded. Terminal failure totals and the normal Functions status remain available. Diagnostics omit task payloads, headers, URLs, and task names.

`Run now` releases the schedule-time gate only. It does not bypass rate limits, concurrency limits, or retry backoff. Virtual task rate limits refill using the Tasks clock, independently of application timers and Date. Advance that axis until the reported wait can make progress; a fixed one-second advance is not sufficient for every fractional rate or queue backlog. Waiting never advances clocks or dispatches future work early.

Retry and rate deadlines use elapsed time; schedule deadlines use the task clock's epoch. Clock rollback therefore does not rewind elapsed retry backoff. A task at its deadline is due and prevents runnable idle, even before its coroutine wakes up. Clock changes notify waiting callers, including a backward move that turns due work into future-only work. Reset supersedes old task generations so a late phase update cannot change new work.
