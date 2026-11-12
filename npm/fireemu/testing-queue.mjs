// Admission rules for a test world's operations. Operations are admitted in call order.
//   ordered    clock helpers and ordinary control calls: run one at a time, in order
//   waiting    calls that block until the daemon is idle (awaitIdle): start after every earlier
//              ordered operation, and never delay a later ordered operation, so a wait that needs
//              a clock move cannot starve it
//   exclusive  reset and dispose: start after every earlier operation and delay every later one.
//              Admitting one cancels the waiting operations admitted before it: the generation
//              they wait on is being retired, so a wait that can never be satisfied must not
//              hold the exclusive operation back.
const settle = promise => promise.then(() => {}, () => {});

/**
 * How long one awaitIdle request may take: the daemon's own wait budget (`timeoutSeconds`, 30 s when
 * omitted, at most 600 s) plus five seconds. The daemon answers when the budget ends, so a longer
 * limit would only matter for a daemon that stopped answering.
 */
export function waitRequestTimeoutMs(body) {
  const seconds = typeof body?.timeoutSeconds === 'number' && Number.isFinite(body.timeoutSeconds) ? Math.min(Math.max(body.timeoutSeconds, 0), 600) : 30;
  return Math.ceil(seconds * 1000) + 5000;
}

export function createWorldQueue() {
  let barrier = Promise.resolve();
  let ordered = Promise.resolve();
  const inflight = new Set();
  const cancellable = new Set();
  const admit = (after, operation) => {
    const job = Promise.all(after).then(operation);
    const done = settle(job);
    inflight.add(done);
    done.then(() => inflight.delete(done));
    return { job, done };
  };
  return Object.freeze({
    ordered(operation) {
      const { job, done } = admit([barrier, ordered], () => operation());
      ordered = done;
      return job;
    },
    waiting(operation) {
      const controller = new AbortController();
      let cancel;
      let skip = false;
      // A cancelled wait aborts its signal and rejects at once; if not started, it never starts.
      const cancelled = new Promise((_, reject) => { cancel = reason => { skip = true; controller.abort(reason); reject(reason); }; });
      cancellable.add(cancel);
      const job = Promise.race([
        Promise.all([barrier, ordered]).then(() => (skip ? cancelled : operation(controller.signal))),
        cancelled,
      ]);
      const done = settle(job);
      inflight.add(done);
      done.then(() => { inflight.delete(done); cancellable.delete(cancel); });
      return job;
    },
    exclusive(operation, reason) {
      for (const cancel of cancellable) cancel(reason);
      const { job, done } = admit([barrier, ...inflight], () => operation());
      barrier = done;
      return job;
    },
    /** Settles when every exclusive and ordered operation admitted so far is done. */
    settled() {
      return Promise.all([barrier, ordered]).then(() => {});
    },
  });
}
