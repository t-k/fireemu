// Observe ServerResponse *before* a callback is enqueued or entered. Registering
// close/finish only after awaiting user code misses already-delivered events.
// Response termination is not cancellation of the running user Promise, nor an
// acknowledgement that a remote client received/applied the response.
export function trackHttpResponse(response) {
  let terminal = false;
  let disposed = false;
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });

  function removeListeners() {
    response.removeListener('finish', settle);
    response.removeListener('close', settle);
    response.removeListener('error', settle);
  }
  function settle() {
    if (terminal) return;
    terminal = true;
    removeListeners();
    resolveDone();
  }
  function refresh() {
    if (response.destroyed || response.writableFinished) settle();
  }
  response.once('finish', settle);
  response.once('close', settle);
  response.once('error', settle);
  refresh();

  return Object.freeze({
    canStart() {
      refresh();
      return !disposed && !terminal && !response.writableEnded;
    },
    wait() {
      refresh();
      return done;
    },
    dispose() {
      disposed = true;
      settle();
    },
  });
}
