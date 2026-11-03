"""Local secrets: which invocation sees which secret in the one process environment.

Production gives every function its own instance, so a secret a function declares is in that instance's environment
only. One runner serves a whole codebase here and has one `os.environ`, so the runner takes the daemon's local
secrets (`FIREEMU_LOCAL_SECRETS_JSON`, from `.secret.local`) out of the environment at start and puts them back for
the duration of an invocation, as the Node runner's `withFunctionEnvironment` does:

- a plain invocation (one that declares no secret with a local value) runs with every local secret hidden, beside
  other plain invocations;
- an invocation that declares a secret with a local value runs alone, with only the secrets it declares;
- invocations start in arrival order, so a plain one that arrives behind a queued secret invocation waits.

The model is `EnvGate.tla` (checked with TLC): an exclusive invocation never overlaps any other, a plain one never
sees a secret, and nothing is exposed while nothing runs.
"""

import collections
import contextlib
import json
import os
import threading

SECRETS_VARIABLE = "FIREEMU_LOCAL_SECRETS_JSON"


def load_local_secrets(environ) -> dict:
    """Takes the daemon's local secrets out of `environ`: name to value, string values only."""
    text = environ.pop(SECRETS_VARIABLE, None)
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except ValueError:
        raise ValueError("the local secrets are not valid JSON") from None
    if not isinstance(parsed, dict):
        raise ValueError("the local secrets are not a JSON object")
    return {name: value for name, value in parsed.items() if isinstance(value, str)}


class EnvironmentGate:
    """One queue of invocations and the environment each may see."""

    def __init__(self, secrets: dict):
        self._secrets = dict(secrets)
        self._condition = threading.Condition()
        self._queue = collections.deque()  # tickets waiting, oldest first
        self._running = 0
        self._exclusive_running = False
        self._saved = {}

    def _hide(self) -> None:
        for name in self._secrets:
            self._saved[name] = os.environ.pop(name, None)

    def _restore(self) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self._saved = {}

    def _may_start(self, ticket) -> bool:
        if self._queue[0] is not ticket:
            return False
        return self._running == 0 if ticket.exclusive else not self._exclusive_running

    def _enter(self, ticket) -> None:
        with self._condition:
            self._queue.append(ticket)
            self._condition.wait_for(lambda: self._may_start(ticket))
            self._queue.popleft()
            if self._running == 0:
                self._hide()
            self._running += 1
            if ticket.exclusive:
                self._exclusive_running = True
                for name in ticket.names:
                    os.environ[name] = self._secrets[name]
            # The next in line may be able to start beside this one.
            self._condition.notify_all()

    def _leave(self, ticket) -> None:
        with self._condition:
            if ticket.exclusive:
                self._exclusive_running = False
                for name in ticket.names:
                    os.environ.pop(name, None)
            self._running -= 1
            if self._running == 0:
                self._restore()
            self._condition.notify_all()

    @contextlib.contextmanager
    def hold(self, declared):
        """Runs the body with the environment `declared` (the function's secret names) is entitled to."""
        if not self._secrets:
            yield
            return
        names = [name for name in dict.fromkeys(declared or ()) if name in self._secrets]
        ticket = _Ticket(names)
        self._enter(ticket)
        try:
            yield
        finally:
            self._leave(ticket)


class _Ticket:
    def __init__(self, names):
        self.names = names
        self.exclusive = bool(names)
