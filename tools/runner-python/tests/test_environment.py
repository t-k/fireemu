"""The secret environment gate: which invocation sees which local secret, and which may run together.

The model is docs.local/runs/python-functions-slice2b/EnvGate.tla (checked with TLC): one FIFO queue; a plain
invocation (one that declares no secret with a local value) runs with every local secret hidden and alongside other
plain ones; an invocation that declares a secret runs alone, with only its own secrets present.
"""

import os
import random
import threading
import time

import pytest

from fireemu_runner.environment import EnvironmentGate, load_local_secrets

SECRETS = {"API_KEY": "key-value", "TOKEN": "token-value"}


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in (*SECRETS, "LOCAL_ONLY"):
        monkeypatch.delenv(name, raising=False)


def visible():
    return {name: os.environ[name] for name in SECRETS if name in os.environ}


# --- loading ---------------------------------------------------------------------------------------


def test_the_local_secrets_are_read_and_removed_from_the_environment():
    environ = {"FIREEMU_LOCAL_SECRETS_JSON": '{"A": "1", "B": "2"}', "OTHER": "x"}
    assert load_local_secrets(environ) == {"A": "1", "B": "2"}
    assert environ == {"OTHER": "x"}


@pytest.mark.parametrize("text", [None, "", "{}"])
def test_no_secrets_is_an_empty_map_and_the_variable_is_still_removed(text):
    environ = {} if text is None else {"FIREEMU_LOCAL_SECRETS_JSON": text}
    assert load_local_secrets(environ) == {}
    assert "FIREEMU_LOCAL_SECRETS_JSON" not in environ


def test_a_member_that_is_not_a_string_is_dropped():
    assert load_local_secrets({"FIREEMU_LOCAL_SECRETS_JSON": '{"A": "1", "B": 2, "C": null, "D": ["x"]}'}) == {"A": "1"}


@pytest.mark.parametrize("text", ["not json", "[1]", '"text"', "3", "null"])
def test_secrets_that_are_not_a_json_object_stop_the_runner(text):
    environ = {"FIREEMU_LOCAL_SECRETS_JSON": text}
    with pytest.raises(ValueError, match="local secrets"):
        load_local_secrets(environ)
    assert "FIREEMU_LOCAL_SECRETS_JSON" not in environ


# --- what an invocation sees -----------------------------------------------------------------------


def test_a_gate_without_secrets_does_nothing():
    gate = EnvironmentGate({})
    os.environ["LOCAL_ONLY"] = "kept"
    with gate.hold(["API_KEY"]):
        assert os.environ["LOCAL_ONLY"] == "kept" and "API_KEY" not in os.environ


def test_a_plain_invocation_sees_no_local_secret_and_the_environment_comes_back():
    gate = EnvironmentGate(SECRETS)
    os.environ["API_KEY"] = "from the process"
    with gate.hold([]):
        assert visible() == {}
    assert os.environ["API_KEY"] == "from the process" and "TOKEN" not in os.environ


def test_an_invocation_sees_exactly_the_local_secrets_it_declares():
    gate = EnvironmentGate(SECRETS)
    with gate.hold(["API_KEY"]):
        assert visible() == {"API_KEY": "key-value"}
    assert visible() == {}
    with gate.hold(["TOKEN", "API_KEY"]):
        assert visible() == SECRETS
    assert visible() == {}


def test_a_declared_secret_with_no_local_value_is_not_invented_and_the_invocation_stays_plain():
    gate = EnvironmentGate(SECRETS)
    with gate.hold(["NOT_LOCAL"]):
        assert visible() == {} and "NOT_LOCAL" not in os.environ
    with gate.hold(["NOT_LOCAL", "TOKEN"]):
        assert visible() == {"TOKEN": "token-value"}


def test_the_environment_is_restored_when_the_body_raises():
    gate = EnvironmentGate(SECRETS)
    os.environ["TOKEN"] = "before"
    with pytest.raises(RuntimeError):
        with gate.hold(["API_KEY"]):
            raise RuntimeError("boom")
    assert os.environ["TOKEN"] == "before" and "API_KEY" not in os.environ
    with gate.hold(["API_KEY"]):  # and the gate is free again
        assert visible() == {"API_KEY": "key-value"}


# --- who may run together --------------------------------------------------------------------------


class Probe:
    """Runs `hold` on a thread, records when it entered and left, and what it saw inside."""

    def __init__(self, gate, declared, label, log):
        self.gate, self.declared, self.label, self.log = gate, declared, label, log
        self.inside = threading.Event()
        self.release = threading.Event()
        self.saw = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        with self.gate.hold(self.declared):
            self.saw = visible()
            self.log.append(("in", self.label))
            self.inside.set()
            self.release.wait(10)
            self.log.append(("out", self.label))

    def start(self):
        self.thread.start()
        return self

    def finish(self):
        self.release.set()
        self.thread.join(10)
        assert not self.thread.is_alive()


def settle():
    time.sleep(0.15)


def test_plain_invocations_overlap_and_the_secrets_stay_hidden_until_the_last_one_leaves():
    gate = EnvironmentGate(SECRETS)
    os.environ["API_KEY"] = "process"
    log = []
    first = Probe(gate, [], "a", log).start()
    assert first.inside.wait(5)
    second = Probe(gate, [], "b", log).start()
    assert second.inside.wait(5), "a second plain invocation must not wait for the first"
    first.finish()
    assert "API_KEY" not in os.environ, "still hidden while the other plain invocation runs"
    second.finish()
    assert os.environ["API_KEY"] == "process"
    assert first.saw == {} and second.saw == {}


def test_an_invocation_with_a_secret_waits_for_running_plain_work_and_runs_alone():
    gate = EnvironmentGate(SECRETS)
    log = []
    plain = Probe(gate, [], "plain", log).start()
    assert plain.inside.wait(5)
    secret = Probe(gate, ["API_KEY"], "secret", log).start()
    settle()
    assert not secret.inside.is_set(), "the secret invocation must wait for the plain one"
    plain.finish()
    assert secret.inside.wait(5)
    assert secret.saw == {"API_KEY": "key-value"}
    secret.finish()
    assert log == [("in", "plain"), ("out", "plain"), ("in", "secret"), ("out", "secret")]


def test_plain_work_that_arrives_behind_a_waiting_secret_invocation_waits_its_turn():
    gate = EnvironmentGate(SECRETS)
    log = []
    first = Probe(gate, [], "first", log).start()
    assert first.inside.wait(5)
    secret = Probe(gate, ["API_KEY"], "secret", log).start()
    settle()
    late = Probe(gate, [], "late", log).start()
    settle()
    assert not late.inside.is_set(), "a later plain invocation must not overtake the queued secret one"
    first.finish()
    assert secret.inside.wait(5)
    settle()
    assert not late.inside.is_set(), "and not run beside it"
    secret.finish()
    assert late.inside.wait(5)
    late.finish()
    assert [entry for entry in log if entry[0] == "in"] == [("in", "first"), ("in", "secret"), ("in", "late")]
    assert late.saw == {}


def test_two_invocations_with_secrets_never_overlap_and_each_sees_only_its_own():
    gate = EnvironmentGate(SECRETS)
    log = []
    one = Probe(gate, ["API_KEY"], "one", log).start()
    assert one.inside.wait(5)
    two = Probe(gate, ["TOKEN"], "two", log).start()
    settle()
    assert not two.inside.is_set()
    one.finish()
    assert two.inside.wait(5)
    assert (one.saw, two.saw) == ({"API_KEY": "key-value"}, {"TOKEN": "token-value"})
    two.finish()


def test_a_random_mix_never_breaks_the_isolation_rules():
    rng = random.Random(20261104)
    for _ in range(25):
        gate = EnvironmentGate(SECRETS)
        lock = threading.Lock()
        running = []  # (kind) of each invocation inside
        failures = []

        def work(declared, kind):
            with gate.hold(declared):
                with lock:
                    running.append(kind)
                    snapshot = list(running)
                seen = visible()
                if kind == "plain" and seen:
                    failures.append(("plain saw a secret", seen))
                if kind != "plain":
                    if len(snapshot) != 1:
                        failures.append(("a secret invocation ran beside another", snapshot))
                    if seen != {kind_secret[kind]: SECRETS[kind_secret[kind]]}:
                        failures.append(("wrong secrets", kind, seen))
                time.sleep(rng.random() * 0.004)
                with lock:
                    running.remove(kind)

        kind_secret = {"api": "API_KEY", "token": "TOKEN"}
        threads = []
        for _ in range(14):
            kind = rng.choice(["plain", "plain", "api", "token"])
            declared = [] if kind == "plain" else [kind_secret[kind]]
            threads.append(threading.Thread(target=work, args=(declared, kind), daemon=True))
        for thread in threads:
            thread.start()
            time.sleep(rng.random() * 0.002)
        for thread in threads:
            thread.join(20)
            assert not thread.is_alive()
        assert failures == []
        assert visible() == {}
