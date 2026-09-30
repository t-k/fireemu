"""Offline process ownership tests; no ports, credentials or production calls."""
import os
from pathlib import Path
import shutil
import sys
import time
import unittest
from unittest.mock import Mock, patch


class ProcessTests(unittest.TestCase):
    def test_platform_birth_identity_is_stable_for_owned_parent(self):
        from baseline_process import birth_identity
        self.assertEqual(birth_identity(os.getpid()), birth_identity(os.getpid()))
        self.assertTrue(birth_identity(os.getpid()))

    def test_blocked_node_loop_is_independently_stopped_and_reaped(self):
        from baseline_process import ProcessStopped, run_owned
        node = shutil.which("node")
        self.assertIsNotNone(node)
        started = time.monotonic()
        with self.assertRaises(ProcessStopped) as stopped:
            run_owned([node, "-e", "process.stdin.once('data',()=>{process.stdout.write('READY');while(true){}})"],
                      input="synthetic", timeout=2, cleanup_seconds=1, env=dict(os.environ))
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)
        self.assertLess(time.monotonic() - started, 3)

    def test_normal_exit_still_requires_owned_session_to_be_empty(self):
        from baseline_process import run_owned
        result = run_owned([sys.executable, "-c", "import sys; print(sys.stdin.read())"],
                           input="synthetic", timeout=3, cleanup_seconds=0.5, env=dict(os.environ))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "synthetic")
        self.assertTrue(result.processQuiescent)
        self.assertTrue(result.directChildReaped)

    def test_unexpected_descendant_is_cleaned_but_never_admitted_as_normal_success(self):
        from baseline_process import ProcessStopped, run_owned
        script = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); print('spawned',flush=True)"
        with self.assertRaises(ProcessStopped) as stopped:
            run_owned([sys.executable, "-c", script], timeout=1.5, cleanup_seconds=0.6, env=dict(os.environ))
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        # A killed orphan can remain kernel-visible until the OS reaps it. The
        # adversarial fixture must be rejected whether absence is proven or not.
        self.assertIsInstance(stopped.exception.quiescent, bool)

    def test_changed_birth_or_command_is_never_signalled(self):
        from baseline_process import Identity, signal_verified
        original = Identity(123, 1, 123, (1, 2), "node", "node owned.mjs")
        for changed in [Identity(123, 1, 123, (2, 2), "node", "node owned.mjs"),
                        Identity(123, 1, 123, (1, 2), "node", "node foreign.mjs")]:
            calls = []
            self.assertFalse(signal_verified(original, 15, inspect=lambda _: changed,
                                             signal_pid=lambda *args: calls.append(args)))
            self.assertEqual(calls, [])

    def test_unreadable_live_session_member_cannot_be_reported_absent(self):
        import baseline_process as m
        with patch.object(m.subprocess, "run", return_value=Mock(stdout="123\n")), \
             patch.object(m.os, "getsid", return_value=123), \
             patch.object(m, "inspect", side_effect=ProcessLookupError("metadata unavailable")):
            with self.assertRaises(ProcessLookupError):
                m.session_members(123, time.monotonic() + 1)

    def test_confirmed_linux_disappearance_is_normalized_but_live_hidden_proc_is_not(self):
        import baseline_process as m
        with patch.object(m.sys, "platform", "linux"), \
             patch.object(m.Path, "read_text", side_effect=FileNotFoundError):
            with patch.object(m.os, "getsid", side_effect=ProcessLookupError):
                with self.assertRaises(m.ProcessGone):
                    m.birth_identity(123)
            with patch.object(m.os, "getsid", return_value=123):
                with self.assertRaises(m.InspectionUnavailable):
                    m.birth_identity(123)


    def test_interrupted_communication_preserves_cancellation_after_owned_cleanup(self):
        import baseline_process as m
        original = m.subprocess.Popen
        children = []
        def start(*args, **kwargs):
            child = original(*args, **kwargs)
            if args[0][0] != sys.executable:
                return child
            children.append(child)
            original_communicate = child.communicate
            def interrupted(*call_args, **call_kwargs):
                child.communicate = original_communicate
                raise KeyboardInterrupt()
            child.communicate = interrupted
            return child
        with patch.object(m.subprocess, "Popen", side_effect=start):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned([sys.executable, "-c", "import time;time.sleep(30)"],
                            timeout=3, cleanup_seconds=1, env=dict(os.environ))
        self.assertEqual(stopped.exception.reason, "cancelled")
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)
        self.assertIsNotNone(children[0].returncode)

    def test_disappearing_member_does_not_hide_another_verified_live_member(self):
        import baseline_process as m
        live = m.Identity(124, 123, 123, (1, 2), "node", "node owned.mjs")
        with patch.object(m.subprocess, "run", return_value=Mock(stdout="123\n124\n")), \
             patch.object(m.os, "getsid", return_value=123), \
             patch.object(m, "inspect", side_effect=[m.ProcessGone(), live]):
            self.assertEqual(m.session_members(123, time.monotonic() + 1), [live])

    def test_unreadable_member_preserves_other_verified_members_for_cleanup(self):
        import baseline_process as m
        live = m.Identity(124, 123, 123, (1, 2), "node", "node owned.mjs")
        with patch.object(m.subprocess, "run", return_value=Mock(stdout="123\n124\n")), \
             patch.object(m.os, "getsid", return_value=123), \
             patch.object(m, "inspect", side_effect=[m.InspectionUnavailable("unreadable"), live]):
            with self.assertRaises(m.InspectionUnavailable) as unavailable:
                m.session_members(123, time.monotonic() + 1)
            self.assertEqual(unavailable.exception.members, [live])

    def test_term_resistant_collector_is_killed_by_verified_pid_and_reaped(self):
        import baseline_process as m
        signals = []
        original = m.signal_verified
        def recorded(identity, number, **kwargs):
            sent = original(identity, number, **kwargs)
            signals.append((number, sent))
            return sent
        with patch.object(m, "signal_verified", side_effect=recorded):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned([shutil.which("node"), "-e", "process.on('SIGTERM',()=>{});process.stdin.once('data',()=>{while(true){}})"],
                            input="synthetic", timeout=6, cleanup_seconds=5, env=dict(os.environ))
        self.assertIn((15, True), signals)
        self.assertIn((9, True), signals)
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)

    def test_successful_exit_with_detached_pipes_still_cleans_same_session_child(self):
        import baseline_process as m
        script = "import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print('done')"
        with self.assertRaises(m.ProcessStopped) as stopped:
            m.run_owned([sys.executable, "-c", script], timeout=3, cleanup_seconds=1, env=dict(os.environ))
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        self.assertTrue(stopped.exception.quiescent)

    def test_interruption_during_signal_cleanup_still_stops_and_reaps_owned_child(self):
        import baseline_process as m
        start_original, signal_original = m.subprocess.Popen, m.signal_verified
        children, interrupted = [], [False]
        def start(*args, **kwargs):
            child = start_original(*args, **kwargs)
            if args[0][0] == sys.executable:
                children.append(child)
            return child
        def stop(identity, number, **kwargs):
            if not interrupted[0]:
                interrupted[0] = True
                raise KeyboardInterrupt()
            return signal_original(identity, number, **kwargs)
        try:
            with patch.object(m.subprocess, "Popen", side_effect=start), \
                 patch.object(m, "signal_verified", side_effect=stop):
                with self.assertRaises(m.ProcessStopped) as stopped:
                    m.run_owned([sys.executable, "-c", "import time;time.sleep(30)"],
                                timeout=2, cleanup_seconds=1, env=dict(os.environ))
            self.assertEqual(stopped.exception.reason, "cancelled")
            self.assertTrue(stopped.exception.quiescent)
            self.assertTrue(stopped.exception.reaped)
        finally:
            # A RED cleanup test must not leave its fake process behind.
            for child in children:
                if child.poll() is None:
                    identity = m.inspect(child.pid, time.monotonic() + 1)
                    signal_original(identity, 9, inspect=lambda pid: m.inspect(pid, time.monotonic() + 1))
                    child.wait(timeout=1)

    def test_descendant_first_seen_after_term_always_invalidates_admission(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        descendant = m.Identity(124, 123, 123, (3, 4), "node", "node child.mjs")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.communicate.return_value = ("", "")
        child.wait.return_value = 0
        inspected = [False]
        def inspect(pid, _deadline):
            if pid == 123 and not inspected[0]:
                inspected[0] = True
                return owned
            raise m.ProcessGone()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m, "inspect", side_effect=inspect), \
             patch.object(m, "session_members", side_effect=[[owned], [], [descendant], [], []]), \
             patch.object(m, "signal_verified", return_value=True):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(stopped.exception.unexpected_descendant)

    def test_observed_descendant_leaving_session_is_not_verified_absent(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        descendant = m.Identity(124, 123, 123, (3, 4), "node", "node child.mjs")
        escaped = m.Identity(124, 1, 999, (3, 4), "node", "node child.mjs")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.wait.return_value = 0
        initialized = [False]
        def inspect(pid, _deadline):
            if pid == 123 and not initialized[0]:
                initialized[0] = True
                return owned
            if pid == 124:
                return escaped
            raise m.ProcessGone()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m, "inspect", side_effect=inspect), \
             patch.object(m, "session_members", side_effect=[[owned, descendant], [descendant], [], [], []]), \
             patch.object(m, "signal_verified", return_value=True):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertFalse(stopped.exception.quiescent)

    def test_self_reaping_descendant_has_positive_kernel_absence_evidence(self):
        import baseline_process as m
        script = """import signal, subprocess, sys, time
child = None
def stop(*_):
    if child is not None:
        child.wait(timeout=2)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(30)'])
print('spawned', flush=True)
while True: time.sleep(.1)
"""
        with self.assertRaises(m.ProcessStopped) as stopped:
            m.run_owned([sys.executable, "-c", script], timeout=4, cleanup_seconds=2, env=dict(os.environ))
        self.assertTrue(stopped.exception.unexpected_descendant)
        self.assertTrue(stopped.exception.reaped)
        self.assertTrue(stopped.exception.quiescent)

    def test_one_shot_cancellation_in_every_shutdown_phase_is_retried(self):
        import baseline_process as m
        phases = ("first-census", "refresh-census", "final-census", "term", "kill", "grace", "wait", "close")
        for phase in phases:
            for cancellation in (KeyboardInterrupt, SystemExit):
                with self.subTest(phase=phase, cancellation=cancellation.__name__):
                    owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
                    child = Mock(pid=123, returncode=0, stdin=None)
                    child.communicate.return_value = ("", "")
                    child.wait.return_value = 0
                    counters = {"census": 0, "inspect": 0}
                    interrupted = [False]
                    def interrupt(at):
                        if phase == at and not interrupted[0]:
                            interrupted[0] = True
                            raise cancellation()
                    def inspect(pid, deadline):
                        counters["inspect"] += 1
                        if counters["inspect"] == 1:
                            return owned
                        raise m.ProcessGone()
                    def census(sid, deadline):
                        counters["census"] += 1
                        at = {2: "first-census", 3: "refresh-census", 5: "final-census"}.get(counters["census"])
                        interrupt(at)
                        return []
                    def stop(identity, number, **kwargs):
                        interrupt("term" if number == 15 else "kill")
                        return True
                    def sleep(seconds):
                        interrupt("grace")
                    def wait(**kwargs):
                        interrupt("wait")
                        return 0
                    child.wait.side_effect = wait
                    child.stdout.close.side_effect = lambda: interrupt("close")
                    with patch.object(m.subprocess, "Popen", return_value=child), \
                         patch.object(m, "inspect", side_effect=inspect), \
                         patch.object(m, "session_members", side_effect=census), \
                         patch.object(m, "signal_verified", side_effect=stop), \
                         patch.object(m.time, "sleep", side_effect=sleep):
                        with self.assertRaises(m.ProcessStopped) as stopped:
                            m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
                    self.assertTrue(interrupted[0])
                    self.assertEqual(stopped.exception.reason, "cancelled")
                    self.assertTrue(stopped.exception.quiescent)
                    self.assertTrue(stopped.exception.reaped)
                    self.assertGreaterEqual(child.wait.call_count, 1)
                    self.assertTrue(child.stdout.close.called)
                    self.assertTrue(child.stderr.close.called)

    def test_repeated_cleanup_cancellation_exhausts_original_deadline(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        child = Mock(pid=123, returncode=0, stdin=None)
        child.communicate.return_value = ("", "")
        clock, calls = [0], [0]
        def now():
            clock[0] += .02
            return clock[0]
        def census(sid, deadline):
            calls[0] += 1
            if calls[0] == 1:
                return []
            raise KeyboardInterrupt()
        with patch.object(m.subprocess, "Popen", return_value=child), \
             patch.object(m.time, "monotonic", side_effect=now), \
             patch.object(m, "inspect", return_value=owned), \
             patch.object(m, "session_members", side_effect=census):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=1, cleanup_seconds=.5, env={})
        self.assertEqual(stopped.exception.reason, "cancelled")
        self.assertFalse(stopped.exception.quiescent)
        self.assertLess(calls[0], 60)
        self.assertLess(clock[0], 1.3)


    def test_real_operator_signal_between_cleanup_phases_is_deferred_and_handlers_restored(self):
        import baseline_process as m
        owned = m.Identity(123, os.getpid(), 123, (1, 2), "node", "node owned.mjs")
        for number in (m.signal.SIGINT, m.signal.SIGTERM):
            with self.subTest(signal=number):
                child = Mock(pid=123, returncode=0, stdin=None)
                child.communicate.return_value = ("", "")
                child.wait.return_value = 0
                count = [0]
                def inspect(pid, deadline):
                    count[0] += 1
                    if count[0] == 1:
                        return owned
                    raise namespace["ProcessGone"]()
                def interrupted_values():
                    # Outside cleanup_step's operation boundary, in terminate's loop.
                    os.kill(os.getpid(), number)
                    return []
                class Ledger(dict):
                    def values(self):
                        if not getattr(self, "interrupted", False):
                            self.interrupted = True
                            return interrupted_values()
                        return super().values()
                # Injection replaces only the observation dictionary via a small source snapshot.
                source = Path(m.__file__).read_text().replace("observed = {}", "observed = injected_ledger()")
                namespace = dict(m.__dict__, injected_ledger=Ledger)
                exec(compile(source, m.__file__, "exec"), namespace)
                previous = m.signal.getsignal(number)
                def throwing(*_):
                    raise KeyboardInterrupt()
                m.signal.signal(number, throwing)
                try:
                    with patch.object(m.subprocess, "Popen", return_value=child):
                        namespace["inspect"] = inspect
                        namespace["session_members"] = Mock(return_value=[])
                        namespace["signal_verified"] = Mock(return_value=True)
                        with self.assertRaises(namespace["ProcessStopped"]) as stopped:
                            namespace["run_owned"](["synthetic"], timeout=3, cleanup_seconds=1, env={})
                    self.assertEqual(stopped.exception.reason, "cancelled")
                    self.assertTrue(stopped.exception.reaped)
                    self.assertTrue(stopped.exception.quiescent)
                    self.assertIs(m.signal.getsignal(number), throwing)
                finally:
                    m.signal.signal(number, previous)

    def test_signal_received_during_handler_restoration_cannot_become_success(self):
        import baseline_process as m
        result = Mock(processQuiescent=True, directChildReaped=True)
        original = m.signal.signal
        previous = m.signal.getsignal(m.signal.SIGINT)
        sent = [False]
        def install(number, handler):
            if number == m.signal.SIGINT and handler is previous and not sent[0]:
                sent[0] = True
                os.kill(os.getpid(), number)
            return original(number, handler)
        with patch.object(m, "_run_owned", return_value=result), \
             patch.object(m.signal, "signal", side_effect=install):
            with self.assertRaises(m.ProcessStopped) as stopped:
                m.run_owned(["synthetic"], timeout=3, cleanup_seconds=1, env={})
        self.assertTrue(sent[0])
        self.assertEqual(stopped.exception.reason, "cancelled")
        self.assertTrue(stopped.exception.quiescent)
        self.assertTrue(stopped.exception.reaped)
        self.assertIs(m.signal.getsignal(m.signal.SIGINT), previous)


if __name__ == "__main__":
    unittest.main()
