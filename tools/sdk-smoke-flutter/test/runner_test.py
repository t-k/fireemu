import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('smoke_runner', root / 'run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTest(unittest.TestCase):
    def test_inherited_credentials_are_not_forwarded(self):
        keys = ['GOOGLE_APPLICATION_CREDENTIALS', 'FIREBASE_TOKEN',
                'GOOGLE_OAUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'FIREBASE_CONFIG']
        with patch.dict(os.environ, {key: 'synthetic-do-not-forward' for key in keys}):
            child = runner.environment()
        self.assertTrue(all(key not in child for key in keys))

    def test_missing_required_case_is_blocked_and_fails(self):
        summary = runner.summarize([], ['first'])
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['cases'], [{'case': 'first', 'status': 'blocked', 'classification': 'prerequisite'}])

    def test_complete_results_pass(self):
        result = {'case': 'first', 'status': 'passed', 'classification': 'ok'}
        self.assertTrue(runner.summarize([result], ['first'])['passed'])

    def test_duplicates_and_unknown_cases_rejected(self):
        result = {'case': 'first', 'status': 'passed', 'classification': 'ok'}
        with self.assertRaises(ValueError):
            runner.summarize([result, result], ['first'])
        with self.assertRaises(ValueError):
            runner.summarize([result], ['other'])

    def test_extra_fields_and_raw_error_text_rejected(self):
        for result in [
            {'case': 'first', 'status': 'failed', 'classification': 'raw secret'},
            {'case': 'first', 'status': 'passed', 'classification': 'ok', 'raw': 'private'},
        ]:
            with self.assertRaises(ValueError):
                runner.summarize([result], ['first'])


if __name__ == '__main__':
    unittest.main()

class OwnershipTest(unittest.TestCase):
    def test_changed_identity_never_signals_group(self):
        process = type('Process', (), {'pid': 123})()
        with patch.object(runner, 'owner_identity', return_value='changed'), patch.object(runner.os, 'killpg') as kill:
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                runner.stop_owned_group(process, 'original')
            kill.assert_not_called()

    def test_empty_or_exited_owner_is_rejected(self):
        from unittest.mock import Mock
        process = Mock(pid=123)
        process.poll.return_value = None
        with patch.object(runner.os, 'getpgid', return_value=123), patch.object(runner.subprocess, 'check_output', return_value=''):
            with self.assertRaisesRegex(RuntimeError, 'Missing'):
                runner.owner_identity(process)
        process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'exited'):
            runner.owner_identity(process)

    def test_startup_eof_and_malformed_ready_never_release_work(self):
        from unittest.mock import Mock
        import tempfile
        for ready in [b'', b'WRONG\n', b'READY 999\n']:
            process = Mock(pid=123)
            process.wait.return_value = 0
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.select, 'select', return_value=([1], [], [])), patch.object(runner.os, 'read', return_value=ready), patch.object(runner.os, 'write') as write, patch.object(runner.os, 'killpg') as kill, patch.object(runner, 'owner_identity') as identity:
                    with self.assertRaisesRegex(RuntimeError, 'Malformed'):
                        runner.execute(['synthetic'], {}, '.', Path(directory)/'log', 1)
                    write.assert_not_called()
                    kill.assert_not_called()
                    identity.assert_not_called()

    def test_cancellation_before_ready_never_signals_or_sends_go(self):
        from unittest.mock import Mock
        import tempfile
        process = Mock(pid=123)
        process.wait.return_value = 0
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.select, 'select', side_effect=SystemExit(143)), patch.object(runner.os, 'write') as write, patch.object(runner.os, 'killpg') as kill:
                with self.assertRaises(SystemExit):
                    runner.execute(['synthetic'], {}, '.', Path(directory)/'log', 1)
                write.assert_not_called()
                kill.assert_not_called()

    def test_native_nonzero_status_is_preserved(self):
        import sys
        import tempfile
        import signal
        import subprocess
        identities = []
        original = runner.owner_identity
        def captured(process):
            identity = original(process)
            identities.append((process.pid, identity))
            return identity
        try:
            with tempfile.TemporaryDirectory() as directory, patch.object(runner, 'owner_identity', side_effect=captured):
                self.assertEqual(runner.execute([sys.executable, '-c', 'import sys; sys.exit(7)'], os.environ.copy(), '.', Path(directory)/'log', 5), 7)
        finally:
            if identities:
                pid, identity = identities[0]
                current = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=,comm=,args='], capture_output=True, text=True).stdout
                if current == identity and str(root/'scripts/process_owner.py') in current and os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGKILL)

    def test_cancelled_go_keeps_verified_owner_alive_until_group_cleanup(self):
        from unittest.mock import Mock
        import tempfile
        process = Mock(pid=123)
        observed = []
        def interrupted_write(fd, value):
            observed.append(fd)
            raise SystemExit(143)
        def cleanup(process, identity):
            try:
                os.fstat(observed[0])
            except OSError:
                self.fail("GO pipe closed before verified owner cleanup")
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.select, 'select', return_value=([1], [], [])), patch.object(runner.os, 'read', return_value=b'READY 123\n'), patch.object(runner.os, 'write', side_effect=interrupted_write), patch.object(runner, 'owner_identity', return_value='verified'), patch.object(runner, 'stop_owned_group', side_effect=cleanup):
                with self.assertRaises(SystemExit):
                    runner.execute(['synthetic'], {}, '.', Path(directory)/'log', 1)
