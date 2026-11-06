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
