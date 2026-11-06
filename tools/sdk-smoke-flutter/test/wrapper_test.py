import importlib.machinery
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader('bounded_xcrun', str(Path(__file__).resolve().parents[1] / 'scripts/xcrun'))
spec = importlib.util.spec_from_loader(loader.name, loader)
wrapper = importlib.util.module_from_spec(spec)
loader.exec_module(wrapper)


class WrapperTest(unittest.TestCase):
    def test_build_injects_two_jobs_and_preserves_each_argument(self):
        args = ['xcodebuild', '-workspace', 'name with spaces', 'SETTING=$literal']
        with patch.object(wrapper.os, 'execv') as execute:
            wrapper.main(args)
        execute.assert_called_once_with('/usr/bin/xcrun', ['xcrun', 'xcodebuild', '-jobs', '2', *args[1:]])

    def test_other_commands_delegate_unchanged(self):
        args = ['--find', 'swift']
        with patch.object(wrapper.os, 'execv') as execute:
            wrapper.main(args)
        execute.assert_called_once_with('/usr/bin/xcrun', ['xcrun', *args])


if __name__ == '__main__':
    unittest.main()
