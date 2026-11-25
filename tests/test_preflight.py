import unittest
from unittest.mock import patch
from scripts import preflight


class ProbeTests(unittest.TestCase):
    def test_missing_command_is_reported(self):
        result = preflight.probe(['/definitely/missing/soc-command'])
        self.assertFalse(result['ok'])
        self.assertTrue(result['output'])

    def test_failed_command_does_not_appear_successful(self):
        result = preflight.probe(['sh', '-c', 'exit 7'])
        self.assertFalse(result['ok'])

    def test_successful_command(self):
        result = preflight.probe(['printf', 'ready'])
        self.assertEqual(result, {'ok': True, 'output': 'ready'})

    @patch('scripts.preflight.subprocess.run', side_effect=TimeoutError('timeout'))
    def test_os_error_is_reported(self, _run):
        self.assertFalse(preflight.probe(['example'])['ok'])


if __name__ == '__main__':
    unittest.main()
