"""The CI policy must reject unknown, expired and yanked findings."""
import copy
import datetime
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class AdvisoryPolicyTest(unittest.TestCase):
    def test_policy_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'scripts').mkdir()
            (root / '.github/security').mkdir(parents=True)
            shutil.copy(ROOT / 'scripts/check-advisories.py', root / 'scripts')
            accepted = {'id': 'TEST-1', 'package': 'test-macro', 'version': '1.0.0', 'kind': 'unmaintained'}
            policy = {'expires': str(datetime.date.today() + datetime.timedelta(days=1)), 'accepted': [accepted]}
            report = {'vulnerabilities': {'list': []}, 'warnings': {'unmaintained': [
                {'kind': 'unmaintained', 'advisory': {'id': 'TEST-1'}, 'package': {'name': 'test-macro', 'version': '1.0.0'}}
            ]}}

            def check(value, rules):
                (root / 'audit.json').write_text(json.dumps(value))
                (root / '.github/security/advisory-policy.json').write_text(json.dumps(rules))
                return subprocess.run(['python3', str(root / 'scripts/check-advisories.py'), str(root / 'audit.json')], capture_output=True).returncode

            self.assertEqual(check(report, policy), 0)
            expired = dict(policy, expires='2000-01-01')
            self.assertNotEqual(check(report, expired), 0)
            unknown = copy.deepcopy(report)
            unknown['vulnerabilities']['list'].append({'advisory': {'id': 'NEW-1'}, 'package': {'name': 'test-macro', 'version': '1.0.0'}})
            self.assertNotEqual(check(unknown, policy), 0)
            yanked = copy.deepcopy(report)
            yanked['warnings']['yanked'] = [{'advisory': None, 'package': {'name': 'test-macro', 'version': '1.0.0'}}]
            self.assertNotEqual(check(yanked, policy), 0)
            self.assertNotEqual(check({}, policy), 0)


if __name__ == '__main__':
    unittest.main()
