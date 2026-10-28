"""The CI policy must reject unknown, expired and yanked findings."""
import contextlib
import copy
import datetime
import io
import json
import pathlib
import runpy
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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


class OsvPolicyTest(unittest.TestCase):
    def test_false_positive_is_exact_expiring_and_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'scripts').mkdir()
            (root / '.github/security').mkdir(parents=True)
            script = root / 'scripts/check-osv.py'
            shutil.copy(ROOT / 'scripts/check-osv.py', script)
            policy = {
                'expires': str(datetime.date.today() + datetime.timedelta(days=1)),
                'accepted': [{'id': 'TEST-1', 'package': 'test-buffer', 'version': '1.0.0',
                              'kind': 'osv_false_positive'}],
            }
            result = {'vulns': [{'id': 'TEST-1'}]}

            def check(rules=policy, response=result, version='1.0.0'):
                (root / 'Cargo.lock').write_text(
                    f'[[package]]\nname="test-buffer"\nversion="{version}"\nsource="registry+test"\n')
                (root / '.github/security/advisory-policy.json').write_text(json.dumps(rules))
                output = io.StringIO()
                body = io.BytesIO(json.dumps({'results': [response]}).encode())
                with patch('urllib.request.urlopen', return_value=body), contextlib.redirect_stdout(output):
                    runpy.run_path(str(script), run_name='__main__')
                return output.getvalue()

            self.assertIn('Visible tracked OSV false positive', check())
            for kwargs in [
                {'version': '1.1.0'},
                {'rules': dict(policy, expires='2000-01-01')},
                {'response': {'vulns': result['vulns'] + [{'id': 'NEW-1'}]}},
                {'response': {'next_page_token': 'more'}},
            ]:
                with self.subTest(kwargs=kwargs), self.assertRaises(SystemExit):
                    check(**kwargs)


if __name__ == '__main__':
    unittest.main()
