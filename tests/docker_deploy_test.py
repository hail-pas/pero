#!/usr/bin/env python3
"""Test private-config packaging without Docker, Rust, Zig, or storage access."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DockerDeployTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in ('scripts', 'services/user-center/config', 'local/deploy/pero/config/keys'):
            (self.root / directory).mkdir(parents=True)
        shutil.copytree(ROOT / 'deploy/pero', self.root / 'deploy/pero')
        for file in ('package-production-config.sh', 'sync-deploy-config.py'):
            shutil.copy2(ROOT / 'scripts' / file, self.root / 'scripts' / file)
        shutil.copy2(ROOT / '.gitignore', self.root / '.gitignore')
        shutil.copy2(ROOT / 'services/user-center/config/default.toml',
                     self.root / 'services/user-center/config/default.toml')
        self.config = self.root / 'local/deploy/pero/config'
        (self.config / 'production.toml').write_text(
            '[database]\nurl="postgres://fixture:dummy@127.0.0.1:5432/fixture"\n'
            'encrypt_key="fixture-encryption"\n[obsolete]\nremoved="old-field"\n')
        for file in ('bootstrap.toml', 'keys/private.pem', 'keys/public.pem'):
            (self.config / file).write_text('non-secret test fixture')
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.env = {**os.environ, 'PERO_PYTHON': sys.executable}
        self.archive = self.root / 'deploy/pero-config.tar.gz'

    def run_packager(self, *arguments):
        return subprocess.run(['bash', str(self.root / 'scripts/package-production-config.sh'), *arguments],
                              cwd=self.root, env=self.env, text=True, capture_output=True)

    def test_private_config_only_archive_and_permissions(self):
        result = self.run_packager()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.archive) as archive:
            self.assertTrue(all(name == 'config' or name.startswith('config/') for name in archive.getnames()))
            production = tomllib.loads(archive.extractfile('config/production.toml').read().decode())
            self.assertEqual(production['database']['encrypt_key'], 'fixture-encryption')
            self.assertIn('notification', production)
            self.assertNotIn('obsolete', production)
            self.assertEqual(archive.getmember('config').mode, 0o700)
            for name in ('production.toml', 'bootstrap.toml', 'keys/private.pem', 'keys/public.pem'):
                self.assertEqual(archive.getmember('config/' + name).mode, 0o600)
            self.assertEqual(archive.extractfile('config/keys/private.pem').read(), b'non-secret test fixture')
        checksum = Path(str(self.archive) + '.sha256').read_text().split()
        self.assertEqual(checksum, [hashlib.sha256(self.archive.read_bytes()).hexdigest(), self.archive.name])
        self.assertEqual(list((self.root / 'deploy').glob('.pero-config.*')), [])

    def test_invalid_config_preserves_previous_package(self):
        self.assertEqual(self.run_packager().returncode, 0)
        previous = self.archive.read_bytes()
        checksum = Path(str(self.archive) + '.sha256').read_bytes()
        (self.config / 'production.toml').write_text('not valid TOML!')
        self.assertNotEqual(self.run_packager().returncode, 0)
        self.assertEqual(self.archive.read_bytes(), previous)
        self.assertEqual(Path(str(self.archive) + '.sha256').read_bytes(), checksum)
        self.assertEqual(list((self.root / 'deploy').glob('.pero-config.*')), [])

    def test_missing_key_stops_before_packaging(self):
        (self.config / 'keys/private.pem').unlink()
        self.assertNotEqual(self.run_packager().returncode, 0)
        self.assertFalse(self.archive.exists())

    def test_git_allows_templates_and_ignores_secrets_and_outputs(self):
        for path in ('deploy/pero/Dockerfile', 'deploy/pero/Dockerfile.dockerignore',
                     'deploy/pero/production.toml.example', 'deploy/pero/initialize.py'):
            result = subprocess.run(['git', 'check-ignore', '-q', path], cwd=self.root)
            self.assertEqual(result.returncode, 1, path)
        for path in ('deploy/pero/config/production.toml', 'deploy/pero/prd/user-center',
                     'deploy/pero-config.tar.gz', 'deploy/pero-config.tar.gz.sha256',
                     'local/deploy/pero/config/keys/private.pem'):
            result = subprocess.run(['git', 'check-ignore', '-q', path], cwd=self.root)
            self.assertEqual(result.returncode, 0, path)


if __name__ == '__main__':
    unittest.main()
