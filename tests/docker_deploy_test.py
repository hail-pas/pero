#!/usr/bin/env python3
"""Test private-config packaging without Docker, Rust, Zig, or storage access."""
import hashlib
import gzip
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

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

    def test_legacy_static_path_moves_to_frontend(self):
        path = self.config / 'production.toml'
        path.write_text(path.read_text() + '\n[askama]\nstatic_dir="prd/ui/static"\n')
        self.assertEqual(self.run_packager().returncode, 0)
        with tarfile.open(self.archive) as archive:
            production = tomllib.loads(archive.extractfile('config/production.toml').read().decode())
        self.assertEqual(production['frontend']['static_dir'], 'prd/ui/static')
        self.assertNotIn('askama', production)

    def test_git_allows_templates_and_ignores_secrets_and_outputs(self):
        for path in ('deploy/pero/Dockerfile', 'deploy/pero/Dockerfile.dockerignore',
                     'deploy/pero/production.toml.example', 'deploy/pero/initialize.py'):
            result = subprocess.run(['git', 'check-ignore', '-q', path], cwd=self.root)
            self.assertEqual(result.returncode, 1, path)
        for path in ('deploy/pero/config/production.toml', 'deploy/pero/prd/user-center',
                     'deploy/pero-config.tar.gz', 'deploy/pero-config.tar.gz.sha256',
                     'deploy/pero-image.env',
                     'local/deploy/pero/config/keys/private.pem'):
            result = subprocess.run(['git', 'check-ignore', '-q', path], cwd=self.root)
            self.assertEqual(result.returncode, 0, path)


class LocalImageBuildTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'scripts').mkdir()
        (self.root / 'bin').mkdir()
        shutil.copy2(ROOT / 'scripts/build-docker-image.sh', self.root / 'scripts/build-docker-image.sh')
        self.calls = self.root / 'calls.jsonl'
        docker = self.root / 'bin/docker'
        docker.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
from pathlib import Path
args=sys.argv[1:]
with Path(os.environ['FAKE_DOCKER_LOG']).open('a') as stream:
    stream.write(json.dumps(args)+'\\n')
if args[:2]==['image','inspect']:
    print(os.environ.get('FAKE_PLATFORM','linux/amd64'))
elif args[:2]==['image','save']:
    if os.environ.get('FAKE_SAVE_FAIL'):sys.exit(2)
    sys.stdout.buffer.write(b'fixture docker save archive')
''')
        docker.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + os.pathsep + os.environ['PATH'],
                    'FAKE_DOCKER_LOG': str(self.calls)}
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.test', 'commit', '-q',
                        '--allow-empty', '-m', 'Build fixture'], check=True)
        revision = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', '--short=12', 'HEAD'], text=True).strip()
        self.image_tag = 'git-' + revision
        self.image = 'pero-user-center:' + self.image_tag
        self.image_env = self.root / 'deploy/pero-image.env'
        self.archive = self.root / 'deploy/pero-user-center-linux-amd64.tar.gz'

    def build(self):
        return subprocess.run(['bash', str(self.root / 'scripts/build-docker-image.sh')],
                              env=self.env, capture_output=True, text=True)

    def test_amd64_build_load_export_checksum(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        build = next(args for args in calls if args[:2] == ['buildx', 'build'])
        self.assertEqual(build[build.index('--platform') + 1], 'linux/amd64')
        self.assertIn('--load', build)
        self.assertEqual(build[build.index('-t') + 1], self.image)
        self.assertEqual(self.image_env.read_text(), 'PERO_IMAGE_TAG=' + self.image_tag + '\n')
        save = next(args for args in calls if args[:2] == ['image', 'save'])
        self.assertEqual(save[save.index('--platform') + 1], 'linux/amd64')
        self.assertEqual(save[-1], self.image)
        self.assertEqual(gzip.decompress(self.archive.read_bytes()), b'fixture docker save archive')
        self.assertEqual(Path(str(self.archive) + '.sha256').read_text().split(),
                         [hashlib.sha256(self.archive.read_bytes()).hexdigest(), self.archive.name])
        self.assertEqual(list((self.root / 'deploy').glob('.pero-image.*')), [])

    def test_wrong_architecture_prevents_export(self):
        self.env['FAKE_PLATFORM'] = 'linux/arm64'
        self.assertNotEqual(self.build().returncode, 0)
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.image_env.exists())
        self.assertFalse(any(args[:2] == ['image', 'save']
                             for args in map(json.loads, self.calls.read_text().splitlines())))

    def test_failed_export_preserves_previous_package(self):
        self.assertEqual(self.build().returncode, 0)
        previous = self.archive.read_bytes()
        checksum = Path(str(self.archive) + '.sha256').read_bytes()
        previous_env = self.image_env.read_bytes()
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Fixture',
                        '-c', 'user.email=fixture@example.test', 'commit', '-q',
                        '--allow-empty', '-m', 'Next build'], check=True)
        self.env['FAKE_SAVE_FAIL'] = '1'
        self.assertNotEqual(self.build().returncode, 0)
        self.assertEqual(self.archive.read_bytes(), previous)
        self.assertEqual(Path(str(self.archive) + '.sha256').read_bytes(), checksum)
        self.assertEqual(self.image_env.read_bytes(), previous_env)
        self.assertEqual(list((self.root / 'deploy').glob('.pero-image.*')), [])


class InitializeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'config/keys').mkdir(parents=True)
        self.url = 'postgres://fixture:p%40ss@db.example:5432/pero'
        (self.root / 'config/production.toml').write_text('[database]\nurl="' + self.url + '"\n')
        for file in ('bootstrap.toml', 'keys/private.pem', 'keys/public.pem'):
            (self.root / 'config' / file).touch()
        spec = importlib.util.spec_from_file_location('pero_initialize', ROOT / 'deploy/pero/initialize.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def initialize(self, runner):
        with patch.object(self.module.os, 'chdir'), \
             patch.object(self.module, 'Path', side_effect=lambda path: self.root / path), \
             patch.object(self.module.subprocess, 'run', runner):
            self.module.main()

    def test_bootstrap_owns_migration_and_provisioning(self):
        from unittest.mock import Mock
        runner = Mock(return_value=subprocess.CompletedProcess([], 0))
        self.initialize(runner)
        runner.assert_called_once()
        self.assertEqual(runner.call_args.args[0],
                         ['prd/bootstrap', '--config-dir', 'config', '--keys-dir', 'config/keys'])
        self.assertEqual(runner.call_args.kwargs['env']['PERO_RUN_MODE'], 'production')
        self.assertTrue(runner.call_args.kwargs['check'])

    def test_bootstrap_failure_stops_initialization(self):
        from unittest.mock import Mock
        runner = Mock(side_effect=subprocess.CalledProcessError(1, ['prd/bootstrap']))
        with self.assertRaises(subprocess.CalledProcessError):
            self.initialize(runner)
        runner.assert_called_once()


if __name__ == '__main__':
    unittest.main()
