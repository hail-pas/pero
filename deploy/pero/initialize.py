#!/usr/bin/env python3
"""Initialize the production schema, provider and administrator. Never clears data."""
import os
from pathlib import Path
import subprocess
import tomllib


def main():
    os.chdir('/opt/pero')
    config = tomllib.loads(Path('config/production.toml').read_text())
    for name in ('bootstrap.toml', 'keys/private.pem', 'keys/public.pem'):
        if not (Path('config') / name).is_file():
            raise SystemExit(f'Missing config/{name}')
    env = {**os.environ, 'PERO_RUN_MODE': 'production', 'DATABASE_URL': config['database']['url']}
    # libpq accepts the URL via PGDATABASE, without putting its password in argv.
    result = subprocess.run(['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', 'SHOW server_version_num;'],
                            env={**env, 'PGDATABASE': env['DATABASE_URL']}, text=True, capture_output=True)
    if result.returncode:
        raise SystemExit('Database connection failed. Check production.toml, published ports and PostgreSQL access rules.')
    if int(result.stdout.strip()) < 180000:
        raise SystemExit('PostgreSQL 18+ required; no initialization performed.')
    subprocess.run(['bash', 'prd/migrate.sh'], env=env, check=True)
    subprocess.run(['prd/bootstrap', '--config-dir', 'config', '--keys-dir', 'config/keys'], env=env, check=True)
    print('Initialization complete. Start the service with docker compose up -d.')


if __name__ == '__main__':
    main()
