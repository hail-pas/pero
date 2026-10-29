#!/usr/bin/env python3
"""Initialize schema, provider and administrator using the release's migration runner."""
import os
from pathlib import Path
import subprocess


def main():
    os.chdir('/opt/pero')
    for name in ('production.toml', 'bootstrap.toml', 'keys/private.pem', 'keys/public.pem'):
        if not (Path('config') / name).is_file():
            raise SystemExit(f'Missing config/{name}')
    # bootstrap connects, migrates and verifies before any provisioning. The URI
    # stays in configuration rather than process arguments or subprocess errors.
    subprocess.run(['prd/bootstrap', '--config-dir', 'config', '--keys-dir', 'config/keys'],
                   env={**os.environ, 'PERO_RUN_MODE': 'production'}, check=True)
    print('Initialization complete. Start the service with docker compose up -d.')


if __name__ == '__main__':
    main()
