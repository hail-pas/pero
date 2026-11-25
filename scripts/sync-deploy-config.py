#!/usr/bin/env python3
"""Refresh deployment configuration, retaining supported explicit overrides."""
import argparse
import json
import os
from pathlib import Path
import tomllib


# Fields supplied by Rust defaults or optional configuration blocks are not
# necessarily present in default.toml. Preserve them when explicitly configured.
OPTIONAL_FIELDS = {
    ('server',): ('graceful_shutdown_timeout_secs', 'cleanup_interval_secs', 'cors'),
    ('server', 'cors'): ('allow_origins', 'allow_methods', 'allow_headers',
                         'allow_credentials', 'expose_headers', 'max_age_secs'),
    ('database',): ('acquire_timeout_secs', 'idle_timeout_secs', 'max_lifetime_secs'),
    ('redis',): ('connect_timeout_secs', 'command_timeout_secs'),
    ('sso',): ('session_cookie_name', 'session_touch_interval_seconds', 'cookie_domain', 'cookie_path'),
    ('http_config',): ('timeout_secs', 'connect_timeout_secs', 'pool_idle_timeout_secs',
                       'pool_max_idle_per_host', 'user_agent', 'retry', 'max_response_bytes'),
    ('http_config', 'retry'): ('enabled', 'max_retries', 'base_delay_millis', 'max_delay_millis'),
    ('notification',): ('smtp', 'sms'),
    ('notification', 'smtp'): ('host', 'port', 'username', 'password', 'from', 'security'),
    ('notification', 'sms'): ('account_sid', 'auth_token', 'from'),
}


def refresh(template, previous, path=()):
    if not isinstance(previous, dict):
        raise ValueError(f'Expected a TOML table: {".".join(path)}')
    result = {}
    keys = dict.fromkeys((*template, *OPTIONAL_FIELDS.get(path, ())))
    for key in keys:
        child = (*path, key)
        if key not in template and key not in previous:
            continue
        value = template.get(key)
        if isinstance(value, dict) or child in OPTIONAL_FIELDS:
            result[key] = refresh(value if isinstance(value, dict) else {},
                                  previous.get(key, {}), child)
        else:
            result[key] = previous.get(key, value)
    return result


def emit(data):
    lines = []
    def section(table, path):
        if path:
            lines.append('[' + '.'.join(path) + ']')
        for key, value in table.items():
            if not isinstance(value, dict):
                # Current public template uses strings, integers, bools and string arrays.
                lines.append(f'{key} = {json.dumps(value, ensure_ascii=False)}')
        lines.append('')
        for key, value in table.items():
            if isinstance(value, dict):
                section(value, path + [key])
    section(data, [])
    return '\n'.join(lines).lstrip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--defaults', required=True, type=Path)
    parser.add_argument('--previous', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    defaults = tomllib.loads(args.defaults.read_text())
    previous = tomllib.loads(args.previous.read_text())
    # Preserve the deployed static path when migrating the legacy template section.
    if 'frontend' in defaults and 'frontend' not in previous:
        legacy = previous.get('askama', {})
        if 'static_dir' in legacy:
            previous['frontend'] = {'static_dir': legacy['static_dir']}
    result = refresh(defaults, previous)
    rendered = emit(result)
    assert tomllib.loads(rendered) == result
    temporary = args.output.with_name(args.output.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('# Generated from the current source default.toml; private deployment values retained.\n')
        stream.write(rendered)
    temporary.replace(args.output)
    print('Updated configuration using current template fields; no secret values printed.')


if __name__ == '__main__':
    main()
