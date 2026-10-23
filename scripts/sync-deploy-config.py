#!/usr/bin/env python3
"""Use current default.toml as the schema; copy matching old deployment values only."""
import argparse
import json
import os
from pathlib import Path
import tomllib


def refresh(template, previous):
    result = {}
    for key, value in template.items():
        old = previous.get(key)
        if isinstance(value, dict):
            result[key] = refresh(value, old if isinstance(old, dict) else {})
        else:
            result[key] = old if key in previous else value
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
