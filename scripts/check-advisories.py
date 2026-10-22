#!/usr/bin/env python3
"""Check the complete audit output; narrowly scoped, expiring triage is explicit."""
import datetime
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
report = json.loads(pathlib.Path(sys.argv[1]).read_text())
policy = json.loads((root / '.github/security/advisory-policy.json').read_text())
findings = report['vulnerabilities']['list'] + [item for group in report['warnings'].values() for item in group]
for finding in findings:
    advisory = (finding.get('advisory') or {})
    package = finding['package']
    identity = (advisory.get('id'), package['name'], package['version'])
    accepted = next((a for a in policy['accepted'] if (a['id'], a['package'], a['version']) == identity and a['kind'] == finding.get('kind')), None)
    if accepted is None or datetime.date.today() > datetime.date.fromisoformat(policy['expires']):
        sys.exit(f'Untriaged or expired advisory: {identity}')
    print(f'Visible tracked advisory: {identity}; review by {policy["expires"]}')
print(f'Audited {len(findings)} findings; no untriaged findings')
