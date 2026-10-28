#!/usr/bin/env python3
"""Check exact Cargo.lock versions against OSV, including GitHub advisories."""
import datetime
import json
import pathlib
import sys
import tomllib
import urllib.request

root = pathlib.Path(__file__).resolve().parents[1]
with (root / "Cargo.lock").open("rb") as source:
    packages = [
        package
        for package in tomllib.load(source)["package"]
        if package.get("source", "").startswith("registry+")
    ]
queries = [
    {
        "package": {"name": package["name"], "ecosystem": "crates.io"},
        "version": package["version"],
    }
    for package in packages
]
request = urllib.request.Request(
    "https://api.osv.dev/v1/querybatch",
    data=json.dumps({"queries": queries}).encode(),
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(request, timeout=60) as response:
    results = json.load(response)["results"]
if len(results) != len(packages):
    sys.exit("Incomplete OSV response")
# A truncated response must never be reported as a clean audit.
if any(result.get("next_page_token") for result in results):
    sys.exit("Incomplete OSV response: pagination required")
policy = json.loads((root / ".github/security/advisory-policy.json").read_text())
findings = []
tracked = 0
for package, result in zip(packages, results):
    for vulnerability in result.get("vulns", []):
        identity = (vulnerability["id"], package["name"], package["version"])
        accepted = next((
            entry for entry in policy.get("accepted", [])
            if entry["kind"] == "osv_false_positive"
            and (entry["id"], entry["package"], entry["version"]) == identity
        ), None)
        if accepted and datetime.date.today() <= datetime.date.fromisoformat(policy["expires"]):
            tracked += 1
            print(f'Visible tracked OSV false positive: {identity}; review by {policy["expires"]}')
        else:
            findings.append(f'{package["name"]} {package["version"]}: {vulnerability["id"]}')
if findings:
    sys.exit("\n".join(findings))
print(f"OSV: checked {len(packages)} packages; {tracked} tracked false positives; no untriaged findings")
