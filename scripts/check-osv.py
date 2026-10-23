#!/usr/bin/env python3
"""Check exact Cargo.lock versions against OSV, including GitHub advisories."""
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
findings = [
    f'{package["name"]} {package["version"]}: {vulnerability["id"]}'
    for package, result in zip(packages, results)
    for vulnerability in result.get("vulns", [])
]
if findings:
    sys.exit("\n".join(findings))
print(f"OSV: checked {len(packages)} packages; no known vulnerabilities")
