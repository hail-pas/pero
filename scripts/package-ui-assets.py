#!/usr/bin/env python3
"""Copy the exact Cargo build's generated assets, including for static-file proxies."""
import json
import shutil
import sys
from pathlib import Path

build_log, destination = map(Path, sys.argv[1:])
output = None
for line in build_log.read_text().splitlines():
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        continue
    package = event.get("package_id", "")
    if event.get("reason") == "build-script-executed" and "/user-center#" in package:
        output = Path(event["out_dir"])
if output is None:
    raise SystemExit("Missing user-center build output; refusing to package stale translations")
(destination / "js").mkdir(parents=True, exist_ok=True)
shutil.copy2(output / "i18n.js", destination / "js/i18n.js")
