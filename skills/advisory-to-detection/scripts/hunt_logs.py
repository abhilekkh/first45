"""Hunt First45-format TSV logs for a threat (plus behaviour detectors).

Usage: python hunt_logs.py threat.json logs_folder/
"""
import json
import sys
from pathlib import Path

import _repo  # noqa: F401
from hunt import hunt, load_logs

if len(sys.argv) != 3:
    sys.exit(__doc__)
threat = json.load(open(sys.argv[1], encoding="utf-8"))
findings, summary = hunt(load_logs(Path(sys.argv[2])), threat)
for row in summary.itertuples():
    print(f"{row.host:12} {row.verdict:32} furthest: {row.furthest_stage:22} {row.patch}")
