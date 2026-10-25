"""Write Sigma, Suricata, nginx and firewall rules for a threat file.

Usage: python make_rules.py threat.json out_folder/
"""
import json
import sys
from pathlib import Path

import _repo  # noqa: F401
from rules import all_rules

if len(sys.argv) != 3:
    sys.exit(__doc__)
threat = json.load(open(sys.argv[1], encoding="utf-8"))
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
for name, text in all_rules(threat).items():
    (out / name).write_text(text, encoding="utf-8")
    print("wrote", out / name)
