"""Check that every indicator in a threat file appears in the advisory text.

Usage: python verify.py threat.json advisory.txt
Exit code 1 if anything is unverified.
"""
import json
import sys

import _repo  # noqa: F401
from gemma_client import verify_iocs, _clean

if len(sys.argv) != 3:
    sys.exit(__doc__)
threat = _clean(json.load(open(sys.argv[1], encoding="utf-8")))
text = open(sys.argv[2], encoding="utf-8").read()
result = verify_iocs(threat, text)
for v in result["verified"]:
    print("VERIFIED  ", v)
for v in result["unverified"]:
    print("UNVERIFIED", v)
sys.exit(1 if result["unverified"] else 0)
