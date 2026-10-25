"""First45 - prevention, ONLY with human approval.

AI recommends, a human decides. Nothing is blocked automatically.

Default mode is DRY RUN: we show exactly what would be blocked.
When an admin clicks Approve, the IP goes into state/blocklist.json and
state/nginx-deny.conf (a file the web server can include), and every action is
written to state/audit.log with time, who approved it and why. Undo is one click.

We never change the operating-system firewall from the app. The generated
firewall commands are shown for the admin to run on their own server.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

STATE = Path(__file__).resolve().parent / "state"
BLOCKLIST = STATE / "blocklist.json"
AUDIT = STATE / "audit.log"
NGINX = STATE / "nginx-deny.conf"


def _load() -> dict:
    try:
        return json.loads(BLOCKLIST.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save(data: dict) -> None:
    STATE.mkdir(exist_ok=True)
    BLOCKLIST.write_text(json.dumps(data, indent=2), encoding="utf-8")
    lines = [f"deny {ip};  # {v['reason']} (approved by {v['by']} at {v['at']})" for ip, v in data.items()]
    NGINX.write_text("# First45 approved blocks - include in your nginx server block\n"
                     + "\n".join(lines) + "\n", encoding="utf-8")


def _audit(action: str, ip: str, by: str, reason: str) -> None:
    STATE.mkdir(exist_ok=True)
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')}\t{action}\t{ip}\tby={by}\t{reason}\n")


def blocked_ips() -> set[str]:
    return set(_load())


def approve_block(ip: str, by: str, reason: str) -> None:
    data = _load()
    data[ip] = {"reason": reason, "by": by, "at": datetime.now().isoformat(timespec="seconds")}
    _save(data)
    _audit("BLOCK", ip, by, reason)


def unblock(ip: str, by: str) -> None:
    data = _load()
    if ip in data:
        data.pop(ip)
        _save(data)
        _audit("UNBLOCK", ip, by, "undo")


def reset() -> None:
    _save({})
    _audit("RESET", "*", "system", "demo reset")


def audit_log(last: int = 20) -> list[str]:
    try:
        return AUDIT.read_text(encoding="utf-8").strip().splitlines()[-last:]
    except FileNotFoundError:
        return []
