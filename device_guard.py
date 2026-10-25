"""First45 Device Guard - is THIS computer part of a botnet?

Server logs show attacks from the outside. Device Guard looks from the inside:
it watches every network connection on this machine for a short window, links
each one to the program that opened it, and looks for botnet behaviour.

Detection is deterministic and explainable (no AI guessing):

  stage            detector                     what it means
  ---------------  ---------------------------  ------------------------------------------
  loader_download  Runs from a temp/download    malware is usually dropped in Temp/Downloads
  c2_contact       Talks to advisory IP / port  the advisory (read by Gemma 4) names this C2
  c2_contact       Botnet beaconing             reconnects to one server at a steady rhythm
  c2_contact       Botnet port open             listening on a port botnets use (Mirai: 23, 2323, 48101)
  recon            Scanning to spread           one program dials many IPs on one port (Mirai worm)
  ddos             Outbound flood               hundreds of connections to one target

Prevention is human-approved only (AI recommends, a human decides):
  * stop_process()  - ends the program (needs no admin for your own programs)
  * block_ip()      - Windows Firewall rule in + out (needs the app run as admin;
                      otherwise we return the exact command for the admin to run)
Every action is written to state/device_audit.log and can be undone.

CLI:  python device_guard.py --seconds 20 [--loopback]
"""
from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
AUDIT = STATE / "device_audit.log"
BLOCKS = STATE / "device_blocks.json"
IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------- tuning ---
BOTNET_PORTS = {23, 2323, 48101}          # Mirai telnet scanning + classic Mirai report port
DROP_FOLDERS = ("\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\",
                "\\windows\\temp\\", "/tmp/", "/dev/shm/", "/var/tmp/")
BEACON_MIN_CONNECTIONS = 4               # at least this many new connections to one server...
BEACON_MAX_JITTER = 0.35                 # ...spaced at a steady rhythm (within 35 % of the median gap)
SCAN_MIN_TARGETS = 20                    # distinct IPs dialled on one port...
SCAN_MIN_UNANSWERED = 0.5                # ...and at least half never answered (stuck in SYN_SENT)
WEB_PORTS = {80, 443, 53, 853, 8080, 8443}  # browsing/DNS: many IPs here is normal, not scanning
FLOOD_MIN_CONNECTIONS = 100              # simultaneous connections to one target
# Apps that legitimately poll servers; beaconing alone is not flagged for them (less noise).
TRUSTED_POLLERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "code.exe",
                   "discord.exe", "teams.exe", "ms-teams.exe", "onedrive.exe", "spotify.exe",
                   "slack.exe", "whatsapp.exe", "steam.exe", "svchost.exe", "msedgewebview2.exe"}

STAGES = ["loader_download", "c2_contact", "recon", "ddos"]
STAGE_LABEL = {"loader_download": "Malware landed", "c2_contact": "Phones home",
               "recon": "Scans to spread", "ddos": "Floods a target"}
SEVERITY = {"Talks to advisory attacker IP": 5, "Uses advisory C2 port": 4,
            "Outbound flood": 4, "Scanning to spread": 4, "Botnet beaconing": 3,
            "Botnet port open": 3, "Runs from a temp/download folder": 2}


# ------------------------------------------------------------ collection ---
def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _process_info(pid: int, cache: dict) -> dict:
    if pid in cache:
        return cache[pid]
    info = {"pid": pid, "name": "?", "exe": "", "cmdline": "", "user": ""}
    try:
        p = psutil.Process(pid)
        info["name"] = p.name()
        for key, getter in (("exe", p.exe), ("cmdline", lambda: " ".join(p.cmdline())),
                            ("user", p.username)):
            try:
                info[key] = getter() or ""
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    cache[pid] = info
    return info


def snapshot() -> list[dict]:
    """Every TCP/UDP socket on this machine right now, with the owning process id."""
    rows = []
    for c in psutil.net_connections(kind="inet"):
        if not c.pid:                      # pid 0 = closed/TIME_WAIT sockets, no owner
            continue
        rows.append({
            "pid": c.pid,
            "type": "tcp" if c.type == 1 else "udp",
            "status": c.status,
            "lip": c.laddr.ip if c.laddr else "", "lport": c.laddr.port if c.laddr else 0,
            "rip": c.raddr.ip if c.raddr else "", "rport": c.raddr.port if c.raddr else 0,
        })
    return rows


def watch(seconds: int = 20, interval: float = 1.0, progress=None) -> list[tuple[float, list[dict]]]:
    """Take a snapshot every `interval` seconds. progress(fraction) is called for UI bars."""
    samples, start = [], time.time()
    while True:
        now = time.time()
        samples.append((now, snapshot()))
        if progress:
            progress(min(1.0, (now - start) / max(seconds, 1)))
        if now - start >= seconds:
            break
        time.sleep(interval)
    return samples


# --------------------------------------------------------------- analysis ---
def _iocs(threat: dict | None) -> tuple[set[str], set[int]]:
    if not threat:
        return set(), set()
    iocs = threat.get("iocs") or {}
    verified = set((threat.get("_meta") or {}).get("ioc_check", {}).get("verified", []))
    ips = {ip for ip in iocs.get("ips", []) if not verified or ip in verified}
    ports = {int(p) for p in iocs.get("ports", []) if not verified or str(p) in verified}
    return ips, ports


def analyse(samples: list[tuple[float, list[dict]]], threat: dict | None = None,
            include_loopback: bool = False) -> dict:
    """Snapshots -> {'findings': [...per suspicious program...], 'stats': {...}}."""
    ioc_ips, ioc_ports = _iocs(threat)
    cache: dict = {}
    first_seen: dict = {}                               # (pid, lport, rip, rport) -> time
    listening: dict = defaultdict(set)                  # pid -> {(ip, port)}
    peak_to_target: dict = defaultdict(int)             # (pid, rip) -> max simultaneous
    dialled: dict = defaultdict(set)                    # (pid, rport) -> {rip}
    unanswered: dict = defaultdict(set)                 # (pid, rport) -> {rip} seen only in SYN_SENT
    answered: dict = defaultdict(set)                   # (pid, rport) -> {rip} that connected
    remotes: dict = defaultdict(set)                    # pid -> {"ip:port"}
    pids, total = set(), 0

    for t, rows in samples:
        per_target: dict = defaultdict(int)
        own_ports = {(r["pid"], r["lport"]) for r in rows if r["status"] == "LISTEN"}
        for r in rows:
            pids.add(r["pid"])
            if r["status"] == "LISTEN":
                listening[r["pid"]].add((r["lip"], r["lport"]))
                continue
            if not r["rip"] or (_is_loopback(r["rip"]) and not include_loopback):
                continue
            total += 1
            if (r["pid"], r["lport"]) in own_ports:     # inbound: someone connected TO us
                if r["rip"] in ioc_ips:
                    remotes[r["pid"]].add(f'{r["rip"]}:{r["rport"]}')
                continue
            key = (r["pid"], r["lport"], r["rip"], r["rport"])
            first_seen.setdefault(key, t)
            per_target[(r["pid"], r["rip"])] += 1
            dialled[(r["pid"], r["rport"])].add(r["rip"])
            (unanswered if r["status"] == "SYN_SENT" else answered)[(r["pid"], r["rport"])].add(r["rip"])
            remotes[r["pid"]].add(f'{r["rip"]}:{r["rport"]}')
        for k, n in per_target.items():
            peak_to_target[k] = max(peak_to_target[k], n)

    hits: dict = defaultdict(list)                      # pid -> [(detector, detail, stage)]

    # advisory IOCs (from Gemma 4, verified against the advisory text)
    for pid, rs in remotes.items():
        for rp in sorted(rs):
            ip, port = rp.rsplit(":", 1)
            if ip in ioc_ips:
                hits[pid].append(("Talks to advisory attacker IP", rp, "c2_contact"))
            elif int(port) in ioc_ports:
                hits[pid].append(("Uses advisory C2 port", rp, "c2_contact"))

    # beaconing: many short connections to one server at a steady rhythm
    starts: dict = defaultdict(list)
    for (pid, _lport, rip, rport), t in first_seen.items():
        starts[(pid, rip, rport)].append(t)
    for (pid, rip, rport), times in starts.items():
        if len(times) < BEACON_MIN_CONNECTIONS:
            continue
        times.sort()
        checkins = [times[0]] + [b for a, b in zip(times, times[1:]) if b - a > 0.2]  # merge bursts
        gaps = [b - a for a, b in zip(checkins, checkins[1:])]
        if len(gaps) < BEACON_MIN_CONNECTIONS - 1:
            continue
        mean = statistics.median(gaps)                   # median ignores the odd late check-in
        steady = sum(abs(g - mean) <= BEACON_MAX_JITTER * mean for g in gaps) / len(gaps)
        if mean > 0 and steady >= 0.7:                    # 70 % of check-ins on the rhythm
            name = _process_info(pid, cache)["name"].lower()
            if name not in TRUSTED_POLLERS:
                hits[pid].append(("Botnet beaconing",
                                  f"{len(checkins)} check-ins to {rip}:{rport} every ~{mean:.1f}s", "c2_contact"))

    # scanning to spread (one port, many IPs)
    for (pid, rport), ips in dialled.items():
        if len(ips) < SCAN_MIN_TARGETS or rport in WEB_PORTS:
            continue
        failed = unanswered[(pid, rport)] - answered[(pid, rport)]
        if len(failed) / len(ips) >= SCAN_MIN_UNANSWERED:
            hits[pid].append(("Scanning to spread",
                              f"{len(ips)} different IPs on port {rport}, {len(failed)} never answered", "recon"))

    # outbound flood
    for (pid, rip), n in peak_to_target.items():
        if n >= FLOOD_MIN_CONNECTIONS:
            hits[pid].append(("Outbound flood", f"{n} connections at once to {rip}", "ddos"))

    # listening on a botnet port
    for pid, socks in listening.items():
        for ip, port in socks:
            if port in BOTNET_PORTS | ioc_ports and (include_loopback or not _is_loopback(ip)):
                hits[pid].append(("Botnet port open", f"listening on {ip}:{port}", "c2_contact"))

    # dropped in a temp / download folder (only matters if it also uses the network)
    for pid in set(remotes) | set(listening) | set(hits):
        info = _process_info(pid, cache)
        for path in (info["exe"], info["cmdline"]):
            if any(folder in path.lower() for folder in DROP_FOLDERS):
                hits[pid].append(("Runs from a temp/download folder", path[:200], "loader_download"))
                break

    findings = []
    for pid, items in hits.items():
        info = _process_info(pid, cache)
        unique = list(dict.fromkeys(items))
        detectors = {d for d, _, _ in unique}
        score = sum(SEVERITY[d] for d in detectors)
        critical = "Talks to advisory attacker IP" in detectors or score >= 7
        if detectors == {"Runs from a temp/download folder"}:
            continue                                      # a temp program alone is just a hint
        findings.append({
            **info,
            "verdict": "LIKELY BOTNET" if critical else "SUSPICIOUS",
            "score": score,
            "stages": [s for s in STAGES if any(st == s for _, _, st in unique)],
            "detections": [{"detector": d, "detail": det, "stage": st} for d, det, st in unique],
            "remote_ips": sorted({rp.rsplit(":", 1)[0] for rp in remotes.get(pid, [])}),
        })
    findings.sort(key=lambda f: -f["score"])
    return {"findings": findings,
            "stats": {"programs": len(pids), "connections_seen": total,
                      "snapshots": len(samples),
                      "seconds": round(samples[-1][0] - samples[0][0], 1) if samples else 0,
                      "flagged": len(findings), "ioc_ips": len(ioc_ips), "ioc_ports": len(ioc_ports)}}


# ------------------------------------------------- prevention (approved) ---
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin()) if IS_WINDOWS else os.geteuid() == 0
    except Exception:
        return False


def _audit(action: str, target: str, by: str, reason: str) -> None:
    STATE.mkdir(exist_ok=True)
    with open(AUDIT, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')}\t{action}\t{target}\tby={by}\t{reason}\n")


def audit_log(last: int = 20) -> list[str]:
    try:
        return AUDIT.read_text(encoding="utf-8").strip().splitlines()[-last:]
    except FileNotFoundError:
        return []


def _blocks() -> dict:
    try:
        return json.loads(BLOCKS.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def blocked_ips() -> dict:
    return _blocks()


def stop_process(pid: int, by: str, reason: str) -> str:
    """End one program. Refuses system processes and First45 itself."""
    protected = {0, 4, os.getpid(), os.getppid()}
    if pid in protected:
        return "Refused: system process or First45 itself."
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
        _audit("STOP_PROCESS", f"{name} (pid {pid})", by, reason)
        return f"Stopped {name} (pid {pid})."
    except psutil.NoSuchProcess:
        return "Already gone."
    except psutil.AccessDenied:
        return "Access denied: run First45 as administrator to stop this program."


def firewall_commands(ip: str) -> list[list[str]]:
    ipaddress.ip_address(ip)                              # raises on anything that is not an IP
    name = f"First45 block {ip}"
    if IS_WINDOWS:
        return [["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={d}",
                 "action=block", f"remoteip={ip}"] for d in ("out", "in")]
    return [["iptables", "-I", chain, flag, ip, "-j", "DROP"]
            for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s"))]


def unblock_commands(ip: str) -> list[list[str]]:
    ipaddress.ip_address(ip)
    if IS_WINDOWS:
        return [["netsh", "advfirewall", "firewall", "delete", "rule", f"name=First45 block {ip}"]]
    return [["iptables", "-D", chain, flag, ip, "-j", "DROP"]
            for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s"))]


def block_ip(ip: str, by: str, reason: str) -> str:
    """Add firewall rules (in + out). Without admin rights, return the command instead."""
    try:
        cmds = firewall_commands(ip)
    except ValueError:
        return "Refused: not a valid IP address."
    if _is_loopback(ip):
        return "Refused: loopback (this computer) cannot be firewalled. Stop the program instead."
    shown = " && ".join(" ".join(f'"{a}"' if " " in a else a for a in c) for c in cmds)
    if not is_admin():
        return f"Needs administrator. Run this in an admin terminal:\n{shown}"
    for c in cmds:
        result = subprocess.run(c, capture_output=True, text=True)   # list args, no shell
        if result.returncode != 0:
            return f"Firewall error: {(result.stdout or result.stderr).strip()}"
    data = _blocks()
    data[ip] = {"by": by, "reason": reason, "at": datetime.now().isoformat(timespec="seconds")}
    STATE.mkdir(exist_ok=True)
    BLOCKS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _audit("FIREWALL_BLOCK", ip, by, reason)
    return f"Blocked {ip} in the firewall (in + out)."


def unblock_ip(ip: str, by: str) -> str:
    try:
        cmds = unblock_commands(ip)
    except ValueError:
        return "Refused: not a valid IP address."
    if not is_admin():
        return "Needs administrator: " + " && ".join(" ".join(c) for c in cmds)
    for c in cmds:
        subprocess.run(c, capture_output=True, text=True)
    data = _blocks()
    data.pop(ip, None)
    BLOCKS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _audit("FIREWALL_UNBLOCK", ip, by, "undo")
    return f"Unblocked {ip}."


# --------------------------------------------------------------------- CLI ---
def main() -> None:
    parser = argparse.ArgumentParser(description="First45 Device Guard: botnet check for this computer")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--loopback", action="store_true", help="include 127.0.0.1 (for the safe simulator)")
    parser.add_argument("--threat", default=str(ROOT / "samples" / "threat_php2shell.json"))
    args = parser.parse_args()
    threat = json.loads(Path(args.threat).read_text(encoding="utf-8")) if Path(args.threat).exists() else None
    print(f"Watching this computer for {args.seconds}s ...")
    result = analyse(watch(args.seconds), threat, include_loopback=args.loopback)
    print(json.dumps(result["stats"]))
    if not result["findings"]:
        print("CLEAN: no botnet behaviour seen.")
    for f in result["findings"]:
        print(f"\n[{f['verdict']}] {f['name']} (pid {f['pid']}) score={f['score']}  {f['exe']}")
        for d in f["detections"]:
            print(f"   - {d['detector']}: {d['detail']}")
    sys.exit(1 if any(f["verdict"] == "LIKELY BOTNET" for f in result["findings"]) else 0)


if __name__ == "__main__":
    main()
