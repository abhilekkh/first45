"""First45 - hunt engine.

Two detector families run over the server logs:

  A. ADVISORY detectors  - built from the threat JSON Gemma 4 extracted
                           (attacker IPs, C2 domains, ports). Catch known campaigns.
  B. BEHAVIOUR detectors - need no advisory. Catch common attacks on day zero:
                           web exploits, brute force, scanning, web shells,
                           malware downloads, botnet beaconing, DDoS, odd DNS.

Detection is deterministic (no AI guessing), so every alert is explainable and
repeatable. Gemma 4 is only used before (reading advisories) and after (reports).

Each finding = {host, stage, ts, family, detector, severity, actor, evidence}.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

LOGS = Path(__file__).resolve().parent / "demo_logs"

# Kill chain, in order. Index = how far an attack got.
STAGES = ["recon", "exploit_attempt", "web_shell", "loader_download", "c2_contact", "ddos"]
STAGE_LABEL = {
    "recon": "🔍 Recon / scan",
    "exploit_attempt": "🟡 Exploit attempt",
    "web_shell": "🟠 Web shell",
    "loader_download": "🔴 Malware download",
    "c2_contact": "🔴 Botnet C2 contact",
    "ddos": "⚫ DDoS / flood",
}
COMPROMISE_STAGES = {"web_shell", "loader_download", "c2_contact", "ddos"}

WEB_PATTERNS = {
    "SQL injection": re.compile(r"union(\s|%20)+select|'(\s|%20)*or(\s|%20)*1=1|sleep\(", re.I),
    "Path traversal": re.compile(r"\.\./|%2e%2e%2f|/etc/passwd", re.I),
    "Command injection / RCE": re.compile(r"cmd=|/bin/(ba)?sh|wget(\s|%20)|curl(\s|%20)|PAYLOAD-REDACTED", re.I),
    "Cross-site scripting": re.compile(r"<script|%3cscript", re.I),
}
WEB_SHELL = re.compile(r"/(?:tmp|uploads|sessions?)/[^?]*\.php|/sess_[^/?]*\.php", re.I)
LOGIN_PATH = re.compile(r"login|wp-login|admin", re.I)
EXECUTABLE = re.compile(r"application/x-(?:elf|dosexec|sh)|\.(?:sh|exe|elf)\b", re.I)
COMMON_PORTS = {53, 80, 123, 443, 587, 993}
RARE_TLDS = (".st", ".xyz", ".top", ".tk", ".ru", ".cn", ".zip")
PUBLIC_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}


# ------------------------------------------------------------------ loading ---
def load_logs(folder: Path = LOGS) -> dict[str, pd.DataFrame]:
    logs = {}
    for name in ("web", "dns", "conn", "inventory"):
        df = pd.read_csv(folder / f"{name}.tsv", sep="\t", dtype=str, keep_default_na=False)
        if "ts" in df:
            df["ts"] = pd.to_datetime(df["ts"])
        for col in ("status", "bytes", "dst_port", "bytes_out", "pkts_out"):
            if col in df:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
        logs[name] = df
    return logs


def _f(host, stage, ts, family, detector, severity, actor, evidence) -> dict:
    return {"host": host, "stage": stage, "ts": pd.Timestamp(ts), "family": family,
            "detector": detector, "severity": severity, "actor": actor, "evidence": evidence}


# ------------------------------------------------- A. advisory (IOC) detectors ---
def advisory_detectors(logs: dict, threat: dict | None) -> list[dict]:
    if not threat:
        return []
    iocs = threat.get("iocs", {})
    ips = set(iocs.get("ips", [])) - PUBLIC_RESOLVERS
    domains = {d.lower() for d in iocs.get("domains", [])}
    ports = set(iocs.get("ports", []))
    name = threat.get("name", "advisory")
    # which stage does each indicator belong to, according to the advisory?
    ind_stage = {}
    for st in threat.get("stages", []):
        for ind in st.get("indicators", []):
            ind_stage.setdefault(str(ind).lower(), st.get("stage"))

    out = []
    web = logs["web"]
    for _, r in web[web["client_ip"].isin(ips)].iterrows():
        ok = 200 <= r.status < 300
        out.append(_f(r.host, "exploit_attempt", r.ts, "advisory", f"{name}: known attacker IP",
                      "high" if ok else "medium", r.client_ip,
                      f'{r.method} {r.path} -> HTTP {r.status} ({"SUCCEEDED" if ok else "failed"})'))
    conn = logs["conn"]
    hit = conn[conn["dst_ip"].isin(ips) | conn["dst_port"].isin(ports)]
    for _, r in hit.iterrows():
        stage = ind_stage.get(r.dst_ip) or ind_stage.get(str(r.dst_port)) or "c2_contact"
        if stage not in STAGES:
            stage = "c2_contact"
        out.append(_f(r.host, stage, r.ts, "advisory", f"{name}: connection to IOC",
                      "critical", r.dst_ip, f"{r.proto.upper()} -> {r.dst_ip}:{r.dst_port} {r.detail}".strip()))
    dns = logs["dns"]
    for _, r in dns[dns["query"].str.lower().isin(domains)].iterrows():
        out.append(_f(r.host, "c2_contact", r.ts, "advisory", f"{name}: C2 domain lookup",
                      "critical", r.query, f"DNS query {r.query}"))
    return out


# ---------------------------------------------------- B. behaviour detectors ---
def web_attack_patterns(logs) -> list[dict]:
    out = []
    for _, r in logs["web"].iterrows():
        for label, rx in WEB_PATTERNS.items():
            if rx.search(r.path):
                ok = 200 <= r.status < 300
                out.append(_f(r.host, "exploit_attempt", r.ts, "behaviour", label,
                              "high" if ok else "medium", r.client_ip,
                              f"{r.method} {r.path[:90]} -> HTTP {r.status}"))
                break
    return out


def brute_force(logs, threshold: int = 20, window: str = "5min") -> list[dict]:
    web = logs["web"]
    fails = web[(web["status"].isin([401, 403])) & web["path"].str.contains(LOGIN_PATH)]
    out = []
    for (host, ip), g in fails.groupby(["host", "client_ip"]):
        counts = g.set_index("ts").resample(window).size()
        if counts.max() >= threshold:
            out.append(_f(host, "exploit_attempt", g["ts"].min(), "behaviour", "Brute-force login",
                          "high", ip, f"{len(g)} failed logins (peak {counts.max()} in {window})"))
    return out


def recon_scan(logs, threshold: int = 30) -> list[dict]:
    web = logs["web"]
    nf = web[web["status"] == 404]
    out = []
    for (host, ip), g in nf.groupby(["host", "client_ip"]):
        if g["path"].nunique() >= threshold:
            out.append(_f(host, "recon", g["ts"].min(), "behaviour", "Vulnerability scan",
                          "low", ip, f"{g['path'].nunique()} different missing paths probed (e.g. /.env, /.git/config)"))
    return out


def web_shell(logs) -> list[dict]:
    web = logs["web"]
    out = []
    for _, r in web[web["path"].str.contains(WEB_SHELL)].iterrows():
        if 200 <= r.status < 300:
            out.append(_f(r.host, "web_shell", r.ts, "behaviour", "Web shell used",
                          "critical", r.client_ip, f"{r.method} {r.path[:90]}"))
    return out


def malware_download(logs) -> list[dict]:
    conn = logs["conn"]
    out = []
    for _, r in conn[conn["detail"].str.contains(EXECUTABLE)].iterrows():
        out.append(_f(r.host, "loader_download", r.ts, "behaviour", "Executable downloaded by server",
                      "critical", r.dst_ip, f"{r.dst_ip}:{r.dst_port} {r.detail}"))
    return out


def beaconing(logs, min_count: int = 8, max_jitter: float = 0.15) -> list[dict]:
    """Same host -> same rare ip:port at very regular intervals = botnet heartbeat."""
    conn = logs["conn"]
    out = []
    rare = conn[~conn["dst_port"].isin(COMMON_PORTS)]
    for (host, ip, port), g in rare.groupby(["host", "dst_ip", "dst_port"]):
        if len(g) < min_count:
            continue
        gaps = g["ts"].sort_values().diff().dt.total_seconds().dropna()
        if gaps.mean() > 0 and gaps.std() / gaps.mean() <= max_jitter:
            out.append(_f(host, "c2_contact", g["ts"].min(), "behaviour", "Botnet beaconing",
                          "critical", f"{ip}:{port}",
                          f"{len(g)} connections every ~{gaps.mean():.0f}s to rare port {port}"))
    return out


def ddos(logs, pkts_per_min: int = 50_000) -> list[dict]:
    conn = logs["conn"]
    out = []
    for host, g in conn.groupby("host"):
        per_min = g.set_index("ts")["pkts_out"].resample("1min").sum()
        if per_min.max() >= pkts_per_min:
            peak = per_min.idxmax()
            targets = ", ".join(sorted(g[g["pkts_out"] > 10_000]["dst_ip"].unique())[:3])
            out.append(_f(host, "ddos", peak, "behaviour", "Outbound flood (DDoS)",
                          "critical", targets, f"{int(per_min.max()):,} packets/min sent (normal < 1,000)"))
    return out


def odd_dns(logs) -> list[dict]:
    dns = logs["dns"]
    out = []
    for _, r in dns[dns["query"].str.lower().str.endswith(RARE_TLDS)].iterrows():
        out.append(_f(r.host, "c2_contact", r.ts, "behaviour", "Suspicious domain lookup",
                      "medium", r.query, f"DNS query to rare TLD: {r.query}"))
    return out


BEHAVIOUR_DETECTORS = [web_attack_patterns, brute_force, recon_scan, web_shell,
                       malware_download, beaconing, ddos, odd_dns]


# --------------------------------------------------------------- verdicts ---
def _ver(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return ()


def patch_status(php: str, threat: dict | None) -> str:
    if not threat or php in ("", "none"):
        return "n/a"
    branch = ".".join(php.split(".")[:2])
    if branch in threat.get("no_fix_branches", []):
        fixed = sorted(threat.get("fixed_versions", []), key=_ver)
        return f"❌ PHP {php}: NO PATCH exists - upgrade to {fixed[0] if fixed else 'a supported branch'}+"
    for f in threat.get("fixed_versions", []):
        if f.startswith(branch + "."):
            return (f"✅ PHP {php} is patched" if _ver(php) >= _ver(f)
                    else f"⚠️ PHP {php}: update to {f}")
    return f"⚠️ PHP {php}: check vendor advisory"


def hunt(logs: dict, threat: dict | None, blocked: set[str] | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run every detector. Returns (findings, per-host summary)."""
    blocked = blocked or set()
    findings = advisory_detectors(logs, threat)
    for det in BEHAVIOUR_DETECTORS:
        findings += det(logs)
    cols = ["host", "stage", "ts", "family", "detector", "severity", "actor", "evidence"]
    f = pd.DataFrame(findings, columns=cols)
    if not f.empty:
        f["actor_ip"] = f["actor"].str.split(":").str[0]
        f["prevented"] = f["actor_ip"].isin(blocked)
        f = f.drop_duplicates(["host", "stage", "ts", "actor", "detector"]).sort_values("ts")
    else:
        f["actor_ip"], f["prevented"] = [], []

    rows = []
    for _, h in logs["inventory"].iterrows():
        hf = f[f["host"] == h.host]
        live = hf[~hf["prevented"]]
        reached = [s for s in STAGES if s in set(live["stage"])]
        furthest = reached[-1] if reached else None
        if not len(hf):
            verdict = "🟢 SAFE"
        elif not len(live):
            verdict = "🛡️ PROTECTED (all attacker IPs blocked)"
        elif set(reached) & COMPROMISE_STAGES:
            verdict = "🔴 COMPROMISED"
        else:
            verdict = "🟡 ATTACKED (not compromised)"
        rows.append({"host": h.host, "ip": h.ip, "role": h.role, "php": h.php_version,
                     "verdict": verdict, "furthest_stage": STAGE_LABEL.get(furthest, "-"),
                     "stages": reached, "alerts": len(hf), "prevented": int(hf["prevented"].sum()),
                     "patch": patch_status(h.php_version, threat)})
    return f, pd.DataFrame(rows)


if __name__ == "__main__":
    import json
    threat = json.loads((Path(__file__).parent / "samples" / "threat_php2shell.json").read_text())
    findings, summary = hunt(load_logs(), threat)
    pd.set_option("display.width", 200, "display.max_colwidth", 70)
    print(summary[["host", "verdict", "furthest_stage", "alerts", "patch"]].to_string(index=False))
    print()
    print(findings.groupby(["host", "family", "detector"]).size().to_string())
