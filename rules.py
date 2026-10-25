"""First45 - rule generator.

Turns the threat JSON (from Gemma 4) into ready-to-deploy defenses in OPEN formats:
  * Sigma      - open SIEM rule standard (github.com/SigmaHQ/sigma)
  * Suricata   - open-source IDS/IPS rule syntax
  * nginx      - deny list for the web server
  * firewall   - nftables (Linux) and netsh (Windows) egress blocks

Templates are deterministic: the AI decides WHAT to block (from the advisory),
plain code decides HOW to write it, so the output is always valid syntax.
"""
from __future__ import annotations

import re
import uuid
from datetime import date

import yaml

PUBLIC_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "threat"


def _iocs(threat: dict) -> tuple[list[str], list[str], list[int]]:
    i = threat.get("iocs", {})
    ips = sorted(set(i.get("ips", [])) - PUBLIC_RESOLVERS)
    return ips, sorted(i.get("domains", [])), sorted(i.get("ports", []))


def sigma_rules(threat: dict) -> str:
    """Three Sigma rules: network connection, DNS query, web access from attackers."""
    name = threat.get("name", "Threat")
    refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in threat.get("cves", [])]
    ips, domains, ports = _iocs(threat)
    tags = ["attack.command-and-control"] + [f"cve.{c.lower().removeprefix('cve-')}" for c in threat.get("cves", [])]
    base = {"status": "experimental", "author": "First45 (auto-generated from advisory)",
            "date": date.today().isoformat(), "references": refs, "tags": tags}
    docs = []
    if ips or ports:
        sel = {}
        if ips:
            sel["selection_ip"] = {"DestinationIp": ips}
        if ports:
            sel["selection_port"] = {"DestinationPort": ports}
        docs.append({"title": f"{name} - outbound connection to known infrastructure",
                     "id": str(uuid.uuid5(uuid.NAMESPACE_URL, name + "net")), **base,
                     "logsource": {"category": "network_connection"},
                     "detection": {**sel, "condition": " or ".join(sel)},
                     "falsepositives": ["Unlikely"], "level": "critical"})
    if domains:
        docs.append({"title": f"{name} - DNS lookup of C2 domain",
                     "id": str(uuid.uuid5(uuid.NAMESPACE_URL, name + "dns")), **base,
                     "logsource": {"category": "dns_query"},
                     "detection": {"selection": {"QueryName": domains}, "condition": "selection"},
                     "falsepositives": ["Security researchers"], "level": "critical"})
    if ips:
        docs.append({"title": f"{name} - web request from known exploit source",
                     "id": str(uuid.uuid5(uuid.NAMESPACE_URL, name + "web")), **base,
                     "logsource": {"category": "webserver"},
                     "detection": {"selection": {"c-ip": ips}, "condition": "selection"},
                     "falsepositives": ["Shared/proxy IPs"], "level": "high"})
    return yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True)


def suricata_rules(threat: dict, sid_base: int = 4_500_000) -> str:
    name = threat.get("name", "Threat")
    cves = ",".join(threat.get("cves", []))
    ips, domains, ports = _iocs(threat)
    lines = [f"# First45 Suricata rules for {name} ({cves})"]
    sid = sid_base
    if ips:
        sid += 1
        lines.append(f'alert ip $HOME_NET any -> [{",".join(ips)}] any '
                     f'(msg:"First45 {name} - traffic to known attacker infrastructure"; '
                     f'classtype:trojan-activity; sid:{sid}; rev:1;)')
        sid += 1
        lines.append(f'alert http [{",".join(ips)}] any -> $HOME_NET any '
                     f'(msg:"First45 {name} - request from known exploit source"; '
                     f'classtype:attempted-admin; sid:{sid}; rev:1;)')
    for p in ports:
        sid += 1
        lines.append(f'alert tcp $HOME_NET any -> $EXTERNAL_NET {p} '
                     f'(msg:"First45 {name} - outbound to C2 port {p}"; flow:to_server; '
                     f'classtype:trojan-activity; sid:{sid}; rev:1;)')
    for d in domains:
        sid += 1
        lines.append(f'alert dns $HOME_NET any -> any any (msg:"First45 {name} - C2 domain {d}"; '
                     f'dns.query; content:"{d}"; nocase; classtype:trojan-activity; sid:{sid}; rev:1;)')
    return "\n".join(lines) + "\n"


def nginx_deny(ips: list[str], title: str) -> str:
    body = "\n".join(f"deny {ip};" for ip in ips) or "# (no IPs)"
    return f"# First45 - {title}\n# include this file inside your server {{ }} block\n{body}\n"


def firewall_commands(threat: dict) -> str:
    ips, _, ports = _iocs(threat)
    name = _slug(threat.get("name", "threat"))
    out = ["# ---- Linux (nftables) ----",
           "nft add table inet first45",
           "nft add chain inet first45 out '{ type filter hook output priority 0; }'",
           "nft add chain inet first45 in '{ type filter hook input priority 0; }'"]
    for ip in ips:
        out += [f"nft add rule inet first45 out ip daddr {ip} drop comment \"{name}\"",
                f"nft add rule inet first45 in ip saddr {ip} drop comment \"{name}\""]
    for p in ports:
        out.append(f"nft add rule inet first45 out tcp dport {p} drop comment \"{name}\"")
    out += ["", "# ---- Windows (run as Administrator) ----"]
    if ips:
        out.append(f'netsh advfirewall firewall add rule name="First45 {name} out" dir=out action=block '
                   f'remoteip={",".join(ips)}')
        out.append(f'netsh advfirewall firewall add rule name="First45 {name} in" dir=in action=block '
                   f'remoteip={",".join(ips)}')
    for p in ports:
        out.append(f'netsh advfirewall firewall add rule name="First45 {name} port {p}" dir=out '
                   f'action=block protocol=TCP remoteport={p}')
    return "\n".join(out) + "\n"


def all_rules(threat: dict) -> dict[str, str]:
    """filename -> content, for display and download."""
    slug = _slug(threat.get("name", "threat"))
    ips, _, _ = _iocs(threat)
    return {
        f"{slug}.sigma.yml": sigma_rules(threat),
        f"{slug}.rules": suricata_rules(threat),
        f"{slug}.nginx-deny.conf": nginx_deny(ips, threat.get("name", "")),
        f"{slug}.firewall.txt": firewall_commands(threat),
    }


if __name__ == "__main__":
    import json
    from pathlib import Path
    t = json.loads((Path(__file__).parent / "samples" / "threat_php2shell.json").read_text())
    for fname, text in all_rules(t).items():
        print(f"===== {fname} =====\n{text}")
