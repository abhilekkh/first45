"""First45 - threat-intelligence enrichment.

Features borrowed from the tools a real SOC uses, built in open formats so a small
team gets the same context without a paid platform:

  1. MITRE ATT&CK mapping   - every First45 detector / kill-chain stage -> ATT&CK
                              technique IDs, the way SIEMs (Elastic, Sentinel) and
                              Sigma rules tag detections.
  2. CISA KEV enrichment    - is this CVE in CISA's Known Exploited Vulnerabilities
                              catalog? That is the strongest "exploited in the wild"
                              signal for prioritisation. Cached on disk; degrades to
                              "unknown" when offline.
  3. STIX 2.1 export        - the advisory's IOCs as a STIX bundle, so they import
                              straight into MISP / OpenCTI and other intel platforms.

Everything here is deterministic and explainable. No AI is used in this file.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE = ROOT / "state"
KEV_CACHE = STATE / "kev_catalog.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = 24 * 3600          # refresh the cached catalog at most once a day

# ------------------------------------------------------- MITRE ATT&CK map ---
# Kill-chain stage -> (technique id, technique name). Coarse, always available.
STAGE_ATTACK = {
    "recon": ("T1595", "Active Scanning"),
    "exploit_attempt": ("T1190", "Exploit Public-Facing Application"),
    "web_shell": ("T1505.003", "Server Software Component: Web Shell"),
    "loader_download": ("T1105", "Ingress Tool Transfer"),
    "c2_contact": ("T1071", "Application Layer Protocol"),
    "ddos": ("T1498", "Network Denial of Service"),
}
# Detector name (substring) -> (technique id, technique name). Finer-grained.
DETECTOR_ATTACK = {
    "SQL injection": ("T1190", "Exploit Public-Facing Application"),
    "Path traversal": ("T1083", "File and Directory Discovery"),
    "Command injection": ("T1059", "Command and Scripting Interpreter"),
    "Cross-site scripting": ("T1059.007", "Command and Scripting Interpreter: JavaScript"),
    "Brute-force login": ("T1110", "Brute Force"),
    "Vulnerability scan": ("T1595.002", "Active Scanning: Vulnerability Scanning"),
    "Web shell": ("T1505.003", "Server Software Component: Web Shell"),
    "Executable downloaded": ("T1105", "Ingress Tool Transfer"),
    "Botnet beaconing": ("T1071", "Application Layer Protocol"),
    "Outbound flood": ("T1498", "Network Denial of Service"),
    "Suspicious domain lookup": ("T1071.004", "Application Layer Protocol: DNS"),
    "known attacker IP": ("T1190", "Exploit Public-Facing Application"),
    "connection to IOC": ("T1071", "Application Layer Protocol"),
    "C2 domain lookup": ("T1071.004", "Application Layer Protocol: DNS"),
    # Device Guard detectors
    "advisory attacker IP": ("T1071", "Application Layer Protocol"),
    "advisory C2 port": ("T1571", "Non-Standard Port"),
    "Botnet port open": ("T1571", "Non-Standard Port"),
    "Scanning to spread": ("T1046", "Network Service Discovery"),
    "temp/download folder": ("T1105", "Ingress Tool Transfer"),
}


def technique_url(tid: str) -> str:
    """ATT&CK web page for a technique (sub-techniques use the /PARENT/SUB/ form)."""
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def technique_for_detector(detector: str) -> tuple[str, str] | None:
    for key, tech in DETECTOR_ATTACK.items():
        if key.lower() in (detector or "").lower():
            return tech
    return None


def techniques_for_stages(stages) -> list[tuple[str, str]]:
    """Unique (id, name) techniques for a set/list of kill-chain stages, in order."""
    out, seen = [], set()
    for s in stages:
        tech = STAGE_ATTACK.get(s)
        if tech and tech[0] not in seen:
            seen.add(tech[0])
            out.append(tech)
    return out


# ------------------------------------------------------- CISA KEV lookup ---
def _load_kev_cache() -> dict | None:
    try:
        data = json.loads(KEV_CACHE.read_text(encoding="utf-8"))
        if time.time() - data.get("_fetched_at", 0) <= KEV_MAX_AGE:
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def _refresh_kev() -> dict | None:
    """Download the KEV catalog and cache it. Returns the parsed catalog or None."""
    try:
        import requests
        resp = requests.get(KEV_URL, timeout=20, headers={
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")})
        resp.raise_for_status()
        catalog = resp.json()
    except Exception:                       # offline / blocked / bad JSON: use any stale cache
        try:
            return json.loads(KEV_CACHE.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
    index = {v.get("cveID"): v for v in catalog.get("vulnerabilities", []) if v.get("cveID")}
    out = {"_fetched_at": time.time(), "count": len(index), "index": index}
    try:
        STATE.mkdir(exist_ok=True)
        KEV_CACHE.write_text(json.dumps(out), encoding="utf-8")
    except OSError:
        pass
    return out


def kev_status(cves: list[str]) -> dict:
    """For each CVE, is it in CISA's Known Exploited Vulnerabilities catalog?

    Returns {"available": bool, "hits": [{"cve","dateAdded","name","ransomware"}...],
             "checked": [cve...]}. "available" is False when we have no catalog at all.
    """
    cves = [c for c in (cves or []) if c]
    cat = _load_kev_cache() or _refresh_kev()
    if not cat or "index" not in cat:
        return {"available": False, "hits": [], "checked": cves}
    index = cat["index"]
    hits = []
    for cve in cves:
        v = index.get(cve)
        if v:
            hits.append({"cve": cve, "dateAdded": v.get("dateAdded", "?"),
                         "name": v.get("vulnerabilityName", ""),
                         "ransomware": v.get("knownRansomwareCampaignUse", "Unknown")})
    return {"available": True, "hits": hits, "checked": cves}


# ----------------------------------------------------------- STIX export ---
def stix_bundle(threat: dict) -> str:
    """The advisory's indicators as a STIX 2.1 bundle (imports into MISP / OpenCTI)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objs: list[dict] = []

    def ind(pattern: str, name: str, itype: str) -> None:
        objs.append({"type": "indicator", "spec_version": "2.1",
                     "id": f"indicator--{uuid.uuid4()}", "created": now, "modified": now,
                     "name": name, "pattern_type": "stix", "pattern": pattern,
                     "valid_from": now, "labels": ["malicious-activity"],
                     "x_first45_indicator_type": itype})

    iocs = threat.get("iocs", {}) if threat else {}
    for ip in iocs.get("ips", []):
        ind(f"[ipv4-addr:value = '{ip}']", f"Attacker IP {ip}", "ipv4")
    for dom in iocs.get("domains", []):
        ind(f"[domain-name:value = '{dom}']", f"C2 domain {dom}", "domain")
    for url in iocs.get("urls", []):
        ind(f"[url:value = '{url}']", f"Malicious URL {url}", "url")
    for cve in (threat or {}).get("cves", []):
        objs.append({"type": "vulnerability", "spec_version": "2.1",
                     "id": f"vulnerability--{uuid.uuid4()}", "created": now, "modified": now,
                     "name": cve, "external_references": [
                         {"source_name": "cve", "external_id": cve}]})
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}
    return json.dumps(bundle, indent=2)


if __name__ == "__main__":                 # quick self-check
    t = json.loads((ROOT / "samples" / "threat_php2shell.json").read_text(encoding="utf-8"))
    print("ATT&CK for stages:", techniques_for_stages(["recon", "exploit_attempt", "c2_contact"]))
    print("KEV:", {k: v for k, v in kev_status(t.get("cves", [])).items() if k != "checked"})
    print("STIX objects:", json.loads(stix_bundle(t))["objects"].__len__())
