---
name: advisory-to-detection
description: Turns a security advisory, CVE write-up or threat-intel news article into working defenses. Extracts CVEs, affected and fixed versions, indicators of compromise (IPs, domains, ports, URLs) and kill-chain stages into a strict JSON threat file, verifies every indicator against the source text, then generates Sigma, Suricata, nginx deny and firewall rules and hunts server logs for the attack. Use when the user shares a vulnerability advisory, asks "are we affected", asks for detection rules, IOC blocklists, or wants to check logs for a known campaign (for example PHP2Shell or Mirai botnets).
license: MIT
compatibility: Requires Python 3.10+ with PyYAML and pandas, run from the First45 repository root (github.com/abhilekkh/first45).
metadata:
  author: first45
  version: "0.1"
---

# Advisory to detection

Defensive skill. Never write or run exploit code, never download malware, never scan systems the user does not own,
and never block anything without the user's explicit approval.

## Steps

1. **Get the advisory text.** If the user gives a URL, fetch the page text. If they give a PDF or screenshot, read its text.
2. **Extract a threat file.** Produce one JSON object that follows [the threat schema](references/threat-schema.md) and save it,
   for example as `threat.json`.
   - Copy every IP, domain, port and version exactly from the advisory. Never invent one.
   - Refang indicators (`92.118.112[.]100` -> `92.118.112.100`).
   - Do not list public DNS resolvers (8.8.8.8, 1.1.1.1, 1.0.0.1) as attacker IPs.
3. **Verify.** Run `python skills/advisory-to-detection/scripts/verify.py threat.json advisory.txt`.
   Remove or flag every indicator it reports as `UNVERIFIED`.
4. **Generate defenses.** Run `python skills/advisory-to-detection/scripts/make_rules.py threat.json out/`.
   This writes Sigma (`.sigma.yml`), Suricata (`.rules`), nginx deny and firewall command files.
5. **Hunt (optional).** If the user has logs in First45's TSV format (see `demo_logs/`), run
   `python skills/advisory-to-detection/scripts/hunt_logs.py threat.json demo_logs/` and summarise each host's verdict.
6. **Respond.** Tell the user, in plain language: are they affected, which version to upgrade to (say clearly when a branch
   has no patch), which hosts show compromise, and which blocks you recommend. Ask before applying any block.

## Example

Input: a news article about PHP2Shell (CVE-2026-109618/109619).
Output: `threat.json` with 6 attacker IPs, 1 C2 domain, ports 50792 and 9999, fixed versions 8.5.12/8.4.27/8.3.36/8.2.35,
no-fix branches 7.4/8.0/8.1, then 3 Sigma rules, 5 Suricata rules and a firewall block list.

## Edge cases

- Advisory has no indicators (only versions): skip IOC rules, still report patch status.
- Indicator appears only in an image: mark it unverified unless the user confirms it.
- Shared hosting or CDN IPs: warn about false positives before recommending a block.
