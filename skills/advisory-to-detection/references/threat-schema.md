# Threat file schema (First45)

```json
{
  "name": "PHP2Shell",
  "cves": ["CVE-2026-109618"],
  "cvss": 9.2,
  "summary": "one plain-English sentence",
  "product": "PHP engine (core)",
  "affected_versions": ["5.4 and later"],
  "fixed_versions": ["8.3.36"],
  "no_fix_branches": ["8.1"],
  "iocs": {"ips": ["92.118.112.100"], "domains": ["thunder.godofthunder.st"], "ports": [50792], "urls": []},
  "stages": [
    {"stage": "loader_download", "description": "...", "indicators": ["92.118.112.100"]}
  ],
  "actions": ["Patch to a fixed PHP version"]
}
```

`stage` is one of: `recon`, `exploit_attempt`, `web_shell`, `loader_download`, `c2_contact`, `ddos`.
Ports are integers. Unknown values are `null` or `[]`.
