# 🛡️ First45

**From security advisory to working defenses in 45 seconds — for teams with no security staff.**

On 21 Oct 2026, **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619, CVSS 9.2) was disclosed: unauthenticated remote code
execution in the PHP engine itself. Within **45 minutes**, Cloudflare saw tens of thousands of exploit attempts; within
two days, millions, many delivering a **Mirai botnet** variant. Colleges, student clubs and small hospitals don't have a
security team to read the advisory, write detection rules and check their servers in time.

First45 does that job, using an **open-weight model (Gemma 4)** at its core:

| # | Step | What First45 does |
|---|------|-------------------|
| 1 | **Read** | Paste any advisory: text, PDF or **screenshot**. Gemma 4 extracts CVEs, affected/fixed versions, indicators (IPs, domains, ports) and attack stages into strict JSON. Every indicator is **checked against the advisory text** to catch AI hallucinations. |
| 2 | **Defend** | Generates rules in **open standards**: Sigma (SIEM), Suricata (IDS), nginx deny list, nftables / Windows firewall commands. |
| 3 | **Hunt** | Scans server logs with advisory detectors **plus 8 behaviour detectors that need no advisory** (web exploits, brute force, scanning, web shells, malware downloads, botnet beaconing, DDoS, suspicious DNS) and shows a **kill-chain timeline** per server. |
| 4 | **Respond** | Verdict per server, patch status ("PHP 8.1: no patch exists, upgrade"), push alerts, **human-approved blocking** with an audit log, and a plain-English **incident report written by Gemma 4**. |

> **AI recommends, a human decides.** Nothing is blocked without approval. First45 never changes a system firewall by itself.

## How it works

```
advisory (text / PDF / screenshot)
   │  gemma_client.extract_threat()  ── Gemma 4 via Gemini API ──►  threat JSON  ──► verify_iocs()
   ▼
rules.py ──► Sigma · Suricata · nginx deny · nftables / netsh
   ▼
hunt.py  ◄── server logs (web, DNS, connections, inventory)
   │  A. advisory detectors (IOCs)   B. behaviour detectors (no advisory needed)
   ▼
kill chain per host:  🔍 recon → 🟡 exploit → 🟠 web shell → 🔴 malware → 🔴 C2 → ⚫ DDoS
   ▼
protect.py (approve / undo / audit)   notify.py (ntfy / Discord)   gemma_client.write_report()
   ▼
app.py (Streamlit UI)                 skills/advisory-to-detection (Agent Skill for any AI agent)
```

### Where the AI is used (easy to verify)

| Step | File → function | AI? |
|------|-----------------|-----|
| Read advisory → threat JSON | `gemma_client.py` → `extract_threat()` | **Gemma 4** (`gemma-4-26b-a4b-it`) via Gemini API |
| Hallucination check | `gemma_client.py` → `verify_iocs()` | No |
| Rule generation | `rules.py` | No (deterministic templates) |
| Log hunting | `hunt.py` | No (explainable detectors) |
| Blocking | `protect.py` | No (**human approval**) |
| Incident report | `gemma_client.py` → `write_report()` | **Gemma 4** |

## Open-source AI used

| Model | Role | Licence / terms |
|-------|------|-----------------|
| **Gemma 4** — `gemma-4-26b-a4b-it` (26B MoE, ~4B active), open weights | Reads advisories (text and images), writes incident reports | **Apache 2.0** — [announcement](https://opensource.googleblog.com/2026/03/gemma-4-expanding-the-gemmaverse-with-apache-20.html) · [model docs](https://ai.google.dev/gemma/docs/core) |

### Best Use of Gemma 4: how we call it

Gemma 4 is called through the **Gemini API** with Google's `google-genai` SDK (`gemma_client.py` → `_generate()`):

```python
from google import genai
client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
client.models.generate_content(model="gemma-4-26b-a4b-it", contents=[THREAT_PROMPT, image_part])
```

Multimodal: advisory **screenshots** are sent as image parts (`types.Part.from_bytes`), and Gemma copies their text into
`advisory_text` so the hallucination check still works.

### Agent Skill (Agent Skills open standard)

[`skills/advisory-to-detection/`](skills/advisory-to-detection/SKILL.md) lets **any skills-compatible AI agent** turn an
advisory into verified indicators, rules and a log hunt. Validated with the reference validator:
`skills-ref validate skills/advisory-to-detection` → *Valid skill*.

## Libraries, APIs and data

| Component | Licence | Used for |
|-----------|---------|----------|
| [google-genai](https://github.com/googleapis/python-genai) | Apache-2.0 | Gemini API client |
| [psutil](https://github.com/giampaolo/psutil) | BSD-3-Clause | Device Guard: connections and processes on this computer |
| [Streamlit](https://github.com/streamlit/streamlit) | Apache-2.0 | Web UI |
| [pandas](https://github.com/pandas-dev/pandas) | BSD-3-Clause | Log analysis |
| [PyYAML](https://github.com/yaml/pyyaml) | MIT | Sigma YAML |
| [pypdf](https://github.com/py-pdf/pypdf) | BSD-3-Clause | PDF advisories |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | BSD-3-Clause | Loads API key |
| [requests](https://github.com/psf/requests) | Apache-2.0 | Push alerts |
| [Pillow](https://github.com/python-pillow/Pillow) | MIT-CMU | Images |
| [Sigma](https://github.com/SigmaHQ/sigma-specification) rule format | DRL 1.1 (rules) / spec | Output format |
| [Suricata](https://suricata.io) rule syntax | GPL-2.0 (engine) | Output format |
| [ntfy](https://ntfy.sh) | Apache-2.0 / GPL-2.0 | Optional phone alerts |
| Gemini API (Google) | [Gemini API terms](https://ai.google.dev/gemini-api/terms) | Serves Gemma 4 |
| **Data:** `demo_logs/` | MIT (ours) | **Synthetic** logs we generated during the event (`make_demo_logs.py`); exploit payloads redacted |
| **Data:** PHP2Shell indicators | public reporting | From [The Hacker News](https://thehackernews.com/2026/10/php2shell-exploit-attempts-hit-millions.html), [Patchstack](https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/), [Picus](https://www.picussecurity.com/resource/php2shell-the-two-critical-php-rce-flaws-cve-2026-109618-cve-2026-109619-explained), [watchTowr](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/) |

Full list in [NOTICE.md](NOTICE.md).

## Prove it on real attacks: the live test lab

The demo network in step 02 is synthetic (safe, offline). To remove any doubt that detection
is real and not hard-coded, step 02 also offers **"Live attack on a local test site (OWASP
Juice Shop)"**. This mirrors how security products are demoed on testbeds: attack a target you
own, never a third party.

| Piece | What it is |
|---|---|
| Target | **OWASP Juice Shop** (the industry-standard intentionally-vulnerable web app), started in Docker on `127.0.0.1:3000` |
| Collector | A small **logging reverse proxy** (`lab.py`) in front of the target, writing a real nginx-format access log, the way a WAF or reverse proxy sits in front of a web server |
| Attacker | A controlled OWASP-style script that sends **real HTTP requests**: endpoint/file **recon scan**, **SQL injection**, **XSS**, **path traversal**, and a **brute-force** login run |
| Detector | First45's own `hunt.py` reads the real log it produced, with nothing pre-written |

One click (**Start test lab**) pulls and runs the container; **Launch live attack** fires the
requests and takes you to the results. Everything stays on `127.0.0.1`. Juice Shop is built to
be attacked, so this is legal and safe; First45 never touches a server it does not own. The
attacker's source IP is shown as `203.0.113.66`, an address reserved for documentation (RFC 5737),
so the block step has a realistic, blockable IP to act on.

What it shows: recon -> exploit attempt on genuine traffic, then **Block -> Protected** on a
re-scan. The later kill-chain stages (web shell, malware, C2, DDoS) need host/network data, which
is exactly what **Device Guard** demonstrates with its simulator. The two halves cover the full
chain between them. Requires Docker Desktop running; the image is downloaded once (~250 MB).

## Device Guard: is THIS computer part of a botnet?

Server logs show attacks from the outside. **Device Guard** (sidebar page in the app) looks from the inside:
it watches every network connection on the computer for 10-60 seconds, links each one to the program that
opened it ([psutil](https://github.com/giampaolo/psutil)), and checks for botnet behaviour with
deterministic, explainable rules (`device_guard.py`):

| Kill-chain stage | Detector | Rule |
|---|---|---|
| Malware landed | Runs from a temp/download folder | program path is in Temp / Downloads / Public |
| Phones home | Talks to advisory attacker IP / C2 port | IOCs extracted by Gemma 4 **and verified** against the advisory |
| Phones home | Botnet beaconing | 4+ new connections to one server, 70 % of them on a steady rhythm |
| Phones home | Botnet port open | listening on a Mirai port (23, 2323, 48101) or an advisory port |
| Scans to spread | Scanning to spread | 20+ different IPs on one non-web port, at least half never answer (SYN_SENT) |
| Floods a target | Outbound flood | 100+ simultaneous connections to one target |

**Prevention is human-approved:** tick "I approve" → **Stop program** (no admin needed for your own programs), or
**Block in firewall** (Windows Firewall rule in + out when First45 runs as administrator; otherwise the exact
`netsh` command is shown). Every action goes to `state/device_audit.log` with who approved it, and firewall
blocks have one-click **Undo**. **Keep guarding** re-scans continuously and sends an ntfy/Discord alert on new
botnet behaviour. **Explain with Gemma 4** turns the findings into a plain-English incident note.

**Safe demo:** `simulate_bot.py` (or **Start simulator** in the sidebar) imitates a Mirai-style bot using
**only 127.0.0.1**: a fake C2 on port 50792 (the C2 port named in the PHP2Shell advisory) and a "bot" copied
into Temp that beacons every 3 s and bursts 120 connections. Tick **Include loopback** and scan. Nothing leaves
the computer.

```bash
python simulate_bot.py                      # safe fake bot (Ctrl+C to stop)
python device_guard.py --seconds 20 --loopback   # same check from the command line
```

## How to run

Requires Python 3.10+ and a free Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey).

```bash
git clone https://github.com/abhilekkh/first45.git
cd first45
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then put your key in GEMINI_API_KEY=
streamlit run app.py
```

Windows shortcut: double-click `run_app.bat`.

Command line:

```bash
python gemma_client.py samples/php2shell_advisory.txt     # advisory -> threat JSON (Gemma 4)
python rules.py                                           # rules for the PHP2Shell sample
python hunt.py                                            # hunt the demo logs
python make_demo_logs.py                                  # regenerate synthetic logs
```

The PHP2Shell sample loads a saved Gemma 4 result instantly (the live call takes about a minute); use
**Re-run Gemma 4 live** in the sidebar to call the model again.

## Safety and ethics

- Defensive only: detect, alert, block, report. **No exploit code, no malware, no scanning of anyone else's systems.**
- Demo logs are synthetic. Attacker IPs are public indicators from published reporting, or documentation ranges
  (198.51.100.0/24, 203.0.113.0/24).
- Blocking needs a named human approver and is logged in `state/audit.log` with undo.
- API keys live in `.env`, which is git-ignored.

## Team

- **Abhilekkh Krishna** ([@abhilekkh](https://github.com/abhilekkh))
- **Jacob Mathew** ([@JacobMathewCS](https://github.com/JacobMathewCS))

Built at **Hacktoberfest x MOSS Hack Day Udupi**, 25 October 2026.

## AI assistance (disclosure)

AI coding tools used to **build** First45 (these are not part of the open-source AI inside the project):

| Tool | What it produced |
|------|------------------|
| **Claude** (Anthropic, via the Claude app) | First drafts of all code files (`gemma_client.py`, `hunt.py`, `rules.py`, `protect.py`, `notify.py`, `app.py`, `make_demo_logs.py`, skill scripts), the Agent Skill `SKILL.md`, this README, NOTICE and CONTRIBUTING, and the PHP2Shell advisory summary in `samples/` (compiled from the cited public sources). |

The team chose the idea and scope, made the design decisions, set up the API key and environment, ran and tested every
step, reviewed the code, and can explain every file. *(Add any other AI tools you used here.)*

## License

[MIT](LICENSE) © 2026 First45 contributors.
