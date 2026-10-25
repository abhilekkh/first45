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
- **TEAMMATE NAME** (add GitHub handle)

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
