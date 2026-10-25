"""First45 - Gemma 4 client.

Every call to the AI model lives in this one file, so anyone (including judges)
can verify exactly where and how the open-weight model is used.

Model : Gemma 4 (open weights, Apache 2.0), served through the Gemini API.
SDK   : google-genai (Apache 2.0).

Two jobs:
  1. extract_threat()  advisory (text, PDF text or screenshot) -> structured threat JSON
  2. write_report()    threat JSON + hunt findings -> plain-English incident report

Usage (command line):
  python gemma_client.py samples/php2shell_advisory.txt
  python gemma_client.py advisory.png
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

DEFAULT_MODEL = "gemma-4-26b-a4b-it"
MODEL = os.getenv("GEMMA_MODEL", DEFAULT_MODEL)

# The five kill-chain stages First45 understands (in attack order).
STAGES = ["recon", "exploit_attempt", "web_shell", "loader_download", "c2_contact", "ddos"]

THREAT_PROMPT = """You are a security analyst helping a small college IT team.
Read the security advisory and extract the facts.

Return ONLY one JSON object (no markdown, no explanation) with exactly these keys:
{
  "name": "short threat name",
  "cves": ["CVE-..."],
  "cvss": 9.2,
  "summary": "one plain-English sentence a non-expert understands",
  "product": "affected software",
  "affected_versions": ["..."],
  "fixed_versions": ["8.3.36"],
  "no_fix_branches": ["7.4"],
  "iocs": {"ips": ["1.2.3.4"], "domains": ["evil.example"], "ports": [50792], "urls": []},
  "stages": [
    {"stage": "exploit_attempt", "description": "...", "indicators": ["..."]}
  ],
  "actions": ["short recommended action"],
  "advisory_text": ""
}

Rules:
- "stage" must be one of: recon, exploit_attempt, web_shell, loader_download, c2_contact, ddos.
- Copy every IP, domain, port and version EXACTLY from the advisory. Never invent one.
- Write IPs and domains without defang brackets: 92.118.112.100, not 92.118.112[.]100.
- Public DNS resolvers (8.8.8.8, 1.1.1.1, 1.0.0.1) are NOT attacker IPs: leave them out of iocs.ips.
- If a fact is missing, use null or an empty list.
- "advisory_text": if the advisory is an IMAGE, copy all of its visible text here; otherwise "".
"""

REPORT_PROMPT = """You are writing an incident report for a college IT admin who is not a security expert.
Use ONLY the facts in THREAT and FINDINGS below. Do not add any IP, version or fact that is not there.

Write Markdown with these sections:
## Verdict
One line per host: SAFE / SCANNED ONLY / COMPROMISED, with the furthest kill-chain stage reached.
## What happened
A short timeline for each affected host, in plain English.
## Do this now
Numbered, concrete steps (patch to which version, isolate which host, block what).
## Why it matters
Two sentences, no jargon.

THREAT:
{threat}

FINDINGS:
{findings}
"""


# ----------------------------------------------------------------- helpers ---
def refang(text: str) -> str:
    """Turn defanged indicators back into normal ones: 1.2.3[.]4 -> 1.2.3.4"""
    return (text.replace("[.]", ".").replace("(.)", ".")
                .replace("hxxp", "http").replace("[:]", ":"))


def _client() -> genai.Client:
    key = os.getenv("GEMINI_API_KEY", "")
    if not key or key.startswith("paste"):
        raise RuntimeError("GEMINI_API_KEY is missing. Put your key in .env (see .env.example).")
    return genai.Client(api_key=key)


def _generate(contents, temperature: float = 0.1, retries: int = 2) -> str:
    """One Gemma 4 call through the Gemini API, with simple retry."""
    client = _client()
    last_error = None
    for attempt in range(retries + 1):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=contents,
                config=types.GenerateContentConfig(temperature=temperature),
            )
            return response.text or ""
        except Exception as error:  # network / rate limit / server error
            last_error = error
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Gemma call failed after {retries + 1} tries: {last_error}")


def _parse_json(raw: str) -> dict:
    """Gemma sometimes wraps JSON in ```json fences or adds a sentence. Take the outer {...}."""
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object in model output")
    return json.loads(raw[start:end + 1])


def _clean(threat: dict) -> dict:
    """Normalise types and drop anything outside our schema."""
    iocs = threat.get("iocs") or {}
    ports = []
    for p in iocs.get("ports") or []:
        try:
            ports.append(int(str(p).strip()))
        except ValueError:
            pass
    threat["iocs"] = {
        "ips": sorted({refang(str(i)).strip() for i in iocs.get("ips") or []}),
        "domains": sorted({refang(str(d)).strip().lower() for d in iocs.get("domains") or []}),
        "ports": sorted(set(ports)),
        "urls": sorted({refang(str(u)).strip() for u in iocs.get("urls") or []}),
    }
    threat["stages"] = [s for s in threat.get("stages") or [] if s.get("stage") in STAGES]
    for key in ("cves", "affected_versions", "fixed_versions", "no_fix_branches", "actions"):
        threat[key] = [str(x) for x in threat.get(key) or []]
    return threat


def verify_iocs(threat: dict, source_text: str) -> dict:
    """Anti-hallucination check: every indicator must appear in the advisory text itself."""
    source = refang(source_text).lower()
    verified, unverified = [], []
    iocs = threat["iocs"]
    for value in iocs["ips"] + iocs["domains"] + iocs["urls"] + [str(p) for p in iocs["ports"]]:
        (verified if value.lower() in source else unverified).append(value)
    for version in threat["fixed_versions"]:
        (verified if version.lower() in source else unverified).append(version)
    return {"verified": verified, "unverified": unverified}


# -------------------------------------------------------------- public API ---
def extract_threat(text: str | None = None, image_bytes: bytes | None = None,
                   mime_type: str = "image/png") -> dict:
    """Advisory -> threat dict. Give either text or an image (screenshot of an advisory)."""
    if not text and not image_bytes:
        raise ValueError("Give advisory text or an image")
    started = time.time()

    if image_bytes:
        contents = [THREAT_PROMPT,
                    types.Part.from_bytes(data=image_bytes, mime_type=mime_type)]
    else:
        contents = THREAT_PROMPT + "\n\nADVISORY:\n" + text

    raw = _generate(contents)
    try:
        threat = _parse_json(raw)
    except (ValueError, json.JSONDecodeError):
        # One repair attempt: show Gemma its own output and ask for valid JSON only.
        raw = _generate(f"Return ONLY valid JSON for this, nothing else:\n{raw}")
        threat = _parse_json(raw)

    threat = _clean(threat)
    source_text = text or threat.get("advisory_text") or ""
    threat["_meta"] = {
        "model": MODEL,
        "input": "image" if image_bytes else "text",
        "seconds": round(time.time() - started, 1),
        "ioc_check": verify_iocs(threat, source_text),
    }
    return threat


def write_report(threat: dict, findings: list[dict]) -> str:
    """Threat + per-host findings -> Markdown incident report written by Gemma 4."""
    slim = {k: v for k, v in threat.items() if k not in ("_meta", "advisory_text")}
    prompt = REPORT_PROMPT.format(threat=json.dumps(slim, indent=2),
                                  findings=json.dumps(findings, indent=2, default=str))
    return _generate(prompt, temperature=0.3).strip()


def read_pdf_text(pdf_bytes: bytes) -> str:
    """PDF advisory -> plain text (Gemma then reads the text)."""
    from io import BytesIO
    from pypdf import PdfReader
    reader = PdfReader(BytesIO(pdf_bytes))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


# --------------------------------------------------------------------- CLI ---
def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = Path(sys.argv[1])
    mime = mimetypes.guess_type(path.name)[0] or ""
    if mime.startswith("image/"):
        threat = extract_threat(image_bytes=path.read_bytes(), mime_type=mime)
    elif mime == "application/pdf":
        threat = extract_threat(text=read_pdf_text(path.read_bytes()))
    else:
        threat = extract_threat(text=path.read_text(encoding="utf-8"))
    print(json.dumps(threat, indent=2))


if __name__ == "__main__":
    main()
