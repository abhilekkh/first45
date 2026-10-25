# Contributing to First45

Thanks for helping small teams defend themselves! First45 is part of **Hacktoberfest**: beginner PRs welcome.

## Setup

See **How to run** in the README. You need a free Gemini API key only for the AI steps; the hunt engine, rules and
demo logs work without one (`python hunt.py`, `python rules.py`).

## Good first issues

- **New behaviour detector**: e.g. detect cryptominer pool connections (ports 3333/4444/5555) in `hunt.py`.
- **New output format**: add a Zeek or ModSecurity rule generator in `rules.py`.
- **Real log formats**: parse nginx/Apache *combined* access logs into First45's `web.tsv` columns.
- **More languages**: let `write_report()` write the incident report in Hindi or Kannada.
- **Tests**: pytest cases for `verify_iocs()` and `patch_status()`.
- **Local model backend**: run Gemma 4 offline via Ollama as an alternative to the Gemini API.

## Rules

- Defensive only: no exploit code, no malware samples, no scanning tools aimed at systems you don't own.
- Keep detectors explainable (each alert must say *why*).
- Never commit `.env` or real customer logs.
- Follow the [MLH Code of Conduct](https://mlh.io/code-of-conduct).
