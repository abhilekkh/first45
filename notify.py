"""First45 - notifications.

Sends a push alert to a phone through ntfy (open-source push service, ntfy.sh)
and/or a Discord webhook. Both are optional: set NTFY_TOPIC and/or
DISCORD_WEBHOOK in .env. Without them, alerts only show in the app.
"""
from __future__ import annotations

import os

import requests
from dotenv import load_dotenv

load_dotenv()


def send_alert(title: str, message: str, priority: str = "high") -> list[str]:
    """Returns a list of channels the alert went to (empty if none configured)."""
    sent = []
    topic = os.getenv("NTFY_TOPIC", "").strip()
    if topic:
        try:
            requests.post(f"https://ntfy.sh/{topic}", data=message.encode("utf-8"),
                          headers={"Title": title, "Priority": priority, "Tags": "rotating_light"},
                          timeout=8)
            sent.append("ntfy")
        except requests.RequestException:
            pass
    hook = os.getenv("DISCORD_WEBHOOK", "").strip()
    if hook:
        try:
            requests.post(hook, json={"content": f"**{title}**\n{message}"[:1900]}, timeout=8)
            sent.append("discord")
        except requests.RequestException:
            pass
    return sent
